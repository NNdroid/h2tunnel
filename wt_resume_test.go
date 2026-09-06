package h2tunnel

// WT 接入 resume/2 的断线续传验证。
//
// 核心断言：WebTransport stream 断开后，用同一 X-Session-ID 重开新 stream，
// 服务端 targetConn 保留（不重拨目标），并从客户端上报的 clientDownlink 处
// 补发下行缺口——即「断线数据续传」而非仅止步于会话 failover。

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// fakeChunkedTarget 接受连接后持续写入 chunkCount 段固定序列（每段 chunk 字节），
// 用于验证下行续传的连续性（各段内容唯一可定位）。
func fakeChunkedTarget(addr string, chunkCount, chunk int) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				// 注意：写完 chunkCount 段后不能立刻 Close，否则服务端 downlinkPump
				// 读到 EOF 会关掉 targetConn（会话判死），stream2 便无法续传。
				// 模拟持续在线目标：写完数据段后挂起，直到对端关闭。
				defer conn.Close()
				for i := 0; i < chunkCount; i++ {
					seg := make([]byte, chunk)
					for j := range seg {
						seg[j] = byte((i*chunk+j)%251 + 1)
					}
					if _, wErr := conn.Write(seg); wErr != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
				// 保持连接存活（读侧检测对端关闭），模拟长连接目标。
				one := make([]byte, 1)
				for {
					if _, rErr := conn.Read(one); rErr != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln, nil
}

// resumeWTHeaders 构造带 resume/2 A 层协商头 + 目标/鉴权头的 WT CONNECT 请求头。
func resumeWTHeaders(sessionID string, target string) http.Header {
	h := make(http.Header)
	h.Set("Protocol", "webtransport")
	h.Set("X-Tunnel-Proto", resumeFrameTypeResume)
	h.Set("X-Session-ID", sessionID)
	h.Set("X-Resume-Version", "2")
	h.Set("X-Resume-Caps", "replay")
	h.Set("X-Resume-Params", "window_kb=256;handshake_ack_timeout=3000;keepalive_interval=15")
	h.Set("X-Target", target)
	h.Set("X-Network", "tcp")
	return h
}

// dialWTStream 建立一条 WT stream 并完成 B 层握手（HANDSHAKE payload 携带
// clientDownlink）。返回 stream。
func dialWTStream(t *testing.T, dialer *webtransport.Dialer, reqURL string, sessionID string, target string, clientDownlink uint64, authToken string) *webtransport.Stream {
	t.Helper()
	hdr := resumeWTHeaders(sessionID, target)
	hdr.Set("X-Auth-Token", authToken)
	_, sess, err := dialer.Dial(context.Background(), reqURL, hdr)
	if err != nil {
		t.Fatalf("WT dial failed: %v", err)
	}
	stream, err := sess.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	// B 层握手：发 HANDSHAKE（payload 带 clientDownlink），等 HANDSHAKE-ACK。
	payload := strconv.FormatUint(clientDownlink, 10)
	if err := writeFrame(stream, resumeFrameHandshake, 0, []byte(payload), 0); err != nil {
		t.Fatalf("write HANDSHAKE: %v", err)
	}
	buf := make([]byte, 4096)
	typ, _, _, err := readFrame(stream, buf)
	if err != nil {
		t.Fatalf("read HANDSHAKE-ACK: %v", err)
	}
	if typ != resumeFrameHandshakeAck {
		t.Fatalf("expect HANDSHAKE-ACK got 0x%02x", typ)
	}
	return stream
}

// readDataFrames 从 stream 读 DATA 帧直到读到 expectBytes 字节。校验 seq 连续。
// baseSeq 是本条流下行的起始坐标系（stream1=0，续传流=clientDownlink）。
func readDataFrames(t *testing.T, stream io.Reader, baseSeq uint64, expectBytes int) []byte {
	t.Helper()
	buf := make([]byte, 64*1024)
	var out []byte
	for len(out) < expectBytes {
		seq, n, err := readResumeFrame(stream, buf)
		if errors.Is(err, errResumeEndFrame) {
			return out
		}
		if err != nil {
			t.Fatalf("read DATA frame: %v (got %d bytes)", err, len(out))
		}
		if seq != baseSeq+uint64(len(out)) {
			t.Fatalf("seq gap: expect %d got %d", baseSeq+uint64(len(out)), seq)
		}
		out = append(out, buf[:n]...)
	}
	return out[:expectBytes]
}

// TestWTResumeReconnect 验证：stream1 读部分下行后关闭，stream2 用同一 session id
// 从 clientDownlink 续传，整体序列连续无缺口无重复。
func TestWTResumeReconnect(t *testing.T) {
	certFile := "test_cert_wtresume.pem"
	keyFile := "test_key_wtresume.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	const (
		chunkCount = 30
		chunk      = 200
		firstRead  = 25 // stream1 读前 25 段（5000 字节）
		targetAddr = "127.0.0.1:29700"
		serverAddr = "127.0.0.1:29743"
		token      = "wt-resume-token"
	)
	serverURL := "https://" + serverAddr

	if _, err := fakeChunkedTarget(targetAddr, chunkCount, chunk); err != nil {
		t.Fatalf("fake target: %v", err)
	}

	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportWT,
		Authenticator: tokenAuth(token),
		LogLevel:      "error",
		SessionWindow: 256,
		Network:       "all",
	})
	// WT-only 服务端不开 TCP listener（requiredListeners 对 wt 只返回 QUIC），
	// 且 fakeChunkedTarget 不回显 —— 这里只验证 QUIC 端口已绑定。
	waitUDPBound(t, serverAddr, 30*time.Second)

	dialer := &webtransport.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      getDefaultQUICConfig(),
	}
	sessionID := "wt-resume-sess-" + fmt.Sprintf("%d", time.Now().UnixNano()%10000)

	// ===== stream1：读前 firstRead 段 =====
	st1 := dialWTStream(t, dialer, serverURL+"/tunnel", sessionID, targetAddr, 0, token)
	part1 := readDataFrames(t, st1, 0, firstRead*chunk)
	if len(part1) != firstRead*chunk {
		t.Fatalf("stream1 read %d bytes, want %d", len(part1), firstRead*chunk)
	}
	clientDownlink := uint64(len(part1))
	_ = st1.Close()
	// 让服务端感知 stream 断开、清空 activeWriter，保留 targetConn 与 ring。
	time.Sleep(300 * time.Millisecond)

	// ===== stream2：同 session id，从 clientDownlink 续传 =====
	st2 := dialWTStream(t, dialer, serverURL+"/tunnel", sessionID, targetAddr, clientDownlink, token)
	defer st2.Close()
	rest := readDataFrames(t, st2, clientDownlink, (chunkCount-firstRead)*chunk)
	if len(rest) != (chunkCount-firstRead)*chunk {
		t.Fatalf("stream2 read %d bytes, want %d", len(rest), (chunkCount-firstRead)*chunk)
	}

	// 拼接验证整体序列连续无重复。
	full := append(append([]byte{}, part1...), rest...)
	for i := range full {
		expect := byte(i%251 + 1)
		if full[i] != expect {
			t.Fatalf("continuity broken at byte %d: got %d want %d", i, full[i], expect)
		}
	}
	t.Logf("✅ WT 断线续传成功: stream1=%dB, stream2=%dB, total=%dB, 无缺口无重复",
		len(part1), len(rest), len(full))
}
