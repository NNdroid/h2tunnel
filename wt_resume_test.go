package h2tunnel

// Resume-after-disconnect verification for WT with resume/2.
//
// Core assertion: after a WebTransport stream drops, reopening a new stream
// with the same X-Session-ID keeps the server-side targetConn alive (no
// redial of the target) and replays the downlink gap starting at the
// clientDownlink reported by the client — i.e. "data resume after
// disconnect", not stopping at session failover.

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

// fakeChunkedTarget keeps writing chunkCount segments of a fixed sequence
// (each chunk bytes) after accepting a connection, used to verify downlink
// resume continuity (each segment's content is uniquely identifiable).
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
				// Note: do not Close right after writing the chunkCount segments, otherwise the
				// server-side downlinkPump sees EOF and closes targetConn (session declared dead),
				// and stream2 could not resume. Simulate an always-online target: hang after
				// writing the data segments until the peer closes.
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
				// Keep the connection alive (the read side detects peer close), simulating a long-lived target.
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

// resumeWTHeaders builds WT CONNECT request headers with the resume/2 layer-A
// negotiation headers + target/auth headers.
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

// dialWTStream establishes a WT stream and completes the layer-B handshake
// (the HANDSHAKE payload carries clientDownlink). Returns the stream.
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
	// Layer-B handshake: send HANDSHAKE (payload carries clientDownlink), wait for HANDSHAKE-ACK.
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

// readDataFrames reads DATA frames from the stream until expectBytes bytes
// are read, verifying seq continuity. baseSeq is the downlink coordinate
// origin for this stream (stream1=0, resume stream=clientDownlink).
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

// TestWTResumeReconnect verifies: stream1 closes after reading part of the
// downlink, stream2 resumes from clientDownlink with the same session id, and
// the overall sequence is contiguous with no gaps or duplicates.
func TestWTResumeReconnect(t *testing.T) {
	certFile := "test_cert_wtresume.pem"
	keyFile := "test_key_wtresume.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	const (
		chunkCount = 30
		chunk      = 200
		firstRead  = 25 // stream1 reads the first 25 segments (5000 bytes)
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
	// A WT-only server opens no TCP listener (requiredListeners returns only QUIC for wt),
	// and fakeChunkedTarget does not echo — here we only verify the QUIC port is bound.
	waitUDPBound(t, serverAddr, 30*time.Second)

	dialer := &webtransport.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      getDefaultQUICConfig(),
	}
	sessionID := "wt-resume-sess-" + fmt.Sprintf("%d", time.Now().UnixNano()%10000)

	// ===== stream1: read the first firstRead segments =====
	st1 := dialWTStream(t, dialer, serverURL+"/tunnel", sessionID, targetAddr, 0, token)
	part1 := readDataFrames(t, st1, 0, firstRead*chunk)
	if len(part1) != firstRead*chunk {
		t.Fatalf("stream1 read %d bytes, want %d", len(part1), firstRead*chunk)
	}
	clientDownlink := uint64(len(part1))
	_ = st1.Close()
	// Let the server notice the stream drop and clear activeWriter, keeping targetConn and the ring.
	time.Sleep(300 * time.Millisecond)

	// ===== stream2: same session id, resume from clientDownlink =====
	st2 := dialWTStream(t, dialer, serverURL+"/tunnel", sessionID, targetAddr, clientDownlink, token)
	defer st2.Close()
	rest := readDataFrames(t, st2, clientDownlink, (chunkCount-firstRead)*chunk)
	if len(rest) != (chunkCount-firstRead)*chunk {
		t.Fatalf("stream2 read %d bytes, want %d", len(rest), (chunkCount-firstRead)*chunk)
	}

	// Concatenate and verify the overall sequence is contiguous with no duplicates.
	full := append(append([]byte{}, part1...), rest...)
	for i := range full {
		expect := byte(i%251 + 1)
		if full[i] != expect {
			t.Fatalf("continuity broken at byte %d: got %d want %d", i, full[i], expect)
		}
	}
	t.Logf("✅ WT resume after disconnect succeeded: stream1=%dB, stream2=%dB, total=%dB, no gaps no duplicates",
		len(part1), len(rest), len(full))
}
