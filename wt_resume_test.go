package h2tunnel

// Resume-after-disconnect verification for WT with resume/2.
//
// Core assertion: after a WebTransport stream drops, reopening a new stream
// with the same X-Session-ID keeps the server-side targetConn alive (no
// redial of the target) and replays the downlink gap starting at the
// clientDownlink reported by the client — i.e. "data resume after
// disconnect", not stopping at session failover.

import (
	"bytes"
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
func dialWTStream(t *testing.T, dialer *webtransport.Transport, reqURL string, sessionID string, target string, clientDownlink uint64, authToken string) *webtransport.Stream {
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

	dialer := &webtransport.Transport{
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

// TestUplinkReplayIsUnrecoverablePastTheWindow shows why the HANDSHAKE-ACK
// watermark is mandatory rather than an optimisation. The client ring is
// bounded (window_kb); once the server's committed offset passes the ring start
// the bytes are gone from memory, so replaying from the zero the client held
// before the fix is a permanent errGap, while replaying from the advertised
// offset succeeds.
func TestUplinkReplayIsUnrecoverablePastTheWindow(t *testing.T) {
	b := newResumeClientRingBuf(1) // 1 KiB recovery window
	for i := 0; i < 2; i++ {
		buf := make([]byte, 1024)
		for j := range buf {
			buf[j] = byte(j % 251)
		}
		b.Append(buf)
	}
	if end := b.WindowEnd(); end != 2048 {
		t.Fatalf("WindowEnd = %d, want 2048", end)
	}

	var stale bytes.Buffer
	if _, err := b.ReplayFrom(0, &stale); !errors.Is(err, errGap) {
		t.Fatalf("ReplayFrom(0) = %d bytes, %v; want errGap — the window rolled past 0", stale.Len(), err)
	}
	var live bytes.Buffer
	if n, err := b.ReplayFrom(1024, &live); err != nil {
		t.Fatalf("ReplayFrom(1024) = %d bytes, %v; want 1024 bytes no error", n, err)
	} else if live.Len() != 1024 {
		t.Fatalf("ReplayFrom(1024) wrote %d bytes, want 1024", live.Len())
	}
}

// TestWTHandshakeAckCarriesTheUplinkWatermark pins the mechanism resume/2 WT
// relies on to reconnect an uplink that has already rolled its ring.
//
// One WT (QUIC) session serves many business streams, so the CONNECT response
// headers — written once per QUIC session — cannot carry the server's committed
// uplink offset, which moves on every stream. The HANDSHAKE-ACK payload does:
// stream1 commits N bytes to the target, and stream2's ACK must advertise N so
// the client replays its ring from there. Without it the client resumes from 0,
// which is a permanent failure once the ring has rolled (see
// TestUplinkReplayIsUnrecoverablePastTheWindow).
func TestWTHandshakeAckCarriesTheUplinkWatermark(t *testing.T) {
	const (
		serverAddr = "127.0.0.1:29745"
		token      = "wt-uplink-watermark-token"
		sent       = 8 * 1024
		frame      = 512
	)
	certFile := "test_cert_wtuplink.pem"
	keyFile := "test_key_wtuplink.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	// Zero segments: writes nothing but holds the socket, so it is a pure sink
	// for the client's uplink and the server's targetConn stays alive.
	targetLn, err := fakeChunkedTarget("127.0.0.1:0", 0, 200)
	if err != nil {
		t.Fatalf("fake target: bind tcp %s: %v — another process owns the port, so no sink exists and the uplink would reach it", "127.0.0.1:0", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })
	targetAddr := targetLn.Addr().String()

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
	waitUDPBound(t, serverAddr, 30*time.Second)

	dialer := &webtransport.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      getDefaultQUICConfig(),
	}
	sessionID := "wt-uplink-watermark-" + fmt.Sprintf("%d", time.Now().UnixNano()%10000)
	headers := resumeWTHeaders(sessionID, targetAddr)
	headers.Set("X-Auth-Token", token)
	_, sess, err := dialer.Dial(context.Background(), "https://"+serverAddr+"/tunnel", headers)
	if err != nil {
		t.Fatalf("WT dial failed: %v", err)
	}
	ctx := context.Background()
	buf := make([]byte, 64*1024)

	// ===== stream1: commit `sent` bytes of uplink to the target =====
	st1, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	if err := writeFrame(st1, resumeFrameHandshake, 0, []byte("0"), 0); err != nil {
		t.Fatalf("write HANDSHAKE: %v", err)
	}
	typ, _, n, err := readFrame(st1, buf)
	if err != nil {
		t.Fatalf("read HANDSHAKE-ACK: %v", err)
	}
	if typ != resumeFrameHandshakeAck {
		t.Fatalf("expect HANDSHAKE-ACK got 0x%02x", typ)
	}
	got1, err := strconv.ParseUint(string(buf[:n]), 10, 64)
	if err != nil {
		t.Fatalf("stream1 ACK payload %q is not a decimal watermark: %v", buf[:n], err)
	}
	if got1 != 0 {
		t.Fatalf("stream1 ACK watermark = %d, want 0 (nothing committed yet)", got1)
	}

	for seq := uint64(0); seq < sent; seq += uint64(frame) {
		payload := make([]byte, frame)
		for i := range payload {
			payload[i] = byte((int(seq) + i) % 251)
		}
		if err := writeFrame(st1, resumeFrameData, seq, payload, 0); err != nil {
			t.Fatalf("write DATA frame seq=%d: %v", seq, err)
		}
	}
	_ = st1.Close()
	// Let the server commit the last frames to the target and clear the
	// activeWriter before stream2 snapshots the watermark.
	time.Sleep(300 * time.Millisecond)

	// ===== stream2: the ACK must advertise the offset stream1 committed =====
	st2, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	defer st2.Close()
	if err := writeFrame(st2, resumeFrameHandshake, 0, []byte("0"), 0); err != nil {
		t.Fatalf("write HANDSHAKE: %v", err)
	}
	typ, _, n, err = readFrame(st2, buf)
	if err != nil {
		t.Fatalf("read HANDSHAKE-ACK: %v", err)
	}
	if typ != resumeFrameHandshakeAck {
		t.Fatalf("expect HANDSHAKE-ACK got 0x%02x", typ)
	}
	got, err := strconv.ParseUint(string(buf[:n]), 10, 64)
	if err != nil {
		t.Fatalf("stream2 ACK payload %q is not a decimal watermark: %v", buf[:n], err)
	}
	if got != sent {
		t.Fatalf("stream2 ACK watermark = %d, want %d (the uplink offset stream1 committed)", got, sent)
	}
	t.Logf("✅ WT HANDSHAKE-ACK advertises the committed uplink watermark: %d bytes", got)
}
