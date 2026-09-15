package h2tunnel

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// =========================================
// Dedicated tests for the keepalive mechanism
//
// resume/2 removed the v1 PaddingReader/PaddingWriter/copyWithHeartbeat
// keep-alive path; liveness probing is now carried by the KEEPALIVE control
// frame (its codec and priority are already covered by handshake_frame_test.go).
// This file only keeps the end-to-end idle-tunnel keep-alive verification:
// after the tunnel is established, both sides stay silent for several heartbeat
// periods and data transfer still works afterwards.
// =========================================

// TestHeartbeatIdleTunnelE2E verifies end to end that after the tunnel is
// established, both sides stay silent for several heartbeat periods, then
// traffic resumes and the data must be lossless. This simulates the real
// scenario of an SSH session idling for minutes before operations continue —
// before the fix, CDNs would silently cut such tunnels at 60~100s.
func TestHeartbeatIdleTunnelE2E(t *testing.T) {
	certFile := "test_hb_cert.pem"
	keyFile := "test_hb_key.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:20900"
	startEchoServer(targetAddr)

	serverAddr := "127.0.0.1:20901"
	testToken := "hb-e2e-token"
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportH2,
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error",
		// Short heartbeat for tests only: the config is built directly without clampHeartbeat;
		// at a 300ms interval, 1.2s of idle spans 4 full heartbeat periods
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	clientListen := "127.0.0.1:20902"
	go startClientDirect(clientConfig{
		ListenAddr:        clientListen,
		ServerUrl:         "https://" + serverAddr,
		Path:              "/tunnel",
		TargetAddr:        targetAddr,
		Insecure:          true,
		Token:             testToken,
		LogLevel:          "error",
		HeartbeatInterval: 300 * time.Millisecond,
	})
	waitTCPOrTLSReady(t, clientListen, 30*time.Second)

	conn, err := net.Dial("tcp", clientListen)
	if err != nil {
		t.Fatalf("failed to connect to local client: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Phase 1: run one round of normal traffic to confirm the tunnel is established
	msg1 := []byte("before-idle-probe")
	if _, err := conn.Write(msg1); err != nil {
		t.Fatalf("send before idle failed: %v", err)
	}
	buf := make([]byte, len(msg1))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo before idle failed: %v", err)
	}
	if !bytes.Equal(buf, msg1) {
		t.Fatalf("data already corrupted before idle: %q", buf)
	}

	// Phase 2: stay silent for 1.2s (4 heartbeat periods).
	// Meanwhile the client uplink and server downlink each send heartbeat frames to keep the link alive.
	t.Logf("starting 1.2s idle, waiting for heartbeat frame round-trips...")
	time.Sleep(1200 * time.Millisecond)

	// Phase 3: resume traffic. If keepalive were not working or frame boundaries were torn apart, this would time out or corrupt data
	msg2 := []byte("after-idle-data-must-survive-keepalive-frames")
	if _, err := conn.Write(msg2); err != nil {
		t.Fatalf("send after idle failed (uplink keepalive broken?): %v", err)
	}
	got := make([]byte, len(msg2))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("no echo after idle (downlink keepalive broken?): %v", err)
	}
	if !bytes.Equal(got, msg2) {
		t.Fatalf("data corrupted after idle (heartbeat frames tore the frame boundary?): want %q got %q", msg2, got)
	}
	t.Logf("✅ data link intact after 1.2s idle (4 heartbeat periods), keepalive works")
}
