package h2tunnel_test

// =========================================
// MASQUE-over-h2 (extended CONNECT) end-to-end:
//   - MASQUE server with a TCP-only listener (listenerPlan: masque → tcp=optional);
//   - client MasqueALPN="h2" connects the h2 leg directly; the auto lane
//     pins a downgrade when UDP is unreachable.
// x/net's extended CONNECT reads GODEBUG at package init, so t.Setenv is
// already too late → skip when the environment is missing (the test job in
// test.yml already injects it into the process env).
// =========================================

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

const masqueH2Token = "masque-h2-token"

func extendedConnectEnabled() bool {
	return strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1")
}

// startTCPOnlyMasqueServer starts a MASQUE server with a TCP-only listener + echo target.
func startTCPOnlyMasqueServer(t *testing.T) string {
	t.Helper()
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(echoListener)
	t.Cleanup(func() { _ = echoListener.Close() })

	dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"echo": {Network: h2tunnel.NetworkTCP, Address: echoListener.Addr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := h2tunnel.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportMASQUE},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP, h2tunnel.NetworkUDP},
		TLSConfig:     tlsConfig,
		Authenticator: mustAuthenticator(masqueH2Token),
		Dialer:        dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(h2tunnel.Listeners{TCP: ln}) }() // no QUIC: legal (optional stack)
	t.Cleanup(func() { _ = server.Close() })
	return "https://" + ln.Addr().String()
}

func newMasqueClient(t *testing.T, endpoint, alpn string) *h2tunnel.Client {
	t.Helper()
	credentials, err := h2tunnel.NewTokenCredentials(masqueH2Token)
	if err != nil {
		t.Fatal(err)
	}
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    endpoint,
		Transport:   h2tunnel.TransportMASQUE,
		TLSConfig:   insecureTLS(),
		Credentials: credentials,
		Tuning:      h2tunnel.ClientTuning{MasqueALPN: alpn},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestMasqueOverH2Pinned explicit h2: must succeed directly against a TCP-only
// server (never touching UDP).
func TestMasqueOverH2Pinned(t *testing.T) {
	if !extendedConnectEnabled() {
		t.Skip("requires GODEBUG=http2xconnect=1 at process start (x/net init reads it once)")
	}
	endpoint := startTCPOnlyMasqueServer(t)
	client := newMasqueClient(t, endpoint, "h2")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		t.Fatalf("masque-over-h2 dial: %v", err)
	}
	defer conn.Close()
	payload := []byte("masque-over-h2-roundtrip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: %q", got)
	}
}

// TestMasqueAutoDowngradesToH2 TCP-only server + auto: one h3 failure pins h2.
func TestMasqueAutoDowngradesToH2(t *testing.T) {
	if !extendedConnectEnabled() {
		t.Skip("requires GODEBUG=http2xconnect=1 at process start (x/net init reads it once)")
	}
	endpoint := startTCPOnlyMasqueServer(t)
	client := newMasqueClient(t, endpoint, "")

	// The lane/attempt layers have backoff; allow enough time for the downgrade to happen.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var conn net.Conn
	var err error
	for i := 0; i < 20; i++ {
		conn, err = client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("auto downgrade never succeeded: %v", err)
		case <-time.After(300 * time.Millisecond):
		}
	}
	if err != nil {
		t.Fatalf("auto downgrade dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
}

// TestMasqueALPNValidation parameter validity: masque-only + allowed value set.
func TestMasqueALPNValidation(t *testing.T) {
	credentials, _ := h2tunnel.NewTokenCredentials("x")
	cases := []struct {
		name      string
		transport h2tunnel.Transport
		alpn      string
		wantErr   string
	}{
		{"non-masque transport", h2tunnel.TransportH2, "h2", "only meaningful with Transport=masque"},
		{"unknown value", h2tunnel.TransportMASQUE, "h4", "must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
				Endpoint:    "https://127.0.0.1:1",
				Transport:   tc.transport,
				TLSConfig:   insecureTLS(),
				Credentials: credentials,
				Tuning:      h2tunnel.ClientTuning{MasqueALPN: tc.alpn},
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
