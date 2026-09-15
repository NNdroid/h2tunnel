package h2tunnel_test

// =========================================
// utls fingerprint camouflage tests:
//   - end-to-end: camouflage fingerprints (chrome/firefox/…) dial the tunnel and echo;
//   - validation: illegal combinations (h2c/h3/…) and unknown names fail right at NewClient;
//   - authenticity: the server really observes utls Chrome traits (GREASE),
//     proving the data plane actually goes through utls rather than silently
//     falling back to native crypto/tls.
// =========================================

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

func newUtlsClient(t *testing.T, endpoint, fingerprint string) *h2tunnel.Client {
	t.Helper()
	credentials, err := h2tunnel.NewTokenCredentials("selfheal-token")
	if err != nil {
		t.Fatal(err)
	}
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:        endpoint,
		Transport:       h2tunnel.TransportH2,
		TLSConfig:       insecureTLS(),
		Credentials:     credentials,
		UtlxFingerprint: fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestUtlsFingerprintsEndToEnd dials one real tunnel per fingerprint and verifies the echo round trip.
func TestUtlsFingerprintsEndToEnd(t *testing.T) {
	endpoint := startAuthlessEchoServer(t)
	for _, fp := range []string{"chrome", "firefox", "edge", "safari", "ios", "qq", " Chrome "} {
		t.Run(strings.TrimSpace(fp), func(t *testing.T) {
			client := newUtlsClient(t, endpoint, fp)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
			if err != nil {
				t.Fatalf("dial with fingerprint %q: %v", fp, err)
			}
			defer conn.Close()
			payload := []byte("utls-" + strings.TrimSpace(fp) + "-echo")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if string(got) != string(payload) {
				t.Fatalf("echo mismatch: %q", got)
			}
		})
	}
}

// TestUtlsValidation rejects misconfigured combinations and unknown names.
func TestUtlsValidation(t *testing.T) {
	credentials, _ := h2tunnel.NewTokenCredentials("x")
	cases := []struct {
		name     string
		options  h2tunnel.ClientOptions
		contains string
	}{
		{
			name: "h2c_no_tls",
			options: h2tunnel.ClientOptions{
				Endpoint: "http://127.0.0.1:1", Transport: h2tunnel.TransportH2C,
				Credentials: credentials, UtlxFingerprint: "chrome",
			},
			contains: "no TLS to camouflage",
		},
		{
			name: "quic_family",
			options: h2tunnel.ClientOptions{
				Endpoint: "https://127.0.0.1:1", Transport: h2tunnel.TransportH3,
				Credentials: credentials, UtlxFingerprint: "chrome",
			},
			contains: "QUIC performs TLS internally",
		},
		{
			name: "webtransport",
			options: h2tunnel.ClientOptions{
				Endpoint: "https://127.0.0.1:1", Transport: h2tunnel.TransportWebTransport,
				Credentials: credentials, UtlxFingerprint: "chrome",
			},
			contains: "QUIC performs TLS internally",
		},
		{
			name: "unknown_fingerprint",
			options: h2tunnel.ClientOptions{
				Endpoint: "https://127.0.0.1:1", Transport: h2tunnel.TransportH2,
				Credentials: credentials, UtlxFingerprint: "netscape",
			},
			contains: "unknown UtlxFingerprint",
		},
		{
			// The 360 utls preset (Auto=7.5) only offers http/1.1 in ALPN, which
			// cannot agree with an h2-only tunnel, so it is not included.
			name: "360_no_h2",
			options: h2tunnel.ClientOptions{
				Endpoint: "https://127.0.0.1:1", Transport: h2tunnel.TransportH2,
				Credentials: credentials, UtlxFingerprint: "360",
			},
			contains: "unknown UtlxFingerprint",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h2tunnel.NewClient(tc.options)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error %q missing %q", err, tc.contains)
			}
		})
	}
}

// TestUtlsChromeHelloCarriesGREASE proves the data plane really dials with
// utls: the server-side ClientHello shows a GREASE cipher suite (Go's
// crypto/tls never sends it, utls.HelloChrome always does) and the request
// carries the camouflaged User-Agent on the wire — not Go's transport default
// "Go-http-client/2.0", which would contradict the Chrome TLS fingerprint.
func TestUtlsChromeHelloCarriesGREASE(t *testing.T) {
	const wantUA = "Mozilla/5.0 (Linux; Android 15; SM-A057G Build/AP3A.240905.015.A2; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.7922.202 Mobile Safari/537.36 w2n/Android"
	var mu sync.Mutex
	sawGREASE := false
	capturedUA := ""
	tlsConfig, err := h2tunnel.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{"h2"}
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		defer mu.Unlock()
		for _, cs := range hello.CipherSuites {
			if cs&0x0f0f == 0x0a0a {
				sawGREASE = true
				break
			}
		}
		return nil, nil
	}
	// Bare https/h2 server: a 404 suffices (handshake + one request round trip).
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedUA = r.UserAgent()
		mu.Unlock()
		http.Error(w, "no", http.StatusNotFound)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, tlsConfig)
	go func() { _ = server.Serve(tlsLn) }()
	t.Cleanup(func() { _ = server.Close() })

	// Dial 3 times: GREASE in Chrome_Auto is a stable trait, but the extra tries
	// guard against any flakiness in extreme cases; native crypto/tls dialing
	// would never capture GREASE.
	for i := 0; i < 3; i++ {
		client := newUtlsClient(t, "https://"+ln.Addr().String(), "chrome")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
		cancel()
		if err == nil {
			t.Fatal("bare server (no tunnel) should reject the resume request")
		}
		var te *h2tunnel.TunnelError
		if !errors.As(err, &te) {
			t.Fatalf("expected TunnelError from bare server, got %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !sawGREASE {
		t.Fatal("server never saw a GREASE ClientHello — utls dial path is not active")
	}
	if capturedUA != wantUA {
		t.Fatalf("wire User-Agent = %q, want %q", capturedUA, wantUA)
	}
}
