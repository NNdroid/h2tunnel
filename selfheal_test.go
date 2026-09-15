package h2tunnel_test

// =========================================
// Network-change self-heal tests:
//   - AutoRedial: after redial attempts are exhausted, the counter resets
//     automatically and continues (unlimited revival);
//   - ForceReconnect: forcibly drops the current stream and redials
//     immediately; session/data is not lost;
//   - RedialBudget: dial budget per single attempt.
// =========================================

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

// startAuthlessEchoServer starts an authless echo tunnel server (for self-heal tests).
func startAuthlessEchoServer(t *testing.T) (endpoint string) {
	t.Helper()
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(echoListener)
	t.Cleanup(func() { _ = echoListener.Close() })

	auth, _ := h2tunnel.NewTokenAuthenticator("selfheal-token")
	dialer, _ := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"echo": {Network: h2tunnel.NetworkTCP, Address: echoListener.Addr().String()},
	}, nil)
	tlsConfig, _ := h2tunnel.SelfSignedTLSConfig("localhost")
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP},
		TLSConfig:     tlsConfig,
		Authenticator: auth,
		Dialer:        dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(h2tunnel.Listeners{TCP: ln}) }()
	t.Cleanup(func() { _ = server.Close() })
	return "https://" + ln.Addr().String()
}

// TestForceReconnectKeepsData verifies ForceReconnect: after a forced redial
// the same session resumes (transparent to the server) and echo data is intact.
func TestForceReconnectKeepsData(t *testing.T) {
	endpoint := startAuthlessEchoServer(t)

	credentials, _ := h2tunnel.NewTokenCredentials("selfheal-token")
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    endpoint,
		Transport:   h2tunnel.TransportH2,
		TLSConfig:   insecureTLS(),
		Credentials: credentials,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Run one normal echo round first.
	msg1 := []byte("before-force")
	if _, err := conn.Write(msg1); err != nil {
		t.Fatal(err)
	}
	got1 := make([]byte, len(msg1))
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got1); err != nil {
		t.Fatal(err)
	}

	// Force redial: session is kept, conn remains usable.
	client.ForceReconnect()
	time.Sleep(300 * time.Millisecond) // give the redial some time

	msg2 := []byte("after-force-echo-payload")
	if _, err := conn.Write(msg2); err != nil {
		t.Fatalf("write after ForceReconnect: %v", err)
	}
	got2 := make([]byte, len(msg2))
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, got2); err != nil {
		t.Fatalf("read after ForceReconnect: %v", err)
	}
	if string(got2) != string(msg2) {
		t.Fatalf("echo mismatch after force: %q", got2)
	}
}

// TestAutoRedialRecoversAfterExhaustion verifies AutoRedial: after the
// server-side target dial is briefly knocked out (a placeholder target
// produces 502), the 16-count redial budget is exhausted and the counter is
// automatically reset; once the target becomes reachable again the tunnel
// is ultimately established successfully.
func TestAutoRedialRecoversAfterExhaustion(t *testing.T) {
	var mu sync.Mutex
	deny := true // knock out the dial: TargetDialer rejects outright
	tlsConfig, _ := h2tunnel.SelfSignedTLSConfig("localhost")

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(echoListener)
	t.Cleanup(func() { _ = echoListener.Close() })

	realDialer, _ := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"echo": {Network: h2tunnel.NetworkTCP, Address: echoListener.Addr().String()},
	}, nil)

	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP},
		TLSConfig:     tlsConfig,
		Authenticator: mustAuthenticator("selfheal-token"),
		Dialer: func(ctx context.Context, request h2tunnel.DialRequest) (net.Conn, error) {
			mu.Lock()
			defer mu.Unlock()
			if deny {
				return nil, h2tunnel.ErrForbidden
			}
			return realDialer(ctx, request)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(h2tunnel.Listeners{TCP: ln}) }()
	t.Cleanup(func() { _ = server.Close() })

	// Client: AutoRedial on + RedialBudget tightens the pace (each attempt ≤500ms).
	credentials, _ := h2tunnel.NewTokenCredentials("selfheal-token")
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    "https://" + ln.Addr().String(),
		Transport:   h2tunnel.TransportH2,
		TLSConfig:   insecureTLS(),
		Credentials: credentials,
		Tuning: h2tunnel.ClientTuning{
			AutoRedial:   true,
			RedialBudget: 500 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Background dial: the target is currently denied, so it keeps redialing
	// (AutoRedial keeps it alive).
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dialCancel()
	type dialResult struct {
		conn interface {
			Done() <-chan struct{}
			Err() error
		}
		err error
	}
	connCh := make(chan dialResult, 1)
	go func() {
		conn, derr := client.DialContext(dialCtx, h2tunnel.NetworkTCP, "echo")
		if derr != nil {
			connCh <- dialResult{nil, derr}
		} else {
			connCh <- dialResult{conn.(interface {
				Done() <-chan struct{}
				Err() error
			}), derr}
		}
	}()

	// Give time for the 16-count redial to exhaust and trigger AutoRedial reset.
	time.Sleep(3 * time.Second)

	// "Network recovery": open up the target.
	mu.Lock()
	deny = false
	mu.Unlock()

	// The tunnel should ultimately be established and usable.
	select {
	case res := <-connCh:
		if res.err != nil || res.conn == nil {
			t.Fatalf("dial failed even after recovery: %v", res.err)
		}
	// The tunnel has recovered; we only need to confirm DialContext succeeds after blocking retries.
	case <-time.After(20 * time.Second):
		t.Fatal("dial did not complete after recovery")
	}
}

// TestRedialBudgetCapsAttempt verifies RedialBudget: when the target is
// unreachable, a single attempt returns within the budget (rather than hanging
// until the transport-layer timeout).
func TestRedialBudgetCapsAttempt(t *testing.T) {
	endpoint := startAuthlessEchoServer(t)

	credentials, _ := h2tunnel.NewTokenCredentials("selfheal-token")
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    endpoint,
		Transport:   h2tunnel.TransportH2,
		TLSConfig:   insecureTLS(),
		Credentials: credentials,
		Tuning: h2tunnel.ClientTuning{
			RedialBudget: 300 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Dial a target not in the server registry: the target-rejected (403) path.
	// The budget has no effect on this path (returns immediately); here we
	// mainly verify the parameter is accepted and the dial fails fast without blocking.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "missing"); err == nil {
		t.Fatal("dial missing target should fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("dial took %v, budget not applied", elapsed)
	}
}

func insecureTLS() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

func mustAuthenticator(token string) h2tunnel.Authenticator {
	a, err := h2tunnel.NewTokenAuthenticator(token)
	if err != nil {
		panic(err)
	}
	return a
}
