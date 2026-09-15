package h2tunnel_test

// =========================================
// Event callback system tests:
//   - typed events dispatched in order (Established / Died / Reconnecting / TargetDenied);
//   - server-side events (Session* / AuthRejected / TargetDenied);
//   - callback panics are recovered and do not affect the engine;
//   - conn.Done()/Err() (context style).
// =========================================

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

// eventCollector is a concurrency-safe event collector.
type eventCollector struct {
	mu sync.Mutex
	s  []string
}

func (c *eventCollector) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.s = append(c.s, s)
}

func (c *eventCollector) count(prefix string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, s := range c.s {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

func (c *eventCollector) waitCount(prefix string, want int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.count(prefix) >= want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// startEventedServer starts a TLS tunnel server with event collection
// (echo target) and returns the server and its https endpoint.
func startEventedServer(t *testing.T, collector *eventCollector) (*h2tunnel.Server, string) {
	t.Helper()
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(echoListener)
	t.Cleanup(func() { _ = echoListener.Close() })

	auth, _ := h2tunnel.NewTokenAuthenticator("evt-token")
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
		EventHandler: func(ev h2tunnel.ServerEvent) {
			collector.add(fmt.Sprintf("%s|%s|%s", ev.Kind, ev.SessionID, ev.Target))
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
	return server, "https://" + ln.Addr().String()
}

func newEventedClient(t *testing.T, endpoint string, events *eventCollector, token string) *h2tunnel.Client {
	t.Helper()
	credentials, err := h2tunnel.NewTokenCredentials(token)
	if err != nil {
		t.Fatal(err)
	}
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    endpoint,
		Transport:   h2tunnel.TransportH2,
		TLSConfig:   &tls.Config{InsecureSkipVerify: true},
		Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetEventHandler(func(ev h2tunnel.ClientEvent) {
		events.add(fmt.Sprintf("%s|%s|%s|%s|%v", ev.Kind, ev.Target, ev.Reason, ev.Network, ev.Err))
	})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestClientEventsLifecycle verifies the Established event, the conn Done/Err
// semantics and panic recovery (a callback panic does not stop the tunnel from
// sending and receiving).
func TestClientEventsLifecycle(t *testing.T) {
	_, endpoint := startEventedServer(t, &eventCollector{})

	var events eventCollector
	client := newEventedClient(t, endpoint, &events, "evt-token")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// context style: while the session is alive, Done is not closed and Err is nil.
	if tc, ok := conn.(interface {
		Done() <-chan struct{}
		Err() error
	}); !ok {
		t.Fatal("conn does not expose Done/Err")
	} else {
		select {
		case <-tc.Done():
			t.Fatal("conn done closed while session alive")
		default:
		}
		if err := tc.Err(); err != nil {
			t.Fatalf("conn err while session alive: %v", err)
		}
	}

	// callback panic: must not affect the engine or subsequent events.
	client.SetEventHandler(func(ev h2tunnel.ClientEvent) {
		events.add(fmt.Sprintf("%s|panic-handler", ev.Kind))
		panic("boom from handler")
	})

	payload := []byte("event-echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("echo after panicking handler: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: %q", got)
	}

	if !events.waitCount(string(h2tunnel.EventTunnelEstablished), 1, 5*time.Second) {
		t.Fatal("no TunnelEstablished event dispatched")
	}
}

// TestClientOptionsEventHandler verifies that ClientOptions.EventHandler
// injected at construction time takes effect (it used to be a dead field:
// only the runtime SetEventHandler received events).
func TestClientOptionsEventHandler(t *testing.T) {
	_, endpoint := startEventedServer(t, &eventCollector{})

	var events eventCollector
	credentials, err := h2tunnel.NewTokenCredentials("evt-token")
	if err != nil {
		t.Fatal(err)
	}
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    endpoint,
		Transport:   h2tunnel.TransportH2,
		TLSConfig:   &tls.Config{InsecureSkipVerify: true},
		Credentials: credentials,
		EventHandler: func(ev h2tunnel.ClientEvent) {
			events.add(fmt.Sprintf("%s|%s", ev.Kind, ev.Target))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	if !events.waitCount(fmt.Sprintf("%s|echo", h2tunnel.EventTunnelEstablished), 1, 5*time.Second) {
		t.Fatal("ClientOptions.EventHandler never fired (dead field)")
	}
}

// TestClientTunnelDiedOnPeerFIN verifies that a normal peer close (peer FIN)
// produces the tunnel-died event + a closed Done + a nil Err (graceful termination).
func TestClientTunnelDiedOnPeerFIN(t *testing.T) {
	_, endpoint := startEventedServer(t, &eventCollector{})

	var events eventCollector
	client := newEventedClient(t, endpoint, &events, "evt-token")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if !events.waitCount(string(h2tunnel.EventTunnelEstablished), 1, 5*time.Second) {
		t.Fatal("no TunnelEstablished event")
	}

	// Normal peer close: write EOF and close the app-side conn → sendLoop
	// sends END → executeResumableTunnelContext returns nil → Done closes,
	// Err is nil, and the TunnelDied(peer FIN) event is dispatched.
	tc, ok := conn.(interface {
		Done() <-chan struct{}
		Err() error
	})
	if !ok {
		t.Fatal("conn does not expose Done/Err")
	}
	_ = conn.Close()

	select {
	case <-tc.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("conn Done not closed after peer FIN")
	}
	if err := tc.Err(); err != nil {
		t.Fatalf("conn Err on clean close = %v, want nil", err)
	}
	if !events.waitCount(string(h2tunnel.EventTunnelDied), 1, 5*time.Second) {
		t.Fatal("no TunnelDied event")
	}
	if !events.waitCount("tunnel_died|echo|peer FIN", 1, time.Second) {
		t.Fatal("TunnelDied reason should be peer FIN")
	}
}

// TestServerEventsSessionLifecycle verifies the server-side SessionOpened /
// AuthRejected / TargetDenied events.
func TestServerEventsSessionLifecycle(t *testing.T) {
	var clientEvents eventCollector
	var serverEvents eventCollector
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(echoListener)
	defer echoListener.Close()

	auth, _ := h2tunnel.NewTokenAuthenticator("evt-token")
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
		EventHandler: func(ev h2tunnel.ServerEvent) {
			serverEvents.add(fmt.Sprintf("%s|%s|%s", ev.Kind, ev.Target, ev.Principal.ID))
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
	endpoint := "https://" + ln.Addr().String()

	// Valid token + registered service → SessionOpened.
	goodClient := newEventedClient(t, endpoint, &clientEvents, "evt-token")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := goodClient.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !serverEvents.waitCount(string(h2tunnel.ServerEventSessionOpened), 1, 5*time.Second) {
		t.Fatal("no SessionOpened event")
	}

	// Wrong token → server-side AuthRejected.
	badCreds, _ := h2tunnel.NewTokenCredentials("WRONG")
	badClient, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    endpoint,
		Transport:   h2tunnel.TransportH2,
		TLSConfig:   &tls.Config{InsecureSkipVerify: true},
		Credentials: badCreds,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = badClient.Close() })
	if _, err := badClient.DialContext(ctx, h2tunnel.NetworkTCP, "echo"); err == nil {
		t.Fatal("dial with wrong token should fail")
	}
	if !serverEvents.waitCount(string(h2tunnel.ServerEventAuthRejected), 1, 5*time.Second) {
		t.Fatal("no AuthRejected event")
	}

	// Valid token + unregistered target → TargetDenied.
	if _, err := goodClient.DialContext(ctx, h2tunnel.NetworkTCP, "unregistered"); err == nil {
		t.Fatal("dial unregistered target should fail")
	}
	if !serverEvents.waitCount(string(h2tunnel.ServerEventTargetDenied), 1, 5*time.Second) {
		t.Fatal("no TargetDenied event")
	}
}

// Helper: get Done/Err from a tunnel conn (the SDK conn implements both methods).
func doneOf(c interface{ Done() <-chan struct{} }) <-chan struct{} { return c.Done() }

func errOf(c interface{ Err() error }) error { return c.Err() }
