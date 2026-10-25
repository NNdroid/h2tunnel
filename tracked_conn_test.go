package h2tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// connIdentity must deduplicate distinct wrappers of the same socket, because
// that is the only way the h2c leg's bufConn entries can be reclaimed: the
// wrapper carries no Unwrap, so object identity cannot link them. It must also
// keep two real sockets apart, or two live legs would share one tracking row.
func TestConnIdentityDedupesWrappersOfOneSocket(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	if connIdentity(&trackedConn{Conn: serverSide}) != connIdentity(serverSide) {
		t.Fatal("connIdentity must link a wrapper to its target")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dials := make([]net.Conn, 2)
	for i := range dials {
		dials[i], err = net.Dial(ln.Addr().Network(), ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = dials[i].Close() }()
	}
	one := <-accepted
	two := <-accepted
	defer func() { _ = one.Close() }()
	defer func() { _ = two.Close() }()
	if connIdentity(one) == connIdentity(two) {
		t.Fatalf("connIdentity collapsed two live sockets into %q", connIdentity(one))
	}
	if connIdentity(one) == connIdentity(&trackedConn{Conn: two}) {
		t.Fatal("connIdentity linked two unrelated sockets through their wrappers")
	}
}

// TestTrackedConnReleasesOnceOnClose covers the wrapper's two contracts: the
// owner is told exactly once no matter how often Close is called, and Unwrap
// still reaches the real socket so tcpConnFrom can find it for Brutal.
func TestTrackedConnReleasesOnceOnClose(t *testing.T) {
	var mu sync.Mutex
	var released []net.Conn
	release := func(c net.Conn) {
		mu.Lock()
		released = append(released, c)
		mu.Unlock()
	}

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	conn := &trackedConn{Conn: serverSide, release: release}
	if conn.Unwrap() != serverSide {
		t.Fatal("Unwrap did not return the wrapped connection")
	}
	if _, ok := tcpConnFrom(conn); ok {
		t.Fatal("tcpConnFrom accepted a pipe conn; it must fail cleanly")
	}
	_ = conn.Close()
	_ = conn.Close()
	mu.Lock()
	got := len(released)
	var first net.Conn
	if got == 1 {
		first = released[0]
	}
	mu.Unlock()
	if got != 1 {
		t.Fatalf("release called %d times, want 1", got)
	}
	if first != conn {
		t.Fatal("release was called with the wrapped conn's target instead of the wrapper")
	}
}

// TestHTTPConnectionsDrainAfterAH2CLegDies guards against an unbounded map:
// net/http deregisters a conn on StateHijacked and skips setState(StateClosed)
// for it, so no ConnState event ever reports the end of an h2c leg. Only the
// listener-installed wrapper's Close can release the entry, and connIdentity is
// what lets it delete the row http2.ServeConn inserted under the h2c bufConn's
// key. Before the wrapper, every completed h2c leg left permanent entries in
// s.httpConns and s.cfg.brutalSockets.
func TestHTTPConnectionsDrainAfterAH2CLegDies(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()

	authenticator, err := NewTokenAuthenticator("tracked-token")
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := NewStaticServiceDialer(map[string]Service{
		"echo": {Network: networkTCP, Address: echo.Addr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerOptions{
		Transports:    []Transport{TransportH2C},
		Networks:      []Network{networkTCP},
		Authenticator: authenticator,
		Dialer:        dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(Listeners{TCP: ln}) }()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-serveResult; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve returned %v", err)
		}
	})

	// A client that opens and closes h2c legs: each one is hijacked and then
	// torn down, so each must leave the tracking maps empty again.
	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
			var raw net.Dialer
			return raw.DialContext(ctx, network, address)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	const legs = 5
	for i := 0; i < legs; i++ {
		resp, err := client.Get("http://" + ln.Addr().String() + "/probe")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		transport.CloseIdleConnections()
		server.waitHTTPConnsDrained(t)
	}
}

// waitHTTPConnsDrained polls until the tracked-connection maps are empty, failing
// the test if a closed h2c leg keeps an entry behind.
func (s *Server) waitHTTPConnsDrained(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var tracked, appliedCount int
	for time.Now().Before(deadline) {
		s.mu.Lock()
		tracked = len(s.httpConns)
		s.mu.Unlock()
		appliedCount = 0
		s.cfg.brutalSockets.applied.Range(func(_, _ any) bool { appliedCount++; return true })
		if tracked == 0 && appliedCount == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the closed h2c leg still holds tracked=%d applied=%d connection entries", tracked, appliedCount)
}
