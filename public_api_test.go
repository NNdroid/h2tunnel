package h2tunnel_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	h2tunnel "github.com/NNdroid/h2tunnel"
)

func TestPublicAPIH2CEndToEnd(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go serveEcho(echoListener)

	credentials, err := h2tunnel.NewTokenCredentials("public-api-token")
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := h2tunnel.NewTokenAuthenticator("public-api-token")
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"echo": {Network: h2tunnel.NetworkTCP, Address: echoListener.Addr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2C},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP},
		Authenticator: authenticator,
		Dialer:        dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(h2tunnel.Listeners{TCP: listener}) }()
	defer func() {
		_ = server.Close()
		if err := <-serveResult; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	}()

	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    "http://" + listener.Addr().String(),
		Transport:   h2tunnel.TransportH2C,
		Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := []byte("public API through h2c")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestPublicAPIDialReportsAuthenticationFailure(t *testing.T) {
	serverAuth, _ := h2tunnel.NewTokenAuthenticator("server-token")
	dialer := h2tunnel.TargetDialer(func(context.Context, h2tunnel.DialRequest) (net.Conn, error) {
		return nil, errors.New("must not dial")
	})
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2C},
		Authenticator: serverAuth,
		Dialer:        dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(h2tunnel.Listeners{TCP: listener})
	defer server.Close()

	badCredentials, _ := h2tunnel.NewTokenCredentials("wrong-token")
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    "http://" + listener.Addr().String(),
		Transport:   h2tunnel.TransportH2C,
		Credentials: badCredentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "forbidden"); err == nil {
		t.Fatal("DialContext unexpectedly succeeded")
	}
}

func TestPublicAPIRequiresSecureServerHooks(t *testing.T) {
	if _, err := h2tunnel.NewServer(h2tunnel.ServerOptions{}); err == nil {
		t.Fatal("NewServer accepted an open-proxy configuration")
	}
	if _, err := h2tunnel.NewTokenCredentials(""); !errors.Is(err, h2tunnel.ErrUnauthenticated) {
		t.Fatalf("empty token error = %v", err)
	}
}

func TestPublicAPIH2CUDP(t *testing.T) {
	udpBackend, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpBackend.Close()
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			n, addr, err := udpBackend.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udpBackend.WriteTo(buffer[:n], addr)
		}
	}()

	credentials, _ := h2tunnel.NewTokenCredentials("udp-token")
	authenticator, _ := h2tunnel.NewTokenAuthenticator("udp-token")
	dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"dns": {Network: h2tunnel.NetworkUDP, Address: udpBackend.LocalAddr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2C},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkUDP},
		Authenticator: authenticator,
		Dialer:        dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(h2tunnel.Listeners{TCP: listener}) }()
	defer func() {
		_ = server.Close()
		<-serveResult
	}()

	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    "http://" + listener.Addr().String(),
		Transport:   h2tunnel.TransportH2C,
		Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	packetConn, err := client.DialPacketContext(ctx, h2tunnel.NetworkUDP, "dns")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	if err := packetConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("udp through public API")
	if _, err := packetConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	n, err := packetConn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != string(payload) {
		t.Fatalf("UDP echo = %q, want %q", buffer[:n], payload)
	}
}

func TestPublicAPIDialContextCancellationReachesTargetDialer(t *testing.T) {
	credentials, _ := h2tunnel.NewTokenCredentials("cancel-token")
	authenticator, _ := h2tunnel.NewTokenAuthenticator("cancel-token")
	dialCanceled := make(chan struct{})
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2C},
		Authenticator: authenticator,
		Dialer: func(ctx context.Context, _ h2tunnel.DialRequest) (net.Conn, error) {
			<-ctx.Done()
			close(dialCanceled)
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(h2tunnel.Listeners{TCP: listener})
	defer server.Close()
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    "http://" + listener.Addr().String(),
		Transport:   h2tunnel.TransportH2C,
		Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "slow-service"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext error = %v, want deadline exceeded", err)
	}
	select {
	case <-dialCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("target dialer did not observe client cancellation")
	}
}

func TestPublicAPITargetDenialIsReturnedBeforeConn(t *testing.T) {
	credentials, _ := h2tunnel.NewTokenCredentials("deny-token")
	authenticator, _ := h2tunnel.NewTokenAuthenticator("deny-token")
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2C},
		Authenticator: authenticator,
		Dialer: func(context.Context, h2tunnel.DialRequest) (net.Conn, error) {
			return nil, h2tunnel.ErrForbidden
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(h2tunnel.Listeners{TCP: listener})
	defer server.Close()
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    "http://" + listener.Addr().String(),
		Transport:   h2tunnel.TransportH2C,
		Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "admin"); err == nil {
		conn.Close()
		t.Fatal("DialContext returned a connection for a denied target")
	}
}

func TestPublicAPIServeStopsWhenOwnedListenerCloses(t *testing.T) {
	authenticator, _ := h2tunnel.NewTokenAuthenticator("listener-token")
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2C},
		Authenticator: authenticator,
		Dialer: func(context.Context, h2tunnel.DialRequest) (net.Conn, error) {
			return nil, h2tunnel.ErrForbidden
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(h2tunnel.Listeners{TCP: listener}) }()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatalf("Serve after listener close = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop after its listener closed")
	}
	if err := server.Serve(h2tunnel.Listeners{}); err == nil {
		t.Fatal("closed server accepted a second Serve call")
	}
}

func TestPublicAPIThroughCDN(t *testing.T) {
	client, safeHeaders := newPublicAPICDNEnvironment(t, 2*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := make([]byte, 72*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("payload changed while traversing CDN proxy")
	}
	if !safeHeaders.Load() {
		t.Fatal("CDN-safe request and response headers were not observed")
	}
}

func BenchmarkPublicAPIThroughCDN72KB(b *testing.B) {
	client, _ := newPublicAPICDNEnvironment(b, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	payload := make([]byte, 72*1024)
	got := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			b.Fatal(err)
		}
	}
}

func newPublicAPICDNEnvironment(tb testing.TB, proxyWriteDelay time.Duration) (*h2tunnel.Client, *atomic.Bool) {
	tb.Helper()
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = echoListener.Close() })
	go serveEcho(echoListener)

	authenticator, _ := h2tunnel.NewTokenAuthenticator("cdn-token")
	dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"echo": {Network: h2tunnel.NetworkTCP, Address: echoListener.Addr().String()},
	}, nil)
	if err != nil {
		tb.Fatal(err)
	}
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP},
		Authenticator: authenticator,
		Dialer:        dialer,
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = server.Close() })
	// Model the common CDN topology: HTTP/2 from client to edge, HTTP/1.1
	// from edge to a private origin. Server.Handler enables full duplex on the
	// downgraded origin request so request and response streams cannot deadlock.
	origin := httptest.NewServer(server.Handler())
	tb.Cleanup(origin.Close)
	originURL, _ := url.Parse(origin.URL)

	var safeHeaders atomic.Bool
	edgeTransport := &http.Transport{DisableCompression: true}
	edge := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := r.Clone(r.Context())
		out.URL.Scheme = originURL.Scheme
		out.URL.Host = originURL.Host
		out.RequestURI = ""
		out.Header = r.Header.Clone()
		// Model a CDN that strips Authorization but forwards an explicitly
		// allowed application header.
		out.Header.Del("Authorization")
		response, err := edgeTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, "origin unavailable", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		if r.Header.Get("Accept-Encoding") == "identity" &&
			r.Header.Get("X-Auth-Token") == "cdn-token" &&
			response.Header.Get("Cache-Control") == "no-store, no-transform" &&
			response.Header.Get("X-Accel-Buffering") == "no" {
			safeHeaders.Store(true)
		}
		for key, values := range response.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		buffer := make([]byte, 32*1024)
		for {
			n, readErr := response.Body.Read(buffer)
			if n > 0 {
				if proxyWriteDelay > 0 {
					time.Sleep(proxyWriteDelay)
				}
				if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
					return
				}
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
			}
			if readErr != nil {
				return
			}
		}
	}))
	edge.EnableHTTP2 = true
	edge.StartTLS()
	tb.Cleanup(edge.Close)
	tb.Cleanup(edgeTransport.CloseIdleConnections)

	credentials, _ := h2tunnel.NewTokenCredentials("cdn-token")
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    edge.URL,
		Transport:   h2tunnel.TransportH2,
		TLSConfig:   &tls.Config{InsecureSkipVerify: true},
		Credentials: credentials,
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = client.Close() })
	return client, &safeHeaders
}

func serveEcho(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}
