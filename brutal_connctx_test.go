package h2tunnel

// The accepted socket must be reachable from a handler, or the per-client Brutal
// decision cannot be applied to the server's socket after authentication.
// net/http hands its per-connection base context to x/net/http2 through the
// unadvertised BaseContext method on the ALPN request wrapper, so a value
// attached in ConnContext should survive into every h2 request; h2c hijacks the
// connection in ServeHTTP and hands r.Context() to http2.ServeConn, so the same
// value must reach it there too. These tests are what make that claim
// load-bearing.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type brutalConnCtxKey struct{}

func TestConnContextReachesTheHTTP2Handler(t *testing.T) {
	for _, mode := range []struct {
		name    string
		withTLS bool
	}{
		{name: "tls ALPN", withTLS: true},
		{name: "h2c", withTLS: false},
	} {
		mode := mode
		t.Run(mode.name, func(t *testing.T) {
			var (
				seen    atomic.Int32
				missing atomic.Int32
				proto   atomic.Value
			)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen.Add(1)
				if _, ok := r.Context().Value(brutalConnCtxKey{}).(net.Conn); !ok {
					missing.Add(1)
				}
				proto.Store(r.Proto)
				w.WriteHeader(http.StatusOK)
			})
			s := &http.Server{
				Handler: handler,
				// The production shape: attach the accepted conn to the context.
				ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
					return context.WithValue(ctx, brutalConnCtxKey{}, conn)
				},
			}
			if mode.withTLS {
				tlsConfig, err := SelfSignedTLSConfig("localhost")
				if err != nil {
					t.Fatal(err)
				}
				s.TLSConfig = tlsConfig
				if !slices.Contains(s.TLSConfig.NextProtos, "h2") {
					s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, "h2")
				}
				if err := http2.ConfigureServer(s, &http2.Server{}); err != nil {
					t.Fatal(err)
				}
			} else {
				s.Handler = h2c.NewHandler(handler, &http2.Server{})
			}

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				if mode.withTLS {
					_ = s.ServeTLS(ln, "", "")
				} else {
					_ = s.Serve(ln)
				}
			}()
			t.Cleanup(func() { _ = s.Close() })

			// Drive HTTP/2 with prior knowledge over whatever the server speaks:
			// TLS for the ALPN path, cleartext for h2c. Both land on the same
			// http2.ServeConn the production server uses.
			transport := &http2.Transport{
				AllowHTTP:       true,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			// http2.Transport exposes only a TLS dial hook and always hands it a
			// non-nil ALPN-h2 config, even for an "http" URL. We mirror
			// Client.newHTTP2Transport: TLS handshake when the server is wrapped
			// in TLS, raw TCP for h2c.
			transport.DialTLSContext = func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
				if !mode.withTLS {
					return (&net.Dialer{}).DialContext(ctx, network, address)
				}
				conn, err := tls.DialWithDialer(&net.Dialer{}, network, address, cfg)
				if err != nil {
					return nil, err
				}
				if err := conn.HandshakeContext(ctx); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return conn, nil
			}
			client := &http.Client{Transport: transport}
			t.Cleanup(transport.CloseIdleConnections)

			scheme := "http"
			if mode.withTLS {
				scheme = "https"
			}
			for i := 0; i < 3; i++ {
				resp, err := client.Get(scheme + "://" + ln.Addr().String() + "/probe")
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %d", resp.StatusCode)
				}
			}

			if got := seen.Load(); got != 3 {
				t.Fatalf("handler runs = %d, want 3", got)
			}
			if got := missing.Load(); got != 0 {
				t.Fatalf("%d of 3 handler calls could not see the accepted connection", got)
			}
			if p, _ := proto.Load().(string); p != "HTTP/2.0" {
				t.Fatalf("negotiated proto = %q, the test must exercise HTTP/2", p)
			}
		})
	}
}
