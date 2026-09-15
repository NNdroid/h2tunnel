// Package h2tunnel provides an embeddable, authenticated, resumable tunnel
// over HTTP/2, HTTP/3, WebTransport, MASQUE, and gRPC transports.
//
// A Client acts as a concurrent net.Conn dialer. A Server authenticates every
// request and delegates target authorization and connection establishment to a
// mandatory TargetDialer. NewClient and NewServer perform no network I/O.
//
// Minimal end-to-end setup (development TLS, closed-by-default service
// registry):
//
//	tlsConfig, _ := h2tunnel.SelfSignedTLSConfig("localhost")
//	auth, _ := h2tunnel.NewTokenAuthenticator("long-random-token")
//	dialer, _ := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
//		"ssh": {Network: h2tunnel.NetworkTCP, Address: "127.0.0.1:22"},
//	}, nil)
//	server, _ := h2tunnel.NewServer(h2tunnel.ServerOptions{
//		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2},
//		TLSConfig:     tlsConfig,
//		Authenticator: auth,
//		Dialer:        dialer,
//	})
//	go server.ListenAndServe(":8443")
//
//	client, _ := h2tunnel.NewClient(h2tunnel.ClientOptions{
//		Endpoint:    "https://localhost:8443",
//		Credentials: credentials,                           // h2tunnel.NewTokenCredentials(...)
//		TLSConfig:   &tls.Config{InsecureSkipVerify: true}, // self-signed dev cert
//	})
//	conn, _ := client.DialContext(ctx, h2tunnel.NetworkTCP, "ssh")
//	// conn is a net.Conn over the tunnel; use it like any TCP connection.
//
// Dial errors match the exported sentinels: errors.Is(err,
// h2tunnel.ErrUnauthenticated) means the token was rejected (HTTP 407/401)
// and errors.Is(err, h2tunnel.ErrForbidden) means the target was denied
// (HTTP 403). See the README for production deployment guidance (CDN
// topology, token hygiene, and logical service registries).
package h2tunnel
