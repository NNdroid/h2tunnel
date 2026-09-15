package h2tunnel_test

// Example functions have no Output lines: they only compile-check the public
// API shape and are not executed as tests.
// Full deployment semantics (CDN topology, token constraints, service
// registry) are documented in the README.

// ExampleServer demonstrates embedding a tunnel server with a closed service registry.
func ExampleServer() {
	// tlsConfig, _ := h2tunnel.SelfSignedTLSConfig("localhost")
	// auth, _ := h2tunnel.NewTokenAuthenticator("long-random-token")
	// dialer, _ := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
	// 	"ssh": {Network: h2tunnel.NetworkTCP, Address: "127.0.0.1:22"},
	// }, nil)
	// server, _ := h2tunnel.NewServer(h2tunnel.ServerOptions{
	// 	Transports:    []h2tunnel.Transport{h2tunnel.TransportH2},
	// 	TLSConfig:     tlsConfig,
	// 	Authenticator: auth,
	// 	Dialer:        dialer,
	// })
	// _ = server.ListenAndServe(":8443")
}

// ExampleClient demonstrates embedding the client and dialing a logical service through the tunnel.
func ExampleClient() {
	// credentials, _ := h2tunnel.NewTokenCredentials("long-random-token")
	// client, _ := h2tunnel.NewClient(h2tunnel.ClientOptions{
	// 	Endpoint:    "https://tunnel.example.com",
	// 	Credentials: credentials,
	// })
	// _ = client.Start(context.Background())
	// conn, err := client.DialContext(context.Background(), h2tunnel.NetworkTCP, "ssh")
	// if err != nil {
	// 	if errors.Is(err, h2tunnel.ErrUnauthenticated) {
	// 		// token rejected → switch to another token
	// 	} else if errors.Is(err, h2tunnel.ErrForbidden) {
	// 		// target rejected → change target or request authorization
	// 	}
	// }
	// _ = conn
}

// ExampleClient_Stats demonstrates collecting tunnel stats (can be pushed to a monitoring system periodically).
func ExampleClient_Stats() {
	// var client *h2tunnel.Client
	// stats := client.Stats()
	// promActiveTunnels.Set(float64(stats.ActiveDials.Load()))
	// promUplinkBytes.Add(float64(stats.UplinkBytes.Load()))
}
