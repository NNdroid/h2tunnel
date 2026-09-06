package h2tunnel_test

// Example 函数无 Output 行：仅编译校验公开 API 形态，不在测试中执行。
// 完整的部署语义（CDN 拓扑、token 约束、服务注册表）见 README。

// ExampleServer 演示嵌入一个关闭式服务注册表的隧道服务端。
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

// ExampleClient 演示嵌入客户端并通过隧道拨号一个逻辑服务。
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
	// 		// token 被拒 → 换 token
	// 	} else if errors.Is(err, h2tunnel.ErrForbidden) {
	// 		// 目标被拒 → 换目标或申请授权
	// 	}
	// }
	// _ = conn
}

// ExampleClient_Stats 演示采集隧道统计（可定期推给监控系统）。
func ExampleClient_Stats() {
	// var client *h2tunnel.Client
	// stats := client.Stats()
	// promActiveTunnels.Set(float64(stats.ActiveDials.Load()))
	// promUplinkBytes.Add(float64(stats.UplinkBytes.Load()))
}
