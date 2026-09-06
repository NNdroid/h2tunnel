package h2tunnel_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

// TestPublicAPIDialErrorSentinels 验证隧道层 HTTP 拒绝会映射到公开哨兵：
// 407/401 → ErrUnauthenticated，403 → ErrForbidden。嵌入方据此区分
// "换 token"还是"换目标"，而不必解析错误字符串。
func TestPublicAPIDialErrorSentinels(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(echoListener)
	defer echoListener.Close()

	authenticator, err := h2tunnel.NewTokenAuthenticator("sentinel-token")
	if err != nil {
		t.Fatal(err)
	}
	// 关闭式注册表：只登记 "echo"，拨 "missing" 必然 403。
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

	newClient := func(token string) *h2tunnel.Client {
		t.Helper()
		var credentials h2tunnel.CredentialProvider
		if token != "" {
			credentials, err = h2tunnel.NewTokenCredentials(token)
			if err != nil {
				t.Fatal(err)
			}
		}
		client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
			Endpoint:    "http://" + listener.Addr().String(),
			Transport:   h2tunnel.TransportH2C,
			Credentials: credentials,
		})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 无凭据 → 服务端 407 → ErrUnauthenticated。
	unauthed := newClient("")
	conn, err := unauthed.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial without credentials should fail")
	}
	if !errors.Is(err, h2tunnel.ErrUnauthenticated) {
		t.Fatalf("dial without credentials: err = %v, want ErrUnauthenticated", err)
	}

	// 凭据正确但目标未登记 → 服务端 403 → ErrForbidden。
	authed := newClient("sentinel-token")
	conn, err = authed.DialContext(ctx, h2tunnel.NetworkTCP, "missing-service")
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial unknown service should fail")
	}
	if !errors.Is(err, h2tunnel.ErrForbidden) {
		t.Fatalf("dial unknown service: err = %v, want ErrForbidden", err)
	}
}
