package h2tunnel_test

// =========================================
// 真实目标协议矩阵：
//   - TCP 目标用真实 HTTP server（net/http），同一条隧道连接上跑 10 次
//     HTTP 请求/响应（keep-alive 复用），并断言目标侧只接受了一条连接；
//   - UDP 目标用真实 DNS server（标准 DNS wire format），同一条
//     PacketConn 上发 10 次独立 A 查询并逐包校验 ID/RCODE/应答记录；
//   - 每个传输协议（h2/h2c/grpc/h3/wt/masque）都要覆盖，UDP 侧 WT 的
//     包 API 不支持（见 PacketConn 文档）。
//
// 相比 echo 矩阵（connmanager_test.go），真实语义目标能暴露
// 「隧道在真实应用协议下的粘包/半包/复用/重建」问题。
// =========================================

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

const (
	protocolMatrixToken = "real-target-token"
	protocolIterations  = 10 // 同一连接上的往返次数
)

// countedListener 统计目标侧接受的连接数（验证隧道 keep-alive 复用）。
type countedListener struct {
	net.Listener
	conns atomic.Int32
}

func (l *countedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.conns.Add(1)
	}
	return c, err
}

// protocolEnv 一套共享测试环境：真实 HTTP 目标 + 真实 DNS 目标 +
// 吞吐基准用的 TCP/UDP echo 目标 + TLS / h2c 两台隧道服务端
// （h2c 无法与 TLS 共监听，必须分开）。
type protocolEnv struct {
	httpListener *countedListener
	dnsConn      net.PacketConn

	tlsURL string // https://127.0.0.1:port
	h2cURL string // http://127.0.0.1:port
}

func newProtocolEnv(t testing.TB) *protocolEnv {
	t.Helper()
	env := &protocolEnv{}

	// —— 真实 HTTP 目标：/iter-N 返回 hello-iter-N ——
	rawHTTP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env.httpListener = &countedListener{Listener: rawHTTP}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s", strings.TrimPrefix(r.URL.Path, "/"))
	})
	httpTarget := &http.Server{Handler: mux}
	go func() { _ = httpTarget.Serve(env.httpListener) }()
	t.Cleanup(func() { _ = httpTarget.Close() })

	// —— 真实 DNS 目标（UDP，标准 wire format 的最小 A 记录应答器）——
	env.dnsConn, err = net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveFakeDNS(env.dnsConn)
	t.Cleanup(func() { _ = env.dnsConn.Close() })

	// —— 吞吐基准用的 echo 目标（TCP + UDP 同地址）——
	benchEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(benchEcho)
	t.Cleanup(func() { _ = benchEcho.Close() })
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveUDPEcho(udpEcho)
	t.Cleanup(func() { _ = udpEcho.Close() })

	// —— 隧道服务端 ——
	authenticator, err := h2tunnel.NewTokenAuthenticator(protocolMatrixToken)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"http":      {Network: h2tunnel.NetworkTCP, Address: rawHTTP.Addr().String()},
		"dns":       {Network: h2tunnel.NetworkUDP, Address: env.dnsConn.LocalAddr().String()},
		"bench-tcp": {Network: h2tunnel.NetworkTCP, Address: benchEcho.Addr().String()},
		"bench-udp": {Network: h2tunnel.NetworkUDP, Address: udpEcho.LocalAddr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// TLS 侧：承载 h2/h3/wt/masque/grpc。
	tlsConfig, err := h2tunnel.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	tlsServer, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2, h2tunnel.TransportH3, h2tunnel.TransportWebTransport, h2tunnel.TransportMASQUE, h2tunnel.TransportGRPC},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP, h2tunnel.NetworkUDP},
		TLSConfig:     tlsConfig,
		Authenticator: authenticator,
		Dialer:        dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsTCP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsQUIC, err := net.ListenPacket("udp", tlsTCP.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsEnv := make(chan error, 1)
	go func() { tlsEnv <- tlsServer.Serve(h2tunnel.Listeners{TCP: tlsTCP, QUIC: tlsQUIC}) }()
	t.Cleanup(func() {
		_ = tlsServer.Close()
		if err := <-tlsEnv; err != nil {
			t.Errorf("TLS Serve returned %v", err)
		}
	})
	env.tlsURL = "https://" + tlsTCP.Addr().String()

	// h2c 侧：明文，h2c 不能与 TLS 混监听。
	h2cServer, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2C},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP, h2tunnel.NetworkUDP},
		Authenticator: authenticator,
		Dialer:        dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	h2cListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h2cEnv := make(chan error, 1)
	go func() { h2cEnv <- h2cServer.Serve(h2tunnel.Listeners{TCP: h2cListener}) }()
	t.Cleanup(func() {
		_ = h2cServer.Close()
		if err := <-h2cEnv; err != nil {
			t.Errorf("h2c Serve returned %v", err)
		}
	})
	env.h2cURL = "http://" + h2cListener.Addr().String()

	return env
}

// serveFakeDNS 最小 DNS 应答器：回显问题段，置 QR/RA，追加一条
// 指向问题名的 A 记录（127.0.0.1）。对任何 QTYPE 都答 A —— 测试
// 客户端只发 A 查询，够用且确定。
func serveFakeDNS(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := buildFakeDNSResponse(buf[:n])
		if resp == nil {
			continue
		}
		if _, err := pc.WriteTo(resp, addr); err != nil {
			return
		}
	}
}

// buildFakeDNSResponse 解析查询报文（头 + 问题段），组装标准应答。
func buildFakeDNSResponse(q []byte) []byte {
	if len(q) < 12+1+4 {
		return nil
	}
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	if i >= len(q) {
		return nil
	}
	i++           // 根标签 0x00
	qEnd := i + 4 // QTYPE + QCLASS
	if qEnd > len(q) {
		return nil
	}
	resp := make([]byte, qEnd+16)
	copy(resp, q[:qEnd])
	resp[2] = q[2] | 0x80 // QR=1
	resp[3] = q[3] | 0x80 // RA=1
	binary.BigEndian.PutUint16(resp[6:8], 1)
	ans := resp[qEnd:]
	binary.BigEndian.PutUint16(ans[0:2], 0xC00C) // 名称压缩指针 → 问题段
	binary.BigEndian.PutUint16(ans[2:4], 1)      // TYPE A
	binary.BigEndian.PutUint16(ans[4:6], 1)      // CLASS IN
	binary.BigEndian.PutUint32(ans[6:10], 300)   // TTL
	binary.BigEndian.PutUint16(ans[10:12], 4)    // RDLENGTH
	ans[12], ans[13], ans[14], ans[15] = 127, 0, 0, 1
	return resp
}

// dnsQuery 构造 A 查询（RD=1）。
func dnsQuery(id uint16, name string) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint16(out, id)
	out = binary.BigEndian.AppendUint16(out, 0x0100) // RD
	out = binary.BigEndian.AppendUint16(out, 1)      // QDCOUNT
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, 1) // QTYPE A
	out = binary.BigEndian.AppendUint16(out, 1) // QCLASS IN
	return out
}

// newProtocolClient 按传输类型创建并启动客户端。
func newProtocolClient(t testing.TB, env *protocolEnv, transport h2tunnel.Transport) *h2tunnel.Client {
	t.Helper()
	var credentials h2tunnel.CredentialProvider
	credentials, err := h2tunnel.NewTokenCredentials(protocolMatrixToken)
	if err != nil {
		t.Fatal(err)
	}
	var tlsConfig *tls.Config
	endpoint := env.tlsURL
	if transport == h2tunnel.TransportH2C {
		endpoint = env.h2cURL
	} else {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} // 自签开发证书
	}
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    endpoint,
		Transport:   transport,
		TLSConfig:   tlsConfig,
		Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("start %s client: %v", transport, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestProtocolRealTargetMatrix 全协议 × 真实目标（HTTP / DNS），同一
// 连接 10 次往返。
func TestProtocolRealTargetMatrix(t *testing.T) {
	env := newProtocolEnv(t)

	tcpCases := []h2tunnel.Transport{
		h2tunnel.TransportH2, h2tunnel.TransportH2C, h2tunnel.TransportGRPC,
		h2tunnel.TransportH3, h2tunnel.TransportWebTransport, h2tunnel.TransportMASQUE,
	}
	udpCases := []h2tunnel.Transport{
		h2tunnel.TransportH2, h2tunnel.TransportH2C, h2tunnel.TransportGRPC,
		h2tunnel.TransportH3, h2tunnel.TransportMASQUE, h2tunnel.TransportWebTransport,
	}

	for _, transport := range tcpCases {
		transport := transport
		t.Run(string(transport)+"_TCP_HTTP_10x", func(t *testing.T) {
			client := newProtocolClient(t, env, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "http")
			if err != nil {
				t.Fatalf("dial http target: %v", err)
			}
			defer conn.Close()

			// 本子测试开始前目标已接受的连接数（计数器跨子测试共享）。
			connsBefore := env.httpListener.conns.Load()

			// 所有请求固定复用同一条隧道连接（keep-alive）。
			httpClient := &http.Client{
				Transport: &http.Transport{
					DialContext: func(context.Context, string, string) (net.Conn, error) {
						return conn, nil
					},
				},
			}
			for i := 1; i <= protocolIterations; i++ {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet,
					fmt.Sprintf("http://target/iter-%d", i), nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := httpClient.Do(req)
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatalf("read body %d: %v", i, err)
				}
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("request %d: status %d", i, resp.StatusCode)
				}
				if want := fmt.Sprintf("hello iter-%d", i); string(body) != want {
					t.Fatalf("request %d: body = %q, want %q", i, body, want)
				}
			}
			// 10 次 HTTP 往返必须全部复用拨号时建立的那条目标侧连接：
			// 目标侧零新增 accept（DialContext 返回时目标连接已建立）。
			if got := env.httpListener.conns.Load(); got != connsBefore {
				t.Fatalf("http target accepted %d extra connections, want 0 (all 10 requests must reuse the tunnel's single target connection)", got-connsBefore)
			}
		})
	}

	for _, transport := range udpCases {
		transport := transport
		t.Run(string(transport)+"_UDP_DNS_10x", func(t *testing.T) {
			client := newProtocolClient(t, env, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			packetConn, err := client.DialPacketContext(ctx, h2tunnel.NetworkUDP, "dns")
			if err != nil {
				t.Fatalf("dial dns target: %v", err)
			}
			defer packetConn.Close()

			expectedIP := []byte{127, 0, 0, 1}
			for i := 1; i <= protocolIterations; i++ {
				name := fmt.Sprintf("iter-%d.h2tunnel.test", i)
				query := dnsQuery(uint16(0x4000+i), name)
				_ = packetConn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := packetConn.Write(query); err != nil {
					t.Fatalf("query %d write: %v", i, err)
				}
				resp := make([]byte, 512)
				n, err := packetConn.Read(resp)
				if err != nil {
					t.Fatalf("query %d read: %v", i, err)
				}
				if n < len(query)+16 {
					t.Fatalf("query %d: response too short (%d bytes)", i, n)
				}
				if gotID := binary.BigEndian.Uint16(resp[0:2]); gotID != uint16(0x4000+i) {
					t.Fatalf("query %d: response ID = %d", i, gotID)
				}
				if rcode := resp[3] & 0x0F; rcode != 0 {
					t.Fatalf("query %d: rcode = %d", i, rcode)
				}
				if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 1 {
					t.Fatalf("query %d: ancount = %d", i, ancount)
				}
				// 应答 RDATA 紧跟在回显的问题段之后：+12(名字指针/类型/类/TTL/RDLENGTH) 前 4 字节是 A 记录。
				rdata := resp[len(query)+12 : len(query)+16]
				if string(rdata) != string(expectedIP) {
					t.Fatalf("query %d: answer = %v, want 127.0.0.1", i, rdata)
				}
			}
		})
	}
}

// TestMASQUEPathDerived 验证 MASQUE 路径嵌在隧道 path 之下：
// path=/abc/stone → CONNECT /abc/stone/.well-known/masque/tcp/...；
// 默认 path（/tunnel）的客户端无法命中路由。
func TestMASQUEPathDerived(t *testing.T) {
	env := newProtocolEnv(t)
	authenticator, err := h2tunnel.NewTokenAuthenticator(protocolMatrixToken)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"http": {Network: h2tunnel.NetworkTCP, Address: env.httpListener.Addr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := h2tunnel.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportMASQUE},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP},
		TLSConfig:     tlsConfig,
		Authenticator: authenticator,
		Dialer:        dialer,
		Path:          "/abc/stone",
	})
	if err != nil {
		t.Fatal(err)
	}
	// masque-only 服务端不开 TCP listener（requiredListeners 只返回 QUIC），
	// 且无需先建 TCP listener 来占端口 —— 直接用 QUIC 监听地址。
	quicConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(h2tunnel.Listeners{QUIC: quicConn}) }()
	defer func() {
		_ = server.Close()
		if err := <-serveErr; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	}()

	newClient := func(path string) *h2tunnel.Client {
		t.Helper()
		credentials, err := h2tunnel.NewTokenCredentials(protocolMatrixToken)
		if err != nil {
			t.Fatal(err)
		}
		client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
			Endpoint:    "https://" + quicConn.LocalAddr().String(),
			Transport:   h2tunnel.TransportMASQUE,
			TLSConfig:   &tls.Config{InsecureSkipVerify: true},
			Credentials: credentials,
			Path:        path,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 自定义 path：masque CONNECT 命中 /abc/stone/.well-known/masque/tcp/...。
	client := newClient("/abc/stone")
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "http")
	if err != nil {
		t.Fatalf("dial with custom path: %v", err)
	}
	defer conn.Close()
	resp, err := (&http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		},
	}).Get("http://target/masque-prefix")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := "hello masque-prefix"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}

	// 默认 path（/tunnel）无法命中 /abc/stone/... 路由，服务端 404。
	plain := newClient("")
	if _, err := plain.DialContext(ctx, h2tunnel.NetworkTCP, "http"); err == nil {
		t.Fatal("dial without prefix should fail (server routes only /ccc/...)")
	}
}
