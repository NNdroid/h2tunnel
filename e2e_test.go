package h2tunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

// =========================================
// 1. 生成一次性测试证书 (TLS)
// =========================================
func generateTestCerts(certFile, keyFile string) error {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"h2tunnel e2e test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, _ := os.Create(keyFile)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}

// =========================================
// 2. 启动 Target 回显服务器 (TCP & UDP)
// =========================================
// waitTCPOrTLSReady 轮询直到 TCP 端口可建立连接（TLS 服务端握手在
// http.Server 层完成，TCP accept 成功即认为监听就绪）。
// 替代固定 sleep：慢速 CI runner 上 2s 可能不够，本地又白等。
func waitTCPOrTLSReady(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server %s not ready within %v", addr, timeout)
}

// waitPortReady 轮询等待 TCP 端口可连接；不带 *testing.T（供 benchmark /
// 无 t 环境使用），超时 panic。
func waitPortReady(addr string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	panic("port " + addr + " not ready within " + timeout.String())
}

// waitUDPReady 通过一次真实回显（本地 → 客户端 → 隧道 → echo target →
// 隧道 → 客户端 → 本地）探测 UDP 客户端就绪。不要用"尝试绑定同端口"来
// 探测：探测 socket 会与被测客户端的 ListenUDP 竞争，窗口期内对方 bind
// 失败（legacy 路径甚至会 Fatal 杀掉整个测试进程）。回显探测无竞争，且
// 顺带验证整条 UDP 链路。前提：客户端的 target 是回显服务（测试均满足）。
func waitUDPReady(t *testing.T, clientAddr string, timeout time.Duration) {
	t.Helper()
	conn, err := net.Dial("udp", clientAddr)
	if err != nil {
		t.Fatalf("dial udp client %s: %v", clientAddr, err)
	}
	defer conn.Close()
	msg := []byte("udp-ready-probe")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(msg); err != nil {
			continue
		}
		buf := make([]byte, len(msg))
		n, err := conn.Read(buf)
		if err == nil && n == len(msg) && string(buf[:n]) == string(msg) {
			return
		}
	}
	t.Fatalf("udp client %s not ready within %v", clientAddr, timeout)
}

// waitUDPBound 非竞争地探测 UDP 端口已被绑定（不建立隧道数据面）。
// 用于预期服务端拒绝、永远等不到回显的场景（如 network=tcp 门禁测试）。
// 原理：connected UDP socket 向未监听端口发包会收到 ICMP Port Unreachable，
// 内核把它变成"下一次"读写的连接拒绝错误 —— 两发之间留出 ICMP 到达时间，
// 第二发报错即未绑定，第二发成功即已绑定。
func waitUDPBound(t *testing.T, clientAddr string, timeout time.Duration) {
	t.Helper()
	conn, err := net.Dial("udp", clientAddr)
	if err != nil {
		t.Fatalf("dial udp client %s: %v", clientAddr, err)
	}
	defer conn.Close()
	probe := []byte("udp-bound-probe")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, _ = conn.Write(probe)
		time.Sleep(30 * time.Millisecond)
		if _, wErr := conn.Write(probe); wErr == nil {
			return
		}
	}
	t.Fatalf("udp client %s not bound within %v", clientAddr, timeout)
}

func startEchoServer(addr string) { // TCP Echo
	go func() {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(conn)
		}
	}()

	// UDP Echo (缓冲区加大到 64KB，防止大包截断死锁)
	go func() {
		uAddr, _ := net.ResolveUDPAddr("udp", addr)
		conn, err := net.ListenUDP("udp", uAddr)
		if err != nil {
			return
		}

		// 🚨 这里的 65536 是关键！必须大于压测的 payloadSize (16384)
		buf := make([]byte, 65536)
		for {
			n, cAddr, err := conn.ReadFromUDP(buf)
			if err == nil {
				conn.WriteToUDP(buf[:n], cAddr)
			}
		}
	}()
}

// =========================================
// 3. 终极自动化测试矩阵
// =========================================
func TestH2TunnelAllModes(t *testing.T) {
	// 1. 准备环境
	certFile := "test_cert.pem"
	keyFile := "test_key.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:20000"
	startEchoServer(targetAddr)

	serverAddr := "127.0.0.1:18443"
	serverURL := "https://" + serverAddr
	testToken := "secret-e2e-token"

	// 2. 启动隧道服务端 (config-only: 直接构造 serverConfig，避免依赖已移除的 CLI flag)
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportAll,
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error", // 减少测试时的日志刷屏，想看详细过程可以改为 debug
	})

	// 给服务端一点时间启动（轮询等待，替代固定 sleep：CI 冷启动慢会 flaky）
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	// 3. 测试用例矩阵
	type testCase struct {
		name       string
		clientPort string
		isUDP      bool
		args       []string
	}

	// 3. 测试用例矩阵 (全量覆盖 10 种协议组合)
	cases := []testCase{
		// ---- TCP 系列 ----
		{"H2_TCP", "20001", false, []string{}},
		{"gRPC_TCP", "20002", false, []string{"-grpc"}},
		{"H3_TCP", "20003", false, []string{"-h3"}},
		{"WT_TCP", "20004", false, []string{"-wt"}},
		{"MASQUE_TCP", "20005", false, []string{"-masque"}},

		// ---- UDP 系列 ----
		{"H2_UDP_Stream", "20006", true, []string{"-udp"}},
		{"gRPC_UDP_Stream", "20007", true, []string{"-udp", "-grpc"}},
		{"H3_UDP_Stream", "20008", true, []string{"-udp", "-h3"}},
		{"WT_UDP_Stream", "20009", true, []string{"-udp", "-wt"}},
		{"MASQUE_UDP", "20010", true, []string{"-udp", "-masque"}},
	}

	// 4. 执行测试矩阵
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientListen := "127.0.0.1:" + tc.clientPort

			// 启动对应的客户端 (config-only: 协议开关从 tc.args 映射到 clientConfig 字段)
			cc := clientConfig{
				ListenAddr: clientListen,
				ServerUrl:  serverURL,
				Path:       "/tunnel",
				TargetAddr: targetAddr,
				Insecure:   true,
				Token:      testToken,
				LogLevel:   "error",
			}
			for i := 0; i < len(tc.args); i++ {
				switch tc.args[i] {
				case "-grpc":
					cc.Transport = transportGRPC
				case "-h3":
					cc.Transport = transportH3
				case "-wt":
					cc.Transport = transportWT
				case "-masque":
					cc.Transport = transportMasque
				case "-udp":
					cc.Network = "udp"
				}
			}
			go startClientDirect(cc)
			if tc.isUDP {
				waitUDPReady(t, clientListen, 30*time.Second)
			} else {
				waitTCPOrTLSReady(t, clientListen, 30*time.Second)
			}

			// 发起真实数据测试
			testMsg := []byte(fmt.Sprintf("Hello h2tunnel via %s", tc.name))
			var conn net.Conn
			var err error

			if tc.isUDP {
				conn, err = net.Dial("udp", clientListen)
			} else {
				conn, err = net.Dial("tcp", clientListen)
			}

			if err != nil {
				t.Fatalf("无法连接到本地客户端监听端口: %v", err)
			}
			defer conn.Close()

			// 设置超时防止测试卡死
			conn.SetDeadline(time.Now().Add(5 * time.Second))

			// 发送测试数据
			_, err = conn.Write(testMsg)
			if err != nil {
				t.Fatalf("数据发送失败: %v", err)
			}

			// 读取回显数据
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("数据接收失败 (未收到回显): %v", err)
			}

			// 校验数据完整性
			if string(buf[:n]) != string(testMsg) {
				t.Fatalf("数据损坏! 预期: %s, 实际收到: %s", testMsg, buf[:n])
			}

			t.Logf("✅ 完美通过!")
		})
	}
}

// =========================================
// 4. 模拟真实非 Echo 服务交互测试 (如 SSH 协议握手)
// 验证 Padding 在真实服务端被正确解封装与封装，绝无数据污染
// =========================================
func TestH2Tunnel_NonEchoService_Realistic(t *testing.T) {
	certFile := "test_cert_realistic.pem"
	keyFile := "test_key_realistic.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:21000"
	serverAddr := "127.0.0.1:21443"
	serverURL := "https://" + serverAddr
	testToken := "realistic-token"

	// 启动非 Echo 模拟服务 (服务端先发送 Banner，再交互)
	ln, err := net.Listen("tcp", targetAddr)
	if err != nil {
		t.Fatalf("无法监听测试服务端口: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))

				// 1. 服务端先主动向客户端发送 SSH-Banner
				_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))

				// 2. 服务端读取客户端发来的 Client-Banner
				buf := make([]byte, 100)
				n, err := conn.Read(buf)
				if err != nil || string(buf[:n]) != "SSH-2.0-CustomClient\r\n" {
					return
				}

				// 3. 服务端回复确认包
				_, _ = conn.Write([]byte("SERVER_HANDSHAKE_OK\r\n"))
			}(c)
		}
	}()

	// 启动 H2Tunnel 服务端
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     transportH2,
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	clientListen := "127.0.0.1:21001"
	go startClientDirect(clientConfig{
		ListenAddr: clientListen,
		ServerUrl:  serverURL,
		Path:       "/tunnel",
		TargetAddr: targetAddr,
		Insecure:   true,
		Token:      testToken,
		LogLevel:   "error",
	})
	waitTCPOrTLSReady(t, clientListen, 30*time.Second)

	conn, err := net.Dial("tcp", clientListen)
	if err != nil {
		t.Fatalf("连接客户端失败: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 1. 客户端应该先读取到服务端主动下发的 Banner
	serverBanner := make([]byte, 21)
	_, err = io.ReadFull(conn, serverBanner)
	if err != nil {
		t.Fatalf("读取服务端 Banner 失败: %v", err)
	}
	if string(serverBanner) != "SSH-2.0-OpenSSH_9.0\r\n" {
		t.Fatalf("服务端 Banner 损坏! 收到: %q", string(serverBanner))
	}

	// 2. 客户端发送 Client-Banner
	_, err = conn.Write([]byte("SSH-2.0-CustomClient\r\n"))
	if err != nil {
		t.Fatalf("发送客户端 Banner 失败: %v", err)
	}

	// 3. 客户端读取服务端二次回复
	reply := make([]byte, 21)
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("读取确认回复失败: %v", err)
	}
	if string(reply) != "SERVER_HANDSHAKE_OK\r\n" {
		t.Fatalf("确认回复损坏! 收到: %q", string(reply))
	}

	t.Log("✅ 真实非 Echo 协议全双工握手测试完美通过！")
}

// =========================================
// 5. 严格协议分流与网络类型门禁测试 (Strict Demux)
// =========================================
func TestH2Tunnel_StrictDemux(t *testing.T) {
	certFile := "test_cert_demux.pem"
	keyFile := "test_key_demux.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:22000"
	startEchoServer(targetAddr)

	serverAddr := "127.0.0.1:22443"
	serverURL := "https://" + serverAddr
	testToken := "demux-token"

	// 启动严格模式服务端：仅允许 gRPC 且仅允许 TCP
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     "grpc", // 严格限定必须为 gRPC
		Network:       "tcp",  // 严格限定只允许 TCP，拒绝 UDP
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	// 测试用例 1: 客户端未开启 gRPC 发起 H2 POST 请求 -> 应被服务端严格分流拦截 (403)
	t.Run("Reject_Non_gRPC_When_Server_Requires_gRPC", func(t *testing.T) {
		clientListen := "127.0.0.1:22001"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Transport:  transportH2, // 故意不使用 gRPC
			Token:      testToken,
			LogLevel:   "error",
		})
		waitTCPOrTLSReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("连接本地客户端失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		_, err = conn.Write([]byte("ping"))
		if err != nil {
			t.Fatalf("写入失败: %v", err)
		}

		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		// 远端返回 403 导致隧道握手失败，本地连接被立即关闭 (EOF)
		if err == nil {
			t.Fatalf("预期连接应被服务端严格拦截并关闭，但成功读取到了数据: %s", string(buf))
		}
		t.Log("✅ 非 gRPC 请求被严格模式成功拦截！")
	})

	// 测试用例 2: 客户端开启 gRPC 发起请求 -> 应顺利通过
	t.Run("Accept_gRPC_When_Server_Requires_gRPC", func(t *testing.T) {
		clientListen := "127.0.0.1:22002"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Transport:  transportGRPC, // 正确使用 gRPC
			Token:      testToken,
			LogLevel:   "error",
		})
		waitTCPOrTLSReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("连接本地客户端失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		testMsg := []byte("Hello Strict gRPC")
		_, err = conn.Write(testMsg)
		if err != nil {
			t.Fatalf("写入失败: %v", err)
		}

		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("读取回显失败: %v", err)
		}
		if string(buf[:n]) != string(testMsg) {
			t.Fatalf("数据不匹配: %s != %s", buf[:n], testMsg)
		}
		t.Log("✅ 合规的 gRPC 请求成功通行！")
	})

	// 测试用例 3: 客户端尝试发送 UDP 数据 -> 应被服务端限制 Network="tcp" 拦截
	t.Run("Reject_UDP_When_Server_Requires_TCP_Only", func(t *testing.T) {
		clientListen := "127.0.0.1:22003"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Transport:  transportGRPC,
			Network:    "udp", // 请求 UDP
			Token:      testToken,
			LogLevel:   "error",
		})
		// 预期服务端拒绝 UDP：等不到回显，这里只验证客户端端口已绑定
		waitUDPBound(t, clientListen, 30*time.Second)

		conn, err := net.Dial("udp", clientListen)
		if err != nil {
			t.Fatalf("连接本地客户端失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, err = conn.Write([]byte("udp ping"))
		if err != nil {
			t.Fatalf("UDP 写入失败: %v", err)
		}

		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("预期 UDP 请求应被服务端拒绝无回显，但收到了数据")
		}
		t.Log("✅ 违规的 UDP 请求被服务端成功拦截！")
	})
}
