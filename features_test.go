package h2tunnel

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ============================================================================
// 1. 本地双栈转发测试 (Dual-Stack TCP + UDP 同端口并发代理)
// 验证 network="all" 时，客户端在同个端口上同时接受并代理 TCP 和 UDP 流量
// ============================================================================
func TestH2Tunnel_Network_DualStack_All(t *testing.T) {
	certFile := "test_cert_dualstack.pem"
	keyFile := "test_key_dualstack.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:23000"
	startEchoServer(targetAddr)

	serverAddr := "127.0.0.1:23443"
	serverURL := "https://" + serverAddr
	testToken := "dualstack-token"

	// 启动服务端（默认允许所有网络与传输类型）
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     "all",
		Network:       "all",
		ExpectedToken: testToken,
		LogLevel:      "error",
	})
	time.Sleep(1 * time.Second)

	clientListen := "127.0.0.1:23001"
	// 启动客户端，明确配置 network="all"
	go startClientDirect(clientConfig{
		ListenAddr: clientListen,
		ServerUrl:  serverURL,
		Path:       "/tunnel",
		TargetAddr: targetAddr,
		Insecure:   true,
		Network:    "all", // 🌟 核心：双栈模式
		Token:      testToken,
		LogLevel:   "error",
	})
	time.Sleep(1 * time.Second)

	// A. 测试 TCP 通道
	t.Run("TCP_Channel_Over_DualStack", func(t *testing.T) {
		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("连接客户端 TCP 端口失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		msg := []byte("DualStack-TCP-Hello")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("发送 TCP 数据失败: %v", err)
		}

		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("TCP 回显校验失败! 收到: %q, err=%v", string(buf[:n]), err)
		}
		t.Log("✅ 双栈模式下的 TCP 通道通信成功！")
	})

	// B. 测试同一个端口的 UDP 通道
	t.Run("UDP_Channel_Over_DualStack", func(t *testing.T) {
		conn, err := net.Dial("udp", clientListen)
		if err != nil {
			t.Fatalf("连接客户端 UDP 端口失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		msg := []byte("DualStack-UDP-Hello")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("发送 UDP 数据失败: %v", err)
		}

		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("UDP 回显校验失败! 收到: %q, err=%v", string(buf[:n]), err)
		}
		t.Log("✅ 双栈模式下的 UDP 通道通信成功！")
	})
}

// ============================================================================
// 2. 严格网络类型门禁测试 (network="udp" 时严格阻断 TCP)
// ============================================================================
func TestH2Tunnel_Network_StrictGating_UDP_Only(t *testing.T) {
	certFile := "test_cert_udponly.pem"
	keyFile := "test_key_udponly.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:24000"
	startEchoServer(targetAddr)

	serverAddr := "127.0.0.1:24443"
	serverURL := "https://" + serverAddr
	testToken := "udponly-token"

	// 服务端严格配置仅允许 UDP 代理
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     "all",
		Network:       "udp", // 🌟 仅允许 UDP
		ExpectedToken: testToken,
		LogLevel:      "error",
	})
	time.Sleep(1 * time.Second)

	// A. 尝试通过客户端发起 TCP 连接 -> 服务端必须拦截（返回 403）
	t.Run("Reject_TCP_Traffic", func(t *testing.T) {
		clientListen := "127.0.0.1:24001"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Network:    "tcp", // 客户端请求 TCP
			Token:      testToken,
			LogLevel:   "error",
		})
		time.Sleep(500 * time.Millisecond)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("连接本地客户端失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, _ = conn.Write([]byte("ping"))
		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("服务端 network=udp 策略本应拦截 TCP 请求，但请求居然成功了: %s", string(buf))
		}
		t.Log("✅ TCP 请求被服务端 network=udp 策略成功拦截！")
	})

	// B. 尝试通过客户端发起 UDP 连接 -> 必须正常通行
	t.Run("Accept_UDP_Traffic", func(t *testing.T) {
		clientListen := "127.0.0.1:24002"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Network:    "udp", // 客户端请求 UDP
			Token:      testToken,
			LogLevel:   "error",
		})
		time.Sleep(500 * time.Millisecond)

		conn, err := net.Dial("udp", clientListen)
		if err != nil {
			t.Fatalf("连接本地客户端失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		msg := []byte("UDP-Gating-Pass")
		_, _ = conn.Write(msg)
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("UDP 请求通信失败: %v, got %q", err, string(buf[:n]))
		}
		t.Log("✅ 合规的 UDP 请求顺利通行！")
	})
}

// ============================================================================
// 3. 严格传输协议门禁测试 (transport="h2" 严格拦截 WebTransport 与 MASQUE)
// ============================================================================
func TestH2Tunnel_Transport_StrictGating_H2_Only(t *testing.T) {
	certFile := "test_cert_h2only.pem"
	keyFile := "test_key_h2only.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:25000"
	startEchoServer(targetAddr)

	serverAddr := "127.0.0.1:25443"
	serverURL := "https://" + serverAddr
	testToken := "h2only-token"

	// 启动严格限定为 h2 的服务端
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     "h2", // 🌟 严格只允许 H2 POST
		Network:       "tcp",
		ExpectedToken: testToken,
		LogLevel:      "error",
	})
	time.Sleep(1 * time.Second)

	// A. 客户端尝试用 gRPC 协议连接 -> 服务端应拦截
	t.Run("Reject_gRPC_Traffic", func(t *testing.T) {
		clientListen := "127.0.0.1:25001"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Transport:  transportGRPC, // 违规协议
			Token:      testToken,
			LogLevel:   "error",
		})
		time.Sleep(500 * time.Millisecond)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("连接本地客户端失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, _ = conn.Write([]byte("ping"))
		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("预期 gRPC 请求应被服务端拒绝，但成功收到回显")
		}
		t.Log("✅ gRPC 请求被服务端 transport=h2 门禁拦截！")
	})

	// B. 客户端尝试用 MASQUE 协议连接 -> 服务端应拦截
	t.Run("Reject_MASQUE_Traffic", func(t *testing.T) {
		clientListen := "127.0.0.1:25002"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Transport:  transportMasque, // 违规协议
			Token:      testToken,
			LogLevel:   "error",
		})
		time.Sleep(500 * time.Millisecond)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("连接本地客户端失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, _ = conn.Write([]byte("ping"))
		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("预期 MASQUE 请求应被服务端拒绝，但成功收到回显")
		}
		t.Log("✅ MASQUE 请求被服务端 transport=h2 门禁拦截！")
	})

	// C. 客户端使用标准 H2 POST 连接 -> 必须成功
	t.Run("Accept_H2_Traffic", func(t *testing.T) {
		clientListen := "127.0.0.1:25003"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Token:      testToken,
			LogLevel:   "error",
		})
		time.Sleep(500 * time.Millisecond)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("连接本地客户端失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		msg := []byte("Standard-H2-Pass")
		_, _ = conn.Write(msg)
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("H2 标准请求失败: %v, got %q", err, string(buf[:n]))
		}
		t.Log("✅ 标准 H2 POST 请求成功通行！")
	})
}

// ============================================================================
// 4. LocalOnly 本地安全转发保护测试
// local_only=true 时，严禁转发到外部公网 IP，防止开放代理被滥用
// ============================================================================
func TestH2Tunnel_LocalOnly_SecurityPolicy(t *testing.T) {
	certFile := "test_cert_localonly.pem"
	keyFile := "test_key_localonly.pem"
	generateTestCerts(certFile, keyFile)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	targetAddr := "127.0.0.1:26000"
	startEchoServer(targetAddr)

	serverAddr := "127.0.0.1:26443"
	serverURL := "https://" + serverAddr
	testToken := "localonly-token"

	// 开启 LocalOnly 保护模式
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     "all",
		LocalOnly:     true, // 🌟 仅允许 localhost / 127.0.0.1 / ::1
		ExpectedToken: testToken,
		LogLevel:      "error",
	})
	time.Sleep(1 * time.Second)

	// A. 请求合法本地目标 -> 允许通行
	t.Run("Allow_Local_Target", func(t *testing.T) {
		clientListen := "127.0.0.1:26001"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Token:      testToken,
			LogLevel:   "error",
		})
		time.Sleep(500 * time.Millisecond)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("连接本地客户端失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		msg := []byte("Local-Target-Allowed")
		_, _ = conn.Write(msg)
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("本地请求失败: %v, got %q", err, string(buf[:n]))
		}
		t.Log("✅ 本地目标 (127.0.0.1) 顺利通行！")
	})

	// B. 尝试请求外部公网目标 -> 服务端必须拦截（返回 403 Forbidden）
	t.Run("Block_External_Public_Target", func(t *testing.T) {
		clientListen := "127.0.0.1:26002"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: "8.8.8.8:53", // 企图利用服务端转发至外部公网
			Insecure:   true,
			Token:      testToken,
			LogLevel:   "error",
		})
		time.Sleep(500 * time.Millisecond)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("连接本地客户端失败: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, _ = conn.Write([]byte("external ping"))
		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("LocalOnly 策略本应拦截公网目标，但连接未被拒绝")
		}
		t.Log("✅ 外部公网目标被 LocalOnly 安全策略成功拦截！")
	})
}

// ============================================================================
// 5. 配置文件与环境变量解析测试
// 验证 Network 正式值与环境变量覆盖
// ============================================================================
func TestH2Tunnel_Config_NetworkAndEnv(t *testing.T) {
	tempDir := t.TempDir()

	// 1. 测试显式 network="udp"
	udpJSON := `{
		"mode": "client",
		"listen": "127.0.0.1:1080",
		"server": "https://example.com:8443",
		"network": "udp"
	}`
	cfgPath := filepath.Join(tempDir, "udp.json")
	_ = os.WriteFile(cfgPath, []byte(udpJSON), 0644)
	cfg, err := loadConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("解析配置失败: %v", err)
	}
	if cfg.Network != "udp" {
		t.Fatalf("配置 network 实际值不匹配: %s", cfg.Network)
	}
	cConfig := buildClientConfig(cfg)
	if !cConfig.IsUDP() || cConfig.IsTCP() {
		t.Fatalf("clientConfig 状态解析错误: IsUDP=%v, IsTCP=%v", cConfig.IsUDP(), cConfig.IsTCP())
	}
	t.Log("✅ 显式 network='udp' 成功激活 UDP 专属模式！")

	// 2. 测试 network="all"
	dualJSON := `{
		"mode": "client",
		"listen": "127.0.0.1:1080",
		"server": "https://example.com:8443",
		"network": "all"
	}`
	dualPath := filepath.Join(tempDir, "dual.json")
	_ = os.WriteFile(dualPath, []byte(dualJSON), 0644)
	dCfg, _ := loadConfigFile(dualPath)
	dClientCfg := buildClientConfig(dCfg)
	if !dClientCfg.IsUDP() || !dClientCfg.IsTCP() {
		t.Fatalf("network='all' 未能同时开启 TCP 和 UDP: IsUDP=%v, IsTCP=%v", dClientCfg.IsUDP(), dClientCfg.IsTCP())
	}
	t.Log("✅ network='all' 成功同时激活 TCP 与 UDP 双栈！")

	// 3. 测试环境变量覆盖
	os.Setenv("H2TUNNEL_NETWORK", "udp")
	os.Setenv("H2TUNNEL_TRANSPORT", "grpc")
	defer os.Unsetenv("H2TUNNEL_NETWORK")
	defer os.Unsetenv("H2TUNNEL_TRANSPORT")

	envCfg := &fileConfig{Network: "tcp", Transport: "h2"}
	if err := applyEnvOverrides(envCfg); err != nil {
		t.Fatal(err)
	}
	if envCfg.Network != "udp" || envCfg.Transport != "grpc" {
		t.Fatalf("环境变量覆盖失败: %+v", envCfg)
	}
	t.Log("✅ 环境变量对 Network 和 Transport 的动态覆盖成功生效！")
}
