package h2tunnel

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ============================================================================
// 1. Local dual-stack forwarding test (Dual-Stack TCP + UDP concurrent proxy on one port)
// Verifies that with network="all" the client accepts and proxies TCP and UDP
// traffic simultaneously on the same port
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

	// start the server (allows all network and transport types by default)
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     "all",
		Network:       "all",
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	clientListen := "127.0.0.1:23001"
	// start the client with network="all" explicitly configured
	go startClientDirect(clientConfig{
		ListenAddr: clientListen,
		ServerUrl:  serverURL,
		Path:       "/tunnel",
		TargetAddr: targetAddr,
		Insecure:   true,
		Network:    "all", // 🌟 core: dual-stack mode
		Token:      testToken,
		LogLevel:   "error",
	})
	waitTCPOrTLSReady(t, clientListen, 30*time.Second)

	// A. Test the TCP channel
	t.Run("TCP_Channel_Over_DualStack", func(t *testing.T) {
		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the client TCP port: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		msg := []byte("DualStack-TCP-Hello")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("failed to send TCP data: %v", err)
		}

		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("TCP echo verification failed! received: %q, err=%v", string(buf[:n]), err)
		}
		t.Log("✅ TCP channel communication succeeded in dual-stack mode!")
	})

	// B. Test the UDP channel on the same port
	t.Run("UDP_Channel_Over_DualStack", func(t *testing.T) {
		conn, err := net.Dial("udp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the client UDP port: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		msg := []byte("DualStack-UDP-Hello")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("failed to send UDP data: %v", err)
		}

		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("UDP echo verification failed! received: %q, err=%v", string(buf[:n]), err)
		}
		t.Log("✅ UDP channel communication succeeded in dual-stack mode!")
	})
}

// ============================================================================
// 2. Strict network-type gating test (network="udp" strictly blocks TCP)
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

	// server strictly configured to allow UDP proxying only
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     "all",
		Network:       "udp", // 🌟 UDP only
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	// A. Try a TCP connection through the client -> the server must intercept it (403)
	t.Run("Reject_TCP_Traffic", func(t *testing.T) {
		clientListen := "127.0.0.1:24001"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Network:    "tcp", // client requests TCP
			Token:      testToken,
			LogLevel:   "error",
		})
		waitTCPOrTLSReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the local client: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, _ = conn.Write([]byte("ping"))
		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("server network=udp policy should have blocked the TCP request, but it unexpectedly succeeded: %s", string(buf))
		}
		t.Log("✅ TCP request successfully intercepted by the server's network=udp policy!")
	})

	// B. Try a UDP connection through the client -> must pass through normally
	t.Run("Accept_UDP_Traffic", func(t *testing.T) {
		clientListen := "127.0.0.1:24002"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Network:    "udp", // client requests UDP
			Token:      testToken,
			LogLevel:   "error",
		})
		waitUDPReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("udp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the local client: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		msg := []byte("UDP-Gating-Pass")
		_, _ = conn.Write(msg)
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("UDP request communication failed: %v, got %q", err, string(buf[:n]))
		}
		t.Log("✅ compliant UDP request passed through smoothly!")
	})
}

// ============================================================================
// 3. Strict transport protocol gating test (transport="h2" strictly blocks WebTransport and MASQUE)
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

	// start the server strictly limited to h2
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     "h2", // 🌟 strictly H2 POST only
		Network:       "tcp",
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	// A. Client tries to connect with the gRPC protocol -> the server should intercept
	t.Run("Reject_gRPC_Traffic", func(t *testing.T) {
		clientListen := "127.0.0.1:25001"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Transport:  transportGRPC, // non-compliant protocol
			Token:      testToken,
			LogLevel:   "error",
		})
		waitTCPOrTLSReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the local client: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, _ = conn.Write([]byte("ping"))
		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("gRPC request expected to be rejected by the server, but an echo was received successfully")
		}
		t.Log("✅ gRPC request intercepted by the server's transport=h2 gating!")
	})

	// B. Client tries to connect with the MASQUE protocol -> the server should intercept
	t.Run("Reject_MASQUE_Traffic", func(t *testing.T) {
		clientListen := "127.0.0.1:25002"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: targetAddr,
			Insecure:   true,
			Transport:  transportMasque, // non-compliant protocol
			Token:      testToken,
			LogLevel:   "error",
		})
		waitTCPOrTLSReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the local client: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, _ = conn.Write([]byte("ping"))
		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("MASQUE request expected to be rejected by the server, but an echo was received successfully")
		}
		t.Log("✅ MASQUE request intercepted by the server's transport=h2 gating!")
	})

	// C. Client connects with standard H2 POST -> must succeed
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
		waitTCPOrTLSReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the local client: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		msg := []byte("Standard-H2-Pass")
		_, _ = conn.Write(msg)
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("standard H2 request failed: %v, got %q", err, string(buf[:n]))
		}
		t.Log("✅ standard H2 POST request passed through successfully!")
	})
}

// ============================================================================
// 4. LocalOnly local safe-forwarding protection test
// With local_only=true, forwarding to external public IPs is strictly forbidden,
// preventing open-proxy abuse
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

	// enable LocalOnly protection mode
	go startServerDirect(serverConfig{
		ListenAddr:    serverAddr,
		TLSCert:       certFile,
		TLSKey:        keyFile,
		EnableTLS:     true,
		Path:          "/tunnel",
		Transport:     "all",
		LocalOnly:     true, // 🌟 localhost / 127.0.0.1 / ::1 only
		Authenticator: tokenAuth(testToken),
		LogLevel:      "error",
	})
	waitTCPOrTLSReady(t, serverAddr, 30*time.Second)

	// A. Request a legitimate local target -> allowed through
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
		waitTCPOrTLSReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the local client: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		msg := []byte("Local-Target-Allowed")
		_, _ = conn.Write(msg)
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("local request failed: %v, got %q", err, string(buf[:n]))
		}
		t.Log("✅ local target (127.0.0.1) passed through smoothly!")
	})

	// B. Try requesting an external public target -> the server must intercept it (403 Forbidden)
	t.Run("Block_External_Public_Target", func(t *testing.T) {
		clientListen := "127.0.0.1:26002"
		go startClientDirect(clientConfig{
			ListenAddr: clientListen,
			ServerUrl:  serverURL,
			Path:       "/tunnel",
			TargetAddr: "8.8.8.8:53", // attempt to abuse the server for forwarding to an external public IP
			Insecure:   true,
			Token:      testToken,
			LogLevel:   "error",
		})
		waitTCPOrTLSReady(t, clientListen, 30*time.Second)

		conn, err := net.Dial("tcp", clientListen)
		if err != nil {
			t.Fatalf("failed to connect to the local client: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		_, _ = conn.Write([]byte("external ping"))
		buf := make([]byte, 100)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("LocalOnly policy should have blocked the public target, but the connection was not refused")
		}
		t.Log("✅ external public target successfully intercepted by the LocalOnly security policy!")
	})
}

// ============================================================================
// 5. Config file and environment variable parsing tests
// Verifies canonical Network values and environment variable overrides
// ============================================================================
func TestH2Tunnel_Config_NetworkAndEnv(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Test explicit network="udp"
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
		t.Fatalf("config parse failed: %v", err)
	}
	if cfg.Network != "udp" {
		t.Fatalf("config network value mismatch: %s", cfg.Network)
	}
	cConfig := buildClientConfig(cfg)
	if !cConfig.IsUDP() || cConfig.IsTCP() {
		t.Fatalf("clientConfig state parsing wrong: IsUDP=%v, IsTCP=%v", cConfig.IsUDP(), cConfig.IsTCP())
	}
	t.Log("✅ explicit network='udp' activated UDP-only mode successfully!")

	// 2. Test network="all"
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
		t.Fatalf("network='all' failed to enable both TCP and UDP: IsUDP=%v, IsTCP=%v", dClientCfg.IsUDP(), dClientCfg.IsTCP())
	}
	t.Log("✅ network='all' activated the TCP and UDP dual stack simultaneously!")

	// 3. Test environment variable overrides
	os.Setenv("H2TUNNEL_NETWORK", "udp")
	os.Setenv("H2TUNNEL_TRANSPORT", "grpc")
	defer os.Unsetenv("H2TUNNEL_NETWORK")
	defer os.Unsetenv("H2TUNNEL_TRANSPORT")

	envCfg := &fileConfig{Network: "tcp", Transport: "h2"}
	if err := applyEnvOverrides(envCfg); err != nil {
		t.Fatal(err)
	}
	if envCfg.Network != "udp" || envCfg.Transport != "grpc" {
		t.Fatalf("env override failed: %+v", envCfg)
	}
	t.Log("✅ environment variables dynamically overrode Network and Transport successfully!")
}
