package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestH2Tunnel_JSONConfigParsing(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Test Server Config Parsing
	serverJSON := `{
		"mode": "server",
		"listen": ":18443",
		"path": "/my-tunnel",
		"token": "token1",
		"tls": true,
		"transport": "h3",
		"local_only": true,
		"log_level": "debug"
	}`
	serverPath := filepath.Join(tempDir, "server.json")
	if err := os.WriteFile(serverPath, []byte(serverJSON), 0644); err != nil {
		t.Fatalf("write server.json failed: %v", err)
	}

	sCfg, err := loadConfigFile(serverPath)
	if err != nil {
		t.Fatalf("load server config failed: %v", err)
	}
	if sCfg.Mode != "server" || sCfg.Listen != ":18443" || sCfg.Path != "/my-tunnel" || !sCfg.TLS || sCfg.Transport != transportH3 || !sCfg.LocalOnly || sCfg.LogLevel != "debug" {
		t.Fatalf("parsed server config mismatch: %+v", sCfg)
	}
	if sCfg.Token != "token1" {
		t.Fatalf("parsed token mismatch: got %q", sCfg.Token)
	}

	// 2. Test Client Config Parsing with Transport Enum
	clientJSON := `{
		"mode": "client",
		"listen": "127.0.0.1:3333",
		"server": "https://tunnel.example.com:8443",
		"target": "127.0.0.1:22",
		"path": "/my-tunnel",
		"token": "secret_bearer_token",
		"transport": "masque",
		"insecure": true,
		"sni": "tunnel.example.com",
		"host": "tunnel.example.com",
		"log_level": "warn"
	}`
	clientPath := filepath.Join(tempDir, "client.json")
	if err := os.WriteFile(clientPath, []byte(clientJSON), 0644); err != nil {
		t.Fatalf("write client.json failed: %v", err)
	}

	cCfg, err := loadConfigFile(clientPath)
	if err != nil {
		t.Fatalf("load client config failed: %v", err)
	}
	if cCfg.Mode != "client" || cCfg.Listen != "127.0.0.1:3333" || cCfg.Server != "https://tunnel.example.com:8443" || cCfg.Target != "127.0.0.1:22" || cCfg.Path != "/my-tunnel" || cCfg.Token != "secret_bearer_token" || cCfg.Transport != transportMasque || !cCfg.Insecure || cCfg.SNI != "tunnel.example.com" || cCfg.LogLevel != "warn" {
		t.Fatalf("parsed client config mismatch: %+v", cCfg)
	}
	built := buildClientConfig(cCfg)
	if built.Transport != transportMasque || !built.usesMasque() {
		t.Fatalf("transport enum was not normalized: %+v", built)
	}
}

func TestH2Tunnel_LiveE2E_FromJSONConfig(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Echo Backend Target
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo backend failed: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Find free port for H2C Server
	dummyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy failed: %v", err)
	}
	h2Port := dummyLn.Addr().(*net.TCPAddr).Port
	dummyLn.Close()
	serverListen := fmt.Sprintf("127.0.0.1:%d", h2Port)

	// 3. Create Server JSON Config (Cleartext H2C)
	token := "json_test_token_h2"
	serverConf := fmt.Sprintf(`{
		"mode": "server",
		"listen": "%s",
		"path": "/tunnel",
		"token": "%s",
		"transport": "h2c",
		"log_level": "debug"
	}`, serverListen, token)
	serverConfPath := filepath.Join(tempDir, "server_e2e.json")
	if err := os.WriteFile(serverConfPath, []byte(serverConf), 0644); err != nil {
		t.Fatalf("write server_e2e.json failed: %v", err)
	}

	// 4. Start Server from loaded Config
	sCfg, err := loadConfigFile(serverConfPath)
	if err != nil {
		t.Fatalf("load server_e2e.json failed: %v", err)
	}
	go startServerDirect(buildServerConfig(sCfg))
	time.Sleep(100 * time.Millisecond)

	// 5. Find free port for Client Listen
	clientDummy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client dummy failed: %v", err)
	}
	clientPort := clientDummy.Addr().(*net.TCPAddr).Port
	clientDummy.Close()
	clientListen := fmt.Sprintf("127.0.0.1:%d", clientPort)

	// 6. Create Client JSON Config
	clientConf := fmt.Sprintf(`{
		"mode": "client",
		"listen": "%s",
		"server": "http://%s",
		"path": "/tunnel",
		"target": "%s",
		"token": "%s",
		"log_level": "debug"
	}`, clientListen, serverListen, backendAddr, token)
	clientConfPath := filepath.Join(tempDir, "client_e2e.json")
	if err := os.WriteFile(clientConfPath, []byte(clientConf), 0644); err != nil {
		t.Fatalf("write client_e2e.json failed: %v", err)
	}

	// 7. Start Client from loaded Config
	cCfg, err := loadConfigFile(clientConfPath)
	if err != nil {
		t.Fatalf("load client_e2e.json failed: %v", err)
	}
	go startClientDirect(buildClientConfig(cCfg))
	time.Sleep(150 * time.Millisecond)

	// 8. Connect to Client Listener & Test Echo
	conn, err := net.Dial("tcp", clientListen)
	if err != nil {
		t.Fatalf("dial client failed: %v", err)
	}
	defer conn.Close()

	testData := []byte("Hello H2Tunnel via JSON Configuration!")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write to client tunnel failed: %v", err)
	}

	resp := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read from client tunnel failed: %v", err)
	}

	if string(resp) != string(testData) {
		t.Fatalf("echo mismatch: got %q, want %q", string(resp), string(testData))
	}

	t.Logf("✅ Live E2E H2Tunnel via JSON Config PASSED!")
}
