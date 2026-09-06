package h2tunnel

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveClientTransport(t *testing.T) {
	tests := []struct {
		name    string
		cfg     fileConfig
		want    string
		wantErr bool
	}{
		{name: "default", cfg: fileConfig{}, want: transportH2},
		{name: "trimmed canonical value", cfg: fileConfig{Transport: " H3 "}, want: transportH3},
		{name: "removed alias is invalid", cfg: fileConfig{Transport: "http3"}, wantErr: true},
		{name: "client all is invalid", cfg: fileConfig{Transport: "all"}, wantErr: true},
		{name: "unknown is invalid", cfg: fileConfig{Transport: "websocket"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveClientTransport(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveClientTransport() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("resolveClientTransport() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTransportEnvironmentOverride(t *testing.T) {
	var cfg fileConfig
	if err := json.Unmarshal([]byte(`{"mode":"client","transport":"h3"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("H2TUNNEL_TRANSPORT", "grpc")
	t.Setenv("H2TUNNEL_NETWORK", "udp")
	t.Setenv("H2TUNNEL_SESSION_WINDOW_KB", "512")
	t.Setenv("H2TUNNEL_INSECURE", "true")
	t.Setenv("H2TUNNEL_BACKUP_COUNT", "0")
	if err := applyEnvOverrides(&cfg); err != nil {
		t.Fatal(err)
	}

	got, err := resolveClientTransport(&cfg)
	if err != nil {
		t.Fatalf("environment override is invalid: %v", err)
	}
	if got != transportGRPC || cfg.Transport != transportGRPC {
		t.Fatalf("override failed: resolved=%q configured=%q", got, cfg.Transport)
	}
	if cfg.Network != networkUDP || cfg.SessionWindowKB != 512 || !cfg.Insecure || cfg.BackupCount == nil || *cfg.BackupCount != 0 {
		t.Fatalf("typed environment overrides failed: %+v", cfg)
	}
}

func TestInvalidEnvironmentOverrideIsRejected(t *testing.T) {
	t.Setenv("H2TUNNEL_BACKUP_COUNT", "many")
	if err := applyEnvOverrides(&fileConfig{}); err == nil {
		t.Fatal("invalid integer environment value should be rejected")
	}

	t.Setenv("H2TUNNEL_BACKUP_COUNT", "0")
	t.Setenv("H2TUNNEL_INSECURE", "sometimes")
	if err := applyEnvOverrides(&fileConfig{}); err == nil {
		t.Fatal("invalid boolean environment value should be rejected")
	}
}

func TestConfigValidationRejectsNoOpAndInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{name: "unknown mode", json: `{"mode":"proxy"}`},
		{name: "client transport alias", json: `{"mode":"client","transport":"http3"}`},
		{name: "network alias", json: `{"mode":"client","network":"both"}`},
		{name: "invalid log level", json: `{"mode":"server","log_level":"verbose"}`},
		{name: "server client field", json: `{"mode":"server","target":"127.0.0.1:22"}`},
		{name: "server client policy", json: `{"mode":"server","backup_count":1}`},
		{name: "client server field", json: `{"mode":"client","local_only":true}`},
		{name: "negative backup count", json: `{"mode":"client","backup_count":-1}`},
		{name: "too many tcp primaries", json: `{"mode":"client","network":"tcp","primary_count":2}`},
		{name: "h2c with tls", json: `{"mode":"server","transport":"h2c","tls":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid.json")
			if err := os.WriteFile(path, []byte(tt.json), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfigFile(path); err == nil {
				t.Fatalf("invalid configuration should be rejected: %s", tt.json)
			}
		})
	}
}

func TestConfigValidationCanonicalizesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "default.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "server" || cfg.Path != "/" || cfg.Transport != transportH2 ||
		cfg.Network != networkAll || !cfg.TLS || cfg.LogLevel != "info" {
		t.Fatalf("unexpected canonical defaults: %+v", cfg)
	}
}

func TestAuthUsesCanonicalHeadersOnly(t *testing.T) {
	const token = "secret"
	headers := make(http.Header)
	setXAuth(headers, clientConfig{Token: token})
	if headers.Get("X-Auth-Token") != token || headers.Get("Authorization") != "Bearer "+token {
		t.Fatalf("canonical auth headers not populated: %v", headers)
	}
	if headers.Get("Proxy-Authorization") != "" {
		t.Fatal("removed proxy authorization header must not be sent")
	}

	for _, header := range []string{"X-Auth-Token", "Authorization"} {
		req := httptest.NewRequest(http.MethodPost, "https://example.test/tunnel", nil)
		if header == "Authorization" {
			req.Header.Set(header, "Bearer "+token)
		} else {
			req.Header.Set(header, token)
		}
		authenticator, _ := NewTokenAuthenticator(token)
		if _, err := authenticator(req.Context(), req); err != nil {
			t.Fatalf("canonical header %s should authenticate: %v", header, err)
		}
	}

	// 移除的 Proxy-Authorization 头由 NewTokenAuthenticator 天然不识别（仅接受
	// X-Auth-Token 与 Authorization），此处断言交给 SDK 鉴权器测试覆盖。
}

func TestBuildClientConfigNormalizesRouting(t *testing.T) {
	cfg := &fileConfig{Transport: transportH3, Network: networkAll, Path: "edge"}
	got := buildClientConfig(cfg)
	if got.Transport != transportH3 || !got.usesH3() {
		t.Fatalf("unexpected client transport: %+v", got)
	}
	if got.Network != networkAll || !got.IsTCP() || !got.IsUDP() {
		t.Fatalf("unexpected client network: %q", got.Network)
	}
	if got.Path != "/edge" {
		t.Fatalf("path = %q, want /edge", got.Path)
	}
}

func TestClientTransportFollowsServerScheme(t *testing.T) {
	h2c := buildClientConfig(&fileConfig{Transport: transportH2, Server: "http://127.0.0.1:8080"})
	if h2c.Transport != transportH2C {
		t.Fatalf("http endpoint should normalize h2 to h2c, got %q", h2c.Transport)
	}
	if _, err := resolveClientEndpointTransport(&fileConfig{Transport: transportH2C}, "https://example.test"); err == nil {
		t.Fatal("h2c with https URL should be rejected")
	}
	if _, err := resolveClientEndpointTransport(&fileConfig{Transport: transportH3}, "http://example.test"); err == nil {
		t.Fatal("h3 with http URL should be rejected")
	}
}

func TestBuildClientConfigClampsPrimaryNetworks(t *testing.T) {
	tcpOnly := buildClientConfig(&fileConfig{Network: networkTCP, PrimaryCount: 2})
	if tcpOnly.connectionPolicy.PrimaryCount != 1 || len(tcpOnly.connectionPolicy.PrimaryNetworks) != 1 {
		t.Fatalf("tcp-only client should keep one primary network: %+v", tcpOnly.connectionPolicy)
	}
	dual := buildClientConfig(&fileConfig{Network: networkAll, PrimaryCount: 8})
	if dual.connectionPolicy.PrimaryCount != 2 || len(dual.connectionPolicy.PrimaryNetworks) != 2 {
		t.Fatalf("dual-stack client should clamp to two primary networks: %+v", dual.connectionPolicy)
	}
}

func TestPrepareServerConfig(t *testing.T) {
	tests := []struct {
		name      string
		cfg       serverConfig
		wantTrans string
		wantTLS   bool
		wantH3    bool
		wantErr   bool
	}{
		{name: "empty defaults to h2", cfg: serverConfig{}, wantTrans: transportH2, wantTLS: true, wantH3: false},
		{name: "all starts both stacks", cfg: serverConfig{Transport: transportAll}, wantTrans: transportAll, wantTLS: true, wantH3: true},
		{name: "comma list starts quic", cfg: serverConfig{Transport: "h2,h3,h2"}, wantTrans: "h2,h3", wantTLS: true, wantH3: true},
		{name: "h2c is cleartext", cfg: serverConfig{Transport: transportH2C}, wantTrans: transportH2C, wantTLS: false, wantH3: false},
		{name: "grpc may be cleartext", cfg: serverConfig{Transport: "grpc"}, wantTrans: transportGRPC, wantTLS: false, wantH3: false},
		{name: "h2c cannot mix with tls", cfg: serverConfig{Transport: "h2c,h2"}, wantErr: true},
		{name: "h2c cannot override explicit tls", cfg: serverConfig{Transport: "h2c", EnableTLS: true}, wantErr: true},
		{name: "unknown transport", cfg: serverConfig{Transport: "ws"}, wantErr: true},
		{name: "unknown network", cfg: serverConfig{Network: "icmp"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := prepareServerConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("prepareServerConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.Transport != tt.wantTrans || got.EnableTLS != tt.wantTLS || got.EnableH3 != tt.wantH3 {
				t.Fatalf("got transport=%q tls=%v h3=%v; want %q/%v/%v", got.Transport, got.EnableTLS, got.EnableH3, tt.wantTrans, tt.wantTLS, tt.wantH3)
			}
			if !got.routingPolicy.ready || got.Path != "/" || got.Network != networkAll ||
				got.SessionWindow != sessionWindowDefaultKB || got.DrainTimeout != drainDefault {
				t.Fatalf("server defaults/policy not prepared: %+v", got)
			}
		})
	}
}

func TestBuildServerConfigHasCDNSafeDefault(t *testing.T) {
	server, err := prepareServerConfig(buildServerConfig(&fileConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	if server.Transport != transportH2 || !server.EnableTLS || server.EnableH3 {
		t.Fatalf("default server should be TLS h2: %+v", server)
	}
}

func TestStrictTransportRouting(t *testing.T) {
	tests := []struct {
		name      string
		allowed   string
		method    string
		proto     string
		major     int
		withTLS   bool
		content   string
		wt        bool
		masqueTCP bool
		wantOK    bool
	}{
		{name: "cdn http1 origin remains h2 family", allowed: "h2", method: http.MethodPost, proto: "HTTP/1.1", major: 1, wantOK: true},
		{name: "tls h2", allowed: "h2", method: http.MethodPost, proto: "HTTP/2.0", major: 2, withTLS: true, wantOK: true},
		{name: "h2 policy rejects h3", allowed: "h2", method: http.MethodPost, proto: "HTTP/3.0", major: 3, withTLS: true, wantOK: false},
		{name: "h3 policy accepts h3", allowed: "h3", method: http.MethodPost, proto: "HTTP/3.0", major: 3, withTLS: true, wantOK: true},
		{name: "h3 policy rejects h2", allowed: "h3", method: http.MethodPost, proto: "HTTP/2.0", major: 2, withTLS: true, wantOK: false},
		{name: "h2c cleartext h2", allowed: "h2c", method: http.MethodPost, proto: "HTTP/2.0", major: 2, wantOK: true},
		{name: "h2 rejects h2c", allowed: "h2", method: http.MethodPost, proto: "HTTP/2.0", major: 2, wantOK: false},
		{name: "grpc content type with parameters", allowed: "grpc", method: http.MethodPost, proto: "HTTP/2.0", major: 2, withTLS: true, content: "Application/GRPC+Proto; charset=utf-8", wantOK: true},
		{name: "grpc rejected by h2 policy", allowed: "h2", method: http.MethodPost, proto: "HTTP/2.0", major: 2, withTLS: true, content: "application/grpc", wantOK: false},
		{name: "webtransport", allowed: "wt", method: http.MethodConnect, proto: "HTTP/3.0", major: 3, withTLS: true, wt: true, wantOK: true},
		{name: "masque", allowed: "masque", method: http.MethodConnect, proto: "HTTP/3.0", major: 3, withTLS: true, masqueTCP: true, wantOK: true},
		{name: "comma allow list", allowed: "h2,grpc", method: http.MethodPost, proto: "HTTP/2.0", major: 2, withTLS: true, content: "application/grpc", wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "https://example.test/tunnel", nil)
			req.Proto, req.ProtoMajor = tt.proto, tt.major
			if tt.withTLS {
				req.TLS = &tls.ConnectionState{}
			} else {
				req.TLS = nil
			}
			if tt.content != "" {
				req.Header.Set("Content-Type", tt.content)
			}
			err := checkStrictTransport(req, tt.allowed, tt.wt, tt.masqueTCP, false)
			if (err == nil) != tt.wantOK {
				t.Fatalf("checkStrictTransport() error = %v, wantOK %v", err, tt.wantOK)
			}
		})
	}
}

func TestNetworkRoutingPolicy(t *testing.T) {
	if !isNetworkAllowed(networkTCP, networkAll) || !isNetworkAllowed(networkUDP, networkAll) {
		t.Fatal("all should allow TCP and UDP")
	}
	if !isNetworkAllowed(networkTCP, networkTCP) || isNetworkAllowed(networkUDP, networkTCP) {
		t.Fatal("tcp-only policy mismatch")
	}
	if isNetworkAllowed("icmp", networkAll) || isNetworkAllowed(networkTCP, "icmp") {
		t.Fatal("unknown network must fail closed")
	}
}

func TestBackupCountConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
		want int
	}{
		{name: "omitted defaults one", json: `{}`, want: 1},
		{name: "explicit zero disables", json: `{"backup_count":0}`, want: 0},
		{name: "explicit count", json: `{"backup_count":3}`, want: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg fileConfig
			if err := json.Unmarshal([]byte(tt.json), &cfg); err != nil {
				t.Fatal(err)
			}
			got := buildClientConfig(&cfg).connectionPolicy
			if got.BackupCount != tt.want {
				t.Fatalf("BackupCount = %d, want %d", got.BackupCount, tt.want)
			}
			if normalized := normalizePolicy(got); normalized.BackupCount != tt.want {
				t.Fatalf("normalizePolicy changed explicit count to %d, want %d", normalized.BackupCount, tt.want)
			}
		})
	}
}

func TestConfigRejectsRemovedFields(t *testing.T) {
	removed := []string{
		`"h3":true`,
		`"wt":true`,
		`"masque":true`,
		`"grpc":true`,
		`"backup_line":"hot"`,
		`"standby":true`,
		`"conn_max_age_sec":60`,
		`"alpn":"h2"`,
		`"auth_token":"token"`,
		`"psk":"token"`,
		`"protocol":"h2"`,
	}
	for i, field := range removed {
		path := filepath.Join(t.TempDir(), "removed.json")
		content := []byte(`{"mode":"client",` + field + `}`)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfigFile(path); err == nil {
			t.Fatalf("removed field #%d (%s) should be rejected", i, field)
		}
	}
}

func TestPrimaryTypesAreDeterministic(t *testing.T) {
	p := connectionPolicy{
		PrimaryCount:    2,
		PrimaryNetworks: []string{"udp", "tcp", "udp"},
	}
	want := []string{"tcp", "udp"}
	for i := 0; i < 100; i++ {
		got := p.primaryTypes()
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("primaryTypes() = %v, want stable %v", got, want)
		}
	}
}

func TestManagedLineUsesConfiguredMissedAckLimit(t *testing.T) {
	line := newManagedLine("test", rolePrimary, networkTCP, clientConfig{}, "http://example.test", nil, nil, 7)
	if line.maxMissedAcks != 7 {
		t.Fatalf("maxMissedAcks = %d, want 7", line.maxMissedAcks)
	}
	defaultLine := newManagedLine("test", rolePrimary, networkTCP, clientConfig{}, "http://example.test", nil, nil, 0)
	if defaultLine.maxMissedAcks != backupMaxMissedAcks {
		t.Fatalf("default maxMissedAcks = %d, want %d", defaultLine.maxMissedAcks, backupMaxMissedAcks)
	}
}

func TestExampleConfigsAreRunnable(t *testing.T) {
	for _, file := range []string{"config.client.json", "config.server.json"} {
		cfg, err := loadConfigFile(file)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if cfg.Mode == "client" {
			client := buildClientConfig(cfg)
			if client.Transport != transportH2 || client.Network != networkTCP || client.HeartbeatInterval <= 0 {
				t.Fatalf("client example not normalized: %+v", client)
			}
		} else {
			server, err := prepareServerConfig(buildServerConfig(cfg))
			if err != nil || server.Transport != transportH2 || !server.EnableTLS || server.EnableH3 {
				t.Fatalf("server example not runnable: cfg=%+v err=%v", server, err)
			}
		}
	}
}

func BenchmarkCompiledRoutingPolicy(b *testing.B) {
	policy := compileRoutingPolicy("h2,grpc", networkTCP)
	req := httptest.NewRequest(http.MethodPost, "https://example.test/tunnel", nil)
	req.Proto, req.ProtoMajor = "HTTP/2.0", 2
	req.TLS = &tls.ConnectionState{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := checkStrictTransportPolicy(req, policy, "h2,grpc", false, false, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckAuth(b *testing.B) {
	auth, _ := NewTokenAuthenticator("benchmark-token")
	req := httptest.NewRequest(http.MethodPost, "https://example.test/tunnel", nil)
	req.Header.Set("Authorization", "Bearer benchmark-token")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := auth(req.Context(), req); err != nil {
			b.Fatal("authentication failed")
		}
	}
}
