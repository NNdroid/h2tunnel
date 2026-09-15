package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLeadingConfig(t *testing.T) {
	tests := []struct {
		args    []string
		path    string
		found   bool
		wantErr bool
	}{
		{args: nil},
		{args: []string{"version"}},
		{args: []string{"-c", "client.json"}, path: "client.json", found: true},
		{args: []string{"--config=server.json"}, path: "server.json", found: true},
		{args: []string{"-c"}, wantErr: true},
		{args: []string{"--config="}, wantErr: true},
	}
	for _, test := range tests {
		path, found, err := parseLeadingConfig(test.args)
		if (err != nil) != test.wantErr {
			t.Fatalf("parseLeadingConfig(%q) error = %v, wantErr %v", test.args, err, test.wantErr)
		}
		if path != test.path || found != test.found {
			t.Fatalf("parseLeadingConfig(%q) = (%q, %v), want (%q, %v)", test.args, path, found, test.path, test.found)
		}
	}
}

func TestConfigRejectsRemovedFields(t *testing.T) {
	for _, field := range []string{`"primary_count":2`, `"padding_min_bytes":600`} {
		path := filepath.Join(t.TempDir(), "config.json")
		data := `{"mode":"client","server":"https://example.com","target":"echo",` + field + `}`
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadConfig(path)
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("loadConfig(%s) error = %v, want unknown-field rejection", field, err)
		}
	}
}

func TestConfigPaddingValidationAndEnvironment(t *testing.T) {
	t.Setenv("H2TUNNEL_PADDING_MIN_RECORD_BYTES", "600")
	t.Setenv("H2TUNNEL_PADDING_MAX_RECORD_BYTES", "1200")
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"mode":"client","server":"https://example.com","target":"echo"}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Padding != (paddingConfig{MinRecordBytes: 600, MaxRecordBytes: 1200}) {
		t.Fatalf("padding = %+v", cfg.Padding)
	}

	for _, padding := range []paddingConfig{
		{MaxRecordBytes: 1200},
		{MinRecordBytes: 16, MaxRecordBytes: 600},
		{MinRecordBytes: 600, MaxRecordBytes: 599},
		{MinRecordBytes: 600, MaxRecordBytes: 607},
		{MinRecordBytes: 600, MaxRecordBytes: 65536},
		{MinRecordBytes: 65528},
	} {
		cfg := config{Mode: "server", Padding: padding}
		if err := cfg.validate(); err == nil {
			t.Fatalf("validate accepted padding %+v", padding)
		}
	}
}

func TestConfigRejectsModeSpecificNoOpFields(t *testing.T) {
	server := config{Mode: "server", Server: "https://unused.example"}
	if err := server.validate(); err == nil {
		t.Fatal("server config accepted client-only field")
	}
	client := config{Mode: "client", Server: "https://example.com", Target: "echo", LocalOnly: true}
	if err := client.validate(); err == nil {
		t.Fatal("client config accepted server-only field")
	}
	h2cTLS := config{Mode: "server", Transport: "h2c", Cert: "unused.crt", Key: "unused.key"}
	if err := h2cTLS.validate(); err == nil {
		t.Fatal("h2c server accepted ineffective TLS fields")
	}
	httpTLSOptions := config{Mode: "client", Server: "http://127.0.0.1:8080", Target: "echo", SNI: "unused.example"}
	if err := httpTLSOptions.validate(); err == nil {
		t.Fatal("cleartext client accepted ineffective SNI")
	}
	wtStandby := config{Mode: "client", Server: "https://example.com", Target: "echo", Transport: "wt", StandbyCount: 1}
	if err := wtStandby.validate(); err == nil {
		t.Fatal("WebTransport client accepted ineffective standby_connections")
	}
	wtUDP := config{Mode: "client", Server: "https://example.com", Target: "dns", Transport: "wt", Network: "udp"}
	if err := wtUDP.validate(); err != nil {
		t.Fatalf("WebTransport UDP was rejected: %v", err)
	}
}

func TestConfigDefaultsAreMinimalAndUsable(t *testing.T) {
	server := config{Mode: "server"}
	if err := server.validate(); err != nil {
		t.Fatal(err)
	}
	if server.Listen != ":8443" || server.Path != "/tunnel" || server.Transport != "h2" || server.Network != "tcp" {
		t.Fatalf("unexpected server defaults: %+v", server)
	}
	client := config{Mode: "client", Server: "http://127.0.0.1:8080", Target: "echo"}
	if err := client.validate(); err != nil {
		t.Fatal(err)
	}
	if client.Transport != "h2c" || client.Network != "tcp" || client.Listen != "127.0.0.1:2222" {
		t.Fatalf("unexpected client defaults: %+v", client)
	}
}

func TestRepositoryExampleConfigsUseCurrentSchema(t *testing.T) {
	for _, name := range []string{"config.server.json", "config.client.json"} {
		cfg, err := loadConfig(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg.Mode != strings.TrimSuffix(strings.TrimPrefix(name, "config."), ".json") {
			t.Fatalf("%s loaded as mode %q", name, cfg.Mode)
		}
	}
}

func TestGeneratedProxyAndServiceConfigsMatchCurrentCLI(t *testing.T) {
	nginx := captureStdout(t, func() {
		RunGenNginx([]string{"-domain", "tunnel.example", "-path", "/tunnel"})
	})
	for _, required := range []string{
		"proxy_pass https://127.0.0.1:8443",
		"proxy_request_buffering off",
		"proxy_set_header X-Auth-Token",
		"proxy_ssl_verify off",
	} {
		if !strings.Contains(nginx, required) {
			t.Fatalf("generated Nginx config is missing %q", required)
		}
	}
	systemd := captureStdout(t, func() { RunGenSystemd(nil) })
	if !strings.Contains(systemd, `"transport": "h2"`) || strings.Contains(systemd, `"h3":`) {
		t.Fatalf("generated systemd config uses an obsolete schema:\n%s", systemd)
	}
	if !strings.Contains(systemd, "/usr/local/etc/h2tunnel/config.json") ||
		!strings.Contains(systemd, `"min_record_bytes": 600`) ||
		!strings.Contains(systemd, `"max_record_bytes": 1200`) {
		t.Fatalf("generated systemd config is missing the current path or padding schema:\n%s", systemd)
	}
}

func captureStdout(t *testing.T, run func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	run()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
