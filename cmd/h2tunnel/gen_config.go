package main

import (
	"flag"
	"fmt"
)

func RunGenNginx(args []string) {
	cmd := flag.NewFlagSet("gen-nginx", flag.ExitOnError)
	domain := cmd.String("domain", "yourdomain.com", "Your domain name")
	path := cmd.String("path", "/your_secret_path", "H2Tunnel path")
	backend := cmd.String("backend", "127.0.0.1:8443", "h2tunnel TLS origin address")
	_ = cmd.Parse(args)

	fmt.Printf(`
# ====================================================================
# Nginx streaming reverse proxy snippet (%s)
# (Paste inside your server { ... } block)
# ====================================================================

location %s {
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
    gzip off;
    proxy_pass https://%s;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Auth-Token $http_x_auth_token;
    proxy_set_header Authorization $http_authorization;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    # Remove this only when the origin certificate is publicly trusted.
    proxy_ssl_verify off;
}
`, *domain, *path, *backend)
}

func RunGenSystemd(args []string) {
	cmd := flag.NewFlagSet("gen-systemd", flag.ExitOnError)
	binPath := cmd.String("bin", "/usr/local/bin/h2tunnel", "h2tunnel binary path")
	listen := cmd.String("listen", "127.0.0.1:12345", "Server listen address")
	path := cmd.String("path", "/your_secret_path", "Proxy URL path")
	token := cmd.String("token", "", "Pre-shared token")
	enableH3 := cmd.Bool("h3", false, "Enable HTTP/3 (QUIC)")
	_ = cmd.Parse(args)

	// The `server` subcommand only accepts `-c/--config` (per-parameter flags were
	// removed), so the unit always launches from a config file.
	execLine := fmt.Sprintf("%s -c /etc/h2tunnel/config.json", *binPath)

	transport := "h2"
	if *enableH3 {
		transport = "h3"
	}
	configSample := fmt.Sprintf(`{
  "mode": "server",
  "listen": %q,
  "path": %q,
  "token": %q,
  "transport": %q,
  "log_level": "info"
}`, *listen, *path, *token, transport)

	fmt.Printf(`[Unit]
Description=h2tunnel High-Performance HTTP/2 / HTTP/3 Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/h2tunnel
ExecStart=%s
Restart=always
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, execLine)

	fmt.Println("# Place the following as /etc/h2tunnel/config.json :")
	fmt.Println(configSample)
}
