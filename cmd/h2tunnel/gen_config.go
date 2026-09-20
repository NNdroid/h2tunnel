package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// normalizeLocationPath repairs a Windows path that a shell turned into an
// absolute filesystem path. POSIX shells and MSYS convert a lone "/tunnel" into
// "C:\...\tunnel" before the binary ever sees it, which would emit an
// unparseable `location` directive. The first form to try is the common one:
// the mangled value is the current directory plus the requested path, so the
// working-directory prefix can be stripped exactly. A bare drive-qualified path
// is rewritten to a leading-slash form as a fallback. Plain "/tunnel" input is
// left untouched.
func normalizeLocationPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if wd, err := os.Getwd(); err == nil {
		if rest, ok := strings.CutPrefix(p, strings.ReplaceAll(wd, "\\", "/")); ok && strings.HasPrefix(rest, "/") {
			return rest
		}
	}
	if len(p) >= 3 && p[1] == ':' && p[2] == '/' {
		return "/" + p[3:]
	}
	return p
}

// validateLocationPath rejects a value that cannot be a legitimate location
// path, so the generator fails loudly instead of printing config nginx refuses.
// Whitespace is the signature of a lost quote: MSYS rewrites an unquoted
// "/tunnel" into the shell's own filesystem path, which carries spaces. An HTTP
// location never needs one, and a caller who truly wants it percent-encodes it.
func validateLocationPath(p string) error {
	if strings.ContainsAny(p, " \t\r\n") {
		return fmt.Errorf("location path %q contains whitespace, so the shell dropped the quotes; pass it as -path /tunnel", p)
	}
	if len(p) < 2 || p[0] != '/' || p[1] == '/' {
		return fmt.Errorf("location path %q must start with a single /", p)
	}
	return nil
}

func RunGenNginx(args []string) {
	cmd := flag.NewFlagSet("gen-nginx", flag.ExitOnError)
	domain := cmd.String("domain", "yourdomain.com", "Your domain name")
	path := cmd.String("path", "/your_secret_path", "H2Tunnel path")
	backend := cmd.String("backend", "127.0.0.1:8443", "h2tunnel TLS origin address")
	_ = cmd.Parse(args)
	locPath := normalizeLocationPath(*path)
	if err := validateLocationPath(locPath); err != nil {
		fmt.Fprintln(os.Stderr, "gen-nginx:", err)
		os.Exit(2)
	}

	fmt.Printf(`
# ====================================================================
# Nginx streaming reverse proxy snippet (%s)
# (Paste inside your server { ... } block)
# ====================================================================
#
# No header-forwarding directive is needed here: nginx passes every
# X-* request and response header through by default, and h2tunnel
# sets no Connection or Upgrade header, so there is nothing hop-by-hop
# to preserve. The one Host rewrite that matters is below.

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
    # Optionally keep idle upstream connections (also declare
    # "proxy_keepalive N;" in an upstream {} block):
    # proxy_set_header Connection "";
}
`, *domain, locPath, *backend)
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
	execLine := fmt.Sprintf("%s -c /usr/local/etc/h2tunnel/config.json", *binPath)

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
  "session_max": 4096,
  "session_max_per_principal": 256,
  "padding": {
    "min_record_bytes": 600,
    "max_record_bytes": 1200
  },
  "brutal": {
    "enabled": false,
    "rate_bytes": 0,
    "cwnd_gain": 15
  },
  "log_level": "info"
}`, *listen, *path, *token, transport)

	fmt.Printf(`[Unit]
Description=h2tunnel High-Performance HTTP/2 / HTTP/3 Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/etc/h2tunnel
ExecStart=%s
Restart=always
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, execLine)

	fmt.Println("# Place the following as /usr/local/etc/h2tunnel/config.json :")
	fmt.Println(configSample)
}
