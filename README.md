# h2tunnel

Enterprise High-Performance HTTP/2, HTTP/3 (QUIC), WebTransport, MASQUE (RFC 9298), and gRPC Multiplexing Tunnel.

## Features

- **Multi-Protocol Transport Stack**: Supports `h2`, `h2c`, `h3` (QUIC), `wt` (WebTransport), `masque` (CONNECT-TCP/UDP), and `grpc`.
- **Auto Self-Signed TLS**: Generates high-authenticity ECDSA certificates automatically when TLS is enabled without manual certificate setup.
- **Unified Transport Configuration**: Server listens on both TCP and UDP on a single port for all incoming protocols.
- **Health Check Probe (`/healthz`)**: Built-in HTTP probe endpoint for AWS ALB, Cloudflare, and Nginx health monitors.
- **Stun Node Sharing (`gen-uri`)**: One-click sharing URI and terminal ASCII QR code generation for Android & TV.
- **Graceful Connection Draining**: Clean zero-drop drain shutdown on `SIGINT` / `SIGTERM`.

---

## One-Key Management (Linux Server & Client)

### 1. Server Installation (Default)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/h2tunnel/main/scripts/install.sh | sudo bash -s install server
```

### 2. Client Installation (Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/h2tunnel/main/scripts/install.sh | sudo bash -s install client
```

### 3. Upgrade / Uninstall
```bash
# One-key Upgrade (Keeps existing config.json)
curl -fsSL https://raw.githubusercontent.com/NNdroid/h2tunnel/main/scripts/install.sh | sudo bash -s upgrade

# One-key Uninstall
curl -fsSL https://raw.githubusercontent.com/NNdroid/h2tunnel/main/scripts/install.sh | sudo bash -s uninstall
```

### 4. Service Management
```bash
systemctl start h2tunnel    # Start service
systemctl stop h2tunnel     # Stop service
systemctl restart h2tunnel  # Restart service
systemctl status h2tunnel   # Check status
journalctl -u h2tunnel -f   # View live logs
```

---

## Configuration Reference (`config.json`)

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `mode` | `string` | `"server"` | Operational mode: `"server"` or `"client"`. |
| `listen` | `string` | `":8443"` | Listening address (`":8443"` for server; `"127.0.0.1:2222"` for client). |
| `server` | `string` | `""` | Server URL for client mode (e.g. `"https://example.com:8443"`). |
| `target` | `string` | `"127.0.0.1:22"` | Target backend service to forward to. |
| `path` | `string` | `"/tunnel"` | HTTP endpoint path. |
| `transport` | `string` | `"all"` | Transport mode: `"all"`, `"h2"`, `"h2c"`, `"h3"`, `"wt"`, `"masque"`, `"grpc"`. |
| `token` | `string` | `""` | Proxy-Authorization Token (aliases `auth_token`/`psk`). |
| `tls` | `bool` | `true` | Enable TLS encryption (auto self-signed if cert/key omitted). |
| `cert` | `string` | `""` | Path to custom TLS certificate. |
| `key` | `string` | `""` | Path to custom TLS private key. |
| `local_only` | `bool` | `false` | Restrict proxying strictly to localhost (server). |
| `log_level` | `string` | `"info"` | Logging output level: `debug`, `info`, `warn`, `error`. |

---

## Quick Start

### 1. Export Stun QR Code & Sharing Link
```bash
h2tunnel gen-uri -c /etc/h2tunnel/config.json
```
