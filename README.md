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
| `target` | `string` | `"127.0.0.1:22"` | Client-only target backend requested from the server. |
| `path` | `string` | `"/tunnel"` | HTTP endpoint path. |
| `transport` | `string` | `"h2"` | **Semantics differ by side.** *Server* = an **allow-list** of protocols it will accept; supports **multiple comma-separated values** (e.g. `"h2,h3,masque"`), or `"all"` to accept every protocol on the shared port. *Client* = the **single transport** that process actually runs (`"h2"`, `"h2c"`, `"h3"`, `"wt"`, `"masque"`, `"grpc"`). |
| `network` | `string` | server: `"all"`; client: `"tcp"` | Accepted values: `"tcp"`, `"udp"`, or `"all"`. |
| `token` | `string` | `""` | Single authentication token, sent through CDN-safe request headers. |
| `tls` | `bool` | transport-derived | Server only. `h2`/`h3`/`wt`/`masque`/`all` require TLS, `h2c` disables it, and `grpc` follows this field. |
| `cert` | `string` | `""` | Path to custom TLS certificate. |
| `key` | `string` | `""` | Path to custom TLS private key. |
| `local_only` | `bool` | `false` | Restrict proxying strictly to localhost (server). |
| `insecure` | `bool` | `false` | Client only. Skip upstream TLS certificate verification. |
| `host` | `string` | `""` | Client only. Override the HTTP Host header. |
| `sni` | `string` | `""` | Client only. Override TLS SNI. |
| `log_level` | `string` | `"info"` | Logging output level: `debug`, `info`, `warn`, `error`. |
| `heartbeat_sec` | `int` | `25` | Client only. Application-layer keepalive interval in seconds. Must stay below your CDN/reverse-proxy idle timeout. Negative value disables it (direct connections only). |
| `drain_timeout_sec` | `int` | `30` | Max seconds to drain existing tunnels after `SIGTERM` before force close. |
| `session_window_kb` | `int` | `256` | Ring-buffer window size for recovery; a disconnect longer than this window degrades the session honestly (`ErrGap`). |
| `handshake_ack_ms` | `int` | `3000` | Client only. Data-plane handshake `HANDSHAKE-ACK` timeout (ms). |
| `keepalive_sec` | `int` | `15` | Client only. `KEEPALIVE` heartbeat interval for backup lines / sessions (sec). |
| `primary_count` | `int` | `1` | Client only. Number of primary connections. `2` with `network: "all"` separates TCP and UDP. |
| `backup_count` | `int` | `1` | Client only. Number of warm backup connections; set to `0` to disable backups. |
| `primary_dial_interval_sec` | `int` | `30` | Client only. Re-dial throttle for primary connections. |
| `backup_dial_interval_sec` | `int` | `15` | Client only. Re-dial throttle for backup / replacement connections. |
| `establish_interval_sec` | `int` | `100` | Client only. Primary/backup establish phase offset so a CDN idle-kill does not take down both together. |

> **`transport` is intentionally asymmetric** — a single shared field whose meaning depends on `mode`:
> - **Server = a gateway allow-list.** One `listen` port multiplexes `h2`/`h3`/`grpc`/`wt`/`masque` simultaneously, telling them apart by HTTP method, `Content-Type`, `Protocol` header and HTTP/3. So `"h2,h3,masque"` means "accept these kinds of clients together" — the server never picks just one.
> - **Client = a single choice.** A client process is one tunnel endpoint; each outbound connection can only ride **one** transport stack (WT session, QUIC/h3, or h2/h2c/grpc). `transport` is normalized once and is the only runtime source of truth.
> - Prefer one process per transport on the client side if you need several protocols at once; the server side needs only one config row to serve them all.
> - `h2c` is cleartext and cannot share one listening address with TLS/QUIC transports. For CDN deployment, use `h2` (or `grpc` when the CDN explicitly supports it); the origin may receive HTTP/1.1 after CDN protocol translation and is still classified as the `h2` POST-stream family.
> - Configuration parsing is strict: unknown/removed fields and non-canonical transport or network values are rejected instead of being silently ignored.
> - Mode-specific no-op fields are rejected (for example, `target` in server mode or `local_only` in client mode). Every field can be overridden with its canonical `H2TUNNEL_*` environment variable, such as `H2TUNNEL_TRANSPORT` or `H2TUNNEL_BACKUP_COUNT`; malformed typed values fail fast.

---

## Running Behind a CDN / Reverse Proxy

### Protocol constraints (read this first)

CDN edge nodes only proxy TCP-based HTTP back to your origin. Therefore:

| Transport | Works behind CDN? | Reason |
| :--- | :--- | :--- |
| `h2` (POST stream) | ✅ **Use this** | Standard HTTP/2 streaming |
| `grpc` | ✅ Works | Requires the CDN to support gRPC (e.g. enable it on Cloudflare) |
| `h3` / `wt` / `masque` | ❌ No | Requires end-to-end UDP/QUIC, which standard CDN origin-pull does not forward |

### Idle timeout vs heartbeat

CDN and load balancers silently drop connections with no traffic for a while
(AWS ALB 60s, Nginx `proxy_read_timeout` 60s, Cloudflare 100s → HTTP 524).
When a TCP `resume/2` stream is idle, the client emits a `KEEPALIVE` control
frame and the server replies with `KEEPALIVE-ACK`, creating traffic in both
directions without exposing anything to the tunneled application. Keep
`heartbeat_sec` **below** your provider's idle timeout; the 25s default leaves
a 2x margin against the smallest common timeout (60s). UDP/QUIC transports do
not traverse an ordinary CDN origin proxy (see the table above).

### Response headers

The server emits `Content-Type: application/octet-stream`,
`Cache-Control: no-store, no-transform`, `Content-Encoding: identity` and
`X-Accel-Buffering: no` on tunnel responses, and the client sends
`Accept-Encoding: identity` on requests. These stop CDNs from sniffing,
buffering or compressing the binary stream (an SSH banner would otherwise be
detected as `text/plain` and gzip-buffered, destroying realtime streaming).

### Nginx reverse proxy sample

```nginx
location /tunnel {
    proxy_pass http://127.0.0.1:8443;
    proxy_http_version 1.1;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;              # honor X-Accel-Buffering: no, keep it explicit
    proxy_request_buffering off;
    proxy_read_timeout 300s;          # > heartbeat_sec, adjust to your usage
    proxy_send_timeout 300s;
}
```

### Client IP logging

Behind a CDN, `RemoteAddr` is always the edge node. The server logs the real
client IP from `CF-Connecting-IP` / `True-Client-IP` / `X-Real-IP` /
`X-Forwarded-For` (in that order). These headers are client-forgeable and are
used for logging only — never for access control.

---

## Session Recovery (`resume`)

Resume turns the data plane into a **transport-agnostic engine** (seq frames +
a server-side session table + a ring buffer). Any TCP tunnel stream can be
re-established after a cut and continue from the last acknowledged byte, so
long-lived sessions like SSH survive CDN idle-kills.

### Transport coverage

Resume is a **transport-agnostic engine**, but it runs two distinct data
planes depending on the tunnel type:

- **TCP tunnels → full `resume/2`**: the 16-byte v2 frame header
  (`[type][ver][dataLen][padLen][seq]`) with seq replay and a B-layer
  `HANDSHAKE`/`HANDSHAKE-ACK`.
- **UDP tunnels → datagram resume**: reuses resume's A-layer negotiation +
  ring buffer + re-dial/rebuild, but frames datagrams with a **4-byte length
  prefix** (`writeUDPPacket`) — **no** v2 seq frames, **no** B-layer
  handshake.

| Transport | Resume supported? | Data plane |
| :--- | :--- | :--- |
| `h2` (POST) | ✅ | Full `resume/2` (original implementation) |
| `h3` (QUIC) | ✅ | TCP: full `resume/2`; UDP: datagram resume |
| `grpc` | ✅ | Full `resume/2` — `Content-Type: application/grpc` marker; body carries raw resume frames (no double grpc-framing) |
| `masque` (CONNECT) | ✅ | `masque-tcp`: full `resume/2`; `masque-udp`: datagram resume via capsule |
| `wt` (WebTransport) | ✅ | Full `resume/2` — per-tunnel `WTSessionManager`; each `Stream` is a resume data plane sharing the v2 session table / ring buffer; `clientDownlink` carried in the HANDSHAKE frame payload |

> `masque`/`wt`/`h3` are direct-QUIC transports and do **not** traverse a CDN
> (see the constraint table above). The CDN idle-cut scenario resume solves
> therefore applies mainly to `h2`/`grpc`.

**How `wt` fits the resume engine.** WebTransport is itself a session+stream
protocol, so historically it kept a separate `WTSessionManager` (primary/backup
warm-up + failover via `GetSession`) and only *borrowed* `writeFrame`'s encoding —
it did **not** use the v2 session table / ring buffer / seq replay. That was
tracked as tech debt: a `wt` stream cut could not re-dial and continue from the
last byte (session failover only, no data continuation).

That gap is now closed. `wt` data paths run **through the same `resume/2`
engine** as `h2`/`grpc`/`masque`:
- Each tunnel gets its own `WTSessionManager` whose headers carry the resume
  A-layer negotiation (`X-Tunnel-Proto: resume/2`, `X-Session-ID`,
  `X-Resume-Version/Caps/Params`) plus `Protocol: webtransport`.
- On the server, `handleWebTransportServer` dispatches every business stream to
  the global v2 session table (`prepareResumeSession`) — an existing
  `X-Session-ID` reuses the same `targetConn` + ring buffer; a missing one dials
  the target.
- Since WT streams cannot carry per-stream HTTP headers, `clientDownlink` (the
  resume offset) travels in the **B-layer HANDSHAKE frame payload** as a decimal
  string, and the server replays the downlink gap from there.
- The server-side `resumeSessionWriter.w` was widened from `http.ResponseWriter`
  to `io.Writer` so a `webtransport.Stream` is a drop-in downlink target
  (`flusher` optional; h2/grpc/masque call sites unchanged).

The net effect: **`wt` now does true data continuation** — after a `Stream` cut,
a new stream with the same session id resumes from `clientDownlink` with no gap
and no duplicate (see `TestWTResumeReconnect`).

### Requirements

- **`resume/2` is always enabled** — the `resume` config flag was removed
  (v1 escape hatch deleted). It is the *only* data plane on both ends, so there
  is no one-sided-enablement incompatibility: every stream carries
  `X-Tunnel-Proto: resume/2`.
- All **TCP transports** (`h2`, `h3`, `grpc`, `masque-tcp`, `wt`) run the full
  `resume/2` engine automatically, and **datagram resume** is always on for UDP
  tunnels (`h2-udp`/`h3-udp`, `masque-udp`).

---

## Layered Architecture

h2tunnel is organized as a strict, single-direction dependency stack. Each
layer only talks to the one directly below it; the connection layer sits on
top and manages the concrete transports beneath.

| Layer | Component | Responsibility |
| :--- | :--- | :--- |
| **L3 — Connection Manager** | `ConnectionManager` (`connmanager.go`) | Owns the primary/backup line set, dial intervals, establish phase offset, failover & replenishment, type sharding. Exposes `PickClient(typ)` so business tunnels grab the active primary's dedicated transport pool. |
| **L2 — Session / resume/2** | resume v2 engine (`session.go`, frame codec) | `resume/2` is the **single** upper-layer protocol (v1 removed). Frame encode/decode, control-frame ordering (control frames are serialized ahead of `DATA` via the writer mutex on `resumeSessionWriter` — no dedicated scheduler), ring-buffer seq replay, A+B handshake, KEEPALIVE. **Exception:** UDP tunnels use *datagram resume* (`writeUDPPacket`, 4-byte length prefix — A-layer + rebuild, no v2 seq/handshake). `wt` streams run through this engine like `h2`/`grpc`/`masque`. |
| **L1 — Transports** | `h2` / `h3` / `grpc` / `masque-tcp` / `masque-udp` / `wt` | Only create a stream and expose byte I/O; no session semantics. `wt` keeps its `WTSessionManager` for session multiplexing, but its business streams are wired into the L2 resume engine (v2 session table + ring buffer) for data continuation. |

### Connection policy (`ConnectionManager`)

The client keeps `primary_count` primary lines and `backup_count` backup
lines. Defaults: `1` primary + `1` backup.

- **Type sharding**: when `primary_count > 1`, each net type (`tcp`, `udp`)
  gets its own dedicated primary so the two never contend.
- **Failover**: when a primary dies, the manager promotes a confirmed-alive
  backup to primary, then replenishes a new backup.
- **Establish phase offset**: `establish_interval_sec` staggers primary vs
  backup dialing so a CDN idle-kill never takes both down at once.
- **Probe lines do not dial the target**: backup/primary probe lines only
  complete the A+B handshake and run `KEEPALIVE` — they never connect to the
  target service. This keeps the liveness probe independent of any banner the
  target might push and avoids needless target connections.

### `resume/2` frame protocol

16-byte header `[1B type][1B ver][4B dataLen][2B padLen][8B seq]`. Frame types:
`0x01` DATA, `0x02` END, `0x03` ERROR, `0x10` HANDSHAKE, `0x11` HANDSHAKE-ACK,
`0x12` KEEPALIVE, `0x13` KEEPALIVE-ACK. Non-`resume/2` version → `426`
version-unsupported (no downgrade target).

---

## Quick Start

### 1. Export Stun QR Code & Sharing Link
```bash
h2tunnel gen-uri -c /etc/h2tunnel/config.json
```
