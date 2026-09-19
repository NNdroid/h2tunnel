# h2tunnel

[![Test](https://github.com/NNdroid/h2tunnel/actions/workflows/test.yml/badge.svg)](https://github.com/NNdroid/h2tunnel/actions/workflows/test.yml)

`h2tunnel` is a secure tunneling library embeddable in Go programs, and it also ships a standalone command-line program. It wraps TCP or UDP services inside HTTP/2, HTTP/3, WebTransport, MASQUE, or gRPC connections, with disconnect recovery, CDN-friendly request headers, and bounded session buffering.

The server does not become an open proxy by default: the package API forces callers to provide both an `Authenticator` and a `TargetDialer`. Prefer logical service names (for example `ssh`, `postgres`) and do not let the client decide arbitrary target addresses.

## Installation

Use it as a Go package:

```bash
go get github.com/NNdroid/h2tunnel
```

One-line install of the command-line program (Linux, includes systemd service registration):

```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/h2tunnel/main/scripts/install.sh | sudo bash -s -- install
```

The script prefers a local prebuilt binary, then builds from source, and finally downloads the bare binary matching the system architecture from a GitHub Release (no extraction needed).

Build the command-line program from source:

```bash
go build -trimpath -o h2tunnel ./cmd/h2tunnel
```

## Choosing a transport

| Transport | TCP | UDP | Plain CDN | Typical use |
| --- | ---: | ---: | ---: | --- |
| `h2` | ✅ | ✅ | ✅ recommended | CDN, reverse proxy, general public access |
| `h2c` | ✅ | ✅ | plaintext origin links only | internal networks, TLS terminated at an external gateway |
| `grpc` | ✅ | ✅ | ✅, requires CDN with gRPC enabled | existing gRPC infrastructure |
| `h3` | ✅ | ✅ | usually no origin forwarding | end-to-end QUIC direct connection |
| `masque` | ✅ | ✅ | usually no origin forwarding | standard CONNECT-TCP/UDP direct connection |
| `wt` | ✅ | ✅ | usually no origin forwarding | WebTransport streams carrying TCP byte streams and UDP datagrams |

Plain CDNs do not forward UDP/QUIC verbatim to the origin, so for CDN scenarios prefer `h2`; H3, WebTransport, and MASQUE should be used as end-to-end direct connections.

## Package API overview

Client:

```go
func NewClient(ClientOptions) (*Client, error)
func (*Client) Start(context.Context) error
func (*Client) DialContext(context.Context, string, string) (net.Conn, error)
func (*Client) DialPacketContext(context.Context, string, string) (PacketConn, error)
func (*Client) NegotiateBrutal(context.Context) (BrutalTuning, error)
func (*Client) Shutdown(context.Context) error
func (*Client) Close() error
```

Server:

```go
func NewServer(ServerOptions) (*Server, error)
func (*Server) Handler() http.Handler
func (*Server) Serve(Listeners) error
func (*Server) ListenAndServe(string) error
func (*Server) Listeners() Listeners
func (*Server) Shutdown(context.Context) error
func (*Server) Close() error
```

Security helpers:

```go
func NewTokenCredentials(string) (CredentialProvider, error)
func NewTokenAuthenticator(string) (Authenticator, error)
func NewStaticServiceDialer(map[string]Service, *net.Dialer) (TargetDialer, error)
```

`Client` is safe for concurrent use; each dial owns an independent logical session. `Server` is a single-lifetime object — create a new instance after closing it. `NewClient` and `NewServer` only validate configuration; they do not open ports or start background tasks.

If `Client.Start` fails it releases all transport resources and resets state, so `Start` can simply be called again to retry; after success, calling `Start` again returns the first result. `Client.Shutdown` returns once the context deadline passes, but existing tunnels keep draining in the background — call `Close` to force every active connection down when you need an immediate stop.

`Server.Listeners()` returns the listeners `Serve` actually bound; with port 0 you can read the real port via `Listeners().QUIC.LocalAddr()` (a WT-only deployment has no TCP listener, so this is the only port-discovery path). The values are for reading addresses only; listener ownership stays with `Serve`.

## Full package API example

### 1. Build a closed service registry

The server below only allows access to two explicitly registered targets. Unknown service names, network-type mismatches, or insufficient roles are rejected.

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/NNdroid/h2tunnel"
)

func main() {
    tokenAuth, err := h2tunnel.NewTokenAuthenticator("replace-with-a-long-random-token")
    if err != nil {
        log.Fatal(err)
    }
    auth := func(ctx context.Context, request *http.Request) (h2tunnel.Principal, error) {
        principal, err := tokenAuth(ctx, request)
        if err != nil {
            return h2tunnel.Principal{}, err
        }
        principal.ID = "operations-client"
        principal.Roles = []string{"ops"}
        return principal, nil
    }

    dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
        "ssh": {
            Network: h2tunnel.NetworkTCP,
            Address: "127.0.0.1:22",
            Roles:   []string{"ops"},
        },
        "dns": {
            Network: h2tunnel.NetworkUDP,
            Address: "127.0.0.1:53",
        },
    }, nil)
    if err != nil {
        log.Fatal(err)
    }

    server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
        Path:          "/tunnel",
        Transports:    []h2tunnel.Transport{h2tunnel.TransportH2},
        Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP, h2tunnel.NetworkUDP},
        Authenticator: auth,
        Dialer:        dialer,
        Tuning: h2tunnel.ServerTuning{
            SessionMax:             4096,
            SessionMaxPerPrincipal: 256,
            Padding: h2tunnel.PaddingTuning{
                MinRecordBytes: 600,
                MaxRecordBytes: 1200,
            },
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    // TLS is terminated at the CDN/Nginx; the origin listens on plain HTTP on the loopback address.
    origin := &http.Server{Addr: "127.0.0.1:8080", Handler: server.Handler()}
    log.Fatal(origin.ListenAndServe())
}
```

`TransportH2` is allowed here instead of `TransportH2C` because client-to-CDN uses H2; even if CDN-to-origin degrades to HTTP/1.1, it still belongs to the H2 POST-stream transport family. The origin must listen only on a trusted network or the loopback address.

Server-side resource bounds (`ServerTuning`, 0 = built-in default):

- `SessionMax` / `SessionMaxPerPrincipal` — cap on concurrent resume sessions, in total and per principal. A flood of distinct never-resumed session ids would otherwise grow the session table without limit; values above the hard cap are clamped rather than rejected.
- Fixed, untunable: `X-Session-ID` must be 1-128 bytes (checked before any target dial), the HTTP/2 server advertises at most 256 concurrent streams, a WebTransport session serves at most 256 concurrent streams, and shared profiles decompress to at most 8 MiB.

### 2. Create a client and dial a logical service

```go
credentials, err := h2tunnel.NewTokenCredentials("replace-with-a-long-random-token")
if err != nil {
    return err
}
client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
    Endpoint:    "https://tunnel.example.com",
    Path:        "/tunnel",
    Transport:   h2tunnel.TransportH2,
    Credentials: credentials,
    Tuning: h2tunnel.ClientTuning{
        SessionWindowBytes: 256 * 1024,
        HeartbeatInterval:  25 * time.Second,
        StandbyConnections: 1,
        Padding: h2tunnel.PaddingTuning{
            MinRecordBytes: 600,
            MaxRecordBytes: 1200,
        },
    },
})
if err != nil {
    return err
}
defer client.Close()

ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "ssh")
if err != nil {
    return err
}
defer conn.Close()
```

`DialContext` returns only after server authentication, target authorization, target connection, and the tunnel handshake have all completed. The passed context propagates all the way to the server-side `TargetDialer`; a timeout or cancellation leaves no target connection still dialing in the background.

### 3. Event callbacks and network-change self-heal (optional)

```go
client.SetEventHandler(func(ev h2tunnel.ClientEvent) {
    switch ev.Kind {
    case h2tunnel.EventReconnecting:
        log.Printf("tunnel reconnecting (attempt %d): %v", ev.Attempt, ev.Err)
    case h2tunnel.EventTunnelDied:
        log.Printf("tunnel died: %s", ev.Reason)
    }
})

// When an OS network-change notification arrives (NotifyAddrChange / NWPathMonitor etc.):
client.ForceReconnect() // abandon the current stream and redial immediately; session/data not lost
```

Callbacks are dispatched on a dedicated goroutine with panic recovery and never block the packet-read loop. Each tunnel exposes `Done() <-chan struct{}` and `Err() error` (context-style lifecycle).

Self-heal tuning (`ClientTuning`):

- `AutoRedial: true` — automatically resets and continues after redial exhaustion (16 attempts), essential for "stay down until the network returns" scenarios; when off, exhaustion terminates the tunnel and dispatches a `TunnelDied` event.
- `RedialBudget` — per-attempt dial budget for stream setup + handshake, tightening the abandon pace during outages; the timer stops once the tunnel is ready and never affects established streams.
- `SessionWindowBytes` — when outage duration × downlink rate exceeds the window, the gap is unrecoverable; raise it for long outages / high throughput.

### 4. Make `http.Client` reach services uniformly through the tunnel

```go
transport := &http.Transport{DialContext: client.DialContext}
httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}

// The URL's host is passed to the server registry as the logical target.
response, err := httpClient.Get("http://internal-api/health")
```

If the logical name includes a port, use the same string as the registry key, e.g. `internal-api:80`. Response bodies are still managed by the ordinary `http.Client`.

### 5. Build an SSH client on top of a reused tunnel

```go
raw, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "ssh")
if err != nil {
    return err
}
sshConn, channels, requests, err := ssh.NewClientConn(raw, "ssh", sshConfig)
if err != nil {
    raw.Close()
    return err
}
sshClient := ssh.NewClient(sshConn, channels, requests)
defer sshClient.Close()
```

### 6. UDP / datagram access

```go
packetConn, err := client.DialPacketContext(ctx, h2tunnel.NetworkUDP, "dns")
if err != nil {
    return err
}
defer packetConn.Close()

_ = packetConn.SetDeadline(time.Now().Add(5 * time.Second))
if _, err := packetConn.Write(dnsQuery); err != nil {
    return err
}
response := make([]byte, 64*1024)
n, err := packetConn.Read(response)
```

What comes back is a "connected" `PacketConn`: the address argument of `WriteTo` cannot change the logical target fixed at creation time. Dial a separate `PacketConn` per remote UDP conversation.

### 7. Application-layer record padding

`PaddingTuning` applies to both TCP byte streams and UDP datagrams, and covers all six transports `h2`, `h2c`, `grpc`, `h3`, `wt`, `masque`. To shape both uplink and downlink, configure it on client and server alike:

```go
padding := h2tunnel.PaddingTuning{
    MinRecordBytes: 600,
    MaxRecordBytes: 1200,
}

clientOptions.Tuning.Padding = padding // client to server
serverOptions.Tuning.Padding = padding // server to client
```

Stream data is sliced into full records whose lengths fall randomly in `[600, 1200]`; short records get padding appended. UDP always keeps one packet per record: short packets are padded, and packets originally above the cap stay intact and are never split. Padding is discarded by the peer after decoding, so the business payload the TCP/UDP target receives is unchanged. Omitting the config or setting both values to `0` disables padding entirely; setting only `MinRecordBytes` makes the cap default to 125% of the minimum.

What is guaranteed here is the **h2tunnel application-layer record size**, not the size of every IP packet on the wire. TLS, HTTP/2, HTTP/3, QUIC, TCP ACKs/retransmissions, CDNs, path MTU, and TSO/GSO may still split or coalesce records; no application can guarantee every actual IP packet is at least 600B. To verify the live packet-size distribution, capture on the target interface with NIC segmentation offload disabled.

### 8. Custom authentication and dynamic routing

Production systems can turn JWT, mTLS identity, or an existing session into a stable `Principal.ID`, then enforce tenant, role, network, and target policies inside the `TargetDialer`.

```go
authenticator := func(ctx context.Context, r *http.Request) (h2tunnel.Principal, error) {
    claims, err := verifyJWT(r.Header.Get("Authorization"))
    if err != nil {
        return h2tunnel.Principal{}, h2tunnel.ErrUnauthenticated
    }
    return h2tunnel.Principal{ID: claims.Subject, Roles: claims.Roles}, nil
}

targetDialer := func(ctx context.Context, request h2tunnel.DialRequest) (net.Conn, error) {
    address, ok := lookupAllowedService(request.Principal.ID, request.Target, request.Network)
    if !ok {
        return nil, h2tunnel.ErrForbidden
    }
    var dialer net.Dialer
    return dialer.DialContext(ctx, string(request.Network), address)
}
```

Never dial `request.Target` without validation inside the `TargetDialer`, or the tunnel becomes an SSRF/open internal proxy. For UDP, the `TargetDialer` must return a connected datagram `net.Conn`, typically a `*net.UDPConn`.

### 9. Direct TLS with H2/H3 sharing one port

```go
certificate, err := tls.LoadX509KeyPair("server.crt", "server.key")
if err != nil {
    return err
}
server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
    Path:       "/tunnel",
    Transports: []h2tunnel.Transport{h2tunnel.TransportH2, h2tunnel.TransportH3},
    Networks:   []h2tunnel.Network{h2tunnel.NetworkTCP, h2tunnel.NetworkUDP},
    TLSConfig: &tls.Config{
        MinVersion:   tls.VersionTLS13,
        Certificates: []tls.Certificate{certificate},
    },
    Authenticator: authenticator,
    Dialer:        targetDialer,
})
if err != nil {
    return err
}

// Automatically creates TCP and UDP listeners on the same numeric port.
return server.ListenAndServe(":8443")
```

The library never persists certificates. When `ListenAndServe` hosts `h2`/`h3`/`wt`/`masque` you must supply a `TLSConfig` containing a certificate; for development use `h2tunnel.SelfSignedTLSConfig("localhost")` to generate one on the fly (it always carries 127.0.0.1/::1 IP SANs so loopback connections pass verification directly); for production use publicly trusted certificates. When embedding via `Handler` into an existing HTTP server, TLS can be handled by the external server or reverse proxy.

### 10. Manage listeners yourself

```go
tcpListener, err := net.Listen("tcp", ":8443")
if err != nil {
    return err
}
udpListener, err := net.ListenPacket("udp", ":8443")
if err != nil {
    tcpListener.Close()
    return err
}
err = server.Serve(h2tunnel.Listeners{TCP: tcpListener, QUIC: udpListener})
```

`Serve` takes over the passed listeners; an unexpected failure of either listener stack closes the other stack and returns the error.

### 11. Graceful shutdown

```go
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

if err := client.Shutdown(shutdownCtx); err != nil {
    _ = client.Close() // force-close after timeout
}
if err := server.Shutdown(shutdownCtx); err != nil {
    _ = server.Close()
}
```

### 12. TCP Brutal congestion control (Linux only)

Set the same `BrutalTuning` on both sides. The feature is off unless `Enabled`
is true, and it is a silent no-op on non-Linux builds or on a kernel without the
`brutal` controller — no error is returned either way.

```go
brutal := h2tunnel.BrutalTuning{
    Enabled:   true,
    RateBytes: 200_000_000, // this side's declared rate, bytes/second
    CwndGain:  20,          // tenths, so 20 = 2.0x
    Negotiate: true,
}

clientOptions.Tuning.Brutal = brutal
serverOptions.Tuning.Brutal = brutal

// Optional: force one shared rate bucket instead of the derived per-client one.
brutal.GroupID = 7
```

The effective `RateBytes` and `CwndGain` are the minimum of the two sides.
`GroupID` is derived when zero: `u64le(HMAC-SHA256(token, seed)[:8]) | 1`, where
the seed is the client's stable group id, so it stays constant across connection
migration. Set a non-zero value to put several distinct clients in one bucket.

```go
// The explicit form of the in-band exchange: it answers with the negotiation
// headers and never dials an origin or opens a session.
tuning, err := client.NegotiateBrutal(ctx)
// tuning.GroupID is what the server derived for this client.
```

`Shutdown` refuses new sessions and waits for existing connections to end naturally; `Close` terminates immediately. When embedded in an external `http.Server`, stop the external server from accepting new requests first, then call the tunnel server's `Shutdown`.

## CDN and reverse-proxy deployment

Recommended path:

```text
app -> h2tunnel Client -> HTTPS/H2 -> CDN -> HTTPS/HTTP origin -> h2tunnel Server -> internal service
```

Tunnel requests and responses set the following key properties:

- `Cache-Control: no-store, no-transform`
- `Content-Type: application/octet-stream`
- `Content-Encoding: identity`
- `Accept-Encoding: identity`
- `User-Agent`: a real browser UA (camouflaged as Android Chrome WebView by default, suppressing Go's `Go-http-client/2.0` default; pairs with `utls` browser TLS fingerprints)
- `X-Accel-Buffering: no`
- `X-Auth-Token`, plus a standard Bearer Authorization as well

These settings stop proxies from caching, compressing, or buffering binary streams. The server never advances the recovery cursor on non-2xx responses, auth failures, or proxy-substituted error pages.

### Nginx: TLS to the origin

The standalone CLI's `h2` mode listens with TLS at the origin. Nginx can proxy like this:

```nginx
location /tunnel {
    proxy_pass https://127.0.0.1:8443;
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
    gzip off;
    proxy_set_header Host $host;
    proxy_set_header X-Auth-Token $http_x_auth_token;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;
    # CLI-generated certificates are only fit for a protected local origin link.
    proxy_ssl_verify off;
}
```

For a plaintext origin, use the `Server.Handler()` embedding example above and let the external server listen only on `127.0.0.1` or a protected private address. Do not allow the CDN to cache `/tunnel`, and do not enable request/response buffering.

The heartbeat interval must be smaller than the shortest idle timeout on the path. The default 25s suits common 60s proxy timeouts; adjust explicitly if the CDN's shortest timeout differs. Controlled proxy latency, error responses, auth-header forwarding, cache/buffer headers, and steady-state throughput are all covered by automated tests.

## CLI usage

### Server configuration

```json
{
  "mode": "server",
  "listen": ":8443",
  "path": "/tunnel",
  "transport": "h2",
  "network": "tcp",
  "token": "replace-with-a-long-random-token",
  "tls": true,
  "cert": "/usr/local/etc/h2tunnel/server.crt",
  "key": "/usr/local/etc/h2tunnel/server.key",
  "local_only": true,
  "session_window_kb": 256,
  "session_max": 4096,
  "session_max_per_principal": 256,
  "drain_timeout_sec": 30,
  "padding": {
    "min_record_bytes": 600,
    "max_record_bytes": 1200
  },
  "brutal": {
    "enabled": false,
    "rate_bytes": 0,
    "cwnd_gain": 15,
    "negotiate": true
  },
  "log_level": "info"
}
```

When `cert` and `key` are both empty, the CLI generates an in-process self-signed certificate; for public production origins provide a real certificate. `local_only: true` resolves the target host and rejects any non-loopback address, reducing SSRF risk.

### Client configuration

```json
{
  "mode": "client",
  "listen": "127.0.0.1:2222",
  "server": "https://tunnel.example.com",
  "target": "127.0.0.1:22",
  "path": "/tunnel",
  "transport": "h2",
  "network": "tcp",
  "token": "replace-with-a-long-random-token",
  "sni": "tunnel.example.com",
  "host": "tunnel.example.com",
  "insecure": false,
  "utls": "chrome",
  "heartbeat_sec": 25,
  "session_window_kb": 256,
  "handshake_ack_ms": 3000,
  "keepalive_sec": 15,
  "standby_connections": 1,
  "drain_timeout_sec": 30,
  "padding": {
    "min_record_bytes": 600,
    "max_record_bytes": 1200
  },
  "brutal": {
    "enabled": false,
    "rate_bytes": 0,
    "cwnd_gain": 15,
    "negotiate": true
  },
  "log_level": "info"
}
```

Starting it:

```bash
h2tunnel -c /usr/local/etc/h2tunnel/config.json
h2tunnel server -c /usr/local/etc/h2tunnel/config.json
h2tunnel client -c /usr/local/etc/h2tunnel/config.client.json
h2tunnel version
```

The client's `listen` is the TCP/UDP entry given to local programs, and `target` is the address the server will ultimately connect to. The CLI is a direct-address proxy; use the package API when you need logical service registries, per-identity routing, or embedding into another program uniformly.

### Configuration fields

Config parsing is strict: unknown fields, removed fields, wrong types, and fields with no effect in the current mode all fail hard, with no backward compatibility for old versions.

| Field | Mode | Default | Description |
| --- | --- | --- | --- |
| `mode` | shared | `server` | `server` or `client` |
| `listen` | shared | server `:8443`; client `127.0.0.1:2222` | listen address |
| `server` | client | required | full `http://` or `https://` server address |
| `target` | client | required | target address the server should connect to |
| `path` | shared | `/tunnel` | tunnel HTTP path; MASQUE endpoints are nested beneath it: `<path>/.well-known/masque/{tcp,udp}/...` (e.g. `path=/tunnel` → `/tunnel/.well-known/masque/...`; `path=/` yields the standard `/.well-known/masque`) |
| `token` | shared | empty | pre-shared auth token; must be set in production |
| `transport` | shared | server `h2`; client inferred from URL | server accepts comma-separated lists or `all`; client picks exactly one |
| `network` | shared | `tcp` | `tcp`, `udp`, or `all` |
| `tls` | server | `false` | enable TLS; `h2/h3/wt/masque` imply TLS automatically, `h2c` forces plaintext |
| `cert` / `key` | server | empty | TLS certificate and private key, must be set together |
| `local_only` | server | `false` | allow loopback targets only |
| `insecure` | client | `false` | skip certificate verification, for controlled testing only |
| `host` | client | empty | override the HTTP Host, for CDN multi-tenant origin routing |
| `sni` | client | URL hostname | override the TLS SNI |
| `utls` | client | empty | TLS ClientHello fingerprint camouflage: `chrome`, `firefox`, `edge`, `safari`, `ios`, `qq`; only effective for `h2`/`grpc` (the QUIC family does TLS inside quic-go and cannot be injected) |
| `masque_alpn` | client | empty (auto) | MASQUE carrier: `h3` (QUIC only), `h2` (TCP extended CONNECT only), empty = auto (h3 first; pins h2 when UDP is unreachable) |
| `padding.min_record_bytes` | shared | `0` (off) | minimum application-layer tunnel record length; must be `17..65527`. The client shapes the uplink, the server shapes the downlink |
| `padding.max_record_bytes` | shared | 125% of the minimum | random cap for application-layer tunnel records; at most `65535`, at least 8B above the minimum. Large UDP packets are never split to satisfy the cap |
| `pprof` | server | empty | when non-empty, start `net/http/pprof` at that address (e.g. `127.0.0.1:6060`); bind only to trusted addresses |
| `brutal.enabled` | shared | `false` | Linux TCP Brutal congestion control. On other operating systems, or when the running kernel has no `brutal` controller, this is a silent no-op (one WARN at startup) and traffic falls back to the default controller |
| `brutal.rate_bytes` | shared | `0` (no local preference) | declared bandwidth in bytes/second for this side; the effective value is the minimum of the two sides. `0` means "no opinion, take the peer's value"; if both sides say `0` only the congestion algorithm is switched and no rate is pushed |
| `brutal.cwnd_gain` | shared | `0` (→ 15) | congestion window gain in tenths: `15` = 1.5x, `20` = 2.0x. `0` selects the built-in 1.5x; anything above 1000 fails at startup. The effective value is the minimum of the two sides |
| `brutal.group_id` | shared | `0` (derive) | static connection-group id. `0` derives one per client: `u64le(HMAC-SHA256(token, groupSeed)[:8]) \| 1`, where the seed is `X-Client-Group` (a random value generated once per client instance) with `X-Session-ID` as the fallback. Set a value to merge several distinct clients into one shared bucket. `1` is forced so the id can never read as "no group" |
| `brutal.negotiate` | shared | `true` | when `false`, skip the bandwidth exchange and apply this side's own values only |
| `heartbeat_sec` | client | `25` | CDN bidirectional heartbeat; negative disables it |
| `session_window_kb` | shared | `256` | bounded ring window per resumable session |
| `session_max` | server | `4096` | cap on concurrent resume sessions. Bounds memory under a flood of distinct (never-resumed) session ids. `0` selects the built-in default; values above the hard cap are clamped, not rejected |
| `session_max_per_principal` | server | `256` | per-principal session cap, so one principal cannot consume the whole table. `0` selects the built-in default |
| `handshake_ack_ms` | client | `3000` | data-plane handshake ack timeout |
| `keepalive_sec` | client | `15` | session/backup-line keepalive interval |
| `standby_connections` | client | `0` | number of hot standby connections |
| `drain_timeout_sec` | shared | `30` | seconds to wait for existing sessions at exit |
| `log_level` | shared | `info` | `debug`, `info`, `warn`, `error` |

Every field can be overridden by an uppercased env var of the same name, e.g. `H2TUNNEL_SERVER`, `H2TUNNEL_TRANSPORT`, `H2TUNNEL_STANDBY_CONNECTIONS`, `H2TUNNEL_UTLS`, `H2TUNNEL_MASQUE_ALPN`, `H2TUNNEL_PADDING_MIN_RECORD_BYTES`, `H2TUNNEL_PADDING_MAX_RECORD_BYTES`, `H2TUNNEL_PPROF`, `H2TUNNEL_BRUTAL_ENABLED`, `H2TUNNEL_BRUTAL_RATE_BYTES`, `H2TUNNEL_BRUTAL_CWND_GAIN`, `H2TUNNEL_BRUTAL_GROUP_ID`, `H2TUNNEL_BRUTAL_NEGOTIATE`, `H2TUNNEL_SESSION_MAX`, `H2TUNNEL_SESSION_MAX_PER_PRINCIPAL`. Malformed boolean or integer env values also fail at startup.

### MASQUE dual carriers (h3 / h2)

`transport: masque` describes the **protocol shape** (CONNECT + `.well-known/masque/...` URI + the resume/2 data plane); the carrier is selectable:

- **`h3`**: QUIC/UDP, ALPN `h3`.
- **`h2`**: TCP/TLS over HTTP/2 extended CONNECT (RFC 8441, `:protocol` pseudo-header).
- **auto (default)**: h3 first; the first failed h3 dial pins h2 (links with UDP blocked need not wait for the QUIC timeout again per connection). Use `masque_alpn` to force one.

Server-side listeners are automatic for both carriers: `masque` makes TCP and QUIC **optional stacks** (`listenerPlan`), and `ListenAndServe` opens both by default. ⚠️ **For the server to accept extended CONNECT over h2, the process must set `GODEBUG=http2xconnect=1` at startup** (x/net reads that switch only once in `init`, and `//go:debug` rejects non-stdlib keys). Without it the h3 carrier is unaffected and only the h2 leg is explicitly rejected with `extended connect not supported by peer` — the CLI logs a WARN when masque is enabled and the switch is missing. This limitation disappears if x/net upstream drops the gate.

### TCP Brutal congestion control (Linux)

`brutal.enabled` switches the tunnel's TCP legs to the [TCP Brutal](https://github.com/synack42/TCP-Brutal) kernel congestion controller, which is deliberately aggressive and pushes hard at a rate you declare. It is a Linux kernel module: on macOS, Windows, or a Linux kernel that has no `brutal` in `/proc/net/ipv4/tcp_available`, the flag is accepted but does nothing, and a single WARN is logged at startup — the same config file keeps working once the module is loaded.

The scope is the tunnel leg itself (client↔server) and the server's accepted client sockets. It does not apply to the server→origin upstream connection, to the client's local loopback listener, or to any QUIC/UDP leg.

**Bandwidth exchange.** Proxy protocols carry no bandwidth field, so the two sides negotiate through the tunnel instead: the client sends `X-Brutal-Offer: rate=,gain=,nonce=` on its requests, and the server answers with `X-Brutal-Params: rate=,gain=,group_id=,nonce=`. The effective value is the minimum on both axes — a client cannot claim more than the server configured, and the server cannot push a rate above what the client declared. A fresh 16-byte nonce travels in both headers and is echoed back; the client applies a reply only when its nonce matches, which stops a cached or out-of-band reply from reconfiguring the connection. The nonce is deliberately **not** part of the HMAC input — folding it in would give every exchange its own group id and defeat grouping.

If the inline exchange ever needs to be separated, dial the sentinel target `_BrutalBwExchange`: it is recognized before any target substitution, never dials an origin, never opens a session, and answers with the negotiation headers plus an END frame.

**Connection groups.** Kernel-side rate limiting is per connection group: every socket with the same non-zero `group_id` (same user, same netns) shares `rate_bytes` as a *total*, so adding more links cannot multiply the allowance. The id is derived as `u64le(HMAC-SHA256(token, seed)[:8]) | 1` on both sides, independently — the shared token is the key and the seed is what differs per client. The seed is `X-Client-Group`, a random 128-bit value generated once per client instance, so it survives connection migration (the remote IP changes, the id does not), falling back to `X-Session-ID` for older clients. `brutal.group_id` overrides the derivation to merge several distinct clients into one bucket on purpose. The server reads the token it derives from out of `X-Auth-Token` or `Authorization: Bearer` — the same sources the built-in token authenticator accepts — so a custom `Authenticator` that reads the token from another header still authenticates the request but produces no group id (the connection runs ungrouped).

The server configures each accepted socket **after** authentication, using the group derived from that connection's token and seed — so an unauthenticated peer never receives the configured rate and never learns a derived group id, and per-client grouping is available on both sides. It is applied once per connection, not once per request.

Two honest limitations: the negotiation result reaches the *next* dial rather than the socket carrying the reply, so the very first leg of a process runs at the client's own declared rate (negotiation only ever lowers the value, so it converges); and the client's rate declaration also caps the **server's downlink** to that client, because `rate` is a single per-socket send budget shared by both directions of the merge — a client that declares a small rate throttles itself.

### Multi-protocol server

The server's `transport` is an allow-list, for example:

```json
{
  "mode": "server",
  "listen": ":8443",
  "transport": "h2,h3,masque",
  "network": "all",
  "token": "replace-with-a-long-random-token"
}
```

TCP-based TLS and QUIC-based protocols can share one numeric port. `h2c` is plaintext and cannot mix with TLS/H3 protocols on the same listen address. Each client process selects exactly one transport. Note `h2` is now a TLS-only transport: use `h2c` for a plaintext origin.

### Generating auxiliary configs

```bash
h2tunnel gen-nginx -domain tunnel.example.com -path /tunnel -backend 127.0.0.1:8443
h2tunnel gen-systemd -bin /usr/local/bin/h2tunnel -listen :8443 -path /tunnel -token 'TOKEN'
h2tunnel gen-uri -host tunnel.example.com -port 443 -path /tunnel -token 'TOKEN'
```

## Performance and reliability

- Transport/network dispatch on hot paths is compiled into bitmasks at server start; request handling never re-parses config strings.
- Recovery windows are strictly bounded and never grow with connection lifetime.
- TCP and UDP use independent primary lines so datagram bursts cannot stall byte streams; enable `standby_connections` only when fast failover matters.
- TLS configs are cloned at client and server construction, so callers can safely reuse their own templates.
- UDP writes use bounded queues and direct selection instead of one goroutine per datagram.
- CDN non-2xx responses never commit unacknowledged data; after service recovery it continues from the server-confirmed cursor.

If you prefer lower memory, lower `session_window_kb`; if the link is flaky or throughput is high, raise it. When unacknowledged data during recovery exceeds the window it fails explicitly instead of silently dropping or reordering.

## Testing and verification

```bash
go test ./...
go vet ./...
go build ./cmd/h2tunnel
```

Tests cover out-of-package API compilation and real TCP/UDP end-to-end transport, auth failures, target denial, context cancellation propagation, CDN latency/error/buffering behavior, recovery handshakes, concurrent closes, and steady-state benchmarks. `TestProtocolRealTargetMatrix` validates every protocol against real semantic targets: the TCP target is a real HTTP server (10 keep-alive round-trips over one tunnel connection, asserting zero new connections on the target side) and the UDP target is a real DNS server (10 independent A queries over one PacketConn, validated packet by packet).

```bash
# All-protocol × TCP/UDP throughput benchmarks (loopback)
go test -run '^$' -bench '^BenchmarkProtocolThroughput$' -benchmem .

# Data-plane microbenchmarks (frame codec / ring / session downlink / uplink isolation)
go test -run '^$' -bench 'BenchmarkWriteFrame32KB|BenchmarkReadFrame32KB|BenchmarkRingAppendOverwrite32KB|BenchmarkRingReadAt32KB|BenchmarkSessionDownlinkWrite|BenchmarkTunnelSessionUplinkUnderDownlink' -benchmem .

# CDN-topology end-to-end benchmark
go test -run '^$' -bench '^BenchmarkPublicAPIThroughCDN72KB$' -benchmem .
```

## Continuous integration and releases

Every push automatically runs `go vet`, `go build`, and `go test -race` on Ubuntu, Windows, and macOS (see `.github/workflows/test.yml`). A separate job runs the suite for real on the two 32-bit release targets (`linux/386` and `linux/arm` with `GOARM=6`), including all benchmarks: GitHub's hosted runners are 64-bit only, so the binaries execute under user-mode emulation (qemu-user, via the go tool's `go_<goos>_<goarch>_exec` cross-exec wrapper). `-race` is skipped there, because the detector plus emulation is an order of magnitude too slow to fit the job; data-race coverage of the same code stays native on 64-bit.

The release flow (`.github/workflows/release.yml`):

1. **Automatic release**: push any `v*` tag to trigger; cross-compiles 7 platforms of bare binaries (linux amd64/arm64/arm/386, windows amd64, darwin amd64/arm64), uploaded directly as Release assets without packaging archives. The `arm` binary is built with `GOARM=6`, so one asset covers every 32-bit ARM board from ARMv6 up (including Raspberry Pi 1/Zero-class SoCs).
2. **Manual build**: trigger the Release workflow manually from the GitHub Actions page; artifacts are only collected into that run's Artifacts (`h2tunnel-manual-<sha>`) and no Release is created.

Binaries inject the version via `-ldflags "-X github.com/NNdroid/h2tunnel.buildVersion=..."`, formatted as `v1.0.yyyyMMdd.<git commit count>-<short commit hash (7)>`, which `h2tunnel version` prints. The tag name itself does not enter version computation; after pushing, the Release title is the computed canonical version.

## Security notes

- Both `Authenticator` and `TargetDialer` are mandatory in the package API.
- Pre-shared tokens should be high-entropy random values and always used with TLS.
- `TLSConfig.InsecureSkipVerify` is only for controlled test environments.
- The server should only expose the networks and transports you need; prefer logical service registries over dialing arbitrary addresses.
- `Principal.ID` must be stable; resumed sessions bind identity, target, and network and must not be reattached by a different identity.
- `/healthz` returns an uncacheable simple health status; other unknown paths return 404.
