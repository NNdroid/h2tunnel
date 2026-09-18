# Changelog

This file records notable changes for library users. Dates are release dates (UTC+8).

## 2026-09-19

### Security hardening
- **Session IDs are bounded**: `X-Session-ID` must be 1-128 bytes after trimming. The id is a map key on every request, the unit of per-principal accounting, and is echoed back into response headers, so an oversized value was a memory-amplification and header-inflation vector that used to be paid for only after the target had already been dialed. The check now runs first; an over-long id gets HTTP 400 with `X-Resume-Error: invalid_params` and never reaches the target. `Principal.ID` stays unbounded because it comes from the embedder's own `Authenticator`, not from the peer.
- **MASQUE-TCP no longer takes its session mode from the client**: the datagram framing and the binding target are pinned to the URI-segment classification, and the classified values are written back into `X-Network`/`X-Target` before the session is prepared. Previously a `X-Network: udp` on a `connect-tcp` request created a UDP-framed session over a TCP dial, so the server read the target's byte stream as UDP packets and lost every packet boundary.
- **Shared-profile decompression is capped**: `gunzipData` reads through `io.LimitReader` at 8 MiB and rejects anything larger, so a compressed profile cannot expand without bound on a server.
- **Transport-policy rejections stop echoing the policy**: a blocked request now gets the generic body `transport forbidden by server policy`. The old body carried `err.Error()`, which named the configured allow-list — an enumeration oracle for which transports a deployment runs. The detail stays in the server log.
- **utls channel binding restored**: the `VerifyConnection` adapter now copies `TLSUnique` and `ECHAccepted`, so an embedder's channel-binding check sees the same `ConnectionState` under camouflage as under native TLS.

### Added
- **Session-table caps**: `ServerTuning.SessionMax` / `ServerTuning.SessionMaxPerPrincipal` bound concurrent resume sessions in total and per principal, so a flood of distinct (never-resumed) session ids cannot grow the table without limit. 0 selects the built-in defaults (4096 total / 256 per principal); values above the hard cap are clamped rather than rejected. CLI keys `session_max` / `session_max_per_principal` plus `H2TUNNEL_SESSION_MAX` / `H2TUNNEL_SESSION_MAX_PER_PRINCIPAL`; they are server-only fields and a client config that carries them is rejected rather than silently ignored. Both sample configs advertise them.
- **HTTP/2 concurrent-stream cap**: the h2 server now advertises `MaxConcurrentStreams = 256` alongside the existing 8 MiB/stream and 32 MiB/connection upload buffers, so a peer cannot fan out an unbounded number of concurrent streams on one connection.
- **WebTransport per-session stream cap**: 256 concurrently served streams per session. At the limit the excess stream is reset instead of queued — a queued stream only enlarges the queue a flood feeds.

### Fixed
- **A naturally dead TCP tunnel stayed in the active set, and could hang `Client.Shutdown`**: two independent root causes. First, `finishWith` only recorded the terminal error and closed `Done()`, so the removal from the active set never happened when the engine exited on its own — `finish()` now runs when the engine does. Second, and deeper, the engine could not exit at all: on a peer-driven normal end (the peer's END frame) the send loop could still be parked reading an application conn nobody closes — a read-only tunnel, or an app blocked in `Read` — so `wg.Wait()` never returned, the engine never returned, and the tunnel stayed registered for the life of the client while the application waited on a read that could never complete. A normal recv end now interrupts the send loop (and closes the request body as a backstop against a send loop parked writing into a back-pressured stream); a recv error deliberately does not, because the send loop failing on its own write is what tells the outer loop to redial rather than terminate. Verified with two negative controls: removing either half reproduces the hang.

### Known limitations
- An abandoned h2 stream (a peer that vanishes without a FIN) keeps its handler goroutine until the connection closes. It is bounded per connection by the new 256-stream cap, and the session table reaper already drops the business session after 60 s idle, so the leaked resource is one goroutine per abandoned stream; closing it would require an idle reader in the uplink hot path, and x/net exposes no read-idle knob on the server side without also killing legitimately quiet links (the default heartbeat is 25 s and can be disabled). Connection-level flooding is a reverse-proxy / WAF concern rather than a tunnel concern.
- x/net's `http2.Server` has no `MaxHeaderListSize` field, so the advertised value is the built-in default and untunable; net/http's 1 MiB total-header limit still rejects oversized headers.

## 2026-09-18

### Added
- **TCP Brutal congestion control (Linux)**: `ClientTuning.Brutal` / `ServerTuning.Brutal` (`BrutalTuning{Enabled, RateBytes, CwndGain, GroupID, Negotiate}`) switch the tunnel's TCP legs to the TCP Brutal kernel controller via `TCP_CONGESTION` + `TCP_BRUTAL_PARAMS(23301)`, packing the `<QIQ` little-endian layout (`rate_bytes`, `cwnd_gain` in tenths, `group_id`). Off by default; a non-Linux build, or a Linux kernel without `brutal` in `/proc/net/ipv4/tcp_available`, logs one WARN at startup and does nothing — the config stays valid. `CwndGain` is validated 1-1000 (0 = the 1.5x default) at construction. Applies to h2/h2c/grpc and the MASQUE-over-h2 leg, on the client's tunnel socket and the server's accepted client socket; not to the server→origin leg, the client's local listener, or any QUIC/UDP leg. The CLI mirrors it with a `brutal` section (`enabled`/`rate_bytes`/`cwnd_gain`/`group_id`/`negotiate`) plus `H2TUNNEL_BRUTAL_ENABLED`/`_RATE_BYTES`/`_CWND_GAIN`/`_GROUP_ID`/`_NEGOTIATE`, and both sample configs gain the block.
- **Bandwidth negotiation over the tunnel**: proxy protocols carry no bandwidth field, so the two sides negotiate in-band in the tunnel's own headers. No capability flag is added and no protocol version moves: the offer must go on the first request of a leg, before the client has seen any server capabilities, so a cap could never gate it — instead an older peer simply ignores the unknown headers. The client sends `X-Brutal-Offer: rate=,gain=,nonce=` and the server answers `X-Brutal-Params: rate=,gain=,group_id=,nonce=`; the effective value is the **minimum** of both sides on each axis independently (a peer that declares a gain but no rate still contributes its gain), so neither side can exceed what the other configured, and if both declare 0 only the algorithm is switched and no starving zero rate is pushed. A fresh 16-byte nonce travels in both headers and is echoed back; the client applies a reply only on a constant-time match. The nonce deliberately never enters the HMAC input — folding it in would make the group id unique per exchange and defeat grouping.
- **Explicit `_BrutalBwExchange` sentinel target**: recognized before any target substitution (bypassing the `127.0.0.1:22` default), never dials an origin and never opens a session — the handler answers the negotiation headers plus an END frame. `Client.NegotiateBrutal(ctx)` drives it from an embedder.
- **Stable connection groups under connection migration**: `group_id` is derived independently on both sides as `u64le(HMAC-SHA256(token, seed)[:8]) | 1` (bit 0 forced so 0 keeps its "no group" meaning). The seed is the new `X-Client-Group` header — a random 128-bit value generated once per client instance, so one client's primary plus standbys share one bucket and the id survives migration, falling back to `X-Session-ID` for older clients. Sockets with a shared non-zero `group_id` share `rate_bytes` as a *total* kernel-side, so adding links cannot multiply the allowance; the static `brutal.group_id` pins a specific group to merge distinct clients on purpose. Group ids are only ever returned after authentication, so an unauthenticated probe cannot enumerate the derivation. Only `rate` and `gain` cross the wire in an offer — a client-supplied `group_id` in `X-Brutal-Offer` is ignored, so a client can never claim another client's bucket.

### Known limitations
- The negotiation result reaches the **next** dial rather than the socket carrying the reply (x/net/http2 keeps no reference to the dialer's connection), so the very first leg of a process runs at the client's own declared rate. Negotiation only ever lowers the value, so it converges monotonically.
- Group derivation reads the presented token from `X-Auth-Token` or `Authorization: Bearer`. A custom `Authenticator` that reads the token from another header still authenticates the request, but the server derives no group id for it — the connection runs ungrouped and the echoed `group_id` reads as absent.
- A kernel route with locked (read-only) Brutal rules rejects both `TCP_BRUTAL_PARAMS` and `TCP_CONGESTION` with `EPERM`; h2tunnel then logs once and leaves the default controller in place.

## 2026-09-13

### Added
- **Application-layer record padding**: `ClientTuning.Padding` / `ServerTuning.Padding` configure a random record range via `PaddingTuning{MinRecordBytes, MaxRecordBytes}`; the CLI mirrors it with nested `padding.min_record_bytes` / `padding.max_record_bytes` keys and same-named env vars. Off by default; when only the minimum is given the cap automatically becomes 125% of it. Covers streamed DATA, replayed DATA, handshake, heartbeat, END, ERROR, and the UDP/MASQUE capsules — TCP/UDP target-visible business content stays unchanged across all six transports. Stream data is reshaped into records at random targets; UDP keeps message boundaries and packets above the cap are never split. This capability only constrains h2tunnel application records; it makes no promise about the size of actual IP packets — TLS, HTTP/QUIC/TCP, CDNs, MTU, and NIC offloads can still split or coalesce records.
- **MASQUE dual-carrier selection**: `ClientTuning.MasqueALPN` (CLI `masque_alpn`) — `h3` (QUIC only), `h2` (TCP extended CONNECT only), empty = auto (h3 first; a failed first dial pins h2 cross-lane, so links with blocked UDP need not wait out the QUIC timeout per connection). Server-side `transport: masque` now treats TCP and QUIC as optional stacks, with `ListenAndServe` opening both by default. ⚠️ The server needs `GODEBUG=http2xconnect=1` at process start to accept extended CONNECT over h2 (x/net reads it once in init; `//go:debug` rejects non-stdlib keys). When missing, h3 is unaffected and the h2 leg is explicitly rejected with `extended connect not supported by peer`; the CLI logs a WARN.
- **pprof**: `h2tunnel.PprofHandler()` exposes the standard net/http/pprof for embedders to mount behind their own admin boundary (the library itself binds no port); the CLI server-side `pprof` config key / `H2TUNNEL_PPROF` enables it at a given address. CI gains a `profile` job producing CPU/allocation flamegraph SVGs and top reports as the `profiles` artifact.

### Changed (internal refactors, behavior unchanged)
- **Server-side listener plan**: the anonymous `(tcp, quic bool)` of `requiredListeners` (one tuple meant both "must be provided" and "provided but unused") is replaced by `listenerPlan` — three states per stack (`unused/optional/required`) derived once from compiled transports; auto-binding, SDK validation, and test environments share `plan.bind()` (port-sharing logic now exists in one place). Fixed: a MASQUE server with only a TCP listener used to be rejected — even though MASQUE-over-h2 is exactly what it serves.
- **Request dispatch**: one `classifyTunnelRequest` produces `tunnelRequest{kind, transport, network, target}`, shared by auth/network-policy/transport-policy/events/dispatch — replacing the three-boolean handoff `isWT/isMasqueTCP/isMasqueUDP` and the triple computation of `requestTransport()`/`getRequestDestination()` per request. Fixes two real bugs along the way: MASQUE-TCP `SessionOpened` events carried an empty Transport; standards-connect-udp (the old `MUDP` entry) did not emit `AuthRejected` on a wrong token.

### Security fixes
- **Fixed: certificate verification silently bypassed (MITM) when `UtlxFingerprint` was enabled**. `utlsTLSConfig` previously copied only `ServerName`/`InsecureSkipVerify`/`RootCAs` from the user `tls.Config` into the `utls.Config`, dropping `VerifyPeerCertificate`, `VerifyConnection`, `Certificates`/`GetClientCertificate`, `MinVersion`/`MaxVersion`, and other fields. Embedders using `InsecureSkipVerify=true` + `VerifyPeerCertificate` fingerprint pinning (e.g. in-house SSH clients) would have pinning silently disabled once camouflage was enabled, accepting any certificate. The copy is now field-by-field: all trust/authn fields pass through, with `VerifyConnection` and client certs adapted via type adapters (`crypto/tls` and `utls` same-named types are not directly assignable); `CipherSuites`/`CurvePreferences` are deliberately not copied (left to the browser fingerprint preset); `ClientSessionCache` is deliberately not copied (resuming across native/utls would skip the pinning callback on resumed connections). Regression test `utls_pinning_test.go` locks `VerifyPeerCertificate` and `VerifyConnection` (with a negative control that fails if the fix is removed). The native-TLS path and the non-camouflaged branch are unaffected (they already used full `tls.Config.Clone()`).

## 2026-09-08

### Added
- **TLS fingerprint camouflage (utls)**: `ClientOptions.UtlxFingerprint` (CLI config key `utls` / env var `H2TUNNEL_UTLS`) rewrites the ClientHello of h2/grpc clients into real-browser shapes (`chrome`, `firefox`, `edge`, `safari`, `ios`, `qq`) against JA3/JA4 fingerprinting; empty default = native crypto/tls, zero behavior change. Only TCP-TLS transports take effect — h3/wt/masque TLS happens inside quic-go and cannot be injected, so misuse errors at `NewClient` (`360` is likewise rejected because its preset does not advertise h2). Bare `net.Listen` dialers and `ClientDialer` custom sockets (VPN protect) coexist with camouflage.

### Changed
- **Outbound requests now carry a browser User-Agent uniformly** (TCP/UDP resume, backup lines, WT CONNECT all covered): previously requests had no UA and Go's Transport injected `Go-http-client/2.0`, directly contradicting the camouflaged browser TLS fingerprint. The default is an Android Chrome WebView UA (with the `w2n/Android` app identifier). Server-side logging/auditing that relied on the `Go-http-client` signature must adjust.
- **Network-change self-heal suite** (effective for TCP/UDP/WT transports):
  - `ClientTuning.AutoRedial` — automatically resets and continues after redial exhaustion (16 attempts), i.e. infinite revival, fitting "stay down until the network returns"; when off, exhaustion terminates and dispatches `TunnelDied(max retries)`.
  - `ClientTuning.RedialBudget` — per-attempt dial budget (constrains stream setup + handshake only; the timer stops once ready), tightening the abandon pace during outages.
  - `Client.ForceReconnect()` — for embedders to force abandonment of the current stream and immediate redial when an OS network-change notification (NotifyAddrChange / NWPathMonitor / ConnectivityManager) arrives; session id and recovery window are preserved, invisible to the peer. Skips the passive lag of heartbeat-timeout detection.
  - The WT-UDP datagram plane gains a disconnect-redial loop (previously a stream break ended the session); the server reuses the UDP socket by session id.
- **Strongly-typed event callback system**: `Client.SetEventHandler` / `ClientOptions.EventHandler` (TunnelEstablished, TunnelDied, Reconnecting, TargetDenied); `Server.SetEventHandler` / `ServerOptions.EventHandler` (SessionOpened/Resumed/Closed, AuthRejected, TargetDenied, ReplayDropped). Callbacks dispatch on a dedicated goroutine with recovery and never block the packet-read loop.
- **Context-ified connection lifecycle**: tunnels expose `Done() <-chan struct{}` and `Err() error`; the `ClientTuning.SessionWindowBytes` comment gains a note on outage duration vs window size.

## 2026-09-06

### Added
- **WebTransport UDP**: `DialPacketContext` now supports the `wt` transport (UDP datagrams carried over WT streams; the server keeps the UDP socket per session id).
- **Stats API**: `Client.Stats() *ClientStats` (dials/failures, active count, uplink/downlink bytes, resume count) and `Server.Stats() *ServerStats` (sessions opened/resumed/active, auth failures).
- **`TunnelError`**: exported type, `HTTPStatus()` recovers the HTTP status when the server rejects; usable with `errors.As(*TunnelError)`.
- **`ClientTuning.DatagramQueueSize`**: configurable UDP uplink queue depth (default 200).
- **`DialRequest.Kind`**: `DialKindBusiness` / `DialKindProbe` — probe lanes never trigger real dials, and `TargetDialer` can skip probe requests accordingly.

### Changed
- **MASQUE paths derived uniformly from `path`**: endpoints become `<path>.well-known/masque/{tcp,udp}/...`; `path=/` yields the standard `/.well-known/masque`. There is no separate MASQUE prefix config anymore.
- **Default `path` changed from `/tunnel` to `/`**.
- **Data-plane logging unified on `log/slog`**: `options.Logger` now covers all data-plane logs (previously zap data-plane logs were invisible to embedders).

### Performance
- h2 uplink flow-control windows raised to 8MB/stream, 32MB/connection (previously x/net's 1MB default starved uplink on high-RTT CDN links).
- Session downlink frame writes moved out of the global lock: the uplink is no longer cross-locked by downlink network writes (uplink-isolation benchmark ~5×).
- `readFrame` allocates zero for the frame header (1 heap alloc per DATA frame on the hot path → 0).

### Fixed
- `Server.Shutdown/Close` did not close externally supplied QUIC PacketConns, so `Serve` never returned in h3/wt/masque deployments.

## 2026-09-05

### Added
- Embeddable SDK (`Server`/`Client`; `NewServer`/`NewClient` mandate `Authenticator`/`Dialer` to prevent a default open proxy).
- `ClientOptions.Dialer` / `QUICDialer`: custom underlying sockets (interface binding, VPN protect).
- `Server.Listeners()`: port discovery for port-0 deployments.
- Test infrastructure: real-target matrix (HTTP/DNS × all protocols), per-protocol TCP/UDP throughput benchmarks, data-plane microbenchmarks.

### Fixed
- Data race when swapping the global logger concurrently (zap core-swap approach).
- Unlocked read/write of `backupLine.ctxCancel`.
- Windows CI: PowerShell split the `-coverprofile=...` argument; quic-go does not support Windows + race (race only on linux/macos).
- h2c hijacked connections leaked on Shutdown (now tracked via ConnState and closed).
