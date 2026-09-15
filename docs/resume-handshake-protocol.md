# Resume Session-Recovery Protocol v2 · Handshake and Capability Negotiation Standard (with Primary/Backup Switchover)

> Goal: upgrade the current "implicit, one-way push-down" resume handshake into an explicit, bidirectional, negotiable, evolvable handshake standard with primary/backup redundancy.
> It supports version negotiation, capability/parameter exchange, negotiation acknowledgement (ack), control-frame priority, error retries, and handshake coordination between the primary and backup lines.

---

## 0. Current-State Diagnosis (Why This Upgrade Is Needed)

The current `resume/1` handshake (`handleH2StreamResumeServer` + `buildResumeRequest`) has the following defects:

| Defect | Current state | Consequence |
|---|---|---|
| **No version negotiation** | `X-Tunnel-Proto: resume/1` is a hardcoded string | Protocol evolution (resume/2) is out of the question; old/new incompatibility can only be fixed by both sides manually editing configuration |
| **No capability exchange** | The server side **guesses** whether datagram is used from the `X-Network` header; **guesses** whether grpc is used from `Content-Type` | The client's real capabilities (e.g. "I support compression / backup line / timeout parameters") cannot be communicated, so there is no dynamic adaptation |
| **No parameter negotiation** | `session_window_kb`, timeouts, etc. are **configured independently on each side** | When the two sides' parameters disagree there is a silent mismatch (e.g. one window big, one small) that cannot be aligned in the handshake |
| **No acknowledgement (ack)** | `X-Resume-Uplink` is one-way downlink coordinate information, **not** a negotiation confirmation | The client has no way to know whether the server accepted its capability set; "negotiation succeeded" has no protocol-level signal |
| **Coarse error granularity** | Relies on HTTP status codes (403/502) | Cannot distinguish "version incompatible / capability unsupported / invalid parameters / backup line unavailable" and the like |
| **No backup-line handshake** | Primary/backup switchover is a purely local client-side behavior | The backup line's liveness, capabilities, and parameters are completely invisible at the protocol layer; switching is a "blind switchover" |
| **Redundant v1 legacy path** | `resume/1` + the Padding frame path + grpcReader + copyWithHeartbeat coexist | The maintenance cost of two implementations doubles; the legacy path has no handshake, no ack, and no primary/backup — a functional blind spot |

**Design decisions for this version (finalized by the user)**:
1. **v2 only, used by default, v1 fully removed**: `resume/2` is the only data plane. The old `resume/1`, the Padding frame path, `grpcReader/Writer`, `copyWithHeartbeat`, `proxyStream`, etc. are all deleted, leaving no escape hatch. WT transport is also unified onto the v2 data plane.
2. **Primary/backup switchover is implemented this iteration**: full hot standby / cold standby + KEEPALIVE liveness confirmation + takeover only of a backup confirmed alive. Primary/backup is not phase 2 — it is a core deliverable of this iteration.
3. **Control frames outrank data frames**: handshake/heartbeat/error control frames are **always prioritized over business data frames** in the send queue, preventing data-plane congestion from blocking handshake and failure signals.

**Format principles**: fields are **extensible + forward-compatible** — unknown capability names and parameter names **must be ignored and work must continue**; never reject the other side just because it added new fields. But the **version** is a hard constraint: no version intersection means failure (v1 is removed, there is no downgrade target).

---

## 1. Field Design and Format Definition of Handshake Messages

### 1.1 Transport carrier

All handshake information goes **in HTTP headers** (request headers + response headers), **not in data-plane frames**.
Reasons:
- The handshake is one-shot and completes at the instant the stream is established; HTTP headers are naturally suited to a single "request-response" exchange.
- Data-plane frames (resumeframe.go) are a **continuously flowing** byte stream; cramming the handshake into them would complicate frame parsing and could not cover the "re-negotiate after a stream rebuild" scenario (re-negotiating capabilities for every new stream would be wasteful).
- Middleware/CDNs can see HTTP headers (friendly to debugging, canary releases, and auditing).

> ⚠️ Exceptions: the **ack confirmation** and the **primary/backup handshake heartbeats** are signals that "need real-time round trips and must be end-to-end";
> they are carried by **handshake control frames** (data-plane sentinel frames) — see 1.4 and section 3.

### 1.2 Request headers (client → server side)

| Header field | Semantics | Example | Required | Compatibility rule |
|---|---|---|---|---|
| `X-Tunnel-Proto` | Protocol name + major version | `resume/2` | ✅ | Still the highest-priority routing key |
| `X-Resume-Version` | The **minimum protocol version supported** by the client | `2` | ✅ | The server decides the response version accordingly |
| `X-Resume-Caps` | Capability list (comma-separated) | `datagram,compress,zstd,backup-line` | Optional | Unknown capabilities are ignored by the server |
| `X-Resume-Params` | Parameters k=v (`;` separated) | `window_kb=512;idle=90;attempts=16` | Optional | Unknown parameters are ignored; known-but-invalid → fall back to defaults and log |
| `X-Resume-Ack` | Receipt acknowledging the server capability set of the **previous stream** | `proto=2;caps=datagram,compress;params=...` | Optional (on rebuild) | See 1.4 |
| `X-Session-ID` | Session id | (existing) | ✅ | Unchanged |
| `X-Resume-Downlink` | Downlink bytes already received by the client | (existing) | ✅ | Unchanged |
| `X-Network` | `tcp` / `udp` | existing | ✅ | Unchanged |
| `X-Target` / masque path | Target address | existing | ✅ | Unchanged |

### 1.3 Response headers (server side → client)

| Header field | Semantics | Example | Required | Compatibility rule |
|---|---|---|---|---|
| `X-Resume-Version` | The **negotiated protocol version** (min of both sides) | `2` | ✅ | Must be returned; the explicit signal that "version negotiation succeeded" |
| `X-Resume-Caps` | The capability set **accepted** by the server (the intersection) | `datagram,compress` | ✅ | The client should only use capabilities within the intersection |
| `X-Resume-Params` | The parameters **finally in effect** on the server (after alignment) | `window_kb=256;idle=90` | ✅ | The client must defer to the response values |
| `X-Resume-Ack` | Server acknowledgement of the client capability set | `ok` or `error:<code>` | ✅ | See 1.4 |
| `X-Resume-Uplink` | Uplink bytes already received by the server (coordinate) | existing | ✅ | Unchanged; a data-plane coordinate, not negotiation |
| `X-Resume-Error` | Negotiation-failure error code | `version-unsupported` | On failure only | See 1.5 |

### 1.4 Acknowledgement mechanism (ack) — two-layer confirmation

Negotiation confirmation is split into **two layers**, addressing "capability alignment" and "endpoint liveness" respectively:

**Layer-A: confirmation inside HTTP headers (negotiation-result confirmation)**
- The server returns `X-Resume-Caps` (the intersection) + `X-Resume-Ack: ok` in the response headers, meaning "I received your capabilities and am applying the intersection".
- The client **must first read** `X-Resume-Ack: ok` with version and parameters as expected **before it is allowed** to start writing uplink data.
- If the capability intersection is empty (no common capability at all) → `X-Resume-Ack: error:<code>` + the corresponding HTTP status code (see 1.5).

**Layer-B: data-plane handshake control frames (endpoint liveness + stream-level confirmation)**
- After the stream is established and before business data is transferred, the client first sends a **handshake control frame** (new frame type `HANDSHAKE`) carrying the client's receipt hash of the response capability set; upon receiving it, the server replies with a `HANDSHAKE-ACK` control frame.
- Purpose: ① prove "this stream is truly alive end-to-end" (an HTTP 200 may be nothing but an intermediate-layer cache/fake response); ② let both sides know "official data may begin".
- **Timeout**: if no HANDSHAKE-ACK is received from the peer within `handshakeAckTimeout` (default 3s, parameterizable), the handshake is judged failed and retry logic kicks in (1.6).

> Why two layers: layer-A is fast (header-level, available as soon as the stream is built) but unreliable (a reverse proxy may rewrite it); layer-B is solid (end-to-end) but costs one extra round trip.
> Production needs both; tests may exercise each separately.

### 1.5 Error and retry handling

Negotiation-failure error codes (response header `X-Resume-Error` + corresponding HTTP status):

| Error code | HTTP | Meaning | Client behavior |
|---|---|---|---|
| `version-unsupported` | 426 | No protocol-version intersection between the two sides | Terminate (v1 is removed, **no downgrade target**; fail outright with an upgrade hint) |
| `no-common-capability` | 406 | Capability intersection is empty | Terminate or downgrade to the minimum capability set (see 2.6) |
| `invalid-params` | 400 | Invalid client parameters | Retry once with the default parameters echoed back by the server |
| `auth-failed` | 401/403 | Authentication failed | Terminate |
| `target-unavailable` | 502/503 | Target unreachable | Retry with exponential backoff |
| `handshake-timeout` | 504 | Layer-B HANDSHAKE-ACK timeout | Retry stream establishment |
| `backup-unavailable` | 200+`X-Resume-Ack:error` | Backup line unavailable | Primary only, see section 3 |

Retry strategy (unified at `resumeMaxAttempts=16` + exponential backoff `200ms→5s`, reusing the existing backoff):
- `version-unsupported` / `no-common-capability` / `auth-failed` → **not retryable** (deterministic failures), terminate immediately.
- Everything else → retry; each retry uses the **latest version/capabilities/parameters echoed back by the server** (adaptive convergence).

### 1.6 Handshake sequence diagram

```
Client                                  Server
  │  POST /tunnel  (X-Tunnel-Proto:resume/2,           │
  │   X-Resume-Version:2, X-Resume-Caps:datagram,      │
  │   compress,backup-line, X-Resume-Params:window_kb=512)  │
  │ ─────────────────────────────────────────────────→  │
  │                       validate version ∩ caps ∩ params   │
  │  ←──────────────────────────────────────────────────  │
  │  200 X-Resume-Version:2, X-Resume-Caps:datagram,     │
  │   compress, X-Resume-Params:window_kb=256;idle=90,   │
  │   X-Resume-Ack:ok, X-Resume-Uplink:0                 │
  │      │ (client proceeds only after verifying ack=ok and valid params) │
  │  ── HANDSHAKE control frame (receipt hash) ─────────→ │
  │  ←─ HANDSHAKE-ACK control frame (confirms end-to-end liveness) ── │
  │      │ (no business data written before ACK received) │
  │  ═══ business data (resume frames) begins ═══          │
```

---

## 2. Extensible, Forward-Compatible Standard Information-Exchange Format

### 2.1 Design constraints
- **Unknown fields are ignored (soft rule)**: the parser **skips without error** any capability/parameter name it does not recognize; but the **version number is a hard constraint** (see 2.4) — an unknown version yields `version-unsupported` directly.
- **Negotiation rules**: protocol version = `min(both sides)` (v2 is the only version; anything but 2 fails); capabilities = the intersection (if empty, downgrade to the minimum set, see 2.6); parameters follow "server side wins + invalid values fall back to defaults".
- **Ordering**: capability and parameter lists **do not depend on order** (they are parsed into sets/maps).
- **Character safety**: capability/parameter names use only `[a-z0-9-]`, values use `[a-zA-Z0-9._-]`, avoiding collisions with separators.

### 2.2 Capability list format (`X-Resume-Caps`)
```
datagram,compress,zstd,backup-line,stream-replay,...
```
- A pure name list, comma-separated. Extending capabilities only requires appending names.
- What the server echoes back = client request ∩ server support (the **intersection**); the client only enables the intersection.

### 2.3 Parameter format (`X-Resume-Params`)
```
window_kb=256;idle=90;attempts=16;handshake_ack_timeout=3000
```
- `k=v` pairs separated by `;`. Values are always decimal integers (units such as ms/bytes/KB are conveyed by the key-name semantics).
- The server echoes the **final effective values** (already clamped into legal ranges); the client always defers to the response values → **both sides' parameters are guaranteed aligned**.

### 2.4 Version negotiation rules
```
negotiated = min( clientMaxSupported, serverMaxSupported )
```
- The version is a **single integer** (currently the only version is `2`).
- The client sends "the highest version it supports" in `X-Resume-Version`; the server replies with the "negotiated version" (min of the two sides).
- Because **v1 has been removed and v2 is the only version**: if either side is not v2, the `min()` result ≠ 2 → report `version-unsupported` per 1.5 and **terminate** (no downgrade target). Version is a **hard constraint** and is not covered by "ignore what is unknown".

### 2.5 Version policy: v2 only, v1 fully removed
- **Server side**: accepts only `X-Tunnel-Proto: resume/2`. If `resume/1` or no version header arrives → immediate 426 `version-unsupported`. The old `handleH2StreamServer`, `executeHTTPTunnel`, `handleH2TCPClientConn`, `proxyStream`, `PaddingReader/Writer`, `grpcReader/Writer`, `copyWithHeartbeat` are all deleted.
- **Client side**: sends only `resume/2`. The `resume:false` escape hatch is gone.
- **WT migration**: WT transport previously could not use the resume data plane; it is now unified onto the v2 session model (see §4.8), eliminating the dual implementation.

### 2.6 Minimum capability-set downgrade (mitigation for `no-common-capability`)
- When the capability intersection is empty, both sides retry using the **minimum baseline capability set** `{replay}` (byte stream + seq replay only, no datagram/backup enhancements).
- Purpose: capabilities are enhancements; an empty intersection should not kill the session outright — fall back to the minimum usable set and negotiate once more. Only terminate if there is still no intersection.

> Version is a **hard constraint** (no intersection = failure); capabilities/parameters are **soft constraints** (no intersection → downgrade to the minimum set / parameters fall back to defaults). This is the design's precise boundary of "forward compatibility".

### 2.7 Control frames outrank data frames (scheduling policy)

**Motivation**: handshake acks, primary/backup heartbeats, and error notifications are **latency-sensitive** signals. If control frames and business data frames queue FIFO in the same sending goroutine, data-plane congestion (a full window, TCP slow start, etc.) blocks the control frames → handshake timeouts, false heartbeat judgments, and failures that cannot be reported in time.

**Implementation (serialization via the writer mutex; no separate scheduler)**
- Control frames and DATA frames share the same HTTP stream; the write path is serialized by each writer's mutex, guaranteeing "control frames are never split and never starved":
  - **Server-side downlink**: `downlinkPump` writes DATA via `writeDownlink`→`resumeSessionWriter.writeFrame`; handshake ACK / KEEPALIVE-ACK write control frames via `writeControl`. Both lock `resumeSessionWriter.mu`, and `downlinkPump` releases the lock after every frame it writes, so control frames slot into the gaps between frames.
  - **Client-side uplink**: a single stream has only one `resumeSendLoop` goroutine writing to `pw` (DATA + END), and HANDSHAKE is written once before the stream is established — there is no concurrent write contention by nature.
  - **Backup line**: `backupLine.keepaliveLoop` owns a dedicated stream to write KEEPALIVE and read KEEPALIVE-ACK.
- Each frame's write-out completes atomically inside the lock-held region (whole header+body+flush), so a control frame can never be split by a DATA frame; and because `downlinkPump` releases the lock frame by frame, control frames are never starved by a long run of DATA frames (worst case: waiting out the write+flush of one DATA frame, far below the KEEPALIVE 15s budget).

**Frame-type tiers**:
| Priority | Frame type | Description |
|---|---|---|
| P0 (highest) | `ERROR` / `END` | Must be delivered immediately, or the peer wedges |
| P1 | `HANDSHAKE` / `HANDSHAKE-ACK` / `KEEPALIVE` / `KEEPALIVE-ACK` | Handshake/heartbeat, with a timeout budget |
| P2 (lowest) | `DATA` | Business data; may yield to the two higher tiers |

> Control frames and data frames **share the same HTTP stream** (still an ordered byte stream); priority is guaranteed by **write-path mutex serialization** (control frames slot in between DATA frames, without relying on HTTP/2 stream priority, and it works uniformly across h2/h3/grpc/masque/wt). `handshake_frame.go` once implemented a `frameMux` dual-queue scheduler, but it was never wired into the production write path and has been removed as dead code.

---

## 3. Handling of the Primary and Backup Lines in the Handshake

### 3.1 Concept distinction (fully implemented this iteration, not phase 2)
- **Primary line**: the main data channel of this resume tunnel.
- **Backup line**: the redundant/backup channel. Currently implemented uniformly as a pre-established, continuously probed hot standby, which can be promoted to take over directly when the primary line drops.
- Primary/backup is decided by `ConnectionPolicy`: `backup_count=0` means a single line; a positive number means maintaining that many hot standbys.

### 3.2 Handshake flow (primary/backup)
- **Primary line**: executes the full section-1 handshake (version/capabilities/parameters + ack). Primary handshake success = `X-Resume-Ack:ok` received + `HANDSHAKE-ACK` received.
- **Backup line**:
  - If the client declares the `backup-line` capability and the server accepts it → the client sets up the backup handshake.
  - The backup handshake **uses the same handshake protocol** (version/capabilities/parameters/ack + control frames), except:
    - it uses a **dedicated session id** (`<primary id>+b`) to avoid colliding with the server's session table;
    - the backup **carries no business data**, only periodic **liveness control frames** (`KEEPALIVE`, reusing the frame structure with `role=backup`);
    - for the backup line the server **does not start downlinkPump business-data double-writing**; it only keeps the targetConn (hot standby) or merely registers metadata (cold standby).

### 3.3 The backup must be included in handshake confirmation — implementation decision for this iteration (confirmed)
**Conclusion: the backup line must be included in handshake confirmation, but via a "dedicated backup handshake + KEEPALIVE liveness confirmation", not by reusing the primary handshake.** Reasons:

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| A. Primary and backup share one handshake | Simple | Cannot be told apart when primary/backup targets differ; a backup failure pollutes the primary handshake | ✗ Rejected |
| B. Fully independent backup handshake + periodic liveness confirmation | Primary/backup isolation; the backup's real availability is verifiable | One extra handshake round trip + heartbeat overhead | ✅ **Implemented this iteration (hot standby)** |
| C. Backup handshakes only at switchover (cold standby) | Zero standing overhead | Slow takeover; backup unavailability only surfaces at switchover | ✅ Implemented this iteration (cold standby) |

**Scope implemented this iteration**:
- Primary line: full bidirectional handshake + ack (section 1).
- Backup line: **independent handshake** + periodic `KEEPALIVE` control-frame renewal (default 15s, parameterizable via `keepalive_interval`); N consecutive (default 3) `KEEPALIVE-ACK` timeouts → the backup is judged dead → rebuild the backup or **downgrade to primary-only**.
- Control-frame priority: the primary/backup `KEEPALIVE`/`KEEPALIVE-ACK` frames are guaranteed to cut in ahead of DATA by writer mutex serialization (see 2.7), so they are **always delivered** even under congestion, keeping liveness judgment reliable.
- Switchover: when the primary handshake/data fails → the client **first switches locally to the backup confirmed alive** (hot standby switches in seconds) while a background task tries to restore the primary; for cold standby, handshake first, then switch.
- **Key point (iron rule)**: only a backup whose liveness was **confirmed through the handshake** may be taken over; an unconfirmed backup is **forbidden from automatic takeover** (avoiding a "blind switchover to a dead line").

### 3.4 Primary/backup handshake timeline
```
Primary:  POST resume/2 (sid=abc)  → 200 ack=ok → HANDSHAKE→ACK → business data (priority P2)
Backup:   POST resume/2 (sid=abc+b, caps=..., role=backup)
       → 200 ack=ok → HANDSHAKE(role=backup)→ACK → KEEPALIVE(15s,P1)↔ACK
Primary down → client switches to the backup at sid=abc+b (liveness confirmed) → takeover in seconds
```

---

## 4. Inventory of Existing-Code Modification Points and Refactoring Steps

> All changes **stay in the working tree, uncommitted** (respecting the iron rule); run `go build` + the relevant `go test` + cross-compilation at each step.

### 4.1 New files
| File | Contents |
|---|---|
| `handshake.go` | Handshake codec: version negotiation `negotiateVersion`, capability intersection `intersectCaps`, parameter alignment `alignParams`, error-code table, `X-Resume-Caps/Params` encoding/decoding |
| ~~`handshake_frame.go`~~ | (removed) Data-plane control frames were already implemented in `resumeframe.go`'s `writeFrame`; it once contained the `frameMux` dual-queue scheduler, which, having never been wired into the production write path, was deleted as dead code — control-frame priority is now guaranteed by `resumeSessionWriter.mu` serialization (see §2.7). |
| `backup.go` | Primary/backup management: client backup-line runners (hot standby `hotBackupRunner` / cold standby `coldBackup`), takeover logic `takeoverIfConfirmed`, KEEPALIVE heartbeat pump |
| `handshake_test.go` | **Complete handshake-protocol tests** (see §5) |

### 4.2 `resumeframe.go` (frame-header extension; no legacy-format compatibility needed after v1 removal)
- The frame header grows from `[4B dataLen][2B padLen][8B seq]` (14B) to **`[1B type][1B ver][4B dataLen][2B padLen][8B seq]` (16B)**.
- Frame types: `0x01=DATA`, `0x02=END`, `0x03=ERROR`, `0x10=HANDSHAKE`, `0x11=HANDSHAKE-ACK`, `0x12=KEEPALIVE`, `0x13=KEEPALIVE-ACK`. `ver` is always `0x02`.
- `resumeFrameTypeResume` changed to `"resume/2"`.
- The old `writeResumeFrame`/`readResumeFrame` are refactored into a unified `writeFrame(type, ver, seq, data)`/`readFrame()`; all reads/writes use the new header.
- **Data-frame writes go through `resumeSessionWriter.writeFrame`** (internally serializing on `resumeSessionWriter.mu`, with control frames inserted ahead of DATA); no more direct raw writes.

### 4.3 `server.go` — `handleH2StreamResumeServer`
1. **Handshake handling (done before `prepareResumeSession`)**:
   - Verify `X-Tunnel-Proto == "resume/2"`; otherwise 426.
   - Parse `X-Resume-Version`/`X-Resume-Caps`/`X-Resume-Params`; the `role` header (primary/backup).
   - Version negotiation (v2 only) + capability intersection + parameter alignment.
   - Write response headers `X-Resume-Version/Caps/Params/Ack`; empty intersection / invalid parameters → return error codes per §1.5.
2. **Layer-B confirmation**: before the business-data loop, wait for and verify the client's `HANDSHAKE` control frame, and reply with `HANDSHAKE-ACK` (via `writeControl`, inserted into the gaps between DATA frames under `resumeSessionWriter.mu` protection).
3. **`role=backup`**: skip the business downlinkPump double-write; instead answer `KEEPALIVE` periodically (P1).
4. Uplink/downlink reads and writes are serialized through `resumeSessionWriter` (control frames first, see §2.7).
5. **Delete** the old `handleH2StreamServer`, `proxyStream`, `copyWithHeartbeat` legacy paths unrelated to resume (see §4.9).

### 4.4 `client_resume.go` / `client_resume_udp.go`
- `buildResumeRequest`/`buildResumeUDPRequest`: `X-Tunnel-Proto: resume/2` + `X-Resume-Version/Caps/Params` + `role` (for the backup).
- `runResumeAttempt`/`runOneStream`: read the response `X-Resume-Ack`; anything but `ok` → handle per error code; after `ok`, write `HANDSHAKE` (P1) and wait for `HANDSHAKE-ACK` (timeout `handshake_ack_timeout`); **zero business bytes go uplink before the ack**.
- Defer to the parameters echoed back by the server and update the local ring window, etc.
- Uplink/downlink reads and writes are serialized via `resumeSessionWriter`/`pw` (control frames first, see §2.7).

### 4.5 `main.go`
- Protocol version and capability sets are fixed inside the internal negotiation layer; no ineffective configuration switches are exposed. Externally, only the actually effective `session_window_kb`, `handshake_ack_ms`, `keepalive_sec`, and connection-policy fields remain.
- `Resume bool`, `ResumeEnabled`, and `backup_line` have all been deleted; the `resume:false` branch (including raw UDP forwarding) no longer exists — resume/2 is always enabled with no downgrade target.
- `buildServerConfig/buildClientConfig` pass through only the fields actually used by the current runtime.

### 4.6 `session.go` control-frame priority (writer mutex serialization)
- `resumeSessionWriter` holds `mu`: every write path (`writeFrame` / `writeControl` / `writeEnd` / `writeRaw`) locks `mu` first, then writes the whole frame and flushes, guaranteeing frame atomicity (a control frame is never split by DATA).
- Server-side downlink: `downlinkPump` writes DATA via `writeDownlink`→`writeFrame`, releasing `mu` per frame; handshake ACK / KEEPALIVE-ACK go through `writeControl` and insert into the frame gaps → control frames are naturally prioritized and never starved (details in §2.7).
- During `replayDownlink` replay, `tunnelSession.mu` is held throughout and `onClose` is temporarily cleared, to avoid concurrent interleaving with `downlinkPump`'s real-time downlink writes (otherwise frames would overlap and seq would go out of order → the client hits `ErrGap` and breaks the stream).
- A backup session does not start the business downlinkPump; it uses `backupLine.keepaliveLoop` instead.

> The originally designed standalone `frameMux` dual-queue scheduler (old version of §4.6) has been removed: its "drain the control queue first, then write the data queue" semantics are now equivalently implemented by "`resumeSessionWriter.mu` per-frame serialization + control frames inserted into frame gaps", with no extra goroutine/queue complexity.

### 4.7 `sharecrypto.go` / `pool.go`
- If the frame-header extension affects buffer-pool size calculations, adjust the budget constants of `paddingWritePool`/`tcpBufPool` accordingly.

### 4.8 `client.go` — WT migrated to the v2 session model ✅ completed
- WT has been folded from its standalone `WTSessionManager` business model into the `resume/2` engine: each tunnel gets its own `WTSessionManager` (headers carrying the layer-A negotiation headers + `Protocol: webtransport`), and the server's `handleWebTransportServer` dispatches every business stream into the v2 session table (`prepareResumeSession`).
- Because WT streams carry no per-stream HTTP headers, `clientDownlink` is now carried in the layer-B `HANDSHAKE` frame payload (a decimal string), and the server replays the downlink gap accordingly.
- The server's `resumeSessionWriter.w` was widened from `http.ResponseWriter` to `io.Writer` (`flusher` optional) so a `webtransport.Stream` can serve directly as the downlink target; the h2/grpc/masque call sites needed no changes.
- Resume-after-disconnect is verified by `TestWTResumeReconnect` (stream1 closes after reading part of the downlink; stream2 resumes from clientDownlink under the same session id, with no gap and no duplication overall).
- Note: attaching `activeWriter` must wait until the layer-B handshake completes (HANDSHAKE-ACK written out); otherwise downlinkPump may write DATA frames into the new stream before the handshake, and the client would read DATA as its first frame and fail the handshake (applies to both h2 and wt).

### 4.9 Deletion inventory (v1 fully removed) — ✅ all landed in M5
| Deleted item | Location | Status |
|---|---|---|
| `resumeFrameTypeResume` old value `resume/1` | resumeframe.go | ✅ changed to `resume/2` |
| `handleH2StreamServer` (non-resume legacy handler) | server.go | ✅ deleted |
| `executeHTTPTunnel` (non-resume client) | client.go | ✅ deleted |
| `handleH2TCPClientConn` / `handleMasqueTCPClientConn` | client.go | ✅ deleted; unified through `executeResumableTunnel` |
| `proxyStream` / `copyWithHeartbeat` | protocol.go | ✅ deleted |
| `PaddingReader` / `PaddingWriter` / `pinger` | protocol.go | ✅ deleted (WT switched to `writeFrame/readFrame`) |
| `grpcReader` / `grpcWriter` | protocol.go | ✅ deleted; grpc only sets Content-Type |
| `calculatePadding` | protocol.go | ✅ deleted (only used by PaddingWriter) |
| `resume:false` branch | main.go | ✅ deleted; resume is always true |
| Tests depending on the legacy path (`TestPaddingPingFrameRoundTrip` etc.) | heartbeat_test.go | ✅ rewritten/deleted |
| WT's v1 Padding path | client.go / server.go | ✅ migrated to the v2 frame data plane |

### 4.10 Tests (see §5 `handshake_test.go` below)

---

## 5. Complete test.go Plan (`handshake_test.go`)

Covers 5 dimensions: unit (codec/negotiation/parameters) + frame header (new v2 header) + sequencing (handshake) + control-frame priority + primary/backup + version rejection. Skeleton:

```go
package main

// ================= 1. Codec unit tests =================

// TestFrameV2RoundTrip round-trip codec for the new 16B frame header (type/ver/dataLen/padLen/seq)
// TestFrameV2Types codec for every frame type (DATA/END/ERROR/HANDSHAKE/HANDSHAKE-ACK/KEEPALIVE/KEEPALIVE-ACK)
// TestHandshakeCapsParse capability-list parsing: normal, empty, unknown entries (should be ignored)
// TestHandshakeCapsIntersect capability intersection: full / partial / empty (should report no-common-capability)
// TestHandshakeParamsParse parameter parsing: k=v lists, invalid values fall back to defaults, unknown keys ignored
// TestHandshakeParamsAlign parameter alignment: clamping out-of-range values, server side wins
// TestHandshakeVersionNegotiate v2 only: min()==2 passes; anything but 2 → version-unsupported

// ================= 2. Control-frame priority tests =================
// Note: the `frameMux` dual-queue scheduler and its unit tests (TestPrioQueue*) were removed as dead code;
// control-frame priority is now guaranteed by `resumeSessionWriter.mu` serialization (see §2.7), and the
// existing v2 frame-codec unit tests in `handshake_frame_test.go` already cover control-frame type encoding/decoding.
// To regress "control frames are always delivered under congestion", layer a heavy DATA stream onto
// the backup-liveness cases in `connmanager_test.go` and check KEEPALIVE-ACK latency.

// ================= 3. Handshake sequencing tests =================

// TestHandshakeAckRequired without ack=ok the client must not write business data (zero-uplink-byte gate)
// TestHandshakeVersionUnsupported version not v2 → 426+version-unsupported, client terminates
// TestHandshakeNoCommonCapability empty capability intersection → 406, client downgrades to the minimum set and retries
// TestHandshakeInvalidParams invalid parameters → server returns defaults, client retries once with them
// TestHandshakeAckTimeout layer-B HANDSHAKE-ACK timeout → retry stream establishment
// TestHandshakeFullRoundTrip full primary-line handshake: header ack + HANDSHAKE→ACK → business data

// ================= 4. Primary/backup line tests =================

// TestBackupLineIndependentHandshake backup uses its own session id + handshake, no clash with the primary
// TestBackupKeepaliveLiveness backup KEEPALIVE renewal; consecutive timeouts → judged dead
// TestBackupTakeoverOnlyIfConfirmed takeover forbidden for an unconfirmed backup; a confirmed one switches in seconds
// TestBackupHotStandby hot standby: primary down → instant switch to the confirmed backup
// TestBackupColdStandby cold standby: handshake only at switchover; slower takeover but succeeds

// ================= 5. Version hard-constraint / v1-removal tests =================

// TestV1Rejected legacy client sends resume/1 → server replies 426 version-unsupported (no downgrade)
// TestNoVersionHeaderRejected missing X-Tunnel-Proto header → 426
// TestV1DataPathRemoved the old Padding/grpcReader/proxyStream symbols no longer exist (compile-time verification)
// TestUnknownCapabilityIgnored unknown capabilities are ignored and the session keeps working (forward compatibility)
```

**Key assertions**:
- After negotiation, both sides' version/parameters are **strictly equal** (alignment correctness).
- The client sends **zero business bytes uplink** before the ack arrives (the confirmation gate is in force).
- Control-frame priority: construct a scenario where data frames would crowd out control frames, and assert the control frame is written out first.
- Backup takeover succeeds **only while keepalive liveness holds**; otherwise assert the takeover is refused.
- **v1 is hard-rejected** (426), and the legacy data-path symbols are gone at compile time (via `//go:build` or a direct assertion that the symbols do not exist).

---

## 6. Implementation Milestones

| Phase | Content | Verification | Status |
|---|---|---|---|
| M1 | Frame header extended to the new v2 16B header + codec unit tests (`handshake_frame_test.go`) | Unit tests green | ✅ Done (control-frame priority moved to `resumeSessionWriter.mu` serialization; the original `frameMux` scheduler removed) |
| M2 | Server-side handshake (version/capabilities/parameters/ack) + layer-B control frames + `role=backup` branch | e2e handshake succeeds | ✅ Done |
| M3 | Client handshake (initiate + verify ack + wait for HANDSHAKE-ACK) + control-frame priority on uplink/downlink | Primary-line e2e all green | ✅ Done |
| M4 | Primary/backup lines (hot standby/cold standby + KEEPALIVE + takeover) | Primary/backup e2e green | ✅ Done |
| M5 | **Delete the v1 legacy path** + WT migration + full regression + gofmt/vet/cross-compile | Full suite green + v1 symbols gone | ✅ Done |

### M5 as landed (v1 fully removed)

v1 symbols deleted (verified absent at compile time):

- Server side: `handleH2StreamServer` (old H2 handler), the `proxyStream` fallback branches of MASQUE-TCP/UDP.
- Client side: `executeHTTPTunnel`, `handleH2TCPClientConn`, `handleMasqueTCPClientConn` (TCP unified through `executeResumableTunnel`).
- `protocol.go`: `proxyStream`, `PaddingReader`, `PaddingWriter`, `grpcReader`, `grpcWriter`, `copyWithHeartbeat`, `pinger`, `calculatePadding`.

Migrations and changes:

- The **WT data plane** is unified on the resume/2 frame protocol: the client's `handleWTTCPClientConn` and the server's `proxyWTStreamV2` carry DATA/END frames via `writeFrame/readFrame` (TCP); UDP uses `writeUDPPacket/readUDPPacket` datagram framing.
- **Client TCP dispatch** becomes resume-only: `runTCPClient` dispatches purely on `Transport` and goes straight into `executeResumableTunnel` (h2/h3/grpc/masque-tcp).
- **Server dispatch**: POST/MASQUE-TCP/MASQUE-UDP all require `X-Tunnel-Proto: resume/2`, otherwise 426 `resume/2 required` (no v1 fallback).
- **UDP stream clients**: all non-WT UDP goes through `connectResumeUDP` (v2); the v1 `grpcWriter/grpcReader` POST fallback branch is deleted.
- **Test migration**: in `features_test.go` and `heartbeat_test.go`, every client/server got `ResumeEnabled: true`; the obsolete `TestPaddingPingFrameRoundTrip`/`TestPaddingReaderAcceptsConsecutivePings` (v1 Padding unit tests) were deleted. *(Later note: once the `ResumeEnabled` field was fully removed, this batch of redundant `ResumeEnabled: true` assignments in tests was also purged.)*
- **Port-conflict fix**: the echo/server port base for the backup tests moved from the `22000` range to the `27000` range to avoid colliding with `TestH2Tunnel_StrictDemux` (`22001`/`22002`/`22003`) — background `go startXxx` goroutines that never exit kept the ports occupied for a long time.

Regression verification: `go build`, `go vet`, `gofmt`, `go test ./...` (all 40 tests green), and cross-compilation for linux/amd64 + linux/arm64 + darwin/arm64 all pass.

> Each phase's changes stay in the working tree; once everything is done, report to the user as a whole and let the user decide whether to commit.
