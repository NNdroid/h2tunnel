# h2tunnel Layered Connection-Management Architecture (resume v2 Unification)

> Status: **Implemented** (L3 `connmanager.go` + generalized `backup.go` + `main.go` config wiring; the full runnable test suite `connmanager_test.go` is green; regression verification passed).
> Scope: Refactor client connection management and primary/backup failover onto resume v2; completely remove all v1-era legacy connection-management paths.
> Related: `docs/resume-handshake-protocol.md` (resume/2 frame protocol, handshake, primary/backup line protocol).

---

## 0. Design Goals and Background

After M1–M5, the current code has already **unified the data plane on the resume v2 frame protocol** (all v1 Padding/grpc/heartbeat paths were deleted). However, **the connection-management layer is still organized as a flat, historically grown structure**:

- Transport selection (h2 / h3 / grpc / masque / wt) is scattered inside the long `runClient` function in `client.go`;
- The pool-level standby `standbyRoundTripper` (`standby.go`) and the backup-line executor `backupLine` (`backup.go`) **are two parallel, overlapping standby implementations**;
- The backup line `backupLine` is currently a narrow interface — "fixed at 1 line, heartbeat only, no business data, created externally" — and is not wired into unified lifecycle management;
- There are no configurable items such as "primary/backup counts", "dial interval", or "establish interval"; type-based sharding (splitting multiple primary connections by transport type) is entirely absent.

The goal of this design is to provide **a cleanly layered connection-management architecture** that satisfies:

1. **Unified protocol**: Keep none of the pre-resume legacy protocols; unify everything on resume v2.
2. **Layered decoupling**:
   - **Foundation layer (mandatory/common logic)**: session resume engine, frame codec, ring buffer, handshake negotiation, seq management, control-frame priority scheduling — the immutable core shared by all protocols.
   - **Transport implementation layer (lowest layer)**: each concrete protocol (h2 / h3 / grpc / masque-tcp / masque-udp / wt) provides only the minimal "establish one byte-pipe / datagram-pipe" implementation, with no business logic mixed in.
   - **Connection management layer (built on top of resume)**: lifecycle management, health probing, count replenishment, failover, and type-based sharding on top of the primary/backup connection pool.
3. **Primary/backup connection management**:
   - Primary/backup counts are **configurable**: defaults are 1 primary, 1 backup.
   - When there is more than 1 primary connection, operate with **type-based sharding**.
   - Whenever a primary connection drops, one backup is promoted to take its place (upgraded to primary), and **a new backup is dialed to replenish the backup count**.
   - Keep separate **dial interval** configuration for primary and backup; the interval between primary and backup establishment defaults to **100 seconds**.

---

## 1. Layer Overview

```
┌────────────────────────────────────────────────────────────┐
│              Application layer (user business)             │
│  SSH / UDP / any net.Conn — cares only about "one usable    │
│  tunnel"                                                   │
└───────────────▲────────────────────────────────────────────┘
                │  consistent net.Conn semantics (read/write + resume on disconnect)
┌───────────────┴────────────────────────────────────────────┐
│  L3  Connection management layer  ConnectionManager        │
│   · primary/backup connection pool (primary 1..N /          │
│     backup 1..M, counts configurable)                      │
│   · primary drops → backup promotes to primary →           │
│     redial to replenish the backup                         │
│   · multiple primaries → type sharding (tcp→h2/h3, udp→...) │
│   · health probing / establish-interval phase offset /     │
│     lifecycle                                              │
└───────────────▲────────────────────────────────────────────┘
                │  every connection = one ResumeSession instance
┌───────────────┴────────────────────────────────────────────┐
│  L2  Session layer (resume v2 engine / foundation common   │
│      logic)  ResumeSession                                 │
│   · frame codec writeFrame/readFrame; control frames       │
│     serialized by the writer mutex, ahead of DATA          │
│   · ring buffer seq replay, session table,                 │
│     A/B two-layer handshake                                │
│   · session recovery (resume on disconnect) —              │
│     transport-agnostic                                     │
└───────────────▲────────────────────────────────────────────┘
                │  establish one stream via Transport (byte / datagram)
┌───────────────┴────────────────────────────────────────────┐
│  L1  Transport implementation layer                        │
│      TransportAdapter (h2/h3/grpc/masque/wt)               │
│   · responsible only for: dial + stream setup + exposing   │
│     io.Reader/io.Writer / datagram send-recv + liveness    │
│     probe; no resume/session/business logic                │
└────────────────────────────────────────────────────────────┘
```

**Dependency direction (strictly one-way)**: `L3 → L2 → L1`. L1 does not know L2/L3 exist; L2 does not know L3 exists; only L3 owns all state about "which connections there are, which are primary, which are backups".

---

## 2. Layers and Responsibilities in Detail

### 2.1 L1 Transport implementation layer (lowest layer)

Goal: abstract "establish a tunnel stream to the server using transport X" into **a unified interface**, flattening away the differences between h2/h3/grpc/masque/wt.

```go
// transport.go —— new
// Transport adapter: an established, usable low-level tunnel channel.
type TunnelConn interface {
    io.Reader
    io.Writer
    io.Closer
    // LocalAddr/RemoteAddr for logging and health decisions
    NetType() string          // "tcp" | "udp"
    Proto() string            // "h2" | "h3" | "grpc" | "masque-tcp" | "masque-udp" | "wt"
    // One connection setup (dial). The implementation is responsible for
    // constructing the http.Client / http3.Transport / wt dialer, initiating
    // the request to the server, and returning a usable stream.
}

// Transport factory: produces one TunnelConn according to configuration.
type TransportFactory interface {
    Dial(ctx context.Context, cfg ClientConfig) (TunnelConn, error)
    // DialInterval is the dial interval for this transport
    // (primary/backup each configurable, see §5)
}
```

**One implementation per protocol** (placed in `transport_*.go`):

| Protocol | Implementation | Channel form | Notes |
|------|------|----------|------|
| h2 | `http2TransportAdapter` | byte stream (POST streaming body/body) | |
| h3 | `http3TransportAdapter` | byte stream (QUIC bidi stream) | |
| grpc | `grpcTransportAdapter` | byte stream (POST + Content-Type: application/grpc) | marker only, no grpc framing layered on top |
| masque-tcp | `masqueTCPTransportAdapter` | byte stream (CONNECT stream) | |
| masque-udp | `masqueUDPTransportAdapter` | datagram (CONNECT + capsule) | |
| wt | `webtransportAdapter` | byte stream (WT bidi stream) | |

> **Key decoupling point**: L1 is only responsible for "stream setup + raw byte/datagram read-write". It does **not touch** resume frames, seq, or handshake — those are L2's job. The branches currently tangled inside `buildResumeRequest` ("masque goes through RoundTrip, h2 goes through Do", etc.) all move down into each adapter's `Dial`.

### 2.2 L2 Session layer (resume v2 engine, foundation common logic)

Goal: promote the resume v2 engine from "a single function embedded in executeResumableTunnel" into **a standalone, reusable session object**.

```go
// session.go —— refactor
// One resume v2 session: exposes a "readable/writable tunnel" to the layer
// above, and carries all resume semantics internally.
type ResumeSession struct {
    id        string
    transport TunnelConn            // underlying L1 channel
    ring      *resumeClientRingBuf  // uplink ring buffer (resume)
    serverUplink atomic.Uint64      // resume position acknowledged by the server
    seq        atomic.Uint64        // uplink seq of this session
    mu         sync.Mutex          // write mutex: serialize control frames and
                                    // DATA; control frames insert ahead of DATA
    // Lifecycle/state
    mu       sync.Mutex
    state    SessionState           // idle/handshaking/active/draining/closed
    role     SessionRole            // primary / backup
    err      error
}

func NewResumeSession(id string, transport TunnelConn, cfg ClientConfig) *ResumeSession
func (s *ResumeSession) Handshake(ctx context.Context) error     // A+B two-layer handshake
func (s *ResumeSession) Read(p []byte) (int, error)              // downlink frame decode → business data
func (s *ResumeSession) Write(p []byte) (int, error)             // business data → uplink seq into ring → write frame
func (s *ResumeSession) Ping() error                             // send a KEEPALIVE control frame (backup liveness probe)
func (s *ResumeSession) Close() error
func (s *ResumeSession) State() SessionState
func (s *ResumeSession) UpgradeToPrimary()                       // promote backup to primary (change role)
```

> **Migrating from executeResumableTunnel**: the existing `runResumeAttempt` / `resumeSendLoop` / `resumeRecvLoop` logic moves wholesale into `ResumeSession`; `Read/Write` are the old recv/send loops. The "redial" responsibility for resume-after-disconnect moves **up to L3** from the single-function loop (ConnectionManager decides whether to "redial a new stream" or "switch to a backup").

### 2.3 Control-Frame Priority (L2 common-core constraint)

`resumeframe.go` defines the logical frame priorities (design intent, not runtime enforcement):

```
P0 = ERROR / END          (session-terminating class, highest priority)
P1 = HANDSHAKE/ACK, KEEPALIVE/ACK (control/handshake, second highest)
P2 = DATA                 (business data, lowest)
```

**Actual runtime guarantee (no standalone scheduler)**: control frames and DATA frames share the same HTTP stream, and the write path is serialized by each writer's mutex, ensuring "control frames are never split and never starved":

- **Server downlink**: `downlinkPump` writes DATA via `writeDownlink` → `resumeSessionWriter.writeFrame`; handshake ACK / KEEPALIVE-ACK write control frames via `writeControl`. Both lock `resumeSessionWriter.mu`, and `downlinkPump` releases the lock as soon as each frame is written out, so control frames slot into the gaps between data frames — they can never be split by the data plane, nor starved.
- **Client uplink**: on a single stream only one `resumeSendLoop` goroutine writes to `pw` (DATA + END), and HANDSHAKE is written exactly once before the stream is established, so there is naturally no concurrent-write contention.
- **Backup line**: `backupLine.keepaliveLoop` exclusively owns one stream to write KEEPALIVE and read KEEPALIVE-ACK — likewise a single writer.

> Historical note: `handshake_frame.go` once implemented a `frameMux` two-queue scheduler (ctrlQ always ahead of dataQ), but it was **never wired into the production write path** (only its unit tests referenced it), and was removed as dead code during code review. The "writer-mutex serialization" described above is the priority guarantee actually in effect today — behaviorally equivalent and simpler.

### 2.4 L3 Connection management layer (the core of this design)

Goal: own all connection state, and handle the primary/backup pool, sharding, failover, and replenishment.

```go
// connmanager.go —— new
// Connection manager: holds N primary + M backup connections, shards by type,
// and switches over + replenishes on failure.
type ConnectionManager struct {
    cfg      ConnectionPolicy      // primary/backup counts / intervals / type-sharding policy
    factory  *TransportFactorySet  // factories for each transport

    mu       sync.RWMutex
    primaries map[string]*ResumeSession  // key: type(proto) → primary connection (at most 1 primary per type)
    backups   []*ResumeSession           // backup connection pool (no business data, liveness probe only)
    // dial/establish throttling
    dialMu    sync.Mutex
    lastDial  map[string]time.Time
}

func (m *ConnectionManager) Start(ctx context.Context)        // start: dial primaries + backups per policy
func (m *ConnectionManager) Pick(proto string) *ResumeSession // business side picks one primary connection
func (m *ConnectionManager) OnPrimaryLost(s *ResumeSession)   // primary lost → triggers switchover + replenishment
func (m *ConnectionManager) replenish()                       // restore primary/backup counts
func (m *ConnectionManager) dialOne(role SessionRole, proto string) *ResumeSession
```

---

## 3. Type-Based Sharding (Multiple Primary Connections)

**Trigger**: `PrimaryCount > 1`.

**Core idea**: the primary connections are not "N fully equivalent" redundancies, but split traffic by network type — one client maintains multiple primary connections at the same time, each serving one class of traffic.

Sharding dimensions (the two network classes in the current code):
- **TCP class**: serves streaming byte traffic such as SSH.
- **UDP class**: serves datagram traffic such as DNS.

```
With PrimaryCount=2:
  primary["tcp"] → current transport (ResumeSession, role=primary)
  primary["udp"] → current transport (ResumeSession, role=primary)

Business traffic:
  TCP traffic → Pick("tcp") → via the TCP primary connection
  UDP traffic → Pick("udp") → via the UDP primary connection
```

The sharding types are derived directly from `network` as an ordered array: `tcp`, `udp`, or `[tcp, udp]`.
Transport protocols are not configured redundantly at this layer; the single `transport` is always used.

> **Note**: this "type sharding" is **connection/channel-level** sharding, not session-level (multiple sessions can still run in parallel within the same business type). The primary connections **never duplicate one another** — each exclusively owns one type, preventing the "CDN kills several connections at once" problem from degenerating into "N duplicated redundancies".

---

## 4. Primary/Backup Failover and Replenishment Flows

### 4.1 State machine (a single connection)

```
                 dialOne() handshake succeeds
   ┌───────────► ┌────────────────┐
   │             │  handshaking    │
   │             └───────┬────────┘
   │                     │  A+B handshake ok
   │                     ▼
   │             ┌────────────────┐   Pick() hits   ┌────────────┐
   │             │  backupAlive    │ ─────────────► │  primary   │
   │             │  (backup, ready │   UpgradeTo    │  (primary, │
   │             │  to take over)  │                │  carrying  │
   │             └───────┬────────┘                 │  business) │
   │                     ▲                          └─────┬──────┘
   │                     │ replenish: dial a new          │ lost/unhealthy
   │                     │ backup                         ▼
   │                     │                        ┌────────────┐
   │                     │                        │primaryLost │
   └── redial ───────────┘                        └────────────┘
```

### 4.2 Primary connection drops → switchover + replenishment (core flow)

```
① Business read/write fails / probing judges primaryLost
        │
        ▼
② ConnectionManager.OnPrimaryLost(the dropped primary[type])
        │
        ▼
③ Pick one backup from the backups pool that is
   "confirmed alive (backupAlive)"
        │  (found: go to ④; none: go to ⑤)
        ▼
④ Promote: backup.UpgradeToPrimary() → primary[type] = that backup
   · The backup previously completed handshake + KEEPALIVE keepalive →
     right after promotion it can keep carrying business (second-level takeover)
   · The original session id stays unchanged; the business side still gets a
     tunnel with the same semantics from Pick(type)
        ▼
⑤ Replenish: replenish() dials one new backup to restore backupCount
   · Throttled by that backup's dial interval (§5)
        ▼
⑥ Done: primary and backup counts return to the configured values
```

**Key constraints**:
- **Only `backupAlive` backups are allowed to take over** (inheriting the §3.3 design, avoiding a blind switch onto a dead line).
- If no backup can take over, `primary[type]` stays empty, and `Pick(type)` blocks/returns a retry; `replenish` immediately redials a primary per the dial interval (primary takes priority over backup).
- **No session is lost at the instant the primary drops**: resume v2's seq + ring buffer guarantee the promoted primary can resume from the break point (if that type allows multiple sessions, other surviving primaries of the same type take temporary charge).

### 4.3 Backup replenishment flow

```
① replenish() checks: backups pool size < BackupCount
        │
        ▼
② Has that backup's "dial interval" come due? (lastDial + backupDialInterval <= now)
        │  No: wait for the interval to elapse (timer) | Yes: continue
        ▼
③ dialOne(role=backup, proto=chosen per the sharding policy)
   · Build an independent session id (<type>+b), role=backup
   · A+B handshake (datagram class skips the B layer, A layer only)
        ▼
④ Enroll in pool: backups = append(backups, new backup) (state=backupAlive)
   · Background KEEPALIVE keepalive (§4.4)
        ▼
⑤ Done
```

### 4.4 Backup keepalive (KEEPALIVE)

- Backups carry no business data; they only run periodic `KEEPALIVE` probes (reusing the existing `backupLine` logic, but objectified into `ResumeSession`).
- `BackupMaxMissedAcks=3` consecutive `KEEPALIVE-ACK`s missed → judged dead, removed from the pool, replenishment triggered.
- KEEPALIVE frames are written out on an exclusively owned stream via `backupLine.keepaliveLoop`, so they never contend with business DATA in the first place; main-line KEEPALIVE-ACK is written via `writeControl`, protected by `resumeSessionWriter.mu`, slotting into the gaps between DATA frames — **always ahead of any DATA and never split**.

---

## 5. Configuration Design

Unified in `Config` (JSON fields) and `ClientConfig` (runtime).

```go
type ConnectionPolicy struct {
    PrimaryCount int               // primary connection count, default 1
    BackupCount  int               // backup connection count, default 1
    PrimaryDialInterval  time.Duration // primary connection dial interval (§5.1)
    BackupDialInterval   time.Duration // backup connection dial interval (§5.1)
    EstablishInterval    time.Duration // primary/backup establish interval (§5.2), default 100s
    BackoffMaxMissedAcks int          // backup failure threshold, default 3
    PrimaryNetworks []string          // enabled primary-line network types, fixed tcp→udp order
}
```

### JSON fields (added to `Config`)

```jsonc
{
  "primary_count": 1,          // primary connection count (type sharding enabled when >1), default 1
  "backup_count": 1,           // backup connection count, default 1
  "primary_dial_interval_sec": 0,   // primary dial interval (seconds), 0=default (see §5.1)
  "backup_dial_interval_sec": 0,    // backup dial interval (seconds), 0=default
  "establish_interval_sec": 100     // primary/backup establish interval (seconds), default 100
}
```

Sharding provides no separate mapping configuration: `transport` is the single source of truth for the transport, `network` decides whether `tcp`, `udp`, or both are enabled, and when `primary_count > 1` the primary lines are split in the fixed `tcp → udp` order.

### 5.0 Upper-Layer Protocol Uniqueness (keep only Resume v2)

- **Single data plane**: `resume/2` is the only upper-layer framing protocol. h2 / h3 / grpc / masque-tcp / masque-udp / wt all act as the **L1 transport implementation layer**, providing only "establish one byte/datagram pipe"; above them, `resume/2` frames + A/B handshake are uniformly layered on.
- **Old protocols fully removed**: all v1-era data planes (Padding frames, grpc secondary framing, proxy heartbeat proxyStream/pinger, etc.) have been deleted (see `resume-handshake-protocol.md` §4.9). Any tunnel request without `X-Tunnel-Proto: resume/2` → the server responds 426, with no fallback target.
- **Transport-layer extensibility**: adding a low-level protocol in the future (e.g. QUIC-Raw, SCTP) only requires a new L1 adapter, **without touching** the L2 session layer or the L3 connection management layer.

### 5.1 Dial Interval (DialInterval)

**Meaning**: the minimum interval between two dial attempts for **the same connection**. Purpose: **resource throttling** — avoid storm-like redials after primary/backup disconnects, and repeated backup replenishment within a short window.

- **Primary dial interval** `primary_dial_interval_sec`: the minimum interval between redials after a primary connection drops. Defaults are differentiated by type — for CDN scenarios (h2/h3/grpc/masque) `30s` is recommended; for direct connections `0` (immediate) is fine.
- **Backup dial interval** `backup_dial_interval_sec`: the minimum interval for backup replenishment. Default `15s` (same order of magnitude as the backup heartbeat period).
- Each is configured independently → "keep separate dial-interval configuration for primary and backup" means exactly this.
- Implementation: `lastDial[role+proto]` + throttling inside `ConnectionManager`; when the interval has not elapsed, arm a timer and dial when it fires.

### 5.2 Establish Interval (EstablishInterval)

**Meaning**: the **phase-offset interval between the primary and backup establishment (dial) actions**, default **100 seconds**.

- **Purpose**: offset (phase-shift) the "age" of the primary and backup connections, preventing the CDN from killing both at the same moment because their connection ages are similar — this is exactly the problem the `maxAge/2` phase-offset rotation in `standbyRoundTripper` tried to solve, but hard-coded at 200s.
- **Usage**: dial the primary first; wait `establish_interval_sec` (default 100s), then dial the backup. Every subsequent replenishment follows the same phase offset, so the connection ages in the pool always stay out of phase.
- **Relation to the dial interval**: `EstablishInterval` constrains the **startup phase** between "primary → backup"; `DialInterval` constrains "redial throttling for the same role". The two are orthogonal and independently configurable.

### 5.3 Validation and Defaults

```go
// Defaults
const (
    defaultPrimaryCount    = 1
    defaultBackupCount     = 1
    defaultEstablishSec    = 100 // primary/backup establish interval defaults to 100 seconds
    primaryDialDefault     = 30 * time.Second // primary redial throttle default
    backupDialDefault      = 15 * time.Second // backup replenishment throttle default
    defaultBackupMissedAck = 3
)

// backup_count uses a pointer to distinguish "unset" from an explicit 0:
// nil → default 1; 0 → backups disabled; positive → that backup count.
// PrimaryNetworks is derived from network; there is no extra shard config.
```

**Primary/backup count rules (mapped one-by-one to the user requirements)**:

| Config | Default | Rule |
|------|------|------|
| `primary_count` | 1 | number of primary connections; **type sharding enabled when >1** (each primary serves one business class) |
| `backup_count` | 1 | number of backup connections; replenished/promoted when a primary dies |
| `primary_dial_interval_sec` | 0→30s | minimum interval between redials after a primary drops (throttling, anti-storm) |
| `backup_dial_interval_sec` | 0→15s | minimum interval for backup replenishment (throttling) |
| `establish_interval_sec` | 100 | the **phase-offset interval between the primary and backup establish actions**; dial the primary first, wait 100s, then dial the backup |

> **Primary/backup failover semantics**: with `primary_count=1` this degenerates into the classic "1 primary + 1 backup" mode. With `primary_count=2` there is one primary each for `tcp`/`udp` (type sharding); when a primary dies → pick a `backupAlive` backup from the pool and promote it to primary → dial a new backup to restore `backup_count`.

---

## 6. Module/File Split (implementation suggestion)

```
client.go                 // entry runClient: assemble ConnectionPolicy + TransportFactorySet
                           // call ConnectionManager.Start(), then dispatch by business type via Pick()
connmanager.go   (new)     // L3 ConnectionManager: primary/backup pool + sharding + switchover + replenishment
resumesession.go (refactor) // L2 ResumeSession: extracted from executeResumableTunnel
resumeframe.go             // L2 frame codec + write-path mutex serialization (control-priority-over-DATA already landed at the writer layer, no separate frameMux file needed)
ring.go                    // L2 ring buffer (kept)
handshake.go               // L2 A/B handshake + capability/parameter negotiation (kept, interfaced)
transport.go     (new)     // L1 TunnelConn / TransportFactory interfaces
transport_h2.go  (new)     // L1 h2 adapter
transport_h3.go  (new)     // L1 h3 adapter
transport_grpc.go(new)     // L1 grpc adapter
transport_masque.go(new)   // L1 masque-tcp / masque-udp adapter
transport_wt.go  (new)     // L1 wt adapter
backup.go                  // logic migrated into ResumeSession(role=backup) + connmanager replenishment; backupLine retired
standby.go                 // retired: its "phase-offset rotation" role is replaced by ConnectionPolicy.EstablishInterval
```

> **Retirement note**: `standbyRoundTripper` and the old standalone standby entry points are uniformly replaced by `ConnectionManager` + `ResumeSession(role)`. Configuration keeps only `backup_count` and the connection-interval policy.

---

## 7. Sequence Diagrams (establish + shard + switchover/replenish)

### 7.1 Startup establishment (PrimaryCount=1, BackupCount=1, EstablishInterval=100s)

```
t=0s       Start()
           ├─ dialOne(primary, tcp) ─► h2 handshake ─► primary["tcp"] = S1 (active)
           │
t=100s     (establish_interval elapsed)
           ├─ dialOne(backup, tcp) ─► h2 handshake ─► backups += S2 (backupAlive)
           │                               └─ S2 background KEEPALIVE keepalive
           │
     Ready: primary=tcp(S1), backup=(S2)
```

### 7.2 TCP primary drops → backup promoted + replenished

```
t1   S1 business read fails → OnPrimaryLost(S1)
     ├─ pick the backupAlive S2 from backups → S2.UpgradeToPrimary()
     │     primary["tcp"] = S2 (second-level takeover, resume continues from the break point)
     └─ replenish()
           ├─ check backupDialInterval: t1 - last backup dial >= 15s? yes
           ├─ dialOne(backup, tcp) ─► S3 (new, backupAlive)
           └─ backups = [S3]
     Done: primary=tcp(S2), backup=(S3)
```

### 7.3 Multi-primary type sharding (PrimaryCount=2, BackupCount=1)

```
t=0s       dialOne(primary, tcp) ─► primary["tcp"] = h2 session
t=100s     dialOne(primary, udp) ─► primary["udp"] = masque-udp session
t=200s     dialOne(backup)      ─► backups += S3
Business traffic:
  SSH  → Pick("tcp") → h2 primary
  DNS  → Pick("udp") → masque-udp primary
t=300s   h2 primary drops → backup S3 promoted to primary(role=tcp) → dial a new backup
```

---

## 8. Boundaries and Caveats

1. **Backups carry no business**: a backup `ResumeSession` only exchanges P1 control frames (KEEPALIVE); the business-side `Pick()` always returns primaries only; backups do not expose a business `Read/Write` path.
2. **Session resume vs. connection switchover**: when a primary drops, resume's seq + ring guarantee that a new stream with "the same session id" can continue. After a backup is promoted to "primary", if the backup's session id differs from the primary's (the current design uses `<primary>+b` for backups), a **decision** is needed:
   - Option A (recommended): **do not change the session id** on promotion — after takeover, the backup re-establishes the stream under the original session id, naturally resuming from the break point.
   - Option B: the backup keeps its own id; the business side starts a new session at takeover. Break-point resume is given up.
   - The design defaults to **Option A**: on `UpgradeToPrimary`, redial the backup connection as the original type with the original session id (near-zero overhead when there is no new break point).
3. **Type sharding ≠ unlimited scaling**: PrimaryCount is recommended to be ≤ the number of business types (default 2: tcp+udp). With PrimaryCount=1 it degenerates into the classic "single primary + single backup" mode, with no sharding.
4. **Default behavior**: when no connection policy is configured, use "1 primary + 1 backup + phase-offset rotation".
5. **Datagram sessions** (UDP): backups/UDP skip the B-layer handshake, A layer only; still use the single client-selected `transport`.
6. **Single configuration entry**: the primary/backup policy is expressed only via `primary_count` / `backup_count` / the two dial intervals / `establish_interval_sec`, where `backup_count=0` disables backups.

---

## 9. Acceptance Suggestions (test checklist)

> Corresponding runnable test file: `connmanager_test.go` (built on a real echo target + tunnel server, `go test -run ConnManager ./...`). **All implemented and passing.**

| ID | Implemented test | Case | Assertions |
|------|----------|------|------|
| T1 | `TestConnManagerEstablishInterval` | PrimaryCount=1, BackupCount=1, establish interval | primary dialed at startup; backup dialed only after the establish_interval phase offset; backups carry no business |
| T2 | `TestConnManagerSwitchoverReplenish` | primary drops, backup alive | backup promoted to primary (resumes under the original id); one new backup dialed automatically |
| T3 | `TestConnManagerAuthFailureNoTakeover` | primary drops, backup not alive / auth failure | no takeover; replenish the primary per primaryDialInterval; replenish the backup per backupDialInterval |
| T4 | `TestConnManagerTypeSharding` | PrimaryCount=2 | one primary each for tcp/udp, type sharding routes each class on its own |
| T5 | `TestConnManagerDialIntervalThrottle` | repeated primary failures | dial-interval throttling in effect, no redial storm |
| T6 | `TestConnManagerBackupKeepaliveFailure` | backup loses consecutive KEEPALIVE ACKs | judged dead, removed from the pool, replenishment triggered |
| T7 | `TestConnManagerEstablishInterval` | establish_interval takes effect | time gap between primary and backup establishment ≈ configured value |
| T8 | `handshake_frame_test` (frame codec) | resume v2 frame encode/decode | DATA/END/ERROR/HANDSHAKE/HANDSHAKE-ACK/KEEPALIVE/KEEPALIVE-ACK encode/decode round-trip + version/type validation correct (control-frame priority is guaranteed by writer-mutex serialization, see §2.3) |
| T9 | `TestConnManagerTransportResumeMatrix` | transport × resume matrix | h2/grpc/masque-tcp/wt/h3 TCP + h2-udp/masque-udp each pass full-duplex echo on top of resume/2 |
| T10 | `TestConnManagerVersionUnsupported` / `TestConnManagerAuthFailureNoTakeover` | error handling | handshake timeout / auth failure / version mismatch → graceful rejection, backups do not take over |
| T11 | `TestConnectionPolicyDefaults` / `TestConnectionPolicyBoundary` | boundaries | primary_count=0 falls back to the default; backup_count=0 disables backups; programmatic calls are safely normalized; external configuration exceeding the number of enabled networks is rejected outright |

---

*This document is an architecture design draft; once confirmed, implement in phases following the milestone cadence in `docs/resume-handshake-protocol.md` §6 (L1 → L2 refactor → L3 → config migration → regression).*
