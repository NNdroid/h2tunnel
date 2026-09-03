# h2tunnel 连接管理分层架构设计（resume v2 统一）

> 状态：**已实施**（L3 `connmanager.go` + `backup.go` 泛化 + `main.go` 配置接线；全量可运行测试 `connmanager_test.go` 全绿；回归验证通过）。
> 范围：客户端连接管理与主备切换的重构，统一到 resume v2；彻底去除 v1 时代所有旧连接管理路径。
> 关联：`docs/resume-handshake-protocol.md`（resume/2 帧协议、握手、主备线路协议）。

---

## 0. 设计目标与背景

当前代码经过 M1–M5 已将 **数据面统一为 resume v2 帧协议**（v1 的 Padding/grpc/心跳路径全部删除）。但**连接管理层的组织仍是历史遗留的平铺结构**：

- 传输选择（h2 / h3 / grpc / masque / wt）散落在 `client.go` 的 `runClient` 长函数里；
- 池级热备 `standbyRoundTripper`（`standby.go`）与备用线路执行器 `backupLine`（`backup.go`）**是两套并行的、职责重叠的热备实现**；
- 备用线路 `backupLine` 目前是「固定 1 条、只做心跳、不参与业务数据、由外部创建」的窄接口，未接入统一的生命周期管理；
- 没有「主备数量」「拨号间隔」「建立间隔」这些可配置项；类型分流（多主连接按传输类型分流）完全没有。

本设计的目标是给出**一套分层清晰的连接管理架构**，满足：

1. **统一协议**：不保留 resume 之前任何旧版协议，全部统一到 resume v2。
2. **分层解耦**：
   - **基座层（必选/公共逻辑）**：会话恢复引擎、帧编解码、环形缓冲、握手协商、seq 管理、控制帧优先调度——所有协议共用的不可变核心。
   - **传输实现层（最底层）**：各具体协议（h2 / h3 / grpc / masque-tcp / masque-udp / wt）只提供「建立一条字节管道 / 数据报管道」的最小实现，不掺业务。
   - **连接管理层（构建在 resume 之上）**：在主备连接池之上做生命周期管理、健康探测、数量补足、切换升级、类型分流。
3. **主备连接管理**：
   - 主备数量**可配置**：默认主 1 条、备 1 条。
   - 主连接 >1 条时按**类型分流**工作。
   - 主连接每断一条，就用一条备用顶上（升级为主），并**重新拨号补足备用数量**。
   - 保留主备各自的**拨号间隔**配置；主/备建立之间的间隔默认 **100 秒**。

---

## 1. 分层总览

```
┌────────────────────────────────────────────────────────────┐
│                    应用层（用户业务）                         │
│   SSH / UDP / 任何 net.Conn —— 只关心「一条能用的隧道」        │
└───────────────▲────────────────────────────────────────────┘
                │ 一致的 net.Conn 语义（读写 + 断线续传）         │
┌───────────────┴────────────────────────────────────────────┐
│  L3  连接管理层  ConnectionManager                          │
│   · 主备连接池（主 1..N / 备 1..M，数量可配）                  │
│   · 主连接断 → 备升级为主 → 重新拨号补备                        │
│   · 多主 → 类型分流（tcp→h2/h3, udp→...）                     │
│   · 健康探测 / 建立间隔错相 / 生命周期                         │
└───────────────▲────────────────────────────────────────────┘
                │ 每一条连接 = 一个 ResumeSession 实例           │
┌───────────────┴────────────────────────────────────────────┐
│  L2  会话层（resume v2 引擎 / 基座公共逻辑）  ResumeSession   │
│   · 帧编解码 writeFrame/readFrame；控制帧由 writer 互斥锁串行化优先于 DATA │
│   · 环形缓冲 seq 重放、会话表、A/B 双层握手                     │
│   · 会话恢复（断线续传）—— 传输无关                         │
└───────────────▲────────────────────────────────────────────┘
                │ 通过 Transport 建立一条流（字节 / 数据报）      │
┌───────────────┴────────────────────────────────────────────┐
│  L1  传输实现层  TransportAdapter (h2/h3/grpc/masque/wt)     │
│   · 只负责：拨号建连 + 建流 + 暴露 io.Reader/io.Writer/       │
│     数据报收发 + 探活；不掺 resume/会话/业务                  │
└────────────────────────────────────────────────────────────┘
```

**依赖方向（严格单向）**：`L3 → L2 → L1`。L1 不知道 L2/L3 的存在；L2 不知道 L3 的存在；L3 才拥有「哪些连接、哪些是主、哪些是备」的全部状态。

---

## 2. 层与职责细化

### 2.1 L1 传输实现层（最底层）

目标：把「用传输 X 建立一条到服务端的隧道流」抽象成**统一的接口**，抹平 h2/h3/grpc/masque/wt 的差异。

```go
// transport.go —— 新增
// 传输适配器：一条已建立的、可用的隧道底层通道。
type TunnelConn interface {
    io.Reader
    io.Writer
    io.Closer
    // LocalAddr/RemoteAddr 供日志与健康判定
    NetType() string          // "tcp" | "udp"
    Proto() string            // "h2" | "h3" | "grpc" | "masque-tcp" | "masque-udp" | "wt"
    // 一次建连（拨号）。实现方负责构造 http.Client / http3.Transport / wt dialer，
    // 发起到服务端的请求并返回可用的流。
}

// 传输工厂：按配置生产一条 TunnelConn。
type TransportFactory interface {
    Dial(ctx context.Context, cfg ClientConfig) (TunnelConn, error)
    // DialInterval 该传输的拨号间隔（主/备各自可配，见 §5）
    DialInterval() time.Duration
}
```

**每种协议一个实现**（放在 `transport_*.go`）：

| 协议 | 实现 | 通道形态 | 备注 |
|------|------|----------|------|
| h2 | `http2TransportAdapter` | 字节流（POST 流式 body/body） | |
| h3 | `http3TransportAdapter` | 字节流（QUIC bidi stream） | |
| grpc | `grpcTransportAdapter` | 字节流（POST + Content-Type: application/grpc） | 仅打标记，不套 grpc 分帧 |
| masque-tcp | `masqueTCPTransportAdapter` | 字节流（CONNECT 流） | |
| masque-udp | `masqueUDPTransportAdapter` | 数据报（CONNECT + capsule） | |
| wt | `webtransportAdapter` | 字节流（WT bidi stream） | |

> **关键解耦点**：L1 只负责「建流 + 原始字节/数据报的读写」。它**不碰** resume 帧、seq、握手——这些是 L2 的事。当前代码里 `buildResumeRequest` 里揉杂的「masque 走 RoundTrip、h2 走 Do」等分支，全部下沉到各自 adapter 的 `Dial` 里。

### 2.2 L2 会话层（resume v2 引擎，基座公共逻辑）

目标：把 resume v2 引擎从「内嵌在 executeResumableTunnel 的单函数」提升为**独立的、可复用的会话对象**。

```go
// session.go —— 重构
// 一条 resume v2 会话：对上层暴露「可读写的隧道」，内部承担全部 resume 语义。
type ResumeSession struct {
    id        string
    transport TunnelConn            // 底层 L1 通道
    ring      *resumeClientRingBuf  // 上行环形缓冲（续传）
    serverUplink atomic.Uint64      // 服务端已确认的续传位置
    seq        atomic.Uint64        // 本会话上行 seq
    mu         sync.Mutex          // 写互斥：控制帧与 DATA 串行化，控制帧优先于 DATA 插入
    // 生命周期/状态
    mu       sync.Mutex
    state    SessionState           // idle/handshaking/active/draining/closed
    role     SessionRole            // primary / backup
    err      error
}

func NewResumeSession(id string, transport TunnelConn, cfg ClientConfig) *ResumeSession
func (s *ResumeSession) Handshake(ctx context.Context) error     // A+B 双层握手
func (s *ResumeSession) Read(p []byte) (int, error)              // 下行解帧→业务数据
func (s *ResumeSession) Write(p []byte) (int, error)             // 业务数据→上行 seq 入 ring→写帧
func (s *ResumeSession) Ping() error                             // 发 KEEPALIVE 控制帧（备用探活）
func (s *ResumeSession) Close() error
func (s *ResumeSession) State() SessionState
func (s *ResumeSession) UpgradeToPrimary()                       // 备用升级为主（改 role）
```

> **从 executeResumableTunnel 迁移**：现有的 `runResumeAttempt` / `resumeSendLoop` / `resumeRecvLoop` 逻辑整体搬入 `ResumeSession`，`Read/Write` 即原 recv/send loop。断线续传的「重拨」职责从单函数循环，**上移到 L3**（由 ConnectionManager 决定「重拨新流」还是「切换备用」）。

### 2.3 控制帧优先（L2 公共核心约束）

`resumeframe.go` 定义帧逻辑优先级（设计意图，非运行时强制）：

```
P0 = ERROR / END          （会话终止类，最高优先）
P1 = HANDSHAKE/ACK、KEEPALIVE/ACK （控制/握手，次高）
P2 = DATA                 （业务数据，最低）
```

**实际运行时保证（无独立调度器）**：控制帧与 DATA 帧共用同一条 HTTP 流，写路径由各自 writer 的互斥锁串行化，保证「控制帧不拆裂、不饿死」：

- **服务端下行**：`downlinkPump` 经 `writeDownlink` → `resumeSessionWriter.writeFrame` 写 DATA；握手 ACK / KEEPALIVE-ACK 经 `writeControl` 写控制帧。两者都锁 `resumeSessionWriter.mu`，`downlinkPump` 每写出一帧即释放锁，控制帧在帧间隙插入，绝不会被数据面拆裂，也不会被饿死。
- **客户端上行**：单条流仅一个 `resumeSendLoop` goroutine 写 `pw`（DATA + END），HANDSHAKE 在建流前单写一次，天然无并发写竞争。
- **备用线路**：`backupLine.keepaliveLoop` 独占一条流写 KEEPALIVE，读 KEEPALIVE-ACK，同样单写者。

> 历史说明：`handshake_frame.go` 曾实现 `frameMux` 双队列调度器（ctrlQ 恒先于 dataQ），但**从未接入生产写路径**（仅其单测引用），已于代码审查中作为死代码移除。上述「writer 互斥锁串行化」即为当前真实生效的优先级保证，行为等价且更简单。

### 2.4 L3 连接管理层（本设计的核心）

目标：拥有全部连接状态，做主备池、分流、切换、补位。

```go
// connmanager.go —— 新增
// 连接管理器：持有 N 条主连接 + M 条备用连接，按类型分流，断线切换+补位。
type ConnectionManager struct {
    cfg      ConnectionPolicy      // 主备数量/间隔/类型分流策略
    factory  *TransportFactorySet  // 各传输的工厂

    mu       sync.RWMutex
    primaries map[string]*ResumeSession  // key: 类型(proto) → 主连接（同一类型至多1条主）
    backups   []*ResumeSession           // 备用连接池（不参与业务数据，只探活）
    // 拨号/建立节流
    dialMu    sync.Mutex
    lastDial  map[string]time.Time
}

func (m *ConnectionManager) Start(ctx context.Context)        // 启动：按策略拨主 + 拨备
func (m *ConnectionManager) Pick(proto string) *ResumeSession // 业务侧取一条主连接
func (m *ConnectionManager) OnPrimaryLost(s *ResumeSession)   // 主断 → 触发切换+补位
func (m *ConnectionManager) replenish()                       // 补足主/备数量
func (m *ConnectionManager) dialOne(role SessionRole, proto string) *ResumeSession
```

---

## 3. 类型分流（多主连接）

**触发条件**：`PrimaryCount > 1`。

**核心思想**：主连接不是「N 条完全等价」的冗余，而是**按类型（网络/协议维度）各管一摊**。即一个客户端同时维持多条主连接，每条服务一类流量。

分流维度（当前代码的两类网络）：
- **TCP 类**：h2 / h3 / grpc / masque-tcp / wt —— 服务 SSH 等流式字节流业务。
- **UDP 类**：masque-udp / stream-udp —— 服务 DNS 等数据报业务。

```
PrimaryCount=2 时：
  primary["tcp"] → h2 (ResumeSession, role=primary)
  primary["udp"] → masque-udp (ResumeSession, role=primary)

业务流入：
  TCP 业务 → Pick("tcp") → 走 h2 主连接
  UDP 业务 → Pick("udp") → 走 masque-udp 主连接
```

**分流表（可扩展）**：`map[string]string`（业务类型 → 协议）。默认：

| 业务类型 | 默认协议 | 说明 |
|----------|----------|------|
| tcp | h2 | 最通用；可配 h3/grpc/masque-tcp/wt |
| udp | masque-udp | 数据报语义；可配 stream-udp |

> **注意**：这里的「类型分流」是**连接/通道级**分流，不是会话级（同一业务类型内部仍可并行多会话）。多条主连接之间**互不重复**——各自独占一个类型，避免 CDN 同时杀掉多条的问题退化为「N 条重复冗余」。

---

## 4. 主备切换与补位流程

### 4.1 状态机（单条连接）

```
                 dialOne() 成功握手
   ┌───────────► ┌────────────────┐
   │             │  handshaking    │
   │             └───────┬────────┘
   │                     │  A+B 握手 ok
   │                     ▼
   │             ┌────────────────┐   Pick() 命中   ┌────────────┐
   │             │  backupAlive    │ ─────────────► │  primary   │
   │             │  (备用，可接管)   │   UpgradeTo    │  (主，承载业务)│
   │             └───────┬────────┘                 └─────┬──────┘
   │                     ▲                               │ 断/失效
   │                     │ 补位拨新备                      ▼
   │                     │                         ┌────────────┐
   │                     │                         │  primaryLost │
   └── 重新拨号 ──────────┘                         └────────────┘
```

### 4.2 主连接断掉 → 切换 + 补位（核心流程）

```
① 业务读写失败 / 探测判定 primaryLost
        │
        ▼
② ConnectionManager.OnPrimaryLost(断掉的 primary[type])
        │
        ▼
③ 从 backups 池挑一条「已确认存活（backupAlive）」的备用
        │  （有：进 ④；无：进 ⑤）
        ▼
④ 升级：备用.UpgradeToPrimary() → primary[type] = 该备用
   · 备用此前已握手 + KEEPALIVE 保活 → 升级后即可继续承载业务（秒级接管）
   · 原 session id 不变，业务侧 Pick(type) 拿到的还是同一语义的隧道
        ▼
⑤ 补位：replenish() 拨一条新的备用，补足 backupCount
   · 遵循该备用拨号间隔（§5）节流
        ▼
⑥ 结束：主数量与备数量重新回到配置值
```

**关键约束**：
- **只有 `backupAlive` 的备用才允许接管**（继承 §3.3 设计，避免盲切死线）。
- 若无可接管备用，`primary[type]` 保持空缺，`Pick(type)` 阻塞/返回重试；`replenish` 立即按拨号间隔补主（主优先于备）。
- **主连接断的瞬间不丢会话**：resume v2 的 seq+环形缓冲保证升级后的主连接可续传断点（若该类型允许多会话，其它未断主连接暂时代管）。

### 4.3 备用补位流程

```
① replenish() 检查 backups 池数量 < BackupCount
        │
        ▼
② 是否已到该备用「拨号间隔」？ (lastDial + backupDialInterval <= now)
        │ 否：等间隔到期（定时器）｜ 是：继续
        ▼
③ dialOne(role=backup, proto=按分流策略选)
   · 构造独立 session id（<type>+b）、role=backup
   · A+B 握手（datagram 类跳过 B 层，仅 A 层）
        ▼
④ 入池：backups = append(backups, 新备用)（state=backupAlive）
   · 后台 KEEPALIVE 保活（§4.4）
        ▼
⑤ 结束
```

### 4.4 备用保活（KEEPALIVE）

- 备用不承载业务数据，只做周期 `KEEPALIVE` 探测（沿用 `backupLine` 现有逻辑，但对象化进 `ResumeSession`）。
- 连续 `BackupMaxMissedAcks=3` 次未收到 `KEEPALIVE-ACK` → 判定失效，移出池，触发补位。
- KEEPALIVE 帧经 `backupLine.keepaliveLoop` 独占流写出，本就不与业务 DATA 争用；主线路 KEEPALIVE-ACK 经 `writeControl` 在 `resumeSessionWriter.mu` 保护下于 DATA 帧间隙插入，**必优先于任何 DATA 且不拆裂**。

---

## 5. 配置项设计

统一落在 `Config`（JSON 字段）与 `ClientConfig`（运行时）。

```go
type ConnectionPolicy struct {
    PrimaryCount int               // 主连接数量，默认 1
    BackupCount  int               // 备用连接数量，默认 1
    PrimaryDialInterval  time.Duration // 主连接拨号间隔（§5.1）
    BackupDialInterval   time.Duration // 备用连接拨号间隔（§5.1）
    EstablishInterval    time.Duration // 主/备建立间隔（§5.2），默认 100s
    BackoffMaxMissedAcks int          // 备用失效判定阈值，默认 3
    Shard map[string]string           // 类型分流表：tcp→h2, udp→masque-udp
}
```

### JSON 字段（新增到 `Config`）

```jsonc
{
  "primary_count": 1,          // 主连接数（>1 时启用类型分流），默认 1
  "backup_count": 1,           // 备用连接数，默认 1
  "primary_dial_interval_sec": 0,   // 主连接拨号间隔（秒），0=默认（见 §5.1）
  "backup_dial_interval_sec": 0,    // 备用连接拨号间隔（秒），0=默认
  "establish_interval_sec": 100,    // 主/备建立间隔（秒），默认 100
  "backup_missed_acks": 3,          // 备用失效阈值（连续丢 ACK 判失效），默认 3
  "shard": { "tcp": "h2", "udp": "masque-udp" }  // 类型分流表（PrimaryCount>1 生效）
}
```

### 5.0 上层协议唯一性（只保留 Resume v2）

- **数据面唯一**：`resume/2` 是唯一上层封装协议。h2 / h3 / grpc / masque-tcp / masque-udp / wt 全部作为 **L1 传输实现层**，只提供「建一条字节/数据报管道」，之上统一套 `resume/2` 帧 + A/B 握手。
- **旧协议彻底移除**：v1 时代的所有数据面（Padding 帧、grpc 二次分帧、代理心跳 proxyStream/pinger 等）已全部删除（见 `resume-handshake-protocol.md` §4.9）。任何不带 `X-Tunnel-Proto: resume/2` 的隧道请求 → 服务端返回 426，无降级目标。
- **传输层扩展性**：未来新增底层协议（如 QUIC-Raw、SCTP）只需新增一个 L1 adapter，**不触碰** L2 会话层与 L3 连接管理层。

### 5.1 拨号间隔（DialInterval）

**含义**：对**同一连接**的两次拨号之间的最小间隔。作用是**资源节流**：避免主/备断线后风暴式重拨、以及备用补位在短时间内重复触发。

- **主连接拨号间隔** `primary_dial_interval_sec`：主连接断后重拨的最小间隔。默认按类型区分——CDN 场景（h2/h3/grpc/masque）建议 `30s`，直连场景可 `0`（立即）。
- **备用连接拨号间隔** `backup_dial_interval_sec`：备用补位的最小间隔。默认 `15s`（备用心跳周期同量级）。
- 各自独立配置 → 「保留主备各自的拨号间隔配置」即此意。
- 实现：`ConnectionManager` 内 `lastDial[role+proto]` + 节流；未到间隔时挂定时器，到期再拨。

### 5.2 建立间隔（EstablishInterval）

**含义**：主连接与备用连接**建立（拨号）动作之间的错相间隔**，默认 **100 秒**。

- **目的**：让主备两条连接的「年龄」错开（错相），避免 CDN 因连接年龄相近而在同一时刻杀掉主备两条——这正是 `standbyRoundTripper` 里 `maxAge/2` 错相轮换想解决、但写死 200s 的问题。
- **用法**：先拨主连接；等待 `establish_interval_sec`（默认 100s）后再拨备用连接。之后每次补位也遵循这个错相，使池内连接的年龄始终不同相。
- **与拨号间隔的关系**：`EstablishInterval` 约束「主→备」之间的**启动相位**；`DialInterval` 约束「同一角色的重拨节流」。二者正交，可独立配置。

### 5.3 校验与默认值

```go
// 默认值
const (
    defaultPrimaryCount    = 1
    defaultBackupCount     = 1
    defaultEstablishSec    = 100 // 主/备建立间隔默认 100 秒
    primaryDialDefault     = 30 * time.Second // 主连接重拨节流默认
    backupDialDefault      = 15 * time.Second // 备用补位节流默认
    defaultBackupMissedAck = 3
)

func resolveConnectionPolicy(cfg *Config) ConnectionPolicy {
    p := ConnectionPolicy{
        PrimaryCount:        cfg.PrimaryCount,       // 0→1
        BackupCount:         cfg.BackupCount,        // 0→1
        PrimaryDialInterval: resolveDial(cfg.PrimaryDialIntervalSec, primaryDialDefault),
        BackupDialInterval:  resolveDial(cfg.BackupDialIntervalSec, backupDialDefault),
        EstablishInterval:   resolveDial(cfg.EstablishIntervalSec, defaultEstablishSec*time.Second), // 默认100s
        BackoffMaxMissedAcks: cfg.BackupMissedAcks,  // 0→3
        Shard: normalizeShard(cfg.Shard),            // 默认 {tcp:h2, udp:masque-udp}
    }
    if p.PrimaryCount > 1 {
        // 类型分流：校验 shard 覆盖所有业务类型，未覆盖的类型并入默认
    }
    return p
}
```

**主备数量规则（用户需求逐条对应）**：

| 配置 | 默认 | 规则 |
|------|------|------|
| `primary_count` | 1 | 主连接条数；**>1 时启用类型分流**（每条主服务一类业务） |
| `backup_count` | 1 | 备用连接条数；主阵亡时补足/升级 |
| `primary_dial_interval_sec` | 0→30s | 主连接断后重拨的最小间隔（节流，防风暴） |
| `backup_dial_interval_sec` | 0→15s | 备用补位的最小间隔（节流） |
| `establish_interval_sec` | 100 | 主/备**建立动作之间的错相间隔**；先拨主、等 100s 再拨备 |
| `backup_missed_acks` | 3 | 备用连续丢 KEEPALIVE-ACK 次数阈值 → 判失效 |
| `shard` | `{tcp:h2, udp:masque-udp}` | 类型→协议分流表（PrimaryCount>1 时生效） |

> **主备切换语义**：`primary_count=1` 时退化为「1 主 + 1 备」经典模式。`primary_count=2` 时 `tcp`/`udp` 各一条主（类型分流）；某条主阵亡 → 从备用池挑 `backupAlive` 的备用升级为主 → 再拨一条新备补足 `backup_count`。

---

## 6. 模块/文件划分（实施建议）

```
client.go                 // 入口 runClient：组装 ConnectionPolicy + TransportFactorySet
                           // 调用 ConnectionManager.Start()，然后按业务类型 Pick() 分发
connmanager.go   (新增)    // L3 ConnectionManager：主备池 + 分流 + 切换 + 补位
resumesession.go (重构)    // L2 ResumeSession：从 executeResumableTunnel 提炼
resumeframe.go            // L2 帧编解码 + 写路径互斥串行化（控制帧优先于 DATA 已落地于 writer 层，无需独立 frameMux 文件）
ring.go                   // L2 环形缓冲（保留）
handshake.go              // L2 A/B 握手 + 能力/参数协商（保留，接口化）
transport.go     (新增)    // L1 TunnelConn / TransportFactory 接口
transport_h2.go  (新增)    // L1 h2 adapter
transport_h3.go  (新增)    // L1 h3 adapter
transport_grpc.go(新增)    // L1 grpc adapter
transport_masque.go(新增)  // L1 masque-tcp / masque-udp adapter
transport_wt.go  (新增)    // L1 wt adapter
backup.go                 // 逻辑迁入 ResumeSession(role=backup) + connmanager 补位；backupLine 退役
standby.go                // 退役：其「错相轮换」职责由 ConnectionPolicy.EstablishInterval 替代
```

> **退役声明**：`standbyRoundTripper` 与 `backupLine` 两套旧热备实现，被 `ConnectionManager` + `ResumeSession(role)` 统一取代。`standby` 配置项与 `backup_line` 配置项**合并语义**到 `ConnectionPolicy`（主备数量/间隔），不再保留独立入口。

---

## 7. 时序图（建立 + 分流 + 切换补位）

### 7.1 启动建立（PrimaryCount=1, BackupCount=1, EstablishInterval=100s）

```
t=0s       Start()
           ├─ dialOne(primary, tcp) ─► h2 握手 ─► primary["tcp"] = S1 (active)
           │
t=100s     （establish_interval 到期）
           ├─ dialOne(backup, tcp) ─► h2 握手 ─► backups += S2 (backupAlive)
           │                               └─ S2 后台 KEEPALIVE 保活
           │
     就绪：primary=tcp(S1), backup=(S2)
```

### 7.2 TCP 主连接断 → 备升级 + 补位

```
t1   S1 业务读失败 → OnPrimaryLost(S1)
     ├─ 挑 backups 里 backupAlive 的 S2 → S2.UpgradeToPrimary()
     │     primary["tcp"] = S2（秒级接管，resume 续传断点）
     └─ replenish()
           ├─ 校验 backupDialInterval：t1-上次拨备 >= 15s？是
           ├─ dialOne(backup, tcp) ─► S3（new, backupAlive）
           └─ backups = [S3]
     结束：primary=tcp(S2), backup=(S3)
```

### 7.3 多主类型分流（PrimaryCount=2, BackupCount=1）

```
t=0s       dialOne(primary, tcp) ─► primary["tcp"] = h2 会话
t=100s     dialOne(primary, udp) ─► primary["udp"] = masque-udp 会话
t=200s     dialOne(backup)      ─► backups += S3
业务流：
  SSH  → Pick("tcp") → h2 主
  DNS  → Pick("udp") → masque-udp 主
t=300s   h2 主断 → 备 S3 升级为主(role=tcp) → 补一条新备
```

---

## 8. 边界与注意事项

1. **备用不承载业务**：备用 `ResumeSession` 只走 P1 控制帧（KEEPALIVE），业务侧 `Pick()` 永远只返回 primary；备用不对外暴露 `Read/Write` 业务路径。
2. **会话续传与连接切换的关系**：主连接断时，resume 的 seq+ring 保证「同 session id」新流可续传。备用升级为「主」后，若备用 session id 与主不同（当前设计备份用 `<主>+b`），需要**决策**：
   - 方案 A（推荐）：升级时**不换 session id**，备用接管后以原 session id 重建立流，天然续传断点。
   - 方案 B：备用维持独立 id，接管时业务侧新建会话。放弃断点续传。
   - 设计默认 **方案 A**：`UpgradeToPrimary` 时把备用连接重拨为原类型的原 session id（若无新断点，几乎零开销）。
3. **类型分流 ≠ 无限扩容**：PrimaryCount 建议 ≤ 业务类型数（默认 2：tcp+udp）。PrimaryCount=1 时退化为「单主+单备」经典模式，不启用分流。
4. **向后兼容**：新增配置均带默认值，不配置时行为等于当前「1 主 + 1 备 + 错相轮换」。
5. **datagram 会话**（UDP）：备用/UDP 跳过 B 层握手，仅 A 层；分流表里 udp 默认 masque-udp。
6. **旧配置废弃**：`standby` / `conn_max_age_sec` / `backup_line` 三个旧字段在本设计落地后废弃，由 `primary_count`/`backup_count`/`establish_interval_sec` 取代；迁移期保留兼容读取（映射到默认 ConnectionPolicy）。

---

## 9. 验收建议（测试清单）

> 对应可运行测试文件：`connmanager_test.go`（基于真实 echo target + 隧道服务端，`go test -run ConnManager ./...`）。**已全部实现并通过。**

| 编号 | 实现测试 | 用例 | 断言 |
|------|----------|------|------|
| T1 | `TestConnManagerEstablishInterval` | PrimaryCount=1, BackupCount=1，建立间隔 | 启动即拨主；establish_interval 错相后才拨备；备不承载业务 |
| T2 | `TestConnManagerSwitchoverReplenish` | 主断，备 alive | 备升级为主（原 id 续传）；自动补一条新备 |
| T3 | `TestConnManagerAuthFailureNoTakeover` | 主断，备未 alive / 鉴权失败 | 不接管；按 primaryDialInterval 补主；备按 backupDialInterval 补备 |
| T4 | `TestConnManagerTypeSharding` | PrimaryCount=2 | tcp/udp 各一条主，类型分流各走各的 |
| T5 | `TestConnManagerDialIntervalThrottle` | 连续断主 | 拨号间隔节流生效，不风暴重拨 |
| T6 | `TestConnManagerBackupKeepaliveFailure` | 备用连续 KEEPALIVE 丢 ACK | 判失效，移出池，触发补位 |
| T7 | `TestConnManagerEstablishInterval` | establish_interval 配置生效 | 主备建立时间差 ≈ 配置值 |
| T8 | `handshake_frame_test`（帧编解码） | resume v2 帧编解码 | DATA/END/ERROR/HANDSHAKE/HANDSHAKE-ACK/KEEPALIVE/KEEPALIVE-ACK 编解码往返 + 版本/类型校验正确（控制帧优先由 writer 互斥锁串行化保证，见 §2.3） |
| T9 | `TestConnManagerTransportResumeMatrix` | 传输×resume 矩阵 | h2/grpc/masque-tcp/wt/h3 TCP + h2-udp/masque-udp 各在 resume/2 之上全双工回显通过 |
| T10 | `TestConnManagerVersionUnsupported` / `TestConnManagerAuthFailureNoTakeover` | 异常处理 | 握手超时 / 鉴权失败 / 版本不匹配 → 优雅拒绝，备用不接管 |
| T11 | `TestConnectionPolicyDefaults` / `TestConnectionPolicyBoundary` | 边界 | primary_count=0 / backup_count=0 / 非法间隔 → 回退默认；超过业务类型数的主连接 clamp |

---

*本文档为架构设计稿；确认后按 `docs/resume-handshake-protocol.md` §6 的里程碑节奏分阶段实施（L1 → L2 重构 → L3 → 配置迁移 → 回归）。*
