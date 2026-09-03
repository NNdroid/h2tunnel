# Resume 会话恢复协议 v2 · 握手与能力协商标准（含主备切换）

> 目标：把当前「隐式、单向下发」的 resume 握手，升级为「显式、双向、可协商、可演进、含主备冗余」的握手标准。
> 支持版本协商、能力/参数交换、协商确认（ack）、控制帧优先处理、错误重试，以及主备线路的握手协同。

---

## 0. 现状诊断（为什么需要这次升级）

当前 `resume/1` 握手（`handleH2StreamResumeServer` + `buildResumeRequest`）存在以下缺陷：

| 缺陷 | 现状 | 后果 |
|---|---|---|
| **无版本协商** | `X-Tunnel-Proto: resume/1` 硬编码字符串 | 协议演进（resume/2）无从谈起；新旧不兼容只能靠双方手动改配置 |
| **无能力交换** | 服务端从 `X-Network` 头**猜**是否 datagram；从 `Content-Type` **猜**是否 grpc | 客户端真实能力（如"我支持压缩/备用线路/超时参数"）无法告知，无法动态自适应 |
| **无参数协商** | `session_window_kb`、超时等是**双端各自配置** | 双端参数不一致时静默错配（如窗口一大一小），无法在握手中对齐 |
| **无确认(ack)** | `X-Resume-Uplink` 是单向的下行坐标信息，**不是**协商确认 | 服务端是否接受客户端的能力集，客户端无从得知；"协商成功"无协议级信号 |
| **错误粒度粗** | 依赖 HTTP 状态码（403/502） | 无法区分"版本不兼容 / 能力不支持 / 参数非法 / 备用线路不可用"等 |
| **无备用线路握手** | 主/备切换是纯客户端本地行为 | 备用线路的存活、能力、参数在协议层完全不可见，切换是"盲切" |
| **v1 旧路径冗余** | `resume/1` + Padding 帧路径 + grpcReader + copyWithHeartbeat 并存 | 双实现维护成本翻倍；旧路径无握手/无 ack/无主备，是功能盲区 |

**本版设计决策（用户拍板）**：
1. **v2 唯一、默认使用、彻底移除 v1**：`resume/2` 是唯一数据面。旧 `resume/1`、Padding 帧路径、`grpcReader/Writer`、`copyWithHeartbeat`、`proxyStream` 等全部删除，不留逃生通道。WT 传输也统一迁移到 v2 数据面。
2. **主备切换本期实现**：完整热备/冷备 + KEEPALIVE 存活确认 + 仅接管已确认存活的备用。主备不是二期，是本期核心。
3. **控制帧优先于数据帧**：握手/心跳/错误控制帧在发送队列中**始终优先于业务数据帧**，防止数据面拥塞阻塞握手与故障信号。

**格式原则**：字段**可扩展 + 向前兼容**——未知的能力名、参数名**必须忽略并继续工作**，绝不因一方新增字段而拒绝另一方。但**版本**是硬约束：版本无交集即失败（v1 已移除，无降级目标）。

---

## 1. 握手消息的字段设计与格式定义

### 1.1 传输载体

握手信息**全部放在 HTTP 头**（请求头 + 响应头），**不在数据面帧里**。
理由：
- 握手是一次性的、在流建立瞬间完成；HTTP 头天然适合"请求-响应"式一次交换。
- 数据面帧（resumeframe.go）是**持续流动**的字节流，塞入握手会让帧解析复杂化，且无法覆盖"流重建后重新协商"的场景（每建一条流都要重协商能力，浪费）。
- 中间件/CDN 可见 HTTP 头（对调试、灰度、审计友好）。

> ⚠️ 例外：**ack 确认**与**主备握手心跳**属于"需要实时往返且必须端到端"的信号，
> 用**握手控制帧**（数据面哨兵帧）承载，见 1.4 与第 3 节。

### 1.2 请求头（客户端 → 服务端）

| 头字段 | 语义 | 示例 | 必填 | 兼容规则 |
|---|---|---|---|---|
| `X-Tunnel-Proto` | 协议名+大版本 | `resume/2` | ✅ | 仍为最高优先路由键 |
| `X-Resume-Version` | 客户端**支持的最低协议版本** | `2` | ✅ | 服务端据此决定响应版本 |
| `X-Resume-Caps` | 能力列表（逗号分隔） | `datagram,compress,zstd,backup-line` | 可选 | 未知能力服务端忽略 |
| `X-Resume-Params` | 参数 k=v（`;` 分隔） | `window_kb=512;idle=90;attempts=16` | 可选 | 未知参数忽略；已知但非法 → 回退默认并记日志 |
| `X-Resume-Ack` | 对**上一条流**服务端能力集的确认回执 | `proto=2;caps=datagram,compress;params=...` | 可选（重建时） | 见 1.4 |
| `X-Session-ID` | 会话 id | （已有） | ✅ | 不变 |
| `X-Resume-Downlink` | 客户端已收下行字节 | （已有） | ✅ | 不变 |
| `X-Network` | `tcp` / `udp` | 已有 | ✅ | 不变 |
| `X-Target` / masque path | 目标地址 | 已有 | ✅ | 不变 |

### 1.3 响应头（服务端 → 客户端）

| 头字段 | 语义 | 示例 | 必填 | 兼容规则 |
|---|---|---|---|---|
| `X-Resume-Version` | **协商后的协议版本**（min(双方)） | `2` | ✅ | 必回；是"版本协商成功"的显式信号 |
| `X-Resume-Caps` | 服务端**已接受**的能力集（交集） | `datagram,compress` | ✅ | 客户端只应使用交集内的能力 |
| `X-Resume-Params` | 服务端**最终生效**的参数（对齐后） | `window_kb=256;idle=90` | ✅ | 客户端必须以响应值为准 |
| `X-Resume-Ack` | 服务端确认客户端能力集 | `ok` 或 `error:<code>` | ✅ | 见 1.4 |
| `X-Resume-Uplink` | 服务端已收上行字节（坐标） | 已有 | ✅ | 不变，属于数据面坐标而非协商 |
| `X-Resume-Error` | 协商失败错误码 | `version-unsupported` | 仅失败时 | 见 1.5 |

### 1.4 确认机制（ack）—— 双层确认

协商确认分**两层**，分别解决"能力对齐"与"端点活性"：

**A 层：HTTP 头内确认（协商结果确认）**
- 服务端在响应头回 `X-Resume-Caps`（交集）+ `X-Resume-Ack: ok`，表示"我收到了你的能力，并按交集生效"。
- 客户端**必须先读到** `X-Resume-Ack: ok` 且版本、参数都符合预期，**才允许**开始上行数据写入。
- 若服务端能力交集为空（无任何共同能力）→ `X-Resume-Ack: error:<code>` + 对应 HTTP 状态码（见 1.5）。

**B 层：数据面握手控制帧（端点活性 + 流级确认）**
- 流建立后、传业务数据前，客户端先发一个**握手控制帧**（新帧类型 `HANDSHAKE`），携带客户端对响应能力集的回执哈希；服务端收帧后回一个 `HANDSHAKE-ACK` 控制帧。
- 目的：① 证明"这条流真正端到端活着"（HTTP 200 可能只是中间层缓存/假响应）；② 让双方知道"可以开始正式数据"。
- **超时**：若 `handshakeAckTimeout`（默认 3s，可参数化）内未收到对端 HANDSHAKE-ACK，判定握手失败，走重试逻辑（1.6）。

> 双层原因：A 层快（头级，建流即得），但不可靠（可能被反代改写）；B 层稳（端到端），但多一次往返。
> 生产环境两者都要；测试可分别测。

### 1.5 错误与重试处理

协商失败错误码（响应头 `X-Resume-Error` + 对应 HTTP 状态）：

| 错误码 | HTTP | 含义 | 客户端行为 |
|---|---|---|---|
| `version-unsupported` | 426 | 双方协议版本无交集 | 终止（v1 已移除，**无降级目标**，直接失败并提示升级） |
| `no-common-capability` | 406 | 能力交集为空 | 终止或降级到最小能力集（见 2.6） |
| `invalid-params` | 400 | 客户端参数非法 | 用服务端回传的默认参数重试一次 |
| `auth-failed` | 401/403 | 鉴权失败 | 终止 |
| `target-unavailable` | 502/503 | 目标不可达 | 指数退避重试 |
| `handshake-timeout` | 504 | B 层 HANDSHAKE-ACK 超时 | 重试建流 |
| `backup-unavailable` | 200+`X-Resume-Ack:error` | 备用线路不可用 | 仅主用，见第 3 节 |

重试策略（统一到 `resumeMaxAttempts=16` + 指数退避 `200ms→5s`，沿用现有 backoff）：
- `version-unsupported` / `no-common-capability` / `auth-failed` → **不可重试**（确定性失败），立即终止。
- 其余 → 重试；每次重试用**服务端最新回传的版本/能力/参数**（自适应收敛）。

### 1.6 握手时序图

```
Client                                  Server
  │  POST /tunnel  (X-Tunnel-Proto:resume/2,           │
  │   X-Resume-Version:2, X-Resume-Caps:datagram,      │
  │   compress,backup-line, X-Resume-Params:window_kb=512)  │
  │ ─────────────────────────────────────────────────→  │
  │                                    校验版本∩能力∩参数   │
  │  ←──────────────────────────────────────────────────  │
  │  200 X-Resume-Version:2, X-Resume-Caps:datagram,     │
  │   compress, X-Resume-Params:window_kb=256;idle=90,   │
  │   X-Resume-Ack:ok, X-Resume-Uplink:0                 │
  │      │（客户端校验 ack=ok 且参数合法才继续）            │
  │  ── HANDSHAKE 控制帧（回执哈希）──────────────────→   │
  │  ←─ HANDSHAKE-ACK 控制帧（确认端到端活性）──────────  │
  │      │ （收到 ACK 前不写业务数据）                     │
  │  ═══ 业务数据（resume 帧）开始 ═══                     │
```

---

## 2. 可扩展、向前兼容的标准信息交换格式

### 2.1 设计约束
- **未知即忽略（软项）**：解析端对不认识的能力名/参数名，**跳过不报错**；但**版本号是硬约束**（见 2.4），未知版本直接报 `version-unsupported`。
- **协商规则**：协议版本取 `min(双端)`（v2 唯一，非 2 即失败）；能力取交集（空则降级最小集，见 2.6）；参数按"服务端为准 + 非法回退默认"。
- **有序性**：能力列表、参数列表**不依赖顺序**（解析为集合/映射）。
- **字符安全**：能力名/参数名只用 `[a-z0-9-]`，值用 `[a-zA-Z0-9._-]`，避免与分隔符冲突。

### 2.2 能力列表格式（`X-Resume-Caps`）
```
datagram,compress,zstd,backup-line,stream-replay,...
```
- 纯名称列表，逗号分隔。扩展能力只需追加名称。
- 服务端回传的 = 客户端请求 ∩ 服务端支持（**交集**），客户端只启用交集。

### 2.3 参数格式（`X-Resume-Params`）
```
window_kb=256;idle=90;attempts=16;handshake_ack_timeout=3000
```
- `;` 分隔的 `k=v` 键值对。值统一用十进制整数（毫秒/字节/KB 等量纲由键名语义约定）。
- 服务端回传**最终生效值**（已 clamp 到合法区间），客户端一律以响应值为准 → **双端参数必然对齐**。

### 2.4 版本协商规则
```
negotiated = min( clientMaxSupported, serverMaxSupported )
```
- 版本用**单整数**（当前唯一版本 `2`）。
- 客户端 `X-Resume-Version` 发"客户端支持的最高版本"，服务端回"协商版本"（min 两端）。
- 因为 **v1 已移除、v2 是唯一版本**：只要一方不是 v2，`min()` 结果 ≠ 2 → 按 1.5 报 `version-unsupported` 并**终止**（无降级目标）。版本是**硬约束**，不参与"未知即忽略"。

### 2.5 版本策略：v2 唯一，v1 彻底移除
- **服务端**：只接受 `X-Tunnel-Proto: resume/2`。收到 `resume/1` 或无版本头 → 直接 426 `version-unsupported`。旧 `handleH2StreamServer`、`executeHTTPTunnel`、`handleH2TCPClientConn`、`proxyStream`、`PaddingReader/Writer`、`grpcReader/Writer`、`copyWithHeartbeat` 全部删除。
- **客户端**：只发 `resume/2`。不再提供 `resume:false` 逃生通道。
- **WT 迁移**：WT 传输此前无法用 resume 数据面，现统一迁移到 v2 会话模型（见 §4.8），消除双实现。

### 2.6 最小能力集降级（`no-common-capability` 的缓解）
- 当能力交集为空时，双方重试时使用**最小基准能力集** `{replay}`（仅字节流 + seq 重放，无 datagram/backup 等增强）。
- 目的：能力是增强项，空交集不应直接杀死会话；回退到最小可用集再协商一次。若仍无交集才终止。

> 版本是**硬约束**（无交集即失败），能力/参数是**软约束**（无交集降级到最小集 / 参数回退默认）。这是本设计对"向前兼容"的精确边界。

### 2.7 控制帧优先于数据帧（调度策略）

**动机**：握手 ack、主备心跳、错误通知是**时延敏感**信号。若控制帧与业务数据帧在同一个发送 goroutine 里 FIFO 排队，数据面拥塞（如窗口满、TCP 慢启动）会让控制帧被堵住 → 握手超时、心跳误判、故障无法及时上报。

**实现（writer 互斥锁串行化，无独立调度器）**
- 控制帧与 DATA 帧共用同一条 HTTP 流，写路径由各自 writer 的互斥锁串行化，保证「控制帧不拆裂、不饿死」：
  - **服务端下行**：`downlinkPump` 经 `writeDownlink`→`resumeSessionWriter.writeFrame` 写 DATA；握手 ACK / KEEPALIVE-ACK 经 `writeControl` 写控制帧。两者都锁 `resumeSessionWriter.mu`，`downlinkPump` 每写出一帧即释放锁，控制帧在帧间隙插入。
  - **客户端上行**：单条流仅一个 `resumeSendLoop` goroutine 写 `pw`（DATA + END），HANDSHAKE 在建流前单写一次，天然无并发写竞争。
  - **备用线路**：`backupLine.keepaliveLoop` 独占一条流写 KEEPALIVE、读 KEEPALIVE-ACK。
- 每个帧的写出在持锁区间内原子完成（整帧 header+body+flush），控制帧永不会被 DATA 帧拆裂；又因 `downlinkPump` 逐帧释放锁，控制帧也不会被一长串 DATA 饿死（最差等待一个 DATA 帧的写出+flush，远小于 KEEPALIVE 15s 预算）。

**帧类型分级**：
| 优先级 | 帧类型 | 说明 |
|---|---|---|
| P0（最高） | `ERROR` / `END` | 必须立即送达，否则对端卡死 |
| P1 | `HANDSHAKE` / `HANDSHAKE-ACK` / `KEEPALIVE` / `KEEPALIVE-ACK` | 握手/心跳，有超时预算 |
| P2（最低） | `DATA` | 业务数据，可被前两级让行 |

> 控制帧与数据帧**共用同一条 HTTP 流**（仍是顺序字节流），优先级由**写路径互斥锁串行化**保证（控制帧在 DATA 帧之间插入，不依赖 HTTP/2 的 stream priority，跨 h2/h3/grpc/masque/wt 统一生效）。`handshake_frame.go` 曾实现 `frameMux` 双队列调度器，但从未接入生产写路径，已作为死代码移除。

---

## 3. 主线路与备用线路在握手中的处理策略

### 3.1 概念区分（本期完整实现，非二期）
- **主线路**：本次 resume 隧道的主数据通道。
- **备用线路**：冗余/备份通道，本期实现两种角色：
  - **热备（hot standby）**：已建立握手、已拨 targetConn、处于待命，主线路断时**秒级**接管。
  - **冷备（cold standby）**：仅保存会话元数据，主线路断时才实际建流握手，接管较慢但零常驻开销。
- 主/备由配置 `BackupLine` 决定：`none`=单线路；`hot`=热备；`cold`=冷备。默认 `none`，用户按需开启。

### 3.2 握手流程（主/备）
- **主线路**：完整执行第 1 节握手（版本/能力/参数 + ack）。主握手成功 = `X-Resume-Ack:ok` + `HANDSHAKE-ACK` 收到。
- **备用线路**：
  - 客户端声明 `backup-line` 能力且服务端接受 → 客户端建立备用握手。
  - 备用握手**也走同一套握手协议**（版本/能力/参数/ack + 控制帧），但：
    - 用**独立 session id**（`<主id>+b`）避免与服务端会话表冲突；
    - 备用**不传输业务数据**，只发周期性**存活控制帧**（`KEEPALIVE`，复用帧结构带 `role=backup`）；
    - 服务端对备用线路**不启动 downlinkPump 的业务数据双写**，只维持 targetConn（热备）或仅登记元数据（冷备）。

### 3.3 备用必须纳入握手确认 —— 本期实现决策（已确认）
**结论：备用线路必须纳入握手确认，但采用"独立的备用握手 + KEEPALIVE 存活确认"，而非复用主线路握手。** 理由：

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| A. 主备共用同一条握手 | 简单 | 主备目标不同时无法区分；备用故障会污染主握手 | ✗ 否决 |
| B. 备用完全独立握手 + 周期存活确认 | 主备隔离；备用真实可用性可验证 | 多一次握手往返 + 心跳开销 | ✅ **本期实现（热备）** |
| C. 备用只在切换时握手（冷备） | 零常驻开销 | 接管慢；切换时才暴露备用不可用 | ✅ 本期实现（冷备） |

**本期实现范围**：
- 主线路：完整双向握手 + ack（第 1 节）。
- 备用线路：**独立握手** + 周期性 `KEEPALIVE` 控制帧续期（默认 15s，可参数化 `keepalive_interval`）；连续 N 次（默认 3）`KEEPALIVE-ACK` 超时 → 判定备用失效 → 重建备用或**降级为仅主用**。
- 控制帧优先：主备的 `KEEPALIVE`/`KEEPALIVE-ACK` 由 writer 互斥锁串行化保证插队于 DATA 之前（见 2.7），在拥塞下也**必达**，保证存活判定可靠。
- 切换：主线路握手/数据失败 → 客户端**先本地切到已确认存活的备用**（热备秒切），同时后台尝试恢复主线路；冷备则先握手再切。
- **关键点（铁律）**：只有**经过握手确认存活的备用**才允许被接管；未经确认的备用**禁止自动接管**（避免"盲切到死线"）。

### 3.4 主备握手时序
```
主:  POST resume/2 (sid=abc)  → 200 ack=ok → HANDSHAKE→ACK → 业务数据(优先级P2)
备:  POST resume/2 (sid=abc+b, caps=..., role=backup)
       → 200 ack=ok → HANDSHAKE(role=backup)→ACK → KEEPALIVE(15s,P1)↔ACK
主断 → 客户端切到 sid=abc+b 的备用（已确认存活）→ 秒级接管
```

---

## 4. 现有代码修改点清单及改造步骤

> 所有改动**留在 working tree 不提交**（尊重铁律），每步跑 `go build` + 相关 `go test` + 跨编。

### 4.1 新增文件
| 文件 | 内容 |
|---|---|
| `handshake.go` | 握手编解码：版本协商 `negotiateVersion`、能力交集 `intersectCaps`、参数对齐 `alignParams`、错误码表、`X-Resume-Caps/Params` 编解码 |
| ~~`handshake_frame.go`~~ | （已移除）数据面控制帧本就在 `resumeframe.go` 的 `writeFrame` 中实现；曾含 `frameMux` 双队列调度器，因从未接入生产写路径，已作为死代码删除，控制帧优先改由 `resumeSessionWriter.mu` 串行化保证（见 §2.7）。 |
| `backup.go` | 主备管理：客户端备用线路执行器（热备 `hotBackupRunner`/冷备 `coldBackup`）、接管逻辑 `takeoverIfConfirmed`、KEEPALIVE 心跳泵 |
| `handshake_test.go` | **完整的握手协议测试**（见 §5） |

### 4.2 `resumeframe.go`（帧头扩展，v1 移除后无需兼容旧格式）
- 帧头从 `[4B dataLen][2B padLen][8B seq]`（14B）扩展为 **`[1B type][1B ver][4B dataLen][2B padLen][8B seq]`（16B）**。
- 帧类型：`0x01=DATA`、`0x02=END`、`0x03=ERROR`、`0x10=HANDSHAKE`、`0x11=HANDSHAKE-ACK`、`0x12=KEEPALIVE`、`0x13=KEEPALIVE-ACK`。`ver` 恒为 `0x02`。
- `resumeFrameTypeResume` 改为 `"resume/2"`。
- 旧 `writeResumeFrame`/`readResumeFrame` 改造为统一 `writeFrame(type, ver, seq, data)`/`readFrame()`，所有读写走新头。
- **数据帧写入经 `resumeSessionWriter.writeFrame`**（内部持 `resumeSessionWriter.mu` 串行化，控制帧优先于 DATA 插入），不再直接裸写。

### 4.3 `server.go` — `handleH2StreamResumeServer`
1. **握手处理（写在 `prepareResumeSession` 前）**：
   - 校验 `X-Tunnel-Proto == "resume/2"`；否则 426。
   - 解析 `X-Resume-Version`/`X-Resume-Caps`/`X-Resume-Params`；`role` 头（主/备）。
   - 版本协商（v2 唯一）+ 能力交集 + 参数对齐。
   - 写响应头 `X-Resume-Version/Caps/Params/Ack`；交集空/参数非法 → 按 §1.5 回错误码。
2. **B 层确认**：业务数据循环前，等待并校验客户端 `HANDSHAKE` 控制帧，回 `HANDSHAKE-ACK`（经 `writeControl`，在 `resumeSessionWriter.mu` 保护下于 DATA 帧间隙插入）。
3. **`role=backup`**：跳过业务 downlinkPump 双写，改为周期 `KEEPALIVE` 应答（P1）。
4. 上行/下行读写统一经 `resumeSessionWriter` 串行化调度（控制帧优先，见 §2.7）。
5. **删除**旧 `handleH2StreamServer`、`proxyStream`、`copyWithHeartbeat` 中与 resume 无关的旧路径（见 §4.9）。

### 4.4 `client_resume.go` / `client_resume_udp.go`
- `buildResumeRequest`/`buildResumeUDPRequest`：`X-Tunnel-Proto: resume/2` + `X-Resume-Version/Caps/Params` + `role`（备用时）。
- `runResumeAttempt`/`runOneStream`：读响应 `X-Resume-Ack`；非 `ok` → 按错误码处理；`ok` 后写 `HANDSHAKE`（P1），等 `HANDSHAKE-ACK`（超时 `handshake_ack_timeout`）；**ack 前零业务字节上发**。
- 以服务端回传参数为准，更新本地 ring 窗口等。
- 上行/下行读写经 `resumeSessionWriter`/`pw` 串行化（控制帧优先，见 §2.7）。

### 4.5 `main.go`
- `Config` 增加：`ProtocolVersion`（默认 2，恒 2）、`Capabilities []string`、`ResumeParams map[string]int`（`handshake_ack_timeout`/`keepalive_interval`）、`BackupLine string`（`none`/`hot`/`cold`）。
- 移除 `resumeSet`/`Resume bool` 的"逃生通道"语义 → **整个 `Resume bool` 配置字段已删除**，`ResumeEnabled` 内部字段亦已彻底删除（其已无任何读取点，属死字段），`resume:false` 分支（含 UDP 裸转发）全部删除，resume/2 恒启用、无降级目标、无任何开关痕迹。
- `buildServerConfig/buildClientConfig` 透传新字段。

### 4.6 `session.go` 控制帧优先（writer 互斥锁串行化）
- `resumeSessionWriter` 持 `mu`：所有写路径（`writeFrame` / `writeControl` / `writeEnd` / `writeRaw`）都先锁 `mu` 再写整帧并 flush，保证帧原子性（控制帧永不被 DATA 拆裂）。
- 服务端下行：`downlinkPump` 经 `writeDownlink`→`writeFrame` 写 DATA，每帧释放 `mu`；握手 ACK / KEEPALIVE-ACK 经 `writeControl` 在帧间隙插入 → 控制帧天然优先且不饿死（详见 §2.7）。
- `replayDownlink` 重放期间整体持 `tunnelSession.mu` 并临时置空 `onClose`，避免与 `downlinkPump` 的实时下行写并发交错（否则帧交叠 + seq 乱序 → 客户端 `ErrGap` 断流）。
- backup 会话不启动业务 downlinkPump，改走 `backupLine.keepaliveLoop`。

> 原设计的独立 `frameMux` 双队列调度器（§4.6 旧版）已移除：其「先 drain 控制队再写数据队」的语义已由「`resumeSessionWriter.mu` 逐帧串行化 + 控制帧在帧间隙插入」等价实现，且无额外 goroutine/队列复杂度。

### 4.7 `sharecrypto.go` / `pool.go`
- 若帧头扩展影响缓冲池尺寸计算，同步调整 `paddingWritePool`/`tcpBufPool` 的预算常量。

### 4.8 `client.go` — WT 迁移到 v2 会话模型 ✅ 已完成
- WT 已从独立 `WTSessionManager` 业务模型收编进 `resume/2` 引擎：每隧道独立 `WTSessionManager`（headers 携带 A 层协商头 + `Protocol: webtransport`），服务端 `handleWebTransportServer` 把每条业务 stream 派发到 v2 会话表（`prepareResumeSession`）。
- 因 WT stream 无 per-stream HTTP 头，`clientDownlink` 改为在 B 层 `HANDSHAKE` 帧 payload（十进制字符串）携带，服务端据此重放下行缺口。
- 服务端 `resumeSessionWriter.w` 从 `http.ResponseWriter` 放宽为 `io.Writer`（`flusher` 可选），使 `webtransport.Stream` 可直接作为下行目标；h2/grpc/masque 调用点无需改动。
- 断线续传由 `TestWTResumeReconnect` 验证（stream1 读部分下行后关闭，stream2 同 session id 从 clientDownlink 续传，整体无缺口无重复）。
- 注：`activeWriter` 挂载必须等 B 层握手（HANDSHAKE-ACK 写出）后再进行，否则 downlinkPump 可能在握手前把 DATA 帧写进新流、客户端首帧读到 DATA 而握手失败（h2/wt 通用）。

### 4.9 删除清单（v1 彻底移除）— ✅ 已在 M5 全部落地
| 删除对象 | 位置 | 状态 |
|---|---|---|
| `resumeFrameTypeResume` 旧值 `resume/1` | resumeframe.go | ✅ 已改 `resume/2` |
| `handleH2StreamServer`（非 resume 旧 handler） | server.go | ✅ 已删除 |
| `executeHTTPTunnel`（非 resume 客户端） | client.go | ✅ 已删除 |
| `handleH2TCPClientConn` / `handleMasqueTCPClientConn` | client.go | ✅ 已删除，统一走 `executeResumableTunnel` |
| `proxyStream` / `copyWithHeartbeat` | protocol.go | ✅ 已删除 |
| `PaddingReader` / `PaddingWriter` / `pinger` | protocol.go | ✅ 已删除（WT 改用 `writeFrame/readFrame`） |
| `grpcReader` / `grpcWriter` | protocol.go | ✅ 已删除，grpc 仅打 Content-Type |
| `calculatePadding` | protocol.go | ✅ 已删除（仅 PaddingWriter 使用） |
| `resume:false` 分支 | main.go | ✅ 已删除，resume 恒 true |
| 依赖旧路径的测试（`TestPaddingPingFrameRoundTrip` 等） | heartbeat_test.go | ✅ 已改写/删除 |
| WT 的 v1 Padding 路径 | client.go / server.go | ✅ 已迁移至 v2 帧数据面 |

### 4.10 测试（见下 §5 `handshake_test.go`）

---

## 5. test.go 完整规划（`handshake_test.go`）

覆盖 5 个维度：单元（编解码/协商/参数）+ 帧头（v2 新头）+ 时序（握手）+ 控制帧优先 + 主备 + 版本拒绝。骨架如下：

```go
package main

// ================= 一、编解码单元测试 =================

// TestFrameV2RoundTrip 新 16B 帧头 (type/ver/dataLen/padLen/seq) 编解码往返
// TestFrameV2Types 各帧类型 (DATA/END/ERROR/HANDSHAKE/HANDSHAKE-ACK/KEEPALIVE/KEEPALIVE-ACK) 编解码
// TestHandshakeCapsParse 能力列表解析：正常、空、未知项（应忽略）
// TestHandshakeCapsIntersect 能力交集：全交/部分交/无交（应报 no-common-capability）
// TestHandshakeParamsParse 参数解析：k=v 列表、非法值回退默认、未知键忽略
// TestHandshakeParamsAlign 参数对齐：越界 clamp、服务端为准
// TestHandshakeVersionNegotiate v2 唯一：min()==2 通过；非 2 → version-unsupported

// ================= 二、控制帧优先级测试 =================
// 注：`frameMux` 双队列调度器及其单测（TestPrioQueue*）已随死代码移除；
// 控制帧优先现由 `resumeSessionWriter.mu` 串行化保证（见 §2.7），已有
// `handshake_frame_test.go` 的 v2 帧编解码单测覆盖控制帧类型编解码。
// 如需回归「控制帧在拥塞下必达」，可在 `connmanager_test.go` 的备份存活用例上
// 叠加大流量 DATA 验证 KEEPALIVE-ACK 时延。

// ================= 三、握手时序测试 =================

// TestHandshakeAckRequired 无 ack=ok 时客户端禁止写业务数据（零字节上发门禁）
// TestHandshakeVersionUnsupported 版本非 v2 → 426+version-unsupported，客户端终止
// TestHandshakeNoCommonCapability 能力交集空→406，客户端降级最小集重试
// TestHandshakeInvalidParams 参数非法→服务端回默认值，客户端用默认重试一次
// TestHandshakeAckTimeout B层 HANDSHAKE-ACK 超时→重试建流
// TestHandshakeFullRoundTrip 主线路完整握手：头 ack + HANDSHAKE→ACK → 业务数据

// ================= 四、主备线路测试 =================

// TestBackupLineIndependentHandshake 备用独立 session id+握手，不与主冲突
// TestBackupKeepaliveLiveness 备用 KEEPALIVE 续期；连续超时→判定失效
// TestBackupTakeoverOnlyIfConfirmed 未确认存活的备用禁止接管；已确认可秒切
// TestBackupHotStandby 热备：主断→秒切到已确认备用
// TestBackupColdStandby 冷备：切换时才握手，接管较慢但成功

// ================= 五、版本硬约束/移除 v1 测试 =================

// TestV1Rejected 旧客户端发 resume/1 → 服务端 426 version-unsupported（无降级）
// TestNoVersionHeaderRejected 无 X-Tunnel-Proto 头 → 426
// TestV1DataPathRemoved 旧 Padding/grpcReader/proxyStream 符号已不存在（编译期验证）
// TestUnknownCapabilityIgnored 未知能力被忽略，会话仍工作（向前兼容）
```

**关键断言**：
- 协商后双端版本/参数**严格相等**（对齐正确性）。
- 客户端在 ack 到达前**零业务字节上发**（确认门禁生效）。
- 控制帧优先：构造"控制帧压数据帧"场景，断言控制帧先被写出。
- 备用接管**仅在 keepalive 存活**时成功，否则断言拒绝接管。
- **v1 被硬拒绝**（426），且旧数据路径符号已在编译期被移除（用 `//go:build` 或直接断言符号不存在）。

---

## 6. 实施里程碑

| 阶段 | 内容 | 验证 | 状态 |
|---|---|---|---|
| M1 | 帧头扩展为 v2 新 16B 头 + 编解码单测（`handshake_frame_test.go`） | 单元测试绿 | ✅ 完成（控制帧优先改由 `resumeSessionWriter.mu` 串行化，原 `frameMux` 调度器已移除） |
| M2 | 服务端握手（版本/能力/参数/ack）+ B 层控制帧 + `role=backup` 分支 | e2e 握手成功 | ✅ 完成 |
| M3 | 客户端握手（发起+校验 ack+等 HANDSHAKE-ACK）+ 控制帧优先上/下行 | 主线路 e2e 全绿 | ✅ 完成 |
| M4 | 主备线路（热备/冷备 + KEEPALIVE + 接管） | 主备 e2e 绿 | ✅ 完成 |
| M5 | **删除 v1 旧路径** + WT 迁移 + 全量回归 + gofmt/vet/跨编 | 全量绿 + v1 符号不在 | ✅ 完成 |

### M5 实际落地（v1 彻底移除）

已删除的 v1 符号（编译期验证不再存在）：

- 服务端：`handleH2StreamServer`（旧 H2 handler）、MASQUE-TCP/UDP 的 `proxyStream` 兜底分支。
- 客户端：`executeHTTPTunnel`、`handleH2TCPClientConn`、`handleMasqueTCPClientConn`（TCP 统一走 `executeResumableTunnel`）。
- `protocol.go`：`proxyStream`、`PaddingReader`、`PaddingWriter`、`grpcReader`、`grpcWriter`、`copyWithHeartbeat`、`pinger`、`calculatePadding`。

迁移与变更：

- **WT 数据面**统一为 resume/2 帧协议：客户端 `handleWTTCPClientConn` 与服务端 `proxyWTStreamV2` 用 `writeFrame/readFrame`（TCP）承载 DATA/END 帧；UDP 走 `writeUDPPacket/readUDPPacket` 数据报分帧。
- **客户端 TCP 分派**改为 resume-only：`runTCPClient` 去掉 `UseMasque`/非 resume 旧分支，直接 `executeResumableTunnel`（h2/h3/grpc/masque-tcp）。
- **服务端分派**：POST/MASQUE-TCP/MASQUE-UDP 均要求 `X-Tunnel-Proto: resume/2`，否则 426 `resume/2 required`（无 v1 兜底）。
- **UDP 流客户端**：非 WT UDP 全走 `connectResumeUDP`（v2），v1 的 `grpcWriter/grpcReader` POST 兜底分支删除。
- **测试迁移**：`features_test.go`、`heartbeat_test.go` 全部客户端/服务端补 `ResumeEnabled: true`；删除已过时的 `TestPaddingPingFrameRoundTrip`/`TestPaddingReaderAcceptsConsecutivePings`（v1 Padding 单测）。*（后注：随 `ResumeEnabled` 字段彻底删除，测试中这批 `ResumeEnabled: true` 冗余赋值也已统一清除。）*
- **端口冲突修复**：backup 测试 echo/server 端口基址从 `22000` 段迁到 `27000` 段，避免与 `TestH2Tunnel_StrictDemux`（`22001`/`22002`/`22003`）冲突——后台 `go startXxx` 协程不退出导致端口被长期占用。

回归验证：`go build`、`go vet`、`gofmt`、`go test ./...`（40 个测试全绿）、跨编 linux/amd64 + linux/arm64 + darwin/arm64 全部通过。

> 每阶段改动留在 working tree；全部完成后再统一向用户汇报，由用户决定是否提交。
