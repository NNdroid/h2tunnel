# WT 接入 resume/2：设计笔记

> 目标：让 WebTransport（wt）从"独立 WTSessionManager 会话模型"收编进 resume v2
> 引擎，实现与 h2/grpc/masque 同级的**断线数据续传**（ring buffer + seq 重放 +
> A/B 握手 + 服务端目标连接保留），而非仅止步于会话层 failover。

## 背景与差距

当前 wt 数据面（`handleWTTCPClientConn` / `proxyWTStreamV2`）：
- 对每条 TCP 连接 `OpenStreamSync` 开一条流，局部变量 `seq` 裸跑，stream 一断即
  `closeBoth()` 终止整条连接。
- 无 ring buffer / 无 seq 重放 / 无 A+B 握手 / 无会话表续接，服务端对每个新 stream
  重新 `net.DialTimeout` 新目标连接。
- 结论：wt 只做到"会话层 failover"（`WTSessionManager` 主备切换，保证下一跳用活
  session），**不恢复正在进行的业务数据**。

## 关键事实（源码已确认）

1. resume v2 帧编解码 `writeFrame(w io.Writer, ...)` / `readFrame(r io.Reader, ...)`
   **不依赖 HTTP**，纯 `io.Writer`/`io.Reader` 层（resumeframe.go）。
2. `webtransport.Stream` 是 `io.ReadWriteCloser`（有 Read/Write/Close/SetDeadline），
   天然可作为 resume 数据通道。
3. `Session.OpenStreamSync` 可在同一 WT session 上开多条流 → "stream 断后同 session
   开新流续传"可行。
4. `webtransport.Dialer.Dial(ctx, url, reqHdr)` 把 `reqHdr` 作为 HTTP CONNECT 请求头
   发送，服务端 `wtServer.Upgrade(w, r)` 的 `r.Header` 可读到 → **A 层协商头可经
   `wtManager.headers` 透传**，服务端据此完成版本/能力/参数协商与会话恢复。

## 核心改造

### 服务端（server.go / session.go）

1. **抽象 `resumeSessionWriter`**：字段 `w http.ResponseWriter` → `w io.Writer`。
   `http.ResponseWriter` 是 `io.Writer` 子集，h2/grpc/masque 现有调用点
   `&resumeSessionWriter{w: w}` 无需改动，向后兼容。`flusher` 保留为可选
   （WT stream 自带流式写，flusher 传 nil）。
2. **`handleWebTransportServer` 改造**：每个业务 stream 依据 `r.Header` 走会话表：
   - 校验 `X-Tunnel-Proto == resume/2`（非 2 → 拒绝）
   - `prepareResumeSession` → A 层协商 → B 层 HANDSHAKE 握手 → 下行补发 → 上行帧循环
   - stream 断 → 会话（targetConn）保留，等待同 session id 的新 stream 续传
   - 复用 h2 handler 的握手与帧循环逻辑（抽出公共函数 `serveResumeDataPlane`，避免双实现）
3. **`clientDownlink` 经 B 层 HANDSHAKE 帧 payload 透传**：WT stream 无法携带
   per-stream HTTP 头（区别于 h2 的 `X-Resume-Downlink` 请求头），故由客户端在
   数据面首帧 HANDSHAKE 的 payload 里带上行续传起点（十进制字符串），
   `doWTStreamHandshake` 读首帧、回 HANDSHAKE-ACK 后返回 `clientDownlink`。
4. **`activeWriter` 挂载时序**：必须等 B 层握手（HANDSHAKE-ACK 已写出）之后再
   `setActiveWriter`（由 `serveResumeDataPlane` 统一负责，h2/wt 通用）。否则
   downlinkPump 可能在 HANDSHAKE-ACK 之前把 DATA 帧写进新流，客户端首帧读到
   DATA 而非 HANDSHAKE-ACK，握手失败。

### 客户端（client.go / client_resume.go）

1. `newWTManagerForTunnel`：为单条隧道构建独立 `WTSessionManager`，headers 携带
   resume A 层协商头（`X-Tunnel-Proto`、`X-Session-ID`、`X-Resume-Version/Caps/Params`、
   `X-Target`/`X-Network`、`X-Auth`） + `Protocol: webtransport`。
2. `executeResumeWT` / `runResumeWTTry` / `resumeRecvLoopWT`：每次 attempt
   `OpenStreamSync` 拿 stream 作数据通道（stream 即 `io.ReadWriteCloser`），断后
   同 session id 重开新流续传。`resumeSendLoop` 签名从 `*io.PipeWriter` 放宽为
   `io.Writer`，使 WT stream 可直接作上行写目标。

## 验证

- 现有 h2/grpc/masque/masque-udp 传输矩阵回归全绿（抽象改造不影响）
- `TestWTResumeReconnect`：stream1 读前 25×200B 后关闭，stream2 同 session id
  从 `clientDownlink=5000` 续传 5×200B，整体序列连续、无缺口无重复
- build / vet / gofmt / 跨编（linux/amd64, linux/arm64, darwin/arm64, windows/amd64）全绿
