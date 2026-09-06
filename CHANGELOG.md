# Changelog

本文件记录面向库使用者的显著变更。日期为发布日（UTC+8）。

## 2026-09-06

### 新增
- **WebTransport UDP**：`DialPacketContext` 现已支持 `wt` 传输（UDP 数据报经 WT 流承载，服务端按 session id 保持 UDP socket）。
- **Stats 统计接口**：`Client.Stats() *ClientStats`（拨号次数/失败、活跃数、上下行字节、续传次数）与 `Server.Stats() *ServerStats`（会话建立/续传/活跃、鉴权失败）。
- **`TunnelError`**：导出类型，`HTTPStatus()` 可取回服务端拒绝时的 HTTP 状态码；`errors.As(*TunnelError)` 可用。
- **`ClientTuning.DatagramQueueSize`**：UDP 上行队列深度可配（默认 200）。
- **`DialRequest.Kind`**：`DialKindBusiness` / `DialKindProbe` —— 探活 lane 永不触发真实拨号，`TargetDialer` 可据此跳过 probe 请求。

### 变更
- **MASQUE 路径统一由 `path` 派生**：端点为 `<path>.well-known/masque/{tcp,udp}/...`；`path=/` 即标准 `/.well-known/masque`。不再有独立的 MASQUE 前缀配置。
- **默认 `path` 由 `/tunnel` 改为 `/`**。
- **数据面日志统一为 `log/slog`**：`options.Logger` 现在覆盖全部数据面日志（此前 zap 数据面日志对嵌入方不可见）。

### 性能
- h2 上行流控窗口提升至 8MB/流、32MB/连接（此前 x/net 默认 1MB，CDN 高 RTT 链路上行被卡）。
- 会话下行帧写移出全局锁：上行不再被下行网络写互锁（上行隔离度基准 ~5 倍）。
- `readFrame` 帧头零分配（DATA 热路径每帧 1 次堆分配 → 0）。

### 修复
- `Server.Shutdown/Close` 未关闭外部传入的 QUIC PacketConn，导致 `Serve` 在 h3/wt/masque 部署下永不返回。

## 2026-09-05

### 新增
- 可嵌入 SDK（`Server`/`Client`，`NewServer`/`NewClient` 强制 `Authenticator`/`Dialer` 防止默认开放代理）。
- `ClientOptions.Dialer` / `QUICDialer`：底层 socket 自定义（接口绑定、VPN protect）。
- `Server.Listeners()`：端口 0 部署时的端口发现。
- 测试基建：真实目标矩阵（HTTP/DNS × 全协议）、每协议 TCP/UDP 吞吐基准、数据面微基准。

### 修复
- 全局日志器并发替换的数据竞争（zap core 换核方案）。
- `backupLine.ctxCancel` 无锁读写。
- Windows CI：PowerShell 拆分 `-coverprofile=...` 参数；quic-go 不支持 Windows + race（race 仅在 linux/macos）。
- h2c 劫持连接在 Shutdown 时泄漏（ConnState 跟踪并关闭）。
