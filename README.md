# h2tunnel

`h2tunnel` 是一个可嵌入 Go 程序的安全隧道库，同时提供独立命令行程序。它把 TCP 或 UDP 服务封装在 HTTP/2、HTTP/3、WebTransport、MASQUE 或 gRPC 连接中，并提供断线恢复、CDN 友好请求头和有界会话缓冲。

服务端不会默认成为开放代理：包 API 强制要求调用方同时提供 `Authenticator` 和 `TargetDialer`。推荐使用逻辑服务名（例如 `ssh`、`postgres`），不让客户端直接决定任意目标地址。

## 安装

作为 Go 包使用：

```bash
go get github.com/NNdroid/h2tunnel
```

构建命令行程序：

```bash
go build -trimpath -o h2tunnel ./cmd/h2tunnel
```

## 如何选择传输协议

| 传输 | TCP | UDP | 普通 CDN | 典型用途 |
| --- | ---: | ---: | ---: | --- |
| `h2` | ✅ | ✅ | ✅ 推荐 | CDN、反向代理、通用公网访问 |
| `h2c` | ✅ | ✅ | 仅明文源站链路 | 内网、TLS 在外部网关终止 |
| `grpc` | ✅ | ✅ | ✅，需 CDN 开启 gRPC | 已有 gRPC 基础设施 |
| `h3` | ✅ | ✅ | 通常不支持回源 | 端到端 QUIC 直连 |
| `masque` | ✅ | ✅ | 通常不支持回源 | 标准 CONNECT-TCP/UDP 直连 |
| `wt` | ✅ | 包 API 暂不支持 | 通常不支持回源 | WebTransport TCP 字节流 |

普通 CDN 不会把 UDP/QUIC 原样转发到源站，因此 CDN 场景优先选择 `h2`；H3、WebTransport 和 MASQUE 应当端到端直连。

## 包 API 一览

客户端：

```go
func NewClient(ClientOptions) (*Client, error)
func (*Client) Start(context.Context) error
func (*Client) DialContext(context.Context, string, string) (net.Conn, error)
func (*Client) DialPacketContext(context.Context, string, string) (PacketConn, error)
func (*Client) Shutdown(context.Context) error
func (*Client) Close() error
```

服务端：

```go
func NewServer(ServerOptions) (*Server, error)
func (*Server) Handler() http.Handler
func (*Server) Serve(Listeners) error
func (*Server) ListenAndServe(string) error
func (*Server) Shutdown(context.Context) error
func (*Server) Close() error
```

安全辅助函数：

```go
func NewTokenCredentials(string) (CredentialProvider, error)
func NewTokenAuthenticator(string) (Authenticator, error)
func NewStaticServiceDialer(map[string]Service, *net.Dialer) (TargetDialer, error)
```

`Client` 可并发使用；每次拨号拥有独立逻辑会话。`Server` 是单生命周期对象，关闭后请创建新实例。`NewClient` 和 `NewServer` 只校验配置，不打开端口，也不启动后台任务。

## 完整包 API 示例

### 1. 建立一个关闭式服务注册表

下面的服务端只允许访问两个明确登记的目标。未知服务名、网络类型不匹配或角色不足都会被拒绝。

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
    })
    if err != nil {
        log.Fatal(err)
    }

    // TLS 在 CDN/Nginx 终止，源站监听回环地址上的 HTTP。
    origin := &http.Server{Addr: "127.0.0.1:8080", Handler: server.Handler()}
    log.Fatal(origin.ListenAndServe())
}
```

这里允许 `TransportH2` 而不是 `TransportH2C`，因为客户端到 CDN 使用 H2；CDN 到源站即使降级成 HTTP/1.1，也仍属于 H2 POST-stream 传输族。源站必须只监听可信网络或回环地址。

### 2. 创建客户端并拨号逻辑服务

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

`DialContext` 只在服务端鉴权、目标授权、目标连接和隧道握手都完成后返回。传入的 context 会一直传播到服务端 `TargetDialer`；超时或取消不会留下仍在后台拨号的目标连接。

### 3. 让 `http.Client` 统一通过隧道访问服务

```go
transport := &http.Transport{DialContext: client.DialContext}
httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}

// URL 的 host 会作为逻辑目标传给服务端注册表。
response, err := httpClient.Get("http://internal-api/health")
```

如果逻辑名称包含端口，请在注册表中使用相同字符串作为键，例如 `internal-api:80`。响应体仍由普通 `http.Client` 管理。

### 4. 复用隧道建立 SSH 客户端

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

### 5. UDP/数据报访问

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

返回的是“已连接”的 `PacketConn`：`WriteTo` 的地址参数不会改变创建时指定的逻辑目标。每个远端 UDP 对话建议单独拨一个 `PacketConn`。

### 6. 自定义鉴权与动态分流

生产系统可把 JWT、mTLS 身份或已有会话转换成稳定的 `Principal.ID`，然后在 `TargetDialer` 中执行租户、角色、网络和目标策略。

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

不要在 `TargetDialer` 中不加验证地拨 `request.Target`，否则会把隧道变成 SSRF/内网开放代理。对于 UDP，`TargetDialer` 必须返回已连接的数据报 `net.Conn`，通常是 `*net.UDPConn`。

### 7. 直接 TLS/H2 与 H3 共端口服务

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

// 自动创建同一数字端口上的 TCP 与 UDP 监听器。
return server.ListenAndServe(":8443")
```

库不会生成或持久化证书。调用 `ListenAndServe` 托管 `h2`/`h3`/`wt`/`masque` 时必须提供包含证书的 `TLSConfig`。使用 `Handler` 嵌入现有 HTTP 服务时，TLS 可以由外部服务器或反向代理负责。

### 8. 自己管理监听器

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

`Serve` 接管传入的监听器；任意一个监听栈意外失败都会关闭另一个栈并返回错误。

### 9. 优雅关闭

```go
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

if err := client.Shutdown(shutdownCtx); err != nil {
    _ = client.Close() // 超时后强制关闭
}
if err := server.Shutdown(shutdownCtx); err != nil {
    _ = server.Close()
}
```

`Shutdown` 拒绝新会话并等待现有连接自然结束；`Close` 立即关闭。嵌入外部 `http.Server` 时，先停止外部服务器接收新请求，再调用隧道服务器的 `Shutdown`。

## CDN 与反向代理部署

推荐链路：

```text
应用 -> h2tunnel Client -> HTTPS/H2 -> CDN -> HTTPS/HTTP origin -> h2tunnel Server -> 内部服务
```

隧道请求和响应会设置以下关键属性：

- `Cache-Control: no-store, no-transform`
- `Content-Type: application/octet-stream`
- `Content-Encoding: identity`
- `Accept-Encoding: identity`
- `X-Accel-Buffering: no`
- `X-Auth-Token`，并同时提供标准 Bearer Authorization

这些设置避免代理缓存、压缩或缓冲二进制流。服务端在收到非 2xx、鉴权失败或被代理替换的错误页时不会错误推进恢复游标。

### Nginx：TLS 到源站

独立 CLI 的 `h2` 模式会在源站监听 TLS。Nginx 可这样回源：

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
    # CLI 自动生成证书时仅适合受保护的本机回源链路。
    proxy_ssl_verify off;
}
```

如需明文回源，请使用前面的 `Server.Handler()` 嵌入示例，并让外部服务器只监听 `127.0.0.1` 或受保护的私网地址。不要允许 CDN 缓存 `/tunnel`，也不要启用请求/响应缓冲。

心跳间隔必须小于链路中最短的空闲超时。默认 25 秒适合常见的 60 秒代理超时；如果 CDN 最短超时不同，请显式调整。受控代理延迟、错误响应、鉴权头转发、缓存/缓冲头以及稳态吞吐均有自动测试覆盖。

## CLI 使用

### 服务端配置

```json
{
  "mode": "server",
  "listen": ":8443",
  "path": "/tunnel",
  "transport": "h2",
  "network": "tcp",
  "token": "replace-with-a-long-random-token",
  "tls": true,
  "cert": "/etc/h2tunnel/server.crt",
  "key": "/etc/h2tunnel/server.key",
  "local_only": true,
  "session_window_kb": 256,
  "drain_timeout_sec": 30,
  "log_level": "info"
}
```

`cert` 和 `key` 同时留空时，CLI 会生成进程内自签名证书；生产公网源站推荐提供正式证书。`local_only: true` 会解析目标主机并拒绝任何非回环地址，以降低 SSRF 风险。

### 客户端配置

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
  "heartbeat_sec": 25,
  "session_window_kb": 256,
  "handshake_ack_ms": 3000,
  "keepalive_sec": 15,
  "standby_connections": 1,
  "drain_timeout_sec": 30,
  "log_level": "info"
}
```

启动方式：

```bash
h2tunnel -c /etc/h2tunnel/config.server.json
h2tunnel server -c /etc/h2tunnel/config.server.json
h2tunnel client -c /etc/h2tunnel/config.client.json
h2tunnel version
```

客户端 `listen` 是提供给本地程序的 TCP/UDP 入口，`target` 是服务端最终访问的地址。CLI 是直接地址代理；需要逻辑服务注册、按身份分流或统一嵌入其他程序时，应使用包 API。

### 配置字段

配置解析是严格的：未知字段、已删除字段、错误类型和当前模式无作用的字段都会直接报错，不做旧版本兼容。

| 字段 | 模式 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `mode` | 共用 | `server` | `server` 或 `client` |
| `listen` | 共用 | 服务端 `:8443`；客户端 `127.0.0.1:2222` | 监听地址 |
| `server` | 客户端 | 必填 | 完整的 `http://` 或 `https://` 服务端地址 |
| `target` | 客户端 | 必填 | 服务端要连接的目标地址 |
| `path` | 共用 | `/tunnel` | 隧道 HTTP 路径 |
| `token` | 共用 | 空 | 预共享鉴权令牌；生产环境必须设置 |
| `transport` | 共用 | 服务端 `h2`；客户端按 URL 推断 | 服务端可逗号分隔或设为 `all`；客户端只能选一个 |
| `network` | 共用 | `tcp` | `tcp`、`udp` 或 `all` |
| `tls` | 服务端 | `false` | gRPC 是否启用 TLS；`h2/h3/wt/masque` 自动要求 TLS，`h2c` 强制明文 |
| `cert` / `key` | 服务端 | 空 | TLS 证书和私钥，必须成对设置 |
| `local_only` | 服务端 | `false` | 只允许回环目标 |
| `insecure` | 客户端 | `false` | 跳过证书校验，仅用于受控测试 |
| `host` | 客户端 | 空 | 覆盖 HTTP Host，CDN 多租户回源时使用 |
| `sni` | 客户端 | URL 主机名 | 覆盖 TLS SNI |
| `heartbeat_sec` | 客户端 | `25` | CDN 双向心跳；负数关闭 |
| `session_window_kb` | 共用 | `256` | 每个可恢复会话的有界环形窗口 |
| `handshake_ack_ms` | 客户端 | `3000` | 数据面握手确认超时 |
| `keepalive_sec` | 客户端 | `15` | 会话/备用线路保活间隔 |
| `standby_connections` | 客户端 | `0` | 热备用连接数 |
| `drain_timeout_sec` | 共用 | `30` | 退出时等待现有会话的秒数 |
| `log_level` | 共用 | `info` | `debug`、`info`、`warn`、`error` |

每个字段都可用同名大写环境变量覆盖，例如 `H2TUNNEL_SERVER`、`H2TUNNEL_TRANSPORT`、`H2TUNNEL_STANDBY_CONNECTIONS`。环境变量的布尔值或整数格式错误同样会启动失败。

### 多协议服务端

服务端 `transport` 是允许列表，例如：

```json
{
  "mode": "server",
  "listen": ":8443",
  "transport": "h2,h3,masque",
  "network": "all",
  "token": "replace-with-a-long-random-token"
}
```

TLS 的 TCP 协议和 QUIC 协议可共享同一个数字端口。`h2c` 是明文协议，不能在同一监听地址上与 TLS/H3 协议混用。客户端每个进程只选择一个传输。

### 生成辅助配置

```bash
h2tunnel gen-nginx -domain tunnel.example.com -path /tunnel -backend 127.0.0.1:8443
h2tunnel gen-systemd -bin /usr/local/bin/h2tunnel -listen :8443 -path /tunnel -token 'TOKEN'
h2tunnel gen-uri -host tunnel.example.com -port 443 -path /tunnel -token 'TOKEN'
```

## 性能与可靠性

- 热路径的传输/网络分流在服务启动时编译成位掩码，请求处理不重复解析配置字符串。
- 恢复窗口有严格上限，不会随连接生命周期无限增长。
- TCP 与 UDP 使用独立主线路，避免数据报突发阻塞字节流；只在需要快速切换时开启 `standby_connections`。
- TLS 配置在客户端和服务端构造时克隆，调用方可安全复用自己的模板。
- UDP 写入采用有界队列和直接选择，不为每个数据报创建 goroutine。
- CDN 非 2xx 响应不会提交未确认数据；服务恢复后从服务端确认的游标继续。

若更关注内存，把 `session_window_kb` 调低；若链路抖动或吞吐高，把它调高。恢复期间未确认数据超过窗口时会显式失败，而不是静默丢失或乱序。

## 测试与验证

```bash
go test ./...
go vet ./...
go build ./cmd/h2tunnel
```

测试包含包外 API 编译与真实 TCP/UDP 端到端传输、鉴权失败、目标拒绝、context 取消传播、CDN 延迟/错误/缓冲行为、恢复握手、并发关闭和稳态基准。

```bash
go test -run '^$' -bench '^BenchmarkPublicAPIThroughCDN72KB$' -benchmem .
```

## 安全说明

- 包 API 的 `Authenticator` 与 `TargetDialer` 都是必填项。
- 预共享 token 应使用高熵随机值，并始终配合 TLS。
- `TLSConfig.InsecureSkipVerify` 仅适合受控测试环境。
- 服务端只应暴露所需网络和传输；优先用逻辑服务注册表，而不是任意地址拨号。
- `Principal.ID` 必须稳定；恢复会话会绑定身份、目标和网络，不能被另一个身份改接。
- `/healthz` 返回不可缓存的简单健康状态；其他未知路径返回 404。
