# H2Tunnel

H2Tunnel 是一个基于 Go 语言编写的高性能 HTTP/2 隧道工具。它利用 HTTP/2 的双向流（Streaming）特性，将本地的 TCP 流量安全、低延迟地透传至远端服务器。

通过引入高级的自定义 SNI (Server Name Indication) 和 HTTP Host 头部伪装能力，H2Tunnel 具备了强大的抗审查能力和突破 CDN 的网络穿透能力。

## ✨ 核心特性

* **双向实时流转发**：底层基于 `http.Flusher` 实现，彻底告别传统 HTTP 代理的“等待完整请求”机制，提供等同于原生 TCP 的极低延迟体验。
* **双引擎模式**：
  * **H2 (TLS)**：标准加密 HTTP/2 协议，适合直接暴露在公网。
  * **H2C (明文)**：明文 HTTP/2 协议，专为配合 Nginx、Caddy 等前置反向代理（由前置代理卸载 SSL 证书）设计。
* **高级流量伪装**：客户端支持自定义 SNI 与 Host 头部，可轻松突破 CDN (如 Cloudflare) 或实现 Nginx 流量寄生。
* **防滥用安全机制**：内置目标地址白名单限制，防止恶意扫描器将您的服务端作为公网开放代理滥用。

---

## 🛠️ 编译与安装

确保您的机器已安装 Go (>= 1.20)。

### 手动编译

项目中提供了一个 `build.sh` 脚本，可以快速编译出适用于 Linux、Windows 和 macOS 的可执行文件：

```bash
# 赋予执行权限并运行
chmod +x build.sh
./build.sh
```
编译完成后，二进制文件将输出到 `../bin` 目录下。

---

## 🚀 快速开始

### 1. 服务端 (Server) 启动

服务端无需特殊修改，正常启动即可。推荐使用 Nginx 作为前置反向代理卸载 SSL，或者直接使用证书启动 H2 模式。

```bash
# 启动 H2C 明文模式，监听 8443 端口
./h2tunnel server -listen 0.0.0.0:8443

# (可选) 启动 H2 加密模式，需提供证书
./h2tunnel server -listen 0.0.0.0:8443 -cert server.crt -key server.key
```

### 2. 客户端 (Client) 启动与伪装

假设您的服务端真实 IP 为 `1.1.1.1`，您在该服务器前面套了一个 Cloudflare CDN，并且绑定的域名为 `cdn.yourdomain.com`。

您希望在本地暴露 `2222` 端口，连接后端的 `22` (SSH) 端口。

```bash
./h2tunnel client \
  -listen 127.0.0.1:2222 \
  -server https://1.1.1.1:8443 \
  -host cdn.yourdomain.com \
  -target 127.0.0.1:22
```

**流量走向解析：**
1. 客户端向 `1.1.1.1:8443` 发起物理 TCP 连接。
2. TLS 握手时，SNI 显示为 `cdn.yourdomain.com`。
3. HTTP/2 请求的 Header 中，`Host` 字段为 `cdn.yourdomain.com`。
4. 防火墙或 CDN 节点看到这是一个合法的域名请求，予以放行/转发。
5. 最终连接被解包，送达目标 `127.0.0.1:22`。

---

## ⚙️ 命令行参数详解

### 客户端 (Client) 参数
| 参数 | 默认值 | 必填 | 说明 |
| :--- | :--- | :---: | :--- |
| `-listen` | `127.0.0.1:2222` | 否 | 客户端在本地监听的 TCP 地址。 |
| `-server` | `http://127.0.0.1:8443` | **是** | 远端服务端的 URL。必须以 `http://` 或 `https://` 开头。 |
| `-host` | `""` | 否 | **核心伪装参数**：自定义的 SNI 和 HTTP Host 域名。 |
| `-target` | `127.0.0.1:22` | **是** | 解包后需要拨号连接的最终真实目标 TCP 地址。 |
| `-path` | `/tunnel` | 否 | HTTP 请求路径，必须与服务端一致。 |
| `-insecure`| `true` | 否 | 是否跳过 TLS 证书校验。 |

### 服务端 (Server) 参数
| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `-listen` | `:8443` | 服务端的监听地址。 |
| `-cert` | `""` | TLS 证书文件路径。若留空，则启动 H2C 明文模式。 |
| `-key` | `""` | TLS 私钥文件路径。 |
| `-path` | `/tunnel` | 接受代理请求的 URL 路径，必须与客户端一致。 |
| `-local-only`| `true` | 安全开关。为 `true` 时，只允许转发到服务端的 `127.0.0.1` 目标，防止滥用。 |

---

## 💡 高级实战：Nginx 流量寄生

您可以将 H2Tunnel 隐藏在一个正常的 Nginx 网站背后：

**1. Nginx 配置 (服务端)**
```nginx
server {
    listen 443 ssl http2;
    server_name www.myblog.com;
    
    # 您的正常博客配置...
    
    # 隧道流量拦截
    location /secret-tunnel {
        # 转发到本地明文的 h2c 服务端
        grpc_pass grpc://127.0.0.1:8443; 
    }
}
```

**2. 启动 H2Tunnel (服务端)**
```bash
./h2tunnel server -listen 127.0.0.1:8443 -path /secret-tunnel
```

**3. 本地无缝连接 (客户端)**
```bash
./h2tunnel client -listen 127.0.0.1:2222 -server https://www.myblog.com -path /secret-tunnel -target 127.0.0.1:22
```
*所有针对 `/secret-tunnel` 的流量都会转化为内部 TCP 流量，而访问其他路径依旧是正常的博客，隐蔽性极高。*
