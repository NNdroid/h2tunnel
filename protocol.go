package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// 预生成的随机字节数组，用于极速填充 Padding，避免运行时计算和内存分配
var paddingGarbage [4096]byte

// CDN 后各类反代的空闲超时上限（实测公约数）：
//
//	AWS ALB idle_timeout        默认 60s
//	Nginx proxy_read_timeout    默认 60s
//	Cloudflare 回源读超时        100s（超时返回 524）
//
// 取最小公约数 60s 的一半以下作为默认心跳间隔，留出重传与抖动余量。
const (
	heartbeatDefault = 25 * time.Second
	heartbeatMin     = 5 * time.Second
	heartbeatMax     = 5 * time.Minute
	// 优雅下线时等待存量隧道排空的上限
	drainDefault = 30 * time.Second
)

// clampHeartbeat 把用户配置的心跳间隔收敛到安全区间。
// 返回 0 表示关闭心跳（仅建议在源站直连、无中间盒时使用）。
func clampHeartbeat(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return heartbeatDefault
	case d < heartbeatMin:
		return heartbeatMin
	case d > heartbeatMax:
		return heartbeatMax
	}
	return d
}

// maxCapsuleLen bounds the length of a MASQUE/QUIC UDP capsule we are willing to
// consume. capsuleLen comes from the (attacker-controlled) wire, so without this
// cap a malicious peer could force the server to read an unbounded amount of
// stream data — a trivial DoS. 4 MiB is far above any legitimate UDP payload.
const maxCapsuleLen = 1 << 22

var paddingWritePool = sync.Pool{
	New: func() interface{} {
		// 单次最大 chunk 为 1MB (1048576)
		// Header(6) + Padding(最大不到 512)
		// 分配 1048576 + 1024 = 1049600 字节，绝对安全且避免越界
		buf := make([]byte, 1049600)
		return &buf
	},
}

func init() {
	rand.Read(paddingGarbage[:])
}

// fastRand returns a non-cryptographic random int in [0, max). It is used only
// for traffic-obfuscation padding (never for secrets/nonces), so a fast PRNG is
// both safe and dramatically cheaper than crypto/rand per call.
func fastRand(max int) int {
	if max <= 1 {
		return 0
	}
	return mrand.Intn(max)
}

// NormalizeTargetAddr 标准化目标地址（支持 IP:Port 与 Domain:Port）
func NormalizeTargetAddr(addr, defaultPort string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		p, errP := strconv.Atoi(port)
		if errP == nil && p >= 1 && p <= 65535 && host != "" {
			return net.JoinHostPort(host, port)
		}
	}
	// 如果没有带端口，尝试附加默认端口
	if defaultPort != "" && !strings.Contains(addr, ":") {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
}

// IsValidTargetAddr 校验目标地址（支持 IPv4 / IPv6 / 域名 + 端口）
func IsValidTargetAddr(addr string) bool {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	return true
}

func checkTargetIsAvailable(target string, cfg ServerConfig) bool {
	if target == "" {
		return false
	}
	// 如果开启了“仅限本地”模式，则进行主机校验
	if cfg.LocalOnly {
		host, _, err := net.SplitHostPort(target)
		if err != nil {
			host = target
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
		if ip := net.ParseIP(host); ip != nil {
			return ip.IsLoopback()
		}
		// Keep the conventional local hostname for user-friendly configs, but do
		// not accept lookalike names such as localhost.example.com.
		return host == "localhost"
	}
	return true
}

func GetDefaultQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
		// 允许的无序字节数。高吞吐下必须调大，否则会被拥塞控制卡死
		MaxStreamReceiveWindow:     8 * 1024 * 1024,  // 8 MB (默认通常是 512KB)
		MaxConnectionReceiveWindow: 20 * 1024 * 1024, // 20 MB
		// 允许客户端并发开启的最大双向流数量，避免多路复用时因流耗尽导致阻塞
		MaxIncomingStreams: 1000,
		// 如果是纯代理环境，可以考虑关闭 KeepAlive 或调长周期，减少控制帧开销
		KeepAlivePeriod:       9 * time.Second,
		MaxIdleTimeout:        30 * time.Second, // 限制超时时间
		MaxIncomingUniStreams: 10000,            // 调大单向流限制
	}
}

func GetXNetwork(r *http.Request) string {
	network := r.Header.Get("X-Network")
	if network != "udp" {
		network = "tcp"
	}
	return network
}

func GetXTarget(r *http.Request) string {
	target := r.Header.Get("X-Target")
	return target
}

func GetXDst(r *http.Request) (string, string) {
	network := GetXNetwork(r)
	target := GetXTarget(r)

	if target == "" || !IsValidTargetAddr(target) { // 当目标为空或非法时，使用默认值
		switch network {
		case "udp":
			target = "127.0.0.1:53" // DNS
		default:
			target = "127.0.0.1:22" // SSH
		}
	}

	return network, target
}

func SetXNetwork(h http.Header, network string) {
	h.Set("X-Network", network)
}

func SetXTarget(h http.Header, target string) {
	h.Set("X-Target", target)
}

func SetXDst(h http.Header, cfg ClientConfig) (string, string) {
	network := "tcp"
	if cfg.Network == "udp" {
		network = "udp"
	}
	defaultPort := "22"
	if network == "udp" {
		defaultPort = "53"
	}

	target := NormalizeTargetAddr(cfg.TargetAddr, defaultPort)
	if !IsValidTargetAddr(target) {
		if network == "udp" {
			target = "127.0.0.1:53"
		} else {
			target = "127.0.0.1:22"
		}
	}
	SetXNetwork(h, network)
	SetXTarget(h, target)
	return network, target
}

func SetXAuth(h http.Header, cfg ClientConfig) {
	if cfg.Token == "" {
		return
	}
	// ⚠️ 同时投递三个头，是有意为之，不是冗余：
	//   X-Auth-Token        自定义头，任何 CDN / 反代都会原样透传 —— CDN 场景的实际生效者
	//   Authorization       标准头，Nginx / Cloudflare 默认透传 —— 次选
	//   Proxy-Authorization RFC 7230 定义的 hop-by-hop 头，代理「必须」消耗掉，
	//                       直连场景可用，过 CDN 会被剥离 —— 仅为兼容旧部署保留
	// 单发 Proxy-Authorization 时在 CDN / Nginx 反代后面会恒定 407，这是历史 bug。
	h.Set("X-Auth-Token", cfg.Token)
	h.Set("Authorization", "Bearer "+cfg.Token)
	h.Set("Proxy-Authorization", "Bearer "+cfg.Token)
}

// setTunnelRequestHeaders 设置隧道请求侧的反缓冲头，与 server 端的
// setTunnelHeaders 配对：
//
//	Accept-Encoding: identity —— Go Transport 默认会自动补 gzip 并承诺解压，
//	  中间盒看到 Accept-Encoding: gzip 可能直接对响应做压缩缓冲。显式
//	  identity 同时阻止 Transport 自动补头和 CDN 主动压缩。
//	Cache-Control: no-store, no-transform —— 要求 CDN 不缓存、不改写。
func setTunnelRequestHeaders(h http.Header) {
	h.Set("Accept-Encoding", "identity")
	h.Set("Cache-Control", "no-store, no-transform")
}

// checkAuth 统一鉴权（支持多 Token 逗号分隔列表）
func checkAuth(r *http.Request, expectedTokens string) bool {
	if strings.TrimSpace(expectedTokens) == "" {
		return true
	}

	// 优先级：自定义头 > Authorization > Proxy-Authorization。
	// 自定义头放首位是因为它是唯一能保证穿过任意中间盒的载体。
	customTokenHeader := r.Header.Get("X-Auth-Token")
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		authHeader = r.Header.Get("Proxy-Authorization")
	}

	// 拆分支持多 Token 配置（例如: -token token1,token2）
	tokens := strings.Split(expectedTokens, ",")
	for _, tok := range tokens {
		cleanTok := strings.TrimSpace(tok)
		if cleanTok == "" {
			continue
		}
		// 常量时间比较，避免通过响应耗时逐字节爆破 token
		if secureEqual(customTokenHeader, cleanTok) {
			return true
		}
		if secureEqual(authHeader, cleanTok) || secureEqual(authHeader, "Bearer "+cleanTok) {
			return true
		}
	}

	// 鉴权失败时，只记录来源 IP，绝不打印客户端携带的 token（含 Bearer 明文），以防凭据泄露
	zlog.Warnf("[Protocol] 鉴权拦截: 非法/缺失鉴权 (IP: %s)", clientIP(r))
	return false
}

// secureEqual 常量时间字符串比较（长度不等时也要走完，避免长度侧信道）
func secureEqual(a, b string) bool {
	if a == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// clientIP 还原真实客户端 IP。
//
// 在 CDN / 反代后面 r.RemoteAddr 恒为边缘节点地址，直接拿它做日志和审计
// 等于什么都没记。这里按常见约定依次回退取值。
//
// ⚠️ 安全约束：这些头都可以被客户端伪造，因此本函数的返回值只能用于日志、
// 限流统计等辅助用途，**绝不可作为鉴权或访问控制依据**。需要按 IP 做访问
// 控制时，必须在最外层反代上校验，或显式配置可信代理层数后取倒数第 N 跳。
func clientIP(r *http.Request) string {
	for _, h := range []string{"CF-Connecting-IP", "True-Client-IP", "X-Real-IP"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return v
		}
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	return r.RemoteAddr
}

// parseMasqueTarget 遵循 RFC 9298 解析 URI 模板
func parseMasqueTarget(protocol, reqPath string) (string, error) {
	protocol = strings.ToLower(protocol)
	if protocol != "tcp" && protocol != "udp" {
		zlog.Errorf("[Protocol] URI 解析失败: 不支持的底层协议 '%s'", protocol)
		return "", fmt.Errorf("unsupported protocol: %s", protocol)
	}
	cleanPath := strings.Trim(reqPath, "/")
	parts := strings.Split(cleanPath, "/")

	udpIdx := -1
	for i, p := range parts {
		if strings.EqualFold(p, protocol) {
			udpIdx = i
			break
		}
	}

	if udpIdx == -1 || len(parts) < udpIdx+3 {
		return "", fmt.Errorf("invalid masque path: %s", reqPath)
	}

	host, err1 := url.PathUnescape(parts[udpIdx+1])
	port, err2 := url.PathUnescape(parts[udpIdx+2])
	if err1 != nil || err2 != nil || host == "" || port == "" {
		zlog.Errorf("[Protocol] URI Decode 失败: hostErr=%v, portErr=%v", err1, err2)
		return "", fmt.Errorf("failed to unescape host/port")
	}

	target := net.JoinHostPort(host, port)
	if !IsValidTargetAddr(target) {
		return "", fmt.Errorf("invalid parsed masque target: %s", target)
	}
	zlog.Debugf("[Protocol] 🎯 MASQUE URI 解析成功 -> 解析出目标: %s", target)
	return target, nil
}

// --- QUIC VarInt (极高频调用，仅保留严重错误日志) ---
func writeVarInt(w io.Writer, val uint64) error {
	var buf [8]byte
	if val <= 0x3f {
		buf[0] = byte(val)
		return writeAll(w, buf[:1])
	} else if val <= 0x3fff {
		binary.BigEndian.PutUint16(buf[:2], uint16(val)|0x4000)
		return writeAll(w, buf[:2])
	} else if val <= 0x3fffffff {
		binary.BigEndian.PutUint32(buf[:4], uint32(val)|0x80000000)
		return writeAll(w, buf[:4])
	}
	binary.BigEndian.PutUint64(buf[:], val|0xc000000000000000)
	return writeAll(w, buf[:])
}

func readVarInt(r io.Reader) (uint64, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	val := uint64(b[0] & 0x3f)

	if length > 1 {
		buf := make([]byte, length-1)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		for _, v := range buf {
			val = (val << 8) | uint64(v)
		}
	}
	return val, nil
}

// --- MASQUE UDP Capsule ---
func writeUDPCapsule(w io.Writer, p []byte) error {
	// 随机概率插入 Padding Capsule (混淆长度和流量特征)
	if fastRand(10) > 6 { // 30% 的概率插入
		padLen := fastRand(64)
		// 0x1F23 是自定义的未知类型，接收端的 io.Discard 会自动吃掉它
		if err := writeVarInt(w, 0x1F23); err != nil {
			return err
		}
		if err := writeVarInt(w, uint64(padLen)); err != nil {
			return err
		}
		if padLen > 0 {
			if err := writeAll(w, paddingGarbage[:padLen]); err != nil {
				return err
			}
		}
	}

	// 正常写入 Datagram (Type 0x00)
	if err := writeVarInt(w, 0x00); err != nil {
		return err
	}
	if err := writeVarInt(w, uint64(1+len(p))); err != nil {
		return err
	}
	if err := writeVarInt(w, 0x00); err != nil {
		return err
	}
	return writeAll(w, p)
}

func readUDPCapsule(r io.Reader, payloadBuf []byte) (int, error) {
	for {
		capsuleType, err := readVarInt(r)
		if err != nil {
			return 0, err
		}
		capsuleLen, err := readVarInt(r)
		if err != nil {
			return 0, err
		}
		if capsuleLen > maxCapsuleLen {
			return 0, fmt.Errorf("UDP capsule length %d exceeds limit %d", capsuleLen, maxCapsuleLen)
		}

		lr := &io.LimitedReader{R: r, N: int64(capsuleLen)}
		if capsuleType == 0x00 {
			contextID, err := readVarInt(lr)
			if err != nil {
				return 0, err
			}
			if contextID == 0 {
				if lr.N > int64(len(payloadBuf)) {
					return 0, fmt.Errorf("UDP capsule too large for buffer")
				}
				n, err := io.ReadFull(lr, payloadBuf[:lr.N]) // 直接读入复用池，不产生 GC
				return n, err
			}
		}
		if lr.N > 0 {
			io.Copy(io.Discard, lr)
		}
	}
}

// --- Stream UDP Packets ---
func writeUDPPacket(w io.Writer, p []byte) error {
	if len(p) > 65535 {
		return fmt.Errorf("UDP payload > 65535")
	}

	padLen := fastRand(64)
	totalLen := 4 + len(p) + padLen

	bufPtr := udpBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer udpBufPool.Put(bufPtr)

	// 组装 Header
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(p)))
	binary.BigEndian.PutUint16(buf[2:4], uint16(padLen))

	// 拼接 Payload 和 Padding
	copy(buf[4:], p)
	if padLen > 0 {
		copy(buf[4+len(p):], paddingGarbage[:padLen])
	}

	return writeAll(w, buf[:totalLen])
}

func readUDPPacket(r io.Reader, payloadBuf []byte) (int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}

	length := binary.BigEndian.Uint16(hdr[0:2])
	padLen := binary.BigEndian.Uint16(hdr[2:4])

	if int(length) > len(payloadBuf) {
		return 0, fmt.Errorf("UDP packet too large for buffer: %d", length)
	}

	if _, err := io.ReadFull(r, payloadBuf[:length]); err != nil {
		return 0, err
	}

	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return 0, err
		}
	}
	return int(length), nil
}
