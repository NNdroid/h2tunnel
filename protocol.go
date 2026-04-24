package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
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

// 快速获取随机数的轻量级方法（非强加密安全，但满足流量混淆性能要求）
// 可自定义 max 的范围
func fastRand(max int) int {
	var b [1]byte
	rand.Read(b[:])
	return int(b[0]) % max
}

// calculatePadding 智能动态填充算法
// 核心思想：反比例填充 + 块边界对齐
func calculatePadding(dataLen int) int {
	var targetPad int

	// 阶梯式反比例基础填充
	switch {
	case dataLen < 128:
		// 极小包（握手包、心跳包）：重度混淆，随机填充 128 ~ 384 字节
		targetPad = 128 + fastRand(256)
	case dataLen < 512:
		// 小包（控制指令）：中度混淆，随机填充 64 ~ 192 字节
		targetPad = 64 + fastRand(128)
	case dataLen < 8192:
		// 中等包：轻度混淆，随机填充 16 ~ 64 字节
		targetPad = 16 + fastRand(48)
	default:
		// 大型数据流（高速下载）
		targetPad = 0
	}

	// 块对齐增强 (Block Alignment)
	// 强制让 (真实数据 + Padding) 的总长度对齐到 64 字节边界，
	// 这会让流量看起来非常像 AES/ChaCha20 这种标准块加密算法的输出特征。
	totalLen := dataLen + targetPad
	remainder := totalLen % 64
	if remainder != 0 {
		targetPad += (64 - remainder)
	}

	// 绝对安全边界拦截
	// 确保 Padding 永远不会超过我们预分配的 paddingGarbage 垃圾池大小
	if targetPad >= len(paddingGarbage) {
		targetPad = len(paddingGarbage) - 1
	}

	return targetPad
}

func checkTargetIsAvailable(target string, cfg ServerConfig) bool {
	// 如果开启了“仅限本地”模式，则进行前缀校验
	if cfg.LocalOnly {
		return strings.HasPrefix(target, "127.0.0.1:") || 
		       strings.HasPrefix(target, "localhost:") || 
		       strings.HasPrefix(target, "[::1]:")
	}
	
	// 如果没有开启 LocalOnly，则默认放行所有目标
	return true 
}

func GetDefaultQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
		// 允许的无序字节数。高吞吐下必须调大，否则会被拥塞控制卡死
		MaxStreamReceiveWindow:     8 * 1024 * 1024, // 8 MB (默认通常是 512KB)
		MaxConnectionReceiveWindow: 20 * 1024 * 1024, // 20 MB
		// 允许客户端并发开启的最大双向流数量，避免多路复用时因流耗尽导致阻塞
		MaxIncomingStreams: 1000,
		// 如果是纯代理环境，可以考虑关闭 KeepAlive 或调长周期，减少控制帧开销
		KeepAlivePeriod:                  9 * time.Second,
		MaxIdleTimeout:                   30 * time.Second,    // 限制超时时间
		MaxIncomingUniStreams:            10000,               // 调大单向流限制
	}
}

// IsValidIPPort 校驗字串是否為合法的 IP:Port 格式
func IsValidIPPort(addr string) bool {
	// 1. 嘗試將字串拆分為 Host 和 Port
	// net.SplitHostPort 可以完美處理 IPv6 帶括號的情況，例如 "[::1]:8080"
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	// 2. 驗證 IP 是否合法
	// net.ParseIP 會過濾掉非法的 IP (例如 256.256.256.256 或一般的網域名稱)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// 3. 驗證 Port 是否合法
	// 必須是數字，且範圍在 1 ~ 65535 之間
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	if port < 1 || port > 65535 {
		return false
	}

	return true
}

func GetXNetwork(r *http.Request) string {
	network := r.Header.Get("X-Network")
	if network != "udp" { network = "tcp" }
	return network
}

func GetXTarget(r *http.Request) string {
	target := r.Header.Get("X-Target")
	return target
}

func GetXDst(r *http.Request) (string, string) {
	network := GetXNetwork(r)
	target := GetXTarget(r)
	
	if target == "" { // 当目标为空时，使用默认值
		switch network {
		case "udp":
			target = "127.0.0.1:53"// DNS
		default:
			target = "127.0.0.1:22"// SSH
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
	target := ""
	if cfg.UseUDP { network = "udp" }
	isValidTarget := IsValidIPPort(cfg.TargetAddr)
	if isValidTarget { target = cfg.TargetAddr }
	if target == "" || !isValidTarget { // 当目标为空时，使用默认值
		switch network {
		case "udp":
			target = "127.0.0.1:53"// DNS
		default:
			target = "127.0.0.1:22"// SSH
		}
	}
	SetXNetwork(h, network)
	SetXTarget(h, target)
	return network, target
}

func SetXAuth(h http.Header, cfg ClientConfig) {
	if cfg.Token != "" { h.Set("Proxy-Authorization", "Bearer "+cfg.Token) }
}

// checkAuth 统一鉴权
func checkAuth(r *http.Request, expectedToken string) bool {
	if expectedToken == "" {
		return true
	}
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "Bearer "+expectedToken {
		return true
	}
	
	// 鉴权失败时，记录客户端尝试使用的特征，但不打印正确的 expectedToken 以防泄漏
	zlog.Warnf("[Protocol] 鉴权拦截: 收到 Header '%s' (IP: %s)", authHeader, r.RemoteAddr)
	return false
}

// parseMasqueTarget 遵循 RFC 9298 解析 URI 模板
func parseMasqueTarget(protocol, reqPath string) (string, error) {
	zlog.Debugf("[Protocol] 尝试解析 MASQUE URI: %s (预期协议: %s)", reqPath, protocol)

	if protocol != "tcp" && protocol != "udp" {
		zlog.Errorf("[Protocol] URI 解析失败: 不支持的底层协议 '%s'", protocol)
		return "", fmt.Errorf("unsupported protocol")
	}
	cleanPath := strings.Trim(reqPath, "/")
	parts := strings.Split(cleanPath, "/")

	udpIdx := -1
	for i, p := range parts {
		if p == protocol {
			udpIdx = i
			break
		}
	}
	
	if udpIdx == -1 || len(parts) < udpIdx+3 {
		zlog.Warnf("[Protocol] URI 格式非法，未找到规范的 %s 模板分段: %s", protocol, reqPath)
		return "", fmt.Errorf("invalid masque path: %s", reqPath)
	}

	host, err1 := url.PathUnescape(parts[udpIdx+1])
	port, err2 := url.PathUnescape(parts[udpIdx+2])
	if err1 != nil || err2 != nil {
		zlog.Errorf("[Protocol] URI Decode 失败: hostErr=%v, portErr=%v", err1, err2)
		return "", fmt.Errorf("failed to unescape host/port")
	}

	target := net.JoinHostPort(host, port)
	zlog.Debugf("[Protocol] 🎯 MASQUE URI 解析成功 -> 解析出目标: %s", target)
	return target, nil
}

// --- QUIC VarInt (极高频调用，仅保留严重错误日志) ---
func writeVarInt(w io.Writer, val uint64) error {
	if val <= 0x3f {
		_, err := w.Write([]byte{byte(val)})
		return err
	} else if val <= 0x3fff {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(val)|0x4000)
		_, err := w.Write(buf)
		return err
	} else if val <= 0x3fffffff {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(val)|0x80000000)
		_, err := w.Write(buf)
		return err
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val|0xc000000000000000)
	_, err := w.Write(buf)
	return err
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
		if err := writeVarInt(w, 0x1F23); err != nil { return err } 
		if err := writeVarInt(w, uint64(padLen)); err != nil { return err }
		if padLen > 0 {
			if _, err := w.Write(paddingGarbage[:padLen]); err != nil { return err }
		}
	}

	// 正常写入 Datagram (Type 0x00)
	if err := writeVarInt(w, 0x00); err != nil { return err }
	if err := writeVarInt(w, uint64(1+len(p))); err != nil { return err }
	if err := writeVarInt(w, 0x00); err != nil { return err }
	_, err := w.Write(p) 
	return err
}

func readUDPCapsule(r io.Reader, payloadBuf []byte) (int, error) {
	for {
		capsuleType, err := readVarInt(r)
		if err != nil { return 0, err }
		capsuleLen, err := readVarInt(r)
		if err != nil { return 0, err }
		
		lr := &io.LimitedReader{R: r, N: int64(capsuleLen)}
		if capsuleType == 0x00 {
			contextID, err := readVarInt(lr)
			if err != nil { return 0, err }
			if contextID == 0 {
				if lr.N > int64(len(payloadBuf)) { return 0, fmt.Errorf("UDP capsule too large for buffer") }
				n, err := io.ReadFull(lr, payloadBuf[:lr.N]) // 直接读入复用池，不产生 GC
				return n, err
			}
		}
		if lr.N > 0 { io.Copy(io.Discard, lr) }
	}
}

// --- Stream UDP Packets ---
func writeUDPPacket(w io.Writer, p []byte) error {
	if len(p) > 65535 { return fmt.Errorf("UDP payload > 65535") }
	
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
	
	_, err := w.Write(buf[:totalLen])
	return err
}

func readUDPPacket(r io.Reader, payloadBuf []byte) (int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil { return 0, err }
	
	length := binary.BigEndian.Uint16(hdr[0:2])
	padLen := binary.BigEndian.Uint16(hdr[2:4])
	
	if int(length) > len(payloadBuf) { return 0, fmt.Errorf("UDP packet too large for buffer: %d", length) }
	
	if _, err := io.ReadFull(r, payloadBuf[:length]); err != nil { return 0, err } 
	
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return 0, err
		}
	}
	return int(length), nil
}

// --- gRPC Wrappers ---
type grpcWriter struct{ w io.Writer }
func (g *grpcWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 { return 0, nil }
	
	// 只分配 5 个字节的极小头部，Go 编译器会将其优化在栈上，不触发 GC
	var header [5]byte 
	binary.BigEndian.PutUint32(header[1:5], uint32(len(p)))
	
	// 连续写两次，只要底层的 w (如 http2.Stream) 带有缓冲，性能损耗极小
	if _, err := g.w.Write(header[:]); err != nil {
		return 0, err
	}
	if _, err := g.w.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

type grpcReader struct {
	r    io.Reader
	left uint32
}
func (g *grpcReader) Read(p []byte) (n int, err error) {
	for g.left == 0 {
		var header [5]byte
		if _, err := io.ReadFull(g.r, header[:]); err != nil {
			// 连接自然断开时走到这里返回 EOF，不打 Error 日志
			return 0, err
		}
		g.left = binary.BigEndian.Uint32(header[1:5])
	}
	toRead := uint32(len(p))
	if toRead > g.left {
		toRead = g.left
	}
	n, err = g.r.Read(p[:toRead])
	if err != nil && err != io.EOF {
		zlog.Debugf("[gRPC-Reader] 读取帧负载时发生异常: %v", err)
	}
	g.left -= uint32(n)
	return n, err
}

// --- Stream Padding Wrappers ---

// PaddingWriter 对标准 io.Writer 进行混淆包装
type PaddingWriter struct {
	w io.Writer
}

func (pw *PaddingWriter) Write(p []byte) (nTotal int, err error) {
	for len(p) > 0 {
		chunk := p
		// 控制单帧最大限制为 1MB
		if len(chunk) > 1048576 {
			chunk = chunk[:1048576]
		}

		// 智能计算 Padding 长度
		padLen := calculatePadding(len(chunk)) 
		totalLen := 6 + len(chunk) + padLen

		// 🌟 核心优化：从全局池子里“借”一块内存，坚决不用 make
		bufPtr := paddingWritePool.Get().(*[]byte)
		buf := *bufPtr

		// 写入 6 字节 Header
		binary.BigEndian.PutUint32(buf[0:4], uint32(len(chunk)))
		binary.BigEndian.PutUint16(buf[4:6], uint16(padLen))
	
		// 写入真实数据
		copy(buf[6:], chunk)
		
		// 写入垃圾 Padding
		if padLen > 0 {
			copy(buf[6+len(chunk):], paddingGarbage[:padLen])
		}

		// 🌟 提交给底层发送（切片截取到实际组装的 totalLen）
		_, errW := pw.w.Write(buf[:totalLen])
		
		// 🌟 用完立刻“还”回池子，供其他并发连接复用
		paddingWritePool.Put(bufPtr)

		if errW != nil {
			return nTotal, errW
		}

		nTotal += len(chunk)
		p = p[len(chunk):]
	}
	return nTotal, nil
}

//傳遞關閉信號到底層 Writer
func (pw *PaddingWriter) Close() error {
	if closer, ok := pw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// PaddingReader 对应的解包器
type PaddingReader struct {
	r        io.Reader
	leftData uint32
	leftPad  uint16
}

func (pr *PaddingReader) Read(p []byte) (n int, err error) {
	for pr.leftData == 0 {
		// 消耗掉上一帧残留的 Padding (如果有的话)
		if pr.leftPad > 0 {
			_, err := io.CopyN(io.Discard, pr.r, int64(pr.leftPad))
			if err != nil {
				return 0, err
			}
			pr.leftPad = 0
		}

		// 读取新帧的 6 字节 Header
		var header [6]byte
		if _, err := io.ReadFull(pr.r, header[:]); err != nil {
			return 0, err
		}
		pr.leftData = binary.BigEndian.Uint32(header[0:4]) // 解析 4 字节数据长度
		pr.leftPad = binary.BigEndian.Uint16(header[4:6])
	}

	// 读取真实载荷
	toRead := pr.leftData
	if uint32(len(p)) < toRead {
		toRead = uint32(len(p)) // 防御性判断：不能超过用户传入的 slice 容量
	}
	n, err = pr.r.Read(p[:toRead])
	if err != nil && err != io.EOF {
		zlog.Debugf("[PaddingReader] 读取真实数据异常: %v", err)
	}
	pr.leftData -= uint32(n)
	return n, err
}

//傳遞關閉信號到底層 Reader
func (pr *PaddingReader) Close() error {
	if closer, ok := pr.r.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}