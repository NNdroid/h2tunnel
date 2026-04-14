package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

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

// --- MASQUE UDP Capsule (零分配版本) ---
func writeUDPCapsule(w io.Writer, p []byte) error {
	if err := writeVarInt(w, 0x00); err != nil { return err }
	if err := writeVarInt(w, uint64(1+len(p))); err != nil { return err }
	if err := writeVarInt(w, 0x00); err != nil { return err }
	_, err := w.Write(p) // 直接写入 payload，不拼接新切片
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

// --- Stream UDP Packets (零分配版本) ---
func writeUDPPacket(w io.Writer, p []byte) error {
	if len(p) > 65535 { return fmt.Errorf("UDP payload > 65535") }
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	
	if _, err := w.Write(hdr[:]); err != nil { return err }
	_, err := w.Write(p) // 分两次写入，让底层的 buffer 去处理，避免大内存拷贝
	return err
}

func readUDPPacket(r io.Reader, payloadBuf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil { return 0, err }
	
	length := binary.BigEndian.Uint16(hdr[:])
	if int(length) > len(payloadBuf) { return 0, fmt.Errorf("UDP packet too large for buffer") }
	
	if _, err := io.ReadFull(r, payloadBuf[:length]); err != nil { return 0, err } // 直接读入复用池
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