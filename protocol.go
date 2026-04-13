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

// --- MASQUE UDP Capsule ---
func writeUDPCapsule(w io.Writer, p []byte) error {
	if err := writeVarInt(w, 0x00); err != nil { return err }
	if err := writeVarInt(w, uint64(1+len(p))); err != nil { return err }
	if err := writeVarInt(w, 0x00); err != nil { return err }
	_, err := w.Write(p)
	if err != nil {
		zlog.Debugf("[Capsule] 写入底层流失败: %v", err)
	}
	return err
}

func readUDPCapsule(r io.Reader) ([]byte, error) {
	for {
		capsuleType, err := readVarInt(r)
		if err != nil { return nil, err } // 正常的流结束 EOF
		
		capsuleLen, err := readVarInt(r)
		if err != nil {
			zlog.Warnf("[Capsule] 读取 Capsule 长度字段失败: %v", err)
			return nil, err
		}

		lr := &io.LimitedReader{R: r, N: int64(capsuleLen)}
		
		// 0x00: DATAGRAM (RFC 9298)
		if capsuleType == 0x00 {
			contextID, err := readVarInt(lr)
			if err != nil { return nil, err }
			
			if contextID == 0 {
				buf := make([]byte, lr.N)
				if _, err := io.ReadFull(lr, buf); err != nil {
					zlog.Errorf("[Capsule] Payload 读取不完整 (预期 %d bytes): %v", lr.N, err)
					return nil, err
				}
				return buf, nil
			} else {
				zlog.Debugf("[Capsule] ⚠️ 收到非预期的 Context ID (0x%x)，已跳过该报文", contextID)
			}
		} else {
			zlog.Debugf("[Capsule] ⚠️ 收到未知 Capsule Type (0x%x, 长度: %d)，按照扩展标准跳过", capsuleType, capsuleLen)
		}

		// 如果不是我们关心的 Capsule 或者 Context ID 不匹配，安全排空读取缓冲区，丢弃内容
		if lr.N > 0 {
			io.Copy(io.Discard, lr)
		}
	}
}

// --- Stream UDP Packets ---
func writeUDPPacket(w io.Writer, p []byte) error {
	if len(p) > 65535 {
		zlog.Errorf("[StreamUDP] ❌ 拒绝封装超大 UDP 报文 (大小: %d bytes，上限: 65535)", len(p))
		return fmt.Errorf("UDP payload > 65535")
	}
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(p)))
	copy(buf[2:], p)
	_, err := w.Write(buf)
	return err
}

func readUDPPacket(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil { return nil, err } // 正常的 EOF
	
	length := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		zlog.Warnf("[StreamUDP] ⚠️ 包体读取异常 (声明长度 %d): %v", length, err)
		return nil, err
	}
	return buf, nil
}

// --- gRPC Wrappers ---
type grpcWriter struct{ w io.Writer }
func (g *grpcWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 { return 0, nil }
	buf := make([]byte, 5+len(p))
	// Header: 1 byte (0=uncompressed) + 4 bytes length
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(p)))
	copy(buf[5:], p)
	if _, err := g.w.Write(buf); err != nil {
		zlog.Debugf("[gRPC-Writer] 发送帧失败: %v", err)
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