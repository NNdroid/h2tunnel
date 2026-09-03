package main

import (
	"strconv"
	"strings"
)

// =========================================
// handshake.go — 握手协商（版本 / 能力 / 参数）
//
// 协商逻辑是纯函数（无 I/O），便于单元测试。
// 载体：HTTP 头（X-Resume-Version / X-Resume-Caps / X-Resume-Params），
//       版本是硬约束（v2 唯一），能力/参数是软约束（见 §2.6）。
// =========================================

// 默认参数与常量
const (
	// 客户端发送的能力列表（可配置子集）
	capDatagram   = "datagram"    // UDP 数据报模式
	capCompress   = "compress"    // 压缩
	capBackupLine = "backup-line" // 备用线路
	capReplay     = "replay"      // 最小基准能力集（字节流 + seq 重放）

	// 参数键
	paramWindowKB       = "window_kb"
	paramHandshakeAckMs = "handshake_ack_timeout" // 毫秒
	paramKeepaliveSec   = "keepalive_interval"    // 秒

	defaultWindowKB       = 256
	defaultHandshakeAckMs = 3000
	defaultKeepaliveSec   = 15
	maxWindowKB           = 65536
	maxHandshakeAckMs     = 30000
	maxKeepaliveSec       = 3600
)

// resumeCaps 能力集合（交集计算用）。
type resumeCaps struct {
	datagram   bool
	compress   bool
	backupLine bool
}

// parseCaps 解析逗号分隔的能力列表。未知项忽略（向前兼容）。
func parseCaps(s string) resumeCaps {
	var c resumeCaps
	for _, name := range strings.Split(s, ",") {
		switch strings.TrimSpace(name) {
		case capDatagram:
			c.datagram = true
		case capCompress:
			c.compress = true
		case capBackupLine:
			c.backupLine = true
		}
	}
	return c
}

// intersectCaps 返回客户端能力与服务端能力集合的交集（客户端请求 ∩ 服务端支持）。
// 若交集为空且双方都不支持最小基准集，返回空。
func intersectCaps(client, server resumeCaps) resumeCaps {
	return resumeCaps{
		datagram:   client.datagram && server.datagram,
		compress:   client.compress && server.compress,
		backupLine: client.backupLine && server.backupLine,
	}
}

// empty 判断能力交集是否为空（连最小基准集都没有）。
// 注意：replay 是隐式基准，任何 resume 会话都有字节流能力，故交集永不为绝对空；
// 这里仅当连 replay 都不成立（理论不可能）才为 true。
func (c resumeCaps) empty() bool {
	// replay 隐式存在，恒不空
	return false
}

// String 序列化能力列表为逗号分隔（仅列启用的项）。
// 无增强能力时返回最小基准能力集 "replay"（字节流 + seq 重放，任何会话都有）。
func (c resumeCaps) String() string {
	var parts []string
	if c.datagram {
		parts = append(parts, capDatagram)
	}
	if c.compress {
		parts = append(parts, capCompress)
	}
	if c.backupLine {
		parts = append(parts, capBackupLine)
	}
	if len(parts) == 0 {
		return capReplay
	}
	return strings.Join(parts, ",")
}

// resumeParams 协商后的参数（int 毫秒/字节/秒等，量纲由键名语义约定）。
type resumeParams struct {
	windowKB       int
	handshakeAckMs int
	keepaliveSec   int
}

func defaultParams() resumeParams {
	return resumeParams{
		windowKB:       defaultWindowKB,
		handshakeAckMs: defaultHandshakeAckMs,
		keepaliveSec:   defaultKeepaliveSec,
	}
}

// parseParams 解析 `;` 分隔的 k=v 参数。未知键忽略；非法值回退默认。
func parseParams(s string) resumeParams {
	p := defaultParams()
	if s == "" {
		return p
	}
	for _, kv := range strings.Split(s, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(kv[:eq])
		val, err := strconv.Atoi(strings.TrimSpace(kv[eq+1:]))
		if err != nil {
			continue // 非法值 → 保留默认
		}
		switch key {
		case paramWindowKB:
			p.windowKB = val
		case paramHandshakeAckMs:
			p.handshakeAckMs = val
		case paramKeepaliveSec:
			p.keepaliveSec = val
		}
	}
	return p
}

// alignParams 服务端对齐参数：越界 clamp 到合法区间；返回最终生效值（以服务端为准）。
func alignParams(p resumeParams) resumeParams {
	if p.windowKB <= 0 || p.windowKB > maxWindowKB {
		p.windowKB = defaultWindowKB
	}
	if p.handshakeAckMs <= 0 || p.handshakeAckMs > maxHandshakeAckMs {
		p.handshakeAckMs = defaultHandshakeAckMs
	}
	if p.keepaliveSec <= 0 || p.keepaliveSec > maxKeepaliveSec {
		p.keepaliveSec = defaultKeepaliveSec
	}
	return p
}

// String 序列化参数为 `;` 分隔的 k=v。
func (p resumeParams) String() string {
	var sb strings.Builder
	sb.WriteString(paramWindowKB)
	sb.WriteString("=")
	sb.WriteString(strconv.Itoa(p.windowKB))
	sb.WriteString(";")
	sb.WriteString(paramHandshakeAckMs)
	sb.WriteString("=")
	sb.WriteString(strconv.Itoa(p.handshakeAckMs))
	sb.WriteString(";")
	sb.WriteString(paramKeepaliveSec)
	sb.WriteString("=")
	sb.WriteString(strconv.Itoa(p.keepaliveSec))
	return sb.String()
}

// negotiateVersion 版本协商。v2 是唯一版本：
// min(双端) == 2 → 协商成功返回 2；否则返回 0（无交集，version-unsupported）。
// 服务端只需声明自己的最高支持版本；客户端声明最高支持版本。
func negotiateVersion(clientMax, serverMax int) int {
	v := clientMax
	if serverMax < v {
		v = serverMax
	}
	if v < 2 {
		return 0
	}
	return 2
}

// clientCapabilities 客户端声明的能力集（由 cfg 派生）。
func clientCapabilities(cfg ClientConfig) resumeCaps {
	return resumeCaps{
		datagram:   cfg.IsUDP(),
		backupLine: true,
	}
}

// clientParams 客户端请求的握手参数（由 cfg 派生，未配置用默认）。
func clientParams(cfg ClientConfig) resumeParams {
	return resumeParams{
		windowKB:       resolveSessionWindow(cfg.SessionWindow),
		handshakeAckMs: resolveHandshakeAckMs(cfg.HandshakeAckMs),
		keepaliveSec:   resolveKeepaliveSec(cfg.KeepaliveSec),
	}
}
