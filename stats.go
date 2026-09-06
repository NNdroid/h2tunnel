package h2tunnel

import (
	"sync/atomic"
)

// =========================================
// Stats —— 轻量统计快照（可选）。
//
// 嵌入方从 Client.Stats() / Server.Stats() 读取累计计数（适合定期
// 采集进 Prometheus 等监控系统）。所有字段原子递增，读取是无锁快照。
// =========================================

// ClientStats 客户端累计统计。
type ClientStats struct {
	// DialAttempts 发起的拨号次数（TCP DialContext + UDP DialPacketContext）。
	DialAttempts atomic.Int64
	// DialFailures 拨号失败次数（握手未就绪、服务端拒绝等）。
	DialFailures atomic.Int64
	// UplinkBytes 客户端发出（经隧道上行）的字节数。
	UplinkBytes atomic.Int64
	// DownlinkBytes 客户端收到（经隧道下行）的字节数。
	DownlinkBytes atomic.Int64
	// ResumeReconnects TCP/UDP 会话断线续传（同 session 重拨）的次数。
	ResumeReconnects atomic.Int64
	// ActiveDials 进行中的拨号数。
	ActiveDials atomic.Int64
}

// ServerStats 服务端累计统计。
type ServerStats struct {
	// SessionsCreated 建立的隧道会话数（新 session id）。
	SessionsCreated atomic.Int64
	// SessionsResumed 会话续传次数（已有 session id 重新接上）。
	SessionsResumed atomic.Int64
	// SessionsActive 当前活跃会话数（读取时点的近似值）。
	SessionsActive atomic.Int64
	// UplinkBytes 服务端从客户端收到（写入 target）的字节数。
	UplinkBytes atomic.Int64
	// DownlinkBytes 服务端发给客户端（来自 target）的字节数。
	DownlinkBytes atomic.Int64
	// AuthFailures 鉴权失败请求数。
	AuthFailures atomic.Int64
}

// stats 包级实例：Client/Server 各持一个指针（可选启用——为零值时
// 计数器仍然走原子加，代价可忽略，因此不做条件开关）。
type stats struct {
	client ClientStats
	server ServerStats
}

// sessionStats 计数器挂到 sessionTable / session 的写字段。
type sessionCounters struct {
	uplink   *atomic.Int64
	downlink *atomic.Int64
	created  *atomic.Int64
	resumed  *atomic.Int64
}

func clientStatsPtr(o *ClientOptions) *ClientStats {
	// dialCfg 是值拷贝；stats 指针让所有拷贝共享同一组计数器。
	return nil // 由 NewClient 填充（避免 options 循环依赖）
}

func (c *Client) Stats() *ClientStats { return &c.stats.client }

func (s *Server) Stats() *ServerStats {
	s.stats.server.SessionsActive.Store(int64(s.sessions.len()))
	return &s.stats.server
}
