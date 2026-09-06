package h2tunnel

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// =========================================
// MASQUE（RFC 9298 CONNECT-UDP / CONNECT-TCP）传输层 adapter
//
// - masque-tcp：CONNECT 流本质是字节管道，resume/2 是唯一数据面，直接转派到
//   handleH2StreamResumeServer（同 h2 的 resume 引擎）。
// - masque-udp：走 resume 数据面（保持 UDP socket + 重建流），resume handler
//   依据 Protocol: connect-udp 自动选用 capsule 封装。
// - 客户端 runMasqueUDPClient：UDP -> MASQUE capsule 转发（resume 会话恢复）。
// =========================================

// ---> 服务端 MASQUE-TCP
func handleMasqueTCPServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg serverConfig, sessions *sessionTable) {
	// Authenticated h2tunnel clients carry the original (possibly logical)
	// target in X-Target. The MASQUE URI remains standards-shaped for proxies,
	// but must not rewrite an application service name such as "ssh" to
	// "ssh:22" before it reaches the policy dialer.
	target := strings.TrimSpace(getXTarget(r))
	if target == "" {
		var err error
		target, err = parseMasqueTarget("tcp", r.URL.Path)
		if err != nil {
			_, target = getXDst(r)
		}
	}

	if !targetAllowedByRuntime(cfg, target) {
		lgWarnf(sessions.lg(), "[%s] 🚫 Access denied for target address: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// MASQUE-TCP 的 CONNECT 流本质是字节管道，resume/2 是唯一数据面
	// （X-Tunnel-Proto: resume/2 + X-Session-ID）。v1 Padding 路径已移除。
	if r.Header.Get("X-Tunnel-Proto") == resumeFrameTypeResume {
		lgDebugf(sessions.lg(), "[%s] -> Dispatching MASQUE-TCP to RESUME handler", sessionID)
		handleH2StreamResumeServer(w, r, sessionID, cfg, sessions)
		return
	}
	lgWarnf(sessions.lg(), "[%s] ❌ MASQUE-TCP 未携带 resume/2 头，拒绝（v1 已移除）", sessionID)
	w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
	http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
}

// ---> 服务端 MASQUE-UDP
func handleMasqueUDP(w http.ResponseWriter, r *http.Request, cfg serverConfig, sessions *sessionTable) {
	sessionID := fmt.Sprintf("MUDP-%s-%d", r.RemoteAddr, time.Now().UnixNano()%1000)
	lgDebugf(sessions.lg(), "[%s] === New MASQUE-UDP request ===", sessionID)
	var authErr error
	r, authErr = authenticateServerRequest(r, cfg, TransportMASQUE)
	if authErr != nil {
		lgWarnf(sessions.lg(), "[%s] ❌ Authentication failed", sessionID)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 1. 严格网络类型分流校验 (是否允许 UDP)
	policy := cfg.effectiveRoutingPolicy()
	if !policy.allowsNetwork(networkUDP) {
		lgWarnf(sessions.lg(), "[%s] 🚫 严格分流拦截: 服务端限制 Network='%s'，拒绝 MASQUE-UDP 请求 (IP: %s)", sessionID, cfg.Network, clientIP(r))
		http.Error(w, "UDP traffic forbidden by server policy", http.StatusForbidden)
		return
	}

	// 2. 严格传输协议分流校验 (是否允许 MASQUE)
	if err := checkStrictTransportPolicy(r, policy, cfg.Transport, false, false, true); err != nil {
		lgWarnf(sessions.lg(), "[%s] 🚫 严格分流拦截: %v (IP: %s)", sessionID, err, clientIP(r))
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	target := strings.TrimSpace(getXTarget(r))
	var err error
	if target == "" {
		target, err = parseMasqueTarget("udp", r.URL.Path)
	}
	if err != nil || !targetAllowedByRuntime(cfg, target) {
		lgWarnf(sessions.lg(), "[%s] 🚫 MASQUE-UDP target rejected or parse failed: %s", sessionID, r.URL.Path)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// MASQUE-UDP 走 resume 数据面（保持 UDP socket + 重建流）。
	// resume handler 依据 Protocol: connect-udp 自动选用 capsule 封装。
	if r.Header.Get("X-Tunnel-Proto") == resumeFrameTypeResume {
		r.Header.Set("X-Network", "udp")
		r.Header.Set("X-Target", target)
		lgDebugf(sessions.lg(), "[%s] -> Dispatching MASQUE-UDP to RESUME handler (target=%s)", sessionID, target)
		handleH2StreamResumeServer(w, r, sessionID, cfg, sessions)
		return
	}
	lgWarnf(sessions.lg(), "[%s] ❌ MASQUE-UDP 未携带 resume/2 头，拒绝（v1 已移除）", sessionID)
	w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
	http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
}
