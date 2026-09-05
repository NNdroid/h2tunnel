package h2tunnel

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
		zlog.Warnf("[%s] 🚫 Access denied for target address: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// MASQUE-TCP 的 CONNECT 流本质是字节管道，resume/2 是唯一数据面
	// （X-Tunnel-Proto: resume/2 + X-Session-ID）。v1 Padding 路径已移除。
	if r.Header.Get("X-Tunnel-Proto") == resumeFrameTypeResume {
		zlog.Debugf("[%s] -> Dispatching MASQUE-TCP to RESUME handler", sessionID)
		handleH2StreamResumeServer(w, r, sessionID, cfg, sessions)
		return
	}
	zlog.Warnf("[%s] ❌ MASQUE-TCP 未携带 resume/2 头，拒绝（v1 已移除）", sessionID)
	w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
	http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
}

// ---> 服务端 MASQUE-UDP
func handleMasqueUDP(w http.ResponseWriter, r *http.Request, cfg serverConfig, sessions *sessionTable) {
	sessionID := fmt.Sprintf("MUDP-%s-%d", r.RemoteAddr, time.Now().UnixNano()%1000)
	zlog.Debugf("[%s] === New MASQUE-UDP request ===", sessionID)
	var authErr error
	r, authErr = authenticateServerRequest(r, cfg, TransportMASQUE)
	if authErr != nil {
		zlog.Warnf("[%s] ❌ Authentication failed", sessionID)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 1. 严格网络类型分流校验 (是否允许 UDP)
	policy := cfg.effectiveRoutingPolicy()
	if !policy.allowsNetwork(networkUDP) {
		zlog.Warnf("[%s] 🚫 严格分流拦截: 服务端限制 Network='%s'，拒绝 MASQUE-UDP 请求 (IP: %s)", sessionID, cfg.Network, clientIP(r))
		http.Error(w, "UDP traffic forbidden by server policy", http.StatusForbidden)
		return
	}

	// 2. 严格传输协议分流校验 (是否允许 MASQUE)
	if err := checkStrictTransportPolicy(r, policy, cfg.Transport, false, false, true); err != nil {
		zlog.Warnf("[%s] 🚫 严格分流拦截: %v (IP: %s)", sessionID, err, clientIP(r))
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	target := strings.TrimSpace(getXTarget(r))
	var err error
	if target == "" {
		target, err = parseMasqueTarget("udp", r.URL.Path)
	}
	if err != nil || !targetAllowedByRuntime(cfg, target) {
		zlog.Warnf("[%s] 🚫 MASQUE-UDP target rejected or parse failed: %s", sessionID, r.URL.Path)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// MASQUE-UDP 走 resume 数据面（保持 UDP socket + 重建流）。
	// resume handler 依据 Protocol: connect-udp 自动选用 capsule 封装。
	if r.Header.Get("X-Tunnel-Proto") == resumeFrameTypeResume {
		r.Header.Set("X-Network", "udp")
		r.Header.Set("X-Target", target)
		zlog.Debugf("[%s] -> Dispatching MASQUE-UDP to RESUME handler (target=%s)", sessionID, target)
		handleH2StreamResumeServer(w, r, sessionID, cfg, sessions)
		return
	}
	zlog.Warnf("[%s] ❌ MASQUE-UDP 未携带 resume/2 头，拒绝（v1 已移除）", sessionID)
	w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
	http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
}

// ---> 客户端 UDP: MASQUE —— 支持会话恢复
func runMasqueUDPClient(cfg clientConfig, mgr *connectionManager) {
	localAddr, _ := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	localConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		// 只退出本转发循环，不杀进程（legacy 路径无向调用方传错的通道）。
		zlog.Errorf("[M-UDP] ❌ 监听失败: %v", err)
		return
	}
	defer localConn.Close()
	registerClientListener(localConn)

	host, port, _ := net.SplitHostPort(cfg.TargetAddr)
	if host == "" {
		host = cfg.TargetAddr
		port = "53"
	}
	// 预格式化基础 URL 减少循环内的字符串拼接
	baseServerUrl := strings.TrimRight(cfg.ServerUrl, "/")
	masqueUrl := fmt.Sprintf("%s/.well-known/masque/udp/%s/%s/", baseServerUrl, url.PathEscape(host), url.PathEscape(port))

	zlog.Infof("[M-UDP] 🔗 监听就绪: UDP %s -> MASQUE -> %s (resume=true)", cfg.ListenAddr, cfg.TargetAddr)

	var activeConns sync.Map

	for {
		// 1. 🌟 每一跳从池子获取独立缓冲区
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr

		n, clientAddr, err := localConn.ReadFromUDP(buf)
		if err != nil {
			udpBufPool.Put(bufPtr)
			// 优雅下线关闭 socket 时正常退出，而非静默自旋
			if errors.Is(err, net.ErrClosed) {
				zlog.Infof("[M-UDP] 🔇 UDP socket 已关闭，退出接收循环")
				return
			}
			continue
		}

		payload := buf[:n]

		v, ok := activeConns.Load(clientAddr.String())
		if !ok {
			zlog.Infof("[M-UDP] 🟢 发现新 UDP 客户端: %s", clientAddr.String())
			// resume/2 恒启用：MASQUE-UDP 也用 resume 数据面（保持 UDP socket + 重建流）。
			udpSess := connectResumeUDP(newClientSessionID(), cfg, masqueUrl, pickClient(mgr, "udp"), localConn, clientAddr)
			if udpSess == nil {
				// 无可用主线路：丢弃本包，等下次触发重试
				udpBufPool.Put(bufPtr)
				continue
			}
			activeConns.Store(clientAddr.String(), udpSess)

			tmp := make([]byte, n)
			copy(tmp, payload)
			udpBufPool.Put(bufPtr)
			udpSess.enqueue(tmp)
			continue
		} else {
			// 复用连接时的内存策略：
			// 如果包很小，直接拷贝比占用 64KB 的池化内存更划算
			tmp := make([]byte, n)
			copy(tmp, payload)

			// resume/2 恒启用：复用现有 resume 会话，直接入队（内部 select+default 防阻塞）
			if sess, ok := v.(*udpSession); ok {
				udpBufPool.Put(bufPtr) // 归还主循环申请的缓冲区
				sess.enqueue(tmp)
				continue
			}
			udpBufPool.Put(bufPtr) // 归还原始大缓冲区
		}
	}
}
