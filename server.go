package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/webtransport-go"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// setTunnelHeaders 装配穿透 CDN / 反代所必需的响应头。
//
// 背景（这是 CDN 场景下最隐蔽的一个坑）：Go 的 net/http 在 WriteHeader 时
// 若 handler 没有显式设置 Content-Type，会自动对响应前 512 字节做类型嗅探。
// 实测 SSH 握手首包 "SSH-2.0-OpenSSH_9.6p1..." 会被判成
// `text/plain; charset=utf-8`。CDN 一看到 text/* 就启用 gzip/brotli 并缓冲
// 整条响应 —— 隧道从流式退化成「攒够了才发」，实时性归零，同时压缩层还会
// 改写 Content-Length、破坏 chunk 边界。
//
// 因此必须：
//
//	Content-Type: application/octet-stream  明确声明是二进制流，禁止嗅探
//	Cache-Control: no-store, no-transform   禁止缓存与任何内容改写（含压缩）
//	X-Accel-Buffering: no                   Nginx 专用：关闭 proxy_buffering
//	Content-Encoding: identity              禁止 CDN 自作主张再压一层
func setTunnelHeaders(h http.Header) {
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Cache-Control", "no-store, no-transform")
	h.Set("Pragma", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	h.Set("Content-Encoding", "identity")
}

func runServer(args []string) {
	startServerDirect(buildServerConfig(loadConfigFromArgs(args, "server")))
}

func startServerDirect(cfg ServerConfig) {
	initLogger(cfg.LogLevel)
	defer zlog.Sync()

	var err error
	cfg, err = prepareServerConfig(cfg)
	if err != nil {
		zlog.Fatalf("[Server] ❌ invalid routing configuration: %v", err)
	}

	zlog.Infof("[Server] 🚀 h2tunnel %s starting...", Version)
	// resume/2 是唯一数据面（恒启用，v1 逃生通道已移除），服务端恒启动会话回收。
	startSessionReaper()
	zlog.Infof("[Server] 🔁 会话恢复已启用（窗口 %dKB，空闲 60s 超时回收）", cfg.SessionWindow)
	zlog.Infof("[Server] ⚙️ Config -> Listen: %s, Path: %s, Transport: %s, Network: %s, TLS: %v, H3: %v, LocalOnly: %v",
		cfg.ListenAddr, cfg.Path, cfg.Transport, cfg.Network, cfg.EnableTLS, cfg.EnableH3, cfg.LocalOnly)
	zlog.Infof("[Server] 🚦 Strict Demux Policy -> Transport: [%s], Network: [%s] (TCP Allowed: %v, UDP Allowed: %v)",
		cfg.Transport, cfg.Network, isNetworkAllowed("tcp", cfg.Network), isNetworkAllowed("udp", cfg.Network))

	mux := http.NewServeMux()
	var wtServer *webtransport.Server

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		// 必须禁止缓存：CDN 一旦缓存了这个响应，健康检查就永远读到旧结果，
		// 源站已经挂了而 CDN 还在转发流量（AWS ALB / Cloudflare 都踩过）
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK\n"))
	})

	mux.HandleFunc(cfg.Path, func(w http.ResponseWriter, r *http.Request) {
		routeTunnelRequest(w, r, cfg, wtServer)
	})

	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fullPath := r.RequestURI
		if fullPath == "" || !strings.HasPrefix(fullPath, "/") {
			fullPath = r.URL.Path
		}

		zlog.Debugf("[Server] Global request: %s %s (Host: %s)", r.Method, fullPath, r.Host)

		if r.Method == http.MethodConnect && (cfg.EnableH3 || strings.HasPrefix(fullPath, "/.well-known/masque/")) {
			matchedPath := fullPath
			if strings.HasPrefix(matchedPath, "/.well-known/masque/tcp/") {
				zlog.Debugf("[Server] Matched MASQUE-TCP route: %s", matchedPath)
				r.URL.Path = matchedPath
				routeTunnelRequest(w, r, cfg, wtServer)
				return
			}
			if strings.HasPrefix(matchedPath, "/.well-known/masque/udp/") {
				zlog.Debugf("[Server] Matched MASQUE-UDP route: %s", matchedPath)
				r.URL.Path = matchedPath
				handleMasqueUDP(w, r, cfg)
				return
			}
			if matchedPath == cfg.Path {
				zlog.Debugf("[Server] Matched custom CONNECT route: %s", matchedPath)
				routeTunnelRequest(w, r, cfg, wtServer)
				return
			}
			zlog.Warnf("[Server] 拒绝未知的 CONNECT 请求 | Path: '%s'", matchedPath)
			http.Error(w, "Unknown CONNECT Target", http.StatusNotFound)
			return
		}
		mux.ServeHTTP(w, r)
	})

	var cert tls.Certificate
	hasTLS := false

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		c, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			zlog.Fatalf("[Server] Failed to load certificate: %v", err)
		}
		cert = c
		hasTLS = true
	} else if cfg.EnableTLS || cfg.EnableH3 {
		c, _, err := GenerateSelfSignedCert("")
		if err != nil {
			zlog.Fatalf("[Server] Failed to generate self-signed certificate: %v", err)
		}
		cert = c
		hasTLS = true
		zlog.Infof("[Server] 🔐 Auto-generated self-signed TLS certificate")
	}

	if cfg.EnableH3 && hasTLS {
		wtServer = newH3WTServer(cfg.ListenAddr, rootHandler, cert)
		go func() {
			zlog.Infof("[H3 Server] 🚀 Listening (QUIC): %s", cfg.ListenAddr)
			if err := wtServer.ListenAndServe(); err != nil {
				zlog.Errorf("[H3 Server] Exited: %v", err)
			}
		}()
	}

	drainTimeout := cfg.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = drainDefault
	}

	var httpServer *http.Server
	if hasTLS {
		httpServer = &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           rootHandler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       1 * time.Hour,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"h2", "http/1.1"},
			},
		}
		zlog.Infof("[H2 Server] 🟢 Listening (TLS): %s", cfg.ListenAddr)
	} else {
		httpServer = &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           h2c.NewHandler(rootHandler, &http2.Server{IdleTimeout: 1 * time.Hour}),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       1 * time.Hour,
		}
		zlog.Infof("[H2C Server] 🟡 Listening (H2C): %s", cfg.ListenAddr)
	}

	// 监听错误必须显式上报：端口被占用时静默退出，systemd 只能看到一个
	// 没有原因的 exit，排查成本极高。
	serveErr := make(chan error, 1)
	go func() {
		if hasTLS {
			serveErr <- httpServer.ListenAndServeTLS("", "")
		} else {
			serveErr <- httpServer.ListenAndServe()
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			zlog.Errorf("[Server] ❌ 监听器异常退出: %v", err)
			shutdownServers(httpServer, wtServer, drainTimeout)
			os.Exit(1)
		}
	case sig := <-quit:
		zlog.Infof("[Server] 🛑 收到 %v，停止接收新连接，开始排空存量隧道 (上限 %v)", sig, drainTimeout)
		shutdownServers(httpServer, wtServer, drainTimeout)
	}
	zlog.Infof("[Server] 👋 已安全退出")
}

// shutdownServers 执行优雅下线：先关闭 QUIC 监听，再让 HTTP.Server 排空
// 活跃隧道。超过 timeout 仍未结束时强制 Close，避免 systemd kill 时
// 留下大量半开连接给 CDN（表现为 524 / 502 洪泛）。
func shutdownServers(httpServer *http.Server, wtServer *webtransport.Server, timeout time.Duration) {
	if wtServer != nil && wtServer.H3 != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		if err := wtServer.H3.Shutdown(ctx); err != nil {
			zlog.Debugf("[H3 Server] shutdown: %v", err)
			_ = wtServer.H3.Close()
		}
		cancel()
	}
	if httpServer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		zlog.Warnf("[Server] ⚠️ 排空超时 (%v)，强制关闭剩余连接: %v", timeout, err)
		_ = httpServer.Close()
		return
	}
	zlog.Infof("[Server] ✅ 所有隧道已安全排空")
}

func routeTunnelRequest(w http.ResponseWriter, r *http.Request, cfg ServerConfig, wtServer *webtransport.Server) {
	sessionID := fmt.Sprintf("SVR-%s-%d", r.RemoteAddr, time.Now().UnixNano()%10000)
	// CDN / 反代后面 RemoteAddr 恒为边缘节点地址，日志与审计改用
	// clientIP()（CF-Connecting-IP / X-Real-IP / X-Forwarded-For 回退链）。
	// 注意 clientIP 可被伪造，仅用于日志，不参与鉴权与访问控制。
	clientPhysicalAddr := clientIP(r)
	zlog.Debugf("[%s] === New incoming tunnel request ===", sessionID)
	zlog.Debugf("[%s] Proto: %s, Method: %s, Path: %s, Client Physical Addr: %s", sessionID, r.Proto, r.Method, r.URL.Path, clientPhysicalAddr)

	if !checkAuth(r, cfg.ExpectedToken) {
		zlog.Warnf("[%s] ❌ Authentication failed: Access denied (IP: %s)", sessionID, clientIP(r))
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	isMasqueTCP := r.Method == http.MethodConnect && r.Header.Get("Protocol") == "connect-tcp"
	isWT := wtServer != nil && r.Method == http.MethodConnect && r.Header.Get("Protocol") == "webtransport"

	reqNetwork, _ := GetXDst(r)
	if isMasqueTCP {
		reqNetwork = "tcp"
	}

	// 1. 严格网络类型分流校验 (TCP / UDP 限制)
	policy := cfg.effectiveRoutingPolicy()
	if !policy.allowsNetwork(reqNetwork) {
		zlog.Warnf("[%s] 🚫 严格分流拦截: 服务端限制 Network='%s'，拒绝 %s 请求 (IP: %s)", sessionID, cfg.Network, strings.ToUpper(reqNetwork), clientIP(r))
		http.Error(w, fmt.Sprintf("%s traffic forbidden by server policy", strings.ToUpper(reqNetwork)), http.StatusForbidden)
		return
	}

	// 2. 严格传输协议分流校验 (Transport 限制)
	if err := checkStrictTransportPolicy(r, policy, cfg.Transport, isWT, isMasqueTCP, false); err != nil {
		zlog.Warnf("[%s] 🚫 严格分流拦截: %v (IP: %s)", sessionID, err, clientIP(r))
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if isWT {
		zlog.Debugf("[%s] -> Dispatching to WebTransport handler", sessionID)
		handleWebTransportServer(w, r, sessionID, cfg, wtServer)
		return
	}
	if isMasqueTCP {
		zlog.Debugf("[%s] -> Dispatching to MASQUE-TCP handler", sessionID)
		handleMasqueTCPServer(w, r, sessionID, cfg)
		return
	}
	if r.Method == http.MethodPost {
		// resume/2 是唯一数据面（v1 已移除）：POST 必须携带 X-Tunnel-Proto: resume/2。
		if r.Header.Get("X-Tunnel-Proto") == resumeFrameTypeResume {
			zlog.Debugf("[%s] -> Dispatching to H2-Stream RESUME handler", sessionID)
			handleH2StreamResumeServer(w, r, sessionID, cfg)
			return
		}
		zlog.Debugf("[%s] -> 拒绝非 resume/2 的 POST（v1 已移除）", sessionID)
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
		return
	}

	zlog.Warnf("[%s] ❌ Unsupported request method or protocol combination", sessionID)
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// serveResumeDataPlane 服务端 resume/2 数据面公共逻辑：
// B 层握手（stream 模式）→ 下行补发（seq 重放）→ 上行帧循环。
// h2/grpc/masque 传 r.Body 作上行、http.ResponseWriter writer 作下行；
// wt 传 webtransport.Stream 作上行、同 stream writer 作下行。二者复用同一引擎，
// 保证断线（流断）后会话 targetConn 保留，下次同 session id 的新流可续传。
func serveResumeDataPlane(sess *tunnelSession, up io.Reader, writer *resumeSessionWriter, params resumeParams, clientDownlink uint64, sessionID string, handshakeAlreadyDone bool, clearWriter func(*resumeSessionWriter)) {
	datagram := sess.datagram

	// ===== B 层握手确认（stream 模式）=====
	// 业务数据前先等客户端 HANDSHAKE 控制帧并回 HANDSHAKE-ACK，
	// 证明这条流端到端真正活着。datagram 模式靠 A 层 + 数据报往返。
	// wt 分支已在外部完成 B 层握手并解析出 clientDownlink（见 handleWebTransportServer），
	// 此时 handshakeAlreadyDone=true 跳过，避免重复读首帧。
	if !datagram && !handshakeAlreadyDone {
		if !doServerHandshakeAck(up, writer, params.handshakeAckMs, sessionID) {
			return
		}
	}

	// activeWriter 必须等 B 层握手（HANDSHAKE-ACK 已写出）之后才挂载：
	// 否则 downlinkPump 可能在 HANDSHAKE-ACK 之前把 DATA 帧写进新流，
	// 客户端首帧读到 DATA 而非 HANDSHAKE-ACK，握手即失败。
	// clearActiveWriter 由本函数的 defer 负责（含早退路径）。writer 写失败
	// 时不会反向获取 session 锁，避免 downlinkPump 的锁顺序反转。
	sess.setActiveWriter(writer)
	defer clearWriter(writer)

	if !datagram {
		// stream 模式：补发下行缺口（seq 重放）。
		if err := sess.replayDownlink(writer, clientDownlink); err != nil {
			zlog.Warnf("[%s] ❌ 下行补发失败（可能窗口已被覆盖）: %v", sessionID, err)
			_ = writer.writeEnd()
			return // defer clearWriter(writer) 负责清空 activeWriter
		}
	}

	// 上行帧循环
	payloadBuf := make([]byte, 64*1024)
	for {
		var (
			typ byte
			seq uint64
			n   int
			err error
		)
		if datagram {
			// UDP：解出一个数据报包（不做 seq 校验）。
			n, err = sess.frameR(up, payloadBuf)
		} else {
			typ, seq, n, err = readFrame(up, payloadBuf)
		}
		if errors.Is(err, ErrResumeEndFrame) {
			zlog.Debugf("[%s] Resume END 帧收到", sessionID)
			sess.touch()
			return
		}
		if err != nil {
			zlog.Debugf("[%s] Resume 上行读结束: %v", sessionID, err)
			return
		}
		if !datagram {
			switch typ {
			case resumeFrameKeepalive:
				sess.touch()
				if err := writer.writeControl(resumeFrameKeepaliveAck, nil); err != nil {
					return
				}
				continue
			case resumeFrameData:
				// 业务帧继续走 seq 校验与投递。
			default:
				zlog.Warnf("[%s] Resume 上行收到非业务帧 0x%02x", sessionID, typ)
				return
			}
		}
		if err := sess.acceptUplinkSeq(seq, payloadBuf[:n]); err != nil {
			zlog.Warnf("[%s] ❌ Resume 上行 seq 错误: %v", sessionID, err)
			return
		}
	}
}

// parseHeaderVersion 解析 X-Resume-Version 头（客户端最高支持版本）。
func parseHeaderVersion(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// resumeRoleLabel 会话角色日志标签
func resumeRoleLabel(isBackup bool) string {
	if isBackup {
		return "backup"
	}
	return "primary"
}

// serverCapabilities 服务端支持的能力集（由 cfg 派生）。
func serverCapabilities(cfg ServerConfig) resumeCaps {
	return resumeCaps{
		datagram:   cfg.effectiveRoutingPolicy().allowsNetwork(networkUDP),
		backupLine: true,
	}
}

// doServerHandshakeAck 等待客户端 HANDSHAKE 控制帧并回 HANDSHAKE-ACK。
// up 是上行读取源（h2: r.Body；wt: stream）。超时返回 false（握手失败）。
func doServerHandshakeAck(up io.Reader, writer *resumeSessionWriter, timeoutMs int, sessionID string) bool {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	// 读取 HANDSHAKE 帧：设读超时避免永久阻塞。
	type readResult struct {
		typ byte
		n   int
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		payloadBuf := make([]byte, 64*1024)
		typ, _, n, err := readFrame(up, payloadBuf)
		done <- readResult{typ, n, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			zlog.Warnf("[%s] ❌ HANDSHAKE 读取失败: %v", sessionID, res.err)
			return false
		}
		if res.typ != resumeFrameHandshake || res.n != 0 {
			zlog.Warnf("[%s] ❌ 首个帧非 HANDSHAKE（0x%02x），握手失败", sessionID, res.typ)
			return false
		}
	case <-time.After(timeout):
		zlog.Warnf("[%s] ❌ HANDSHAKE 超时 (%v)", sessionID, timeout)
		return false
	}
	// 回 HANDSHAKE-ACK
	if err := writer.writeControl(resumeFrameHandshakeAck, nil); err != nil {
		zlog.Warnf("[%s] ❌ 写 HANDSHAKE-ACK 失败: %v", sessionID, err)
		return false
	}
	zlog.Debugf("[%s] ✅ B 层握手确认完成 (HANDSHAKE→HANDSHAKE-ACK)", sessionID)
	return true
}

// serveBackupKeepaliveOnly 备用（探活）线路存活应答循环：
// 持续读客户端 KEEPALIVE 控制帧并回 KEEPALIVE-ACK，直至流结束或超时。
// 探活线路不挂业务会话（sess 为 nil），故只做控制帧应答，不做 touch/业务。
func serveBackupKeepaliveOnly(up io.Reader, writer *resumeSessionWriter, params resumeParams, sessionID string) {
	keepaliveTimeout := time.Duration(params.keepaliveSec) * 3 * time.Second
	if keepaliveTimeout <= 0 {
		keepaliveTimeout = 45 * time.Second
	}
	payloadBuf := make([]byte, 64*1024)
	for {
		// 备用线路可能长时间无 KEEPALIVE，用带超时读。
		type readResult struct {
			typ byte
			err error
		}
		done := make(chan readResult, 1)
		go func() {
			typ, _, _, err := readFrame(up, payloadBuf)
			done <- readResult{typ, err}
		}()
		select {
		case res := <-done:
			if res.err != nil {
				zlog.Debugf("[%s] 备用线路流结束: %v", sessionID, res.err)
				return
			}
			if res.typ == resumeFrameKeepalive {
				if err := writer.writeControl(resumeFrameKeepaliveAck, nil); err != nil {
					return
				}
			}
		case <-time.After(keepaliveTimeout):
			zlog.Warnf("[%s] 备用线路 KEEPALIVE 超时，判定失效", sessionID)
			return
		}
	}
}

// modeLabel 会话恢复数据面标签（日志用）
func modeLabel(datagram bool) string {
	if datagram {
		return "datagram"
	}
	return "stream"
}
