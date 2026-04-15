package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func runServer(args []string) {
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	cfg := ServerConfig{}
	serverCmd.StringVar(&cfg.ListenAddr, "listen", ":8443", "服务端监听地址")
	serverCmd.StringVar(&cfg.TLSCert, "cert", "", "TLS 证书文件路径")
	serverCmd.StringVar(&cfg.TLSKey, "key", "", "TLS 私钥文件路径")
	serverCmd.StringVar(&cfg.Path, "path", "/tunnel", "代理路径")
	serverCmd.BoolVar(&cfg.LocalOnly, "local-only", false, "是否只允许转发到本地")
	serverCmd.StringVar(&cfg.LogLevel, "loglevel", "info", "日志等级")
	serverCmd.BoolVar(&cfg.EnableH3, "h3", false, "开启 HTTP/3 监听")
	serverCmd.StringVar(&cfg.ExpectedToken, "token", "", "预期的 Proxy-Authorization Token")
	serverCmd.Parse(args)

	initLogger(cfg.LogLevel)
	defer zlog.Sync()
	zlog.Infof("[Server] 🚀 h2tunnel %s 正在启动...", Version)
	zlog.Infof("[Server] ⚙️ 配置 -> 监听: %s, 路径: %s, H3: %v, LocalOnly: %v", cfg.ListenAddr, cfg.Path, cfg.EnableH3, cfg.LocalOnly)

	mux := http.NewServeMux()
	var wtServer *webtransport.Server

	mux.HandleFunc(cfg.Path, func(w http.ResponseWriter, r *http.Request) {
		routeTunnelRequest(w, r, cfg, wtServer)
	})

	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fullPath := r.RequestURI
		if fullPath == "" || !strings.HasPrefix(fullPath, "/") { fullPath = r.URL.Path }

		zlog.Debugf("[Server] 收到全局请求: %s %s (Host: %s)", r.Method, fullPath, r.Host)

		if r.Method == http.MethodConnect && cfg.EnableH3 {
			matchedPath := fullPath
			if strings.HasPrefix(matchedPath, "/.well-known/masque/tcp/") {
				zlog.Debugf("[Server] 命中 MASQUE-TCP 路由: %s", matchedPath)
				r.URL.Path = matchedPath
				routeTunnelRequest(w, r, cfg, wtServer)
				return
			}
			if strings.HasPrefix(matchedPath, "/.well-known/masque/udp/") {
				zlog.Debugf("[Server] 命中 MASQUE-UDP 路由: %s", matchedPath)
				r.URL.Path = matchedPath
				handleMasqueUDP(w, r, cfg)
				return
			}
			if matchedPath == cfg.Path {
				zlog.Debugf("[Server] 命中自定义 CONNECT 路由: %s", matchedPath)
				routeTunnelRequest(w, r, cfg, wtServer)
				return
			}
			zlog.Warnf("[Server] 拒绝未知的 CONNECT 请求 | 路径: '%s'", matchedPath)
			http.Error(w, "Unknown CONNECT Target", http.StatusNotFound)
			return
		}
		mux.ServeHTTP(w, r)
	})

	if cfg.EnableH3 {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil { zlog.Fatalf("[Server] 无法加载证书: %v", err) }
		wtServer = &webtransport.Server{
			H3: &http3.Server{
				Addr:    cfg.ListenAddr,
				Handler: rootHandler,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   []string{http3.NextProtoH3},
				},
				EnableDatagrams: true,
				QUICConfig: GetDefaultQUICConfig(),
			},
		}
		webtransport.ConfigureHTTP3Server(wtServer.H3)
		go func() {
			zlog.Infof("[H3 Server] 🚀 Listening (QUIC): %s", cfg.ListenAddr)
			if err := wtServer.ListenAndServe(); err != nil {
				zlog.Errorf("[H3 Server] 退出: %v", err)
			}
		}()
	}

	if cfg.TLSCert != "" {
		server := &http.Server{Addr: cfg.ListenAddr, Handler: rootHandler}
		zlog.Infof("[H2 Server] 🟢 Listening (TLS): %s", cfg.ListenAddr)
		server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		server := &http.Server{Addr: cfg.ListenAddr, Handler: h2c.NewHandler(rootHandler, &http2.Server{})}
		zlog.Infof("[H2C Server] 🟡 Listening (H2C): %s", cfg.ListenAddr)
		server.ListenAndServe()
	}
}

func routeTunnelRequest(w http.ResponseWriter, r *http.Request, cfg ServerConfig, wtServer *webtransport.Server) {
	// 生成唯一的 Trace ID
	sessionID := fmt.Sprintf("SVR-%s-%d", r.RemoteAddr, time.Now().UnixNano()%10000)
	clientPhysicalAddr := r.RemoteAddr
	zlog.Debugf("[%s] === 新请求进入路由层 ===", sessionID)
	zlog.Debugf("[%s] 协议: %s, Method: %s, Path: %s, 客户端物理通道IP:端口: %s", sessionID, r.Proto, r.Method, r.URL.Path, clientPhysicalAddr)

	// 判断是否允许访问
	if !checkAuth(r, cfg.ExpectedToken) {
		zlog.Warnf("[%s] ❌ 认证失败: 拒绝访问 (IP: %s)", sessionID, r.RemoteAddr)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	isMasqueTCP := r.Method == http.MethodConnect && r.Header.Get("Protocol") == "connect-tcp"
	isWT := wtServer != nil && r.Method == http.MethodConnect && r.Header.Get("Protocol") == "webtransport"

	if isWT {
		zlog.Debugf("[%s] -> 分发至 WebTransport 处理器", sessionID)
		handleWebTransportServer(w, r, sessionID, cfg, wtServer)
		return
	}
	if isMasqueTCP {
		zlog.Debugf("[%s] -> 分发至 MASQUE-TCP 处理器", sessionID)
		handleMasqueTCPServer(w, r, sessionID, cfg)
		return
	}
	if r.Method == http.MethodPost {
		zlog.Debugf("[%s] -> 分发至 H2-Stream (POST) 处理器", sessionID)
		handleH2StreamServer(w, r, sessionID, cfg)
		return
	}

	zlog.Warnf("[%s] ❌ 不支持的请求方法或协议组合", sessionID)
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// 从头部获取目标
func handleWebTransportServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg ServerConfig, wtServer *webtransport.Server) {
	// 先提取目标地址并做安全校验（在 Upgrade 之前）
	network, target := GetXDst(r)
	
	// 注意逻辑反转：如果 target 为空，或者“不允许访问”，则返回 403
	// （假设 checkTargetIsAvailable 返回 true 代表允许，false 代表拒绝）
	if target == "" || !checkTargetIsAvailable(target, cfg) {
		zlog.Warnf("[%s] 🚫 被拒绝的目标地址: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 校验通过后，再执行 WebTransport 升级
	session, err := wtServer.Upgrade(w, r)
	if err != nil {
		zlog.Errorf("[%s] ❌ WebTransport 升级失败: %v", sessionID, err)
		return
	}
	zlog.Infof("[%s] ✅ WT Session 建立成功 | 预期目标: %s (%s)", sessionID, target, network)

	for {
		stream, err := session.AcceptStream(r.Context())
		if err != nil {
			zlog.Debugf("[%s] WT Session 结束接管 Stream: %v", sessionID, err)
			break
		}
		
		// 保留之前修复的伪 StreamID 逻辑
		streamID := fmt.Sprintf("%s-ST%d", sessionID, time.Now().UnixNano()%10000)
		zlog.Debugf("[%s] 接受新 WT Stream, 准备拨号: %s", streamID, target)

		// ⚠️这里必须是 *webtransport.Stream，因为 Read/Write 方法是指针接收者
		go func(s *webtransport.Stream, t string, netType string, sID string) {
			start := time.Now()
			tConn, errDial := net.Dial(netType, t)
			if errDial != nil {
				zlog.Errorf("[%s] ❌ 连接目标失败: %v (耗时: %v)", sID, errDial, time.Since(start))
				s.CancelWrite(1)
				return
			}
			defer tConn.Close()
			zlog.Infof("[%s] 🔗 WT 目标连接成功 (耗时: %v), 开始代理", sID, time.Since(start))
			
			proxyStream(sID, netType, tConn, s, s, nil)
			s.CancelRead(0)
		}(stream, target, network, streamID) // 传入 stream 指针
	}
}

// 从URL获取目标
func handleMasqueTCPServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg ServerConfig) {
	target, err := parseMasqueTarget("tcp", r.URL.Path)
	if err != nil {
		zlog.Errorf("[%s] ❌ MASQUE 路径解析失败: %s, Err: %v", sessionID, r.URL.Path, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 判断是否允许访问
	if target == "" || !checkTargetIsAvailable(target, cfg) {
		zlog.Warnf("[%s] 🚫 被拒绝的目标地址: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	start := time.Now()
	zlog.Debugf("[%s] 正在拨号目标 TCP: %s", sessionID, target)
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		zlog.Errorf("[%s] ❌ 拨号目标失败: %v (耗时: %v)", sessionID, err, time.Since(start))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	zlog.Infof("[%s] 🔗 MASQUE-TCP 目标连接成功 (耗时: %v)", sessionID, time.Since(start))

	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if ok {
		flusher.Flush()
		zlog.Debugf("[%s] 已向客户端 Flush 200 OK，开始双向数据流", sessionID)
	} else {
		zlog.Warnf("[%s] ⚠️ 警告: ResponseWriter 不支持 Flusher，代理可能发生缓冲延迟！", sessionID)
	}
	proxyStream(sessionID, "tcp", targetConn, r.Body, w, flusher)
}

// 从头部获取目标
func handleH2StreamServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg ServerConfig) {
	network, target := GetXDst(r)

	// 判断是否允许访问
	if target == "" || !checkTargetIsAvailable(target, cfg) {
		zlog.Warnf("[%s] 🚫 H2 被拒绝的目标地址: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	isGRPC := r.Header.Get("Content-Type") == "application/grpc"
	zlog.Debugf("[%s] 解析目标: %s (%s), gRPC伪装: %v", sessionID, target, network, isGRPC)

	start := time.Now()
	targetConn, err := net.Dial(network, target)
	if err != nil {
		zlog.Errorf("[%s] ❌ 拨号目标失败: %v", sessionID, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	zlog.Infof("[%s] 🔗 H2-Stream 目标连接成功 (耗时: %v)", sessionID, time.Since(start))

	if isGRPC {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "Grpc-Status")
		w.Header().Add("Trailer", "Grpc-Message")
	}

	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if ok {
		flusher.Flush()
		zlog.Debugf("[%s] 已发送 200 OK 并 Flush", sessionID)
	} else {
		zlog.Warnf("[%s] ⚠️ 警告: ResponseWriter 不支持 Flusher，代理可能发生缓冲延迟！", sessionID)
	}

	var tunnelReader io.Reader = r.Body
	var tunnelWriter io.Writer = w
	if isGRPC {
		tunnelReader = &grpcReader{r: r.Body}
		tunnelWriter = &grpcWriter{w: w}
	}
	
	// 无论如何都要进入代理逻辑，不能跳过！
	proxyStream(sessionID, network, targetConn, tunnelReader, tunnelWriter, flusher)
}

// 从URL获取目标
func handleMasqueUDP(w http.ResponseWriter, r *http.Request, cfg ServerConfig) {
	sessionID := fmt.Sprintf("MUDP-%s-%d", r.RemoteAddr, time.Now().UnixNano()%1000)
	zlog.Debugf("[%s] === 新 MASQUE-UDP 请求 ===", sessionID)

	if !checkAuth(r, cfg.ExpectedToken) {
		zlog.Warnf("[%s] ❌ 认证失败", sessionID)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	target, err := parseMasqueTarget("udp", r.URL.Path)
	// 判断是否允许访问
	if err != nil || target == "" || !checkTargetIsAvailable(target, cfg) {
		zlog.Warnf("[%s] 🚫 MASQUE-UDP 目标拒绝或解析失败: %s", sessionID, r.URL.Path)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	
	zlog.Debugf("[%s] 正在解析目标 UDP: %s", sessionID, target)
	tAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		zlog.Errorf("[%s] ❌ 解析 UDP 地址失败: %v", sessionID, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	tConn, err := net.DialUDP("udp", nil, tAddr)
	if err != nil {
		zlog.Errorf("[%s] ❌ 连接目标 UDP 失败: %v", sessionID, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer tConn.Close()
	
	// 这里可以设置一个相对宽松的 ReadDeadline，防止 UDP 僵尸连接，
	// 也可以在 proxyStream 里统一定义。
	tConn.SetReadDeadline(time.Now().Add(60 * time.Second))
	zlog.Infof("[%s] 🔗 MASQUE-UDP 连接就绪 -> %s", sessionID, target)

	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if ok {
		flusher.Flush()
		zlog.Debugf("[%s] 已发送 200 OK 并 Flush", sessionID)
	} else {
		zlog.Warnf("[%s] ⚠️ 警告: ResponseWriter 不支持 Flusher，代理可能发生缓冲延迟！", sessionID)
	}
	proxyStream(sessionID, "masque-udp", tConn, r.Body, w, flusher)
}