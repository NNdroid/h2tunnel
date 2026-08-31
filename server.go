package main

import (
	"crypto/tls"
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

func isNetworkAllowed(reqNet, configuredNet string) bool {
	configuredNet = strings.ToLower(strings.TrimSpace(configuredNet))
	if configuredNet == "" || configuredNet == "all" || configuredNet == "both" || configuredNet == "tcp+udp" || configuredNet == "tcp,udp" {
		return true
	}
	reqNet = strings.ToLower(strings.TrimSpace(reqNet))
	return reqNet == configuredNet
}

func checkStrictTransport(r *http.Request, configuredTransport string, isWT, isMasqueTCP, isMasqueUDP bool) error {
	trans := strings.ToLower(strings.TrimSpace(configuredTransport))
	if trans == "" || trans == "all" || trans == "auto" {
		return nil // 全协议网关模式，全部允许
	}

	isGRPC := r.Method == http.MethodPost && (r.Header.Get("Content-Type") == "application/grpc" || strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc"))
	isH2Stream := r.Method == http.MethodPost && !isGRPC

	switch trans {
	case "grpc":
		if !isGRPC {
			return fmt.Errorf("transport policy violation: only gRPC allowed, got Method=%s Content-Type=%s", r.Method, r.Header.Get("Content-Type"))
		}
	case "h2", "h2c":
		if !isH2Stream {
			return fmt.Errorf("transport policy violation: only H2-Stream POST allowed, got Method=%s Protocol=%s", r.Method, r.Header.Get("Protocol"))
		}
	case "wt", "webtransport":
		if !isWT {
			return fmt.Errorf("transport policy violation: only WebTransport allowed, got Method=%s Protocol=%s", r.Method, r.Header.Get("Protocol"))
		}
	case "masque":
		if !isMasqueTCP && !isMasqueUDP {
			return fmt.Errorf("transport policy violation: only MASQUE allowed, got Method=%s Protocol=%s", r.Method, r.Header.Get("Protocol"))
		}
	case "h3", "http3", "http/3":
		if r.ProtoMajor != 3 && !strings.HasPrefix(r.Proto, "HTTP/3") {
			return fmt.Errorf("transport policy violation: only HTTP/3 allowed, got %s", r.Proto)
		}
	}
	return nil
}

func runServer(args []string) {
	startServerDirect(buildServerConfig(loadConfigFromArgs(args)))
}

func startServerDirect(cfg ServerConfig) {
	initLogger(cfg.LogLevel)
	defer zlog.Sync()

	// Apply transport mode if specified
	switch strings.ToLower(cfg.Transport) {
	case "h3", "http3", "http/3", "quic":
		cfg.EnableH3 = true
		cfg.EnableTLS = true
	case "wt", "webtransport":
		cfg.EnableH3 = true
		cfg.EnableTLS = true
	case "masque":
		cfg.EnableH3 = true
		cfg.EnableTLS = true
	case "grpc":
		cfg.EnableH3 = false
	case "h2", "tls":
		cfg.EnableTLS = true
		cfg.EnableH3 = false
	case "h2c", "cleartext", "plain":
		cfg.EnableTLS = false
		cfg.EnableH3 = false
	case "all", "auto":
		cfg.EnableH3 = true
	}

	netMode := strings.ToLower(strings.TrimSpace(cfg.Network))
	if netMode == "" {
		netMode = "all"
	}
	cfg.Network = netMode

	zlog.Infof("[Server] 🚀 h2tunnel %s starting...", Version)
	zlog.Infof("[Server] ⚙️ Config -> Listen: %s, Path: %s, Transport: %s, Network: %s, TLS: %v, H3: %v, LocalOnly: %v",
		cfg.ListenAddr, cfg.Path, cfg.Transport, cfg.Network, cfg.EnableTLS, cfg.EnableH3, cfg.LocalOnly)
	zlog.Infof("[Server] 🚦 Strict Demux Policy -> Transport: [%s], Network: [%s] (TCP Allowed: %v, UDP Allowed: %v)",
		cfg.Transport, cfg.Network, isNetworkAllowed("tcp", cfg.Network), isNetworkAllowed("udp", cfg.Network))

	mux := http.NewServeMux()
	var wtServer *webtransport.Server

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
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
		wtServer = &webtransport.Server{
			H3: &http3.Server{
				Addr:    cfg.ListenAddr,
				Handler: rootHandler,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   []string{http3.NextProtoH3},
				},
				EnableDatagrams: true,
				QUICConfig:      GetDefaultQUICConfig(),
			},
		}
		webtransport.ConfigureHTTP3Server(wtServer.H3)
		go func() {
			zlog.Infof("[H3 Server] 🚀 Listening (QUIC): %s", cfg.ListenAddr)
			if err := wtServer.ListenAndServe(); err != nil {
				zlog.Errorf("[H3 Server] Exited: %v", err)
			}
		}()
	}

	if hasTLS {
		server := &http.Server{
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
		server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		server := &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           h2c.NewHandler(rootHandler, &http2.Server{IdleTimeout: 1 * time.Hour}),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       1 * time.Hour,
		}
		zlog.Infof("[H2C Server] 🟡 Listening (H2C): %s", cfg.ListenAddr)
		server.ListenAndServe()
	}
}

func routeTunnelRequest(w http.ResponseWriter, r *http.Request, cfg ServerConfig, wtServer *webtransport.Server) {
	sessionID := fmt.Sprintf("SVR-%s-%d", r.RemoteAddr, time.Now().UnixNano()%10000)
	clientPhysicalAddr := r.RemoteAddr
	zlog.Debugf("[%s] === New incoming tunnel request ===", sessionID)
	zlog.Debugf("[%s] Proto: %s, Method: %s, Path: %s, Client Physical Addr: %s", sessionID, r.Proto, r.Method, r.URL.Path, clientPhysicalAddr)

	if !checkAuth(r, cfg.ExpectedToken) {
		zlog.Warnf("[%s] ❌ Authentication failed: Access denied (IP: %s)", sessionID, r.RemoteAddr)
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
	if !isNetworkAllowed(reqNetwork, cfg.Network) {
		zlog.Warnf("[%s] 🚫 严格分流拦截: 服务端限制 Network='%s'，拒绝 %s 请求 (IP: %s)", sessionID, cfg.Network, strings.ToUpper(reqNetwork), r.RemoteAddr)
		http.Error(w, fmt.Sprintf("%s traffic forbidden by server policy", strings.ToUpper(reqNetwork)), http.StatusForbidden)
		return
	}

	// 2. 严格传输协议分流校验 (Transport 限制)
	if err := checkStrictTransport(r, cfg.Transport, isWT, isMasqueTCP, false); err != nil {
		zlog.Warnf("[%s] 🚫 严格分流拦截: %v (IP: %s)", sessionID, err, r.RemoteAddr)
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
		zlog.Debugf("[%s] -> Dispatching to H2-Stream (POST) handler", sessionID)
		handleH2StreamServer(w, r, sessionID, cfg)
		return
	}

	zlog.Warnf("[%s] ❌ Unsupported request method or protocol combination", sessionID)
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func handleWebTransportServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg ServerConfig, wtServer *webtransport.Server) {
	network, target := GetXDst(r)
	if target == "" || !checkTargetIsAvailable(target, cfg) {
		zlog.Warnf("[%s] 🚫 Access denied for target address: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	session, err := wtServer.Upgrade(w, r)
	if err != nil {
		zlog.Errorf("[%s] ❌ WebTransport upgrade failed: %v", sessionID, err)
		return
	}
	zlog.Infof("[%s] ✅ WT Session established | Target: %s (%s)", sessionID, target, network)

	for {
		stream, err := session.AcceptStream(r.Context())
		if err != nil {
			zlog.Debugf("[%s] WT Session ended: %v", sessionID, err)
			break
		}

		streamID := fmt.Sprintf("%s-ST%d", sessionID, time.Now().UnixNano()%10000)
		zlog.Debugf("[%s] Accepted new WT Stream, dialing: %s", streamID, target)

		go func(s *webtransport.Stream, t string, netType string, sID string) {
			start := time.Now()
			tConn, errDial := net.DialTimeout(netType, t, 10*time.Second)
			if errDial != nil {
				zlog.Errorf("[%s] ❌ Failed to connect target: %v (duration: %v)", sID, errDial, time.Since(start))
				s.CancelWrite(1)
				return
			}
			defer tConn.Close()
			zlog.Infof("[%s] 🔗 WT target connected successfully (duration: %v)", sID, time.Since(start))

			var sReader io.Reader = s
			var sWriter io.Writer = s
			if netType != "udp" {
				sReader = &PaddingReader{r: s}
				sWriter = &PaddingWriter{w: s}
			}

			proxyStream(sID, netType, tConn, sReader, sWriter, nil)
			s.CancelRead(0)
		}(stream, target, network, streamID)
	}
}

func handleMasqueTCPServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg ServerConfig) {
	target, err := parseMasqueTarget("tcp", r.URL.Path)
	if err != nil {
		_, target = GetXDst(r)
	}

	if target == "" || !checkTargetIsAvailable(target, cfg) {
		zlog.Warnf("[%s] 🚫 Access denied for target address: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	start := time.Now()
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		zlog.Errorf("[%s] ❌ Failed to dial target: %v (duration: %v)", sessionID, err, time.Since(start))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	zlog.Infof("[%s] 🔗 MASQUE-TCP target connected successfully (duration: %v)", sessionID, time.Since(start))

	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if ok {
		flusher.Flush()
	}

	var tunnelReader io.Reader = &PaddingReader{r: r.Body}
	var tunnelWriter io.Writer = &PaddingWriter{w: w}
	proxyStream(sessionID, "tcp", targetConn, tunnelReader, tunnelWriter, flusher)
}

func handleH2StreamServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg ServerConfig) {
	network, target := GetXDst(r)
	if target == "" || !checkTargetIsAvailable(target, cfg) {
		zlog.Warnf("[%s] 🚫 Access denied for target address: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	isGRPC := r.Header.Get("Content-Type") == "application/grpc"
	start := time.Now()
	targetConn, err := net.DialTimeout(network, target, 10*time.Second)
	if err != nil {
		zlog.Errorf("[%s] ❌ Failed to dial target: %v", sessionID, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	zlog.Infof("[%s] 🔗 H2-Stream target connected successfully (duration: %v)", sessionID, time.Since(start))

	if isGRPC {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "Grpc-Status")
		w.Header().Add("Trailer", "Grpc-Message")
	}

	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if ok {
		flusher.Flush()
		zlog.Debugf("[%s] Sent 200 OK and Flushed", sessionID)
	}

	var tunnelReader io.Reader = r.Body
	var tunnelWriter io.Writer = w
	if isGRPC {
		tunnelReader = &grpcReader{r: r.Body}
		tunnelWriter = &grpcWriter{w: w}
	}
	if network != "udp" {
		tunnelReader = &PaddingReader{r: tunnelReader}
		tunnelWriter = &PaddingWriter{w: tunnelWriter}
	}

	proxyStream(sessionID, network, targetConn, tunnelReader, tunnelWriter, flusher)
}

func handleMasqueUDP(w http.ResponseWriter, r *http.Request, cfg ServerConfig) {
	sessionID := fmt.Sprintf("MUDP-%s-%d", r.RemoteAddr, time.Now().UnixNano()%1000)
	zlog.Debugf("[%s] === New MASQUE-UDP request ===", sessionID)

	// 1. 严格网络类型分流校验 (是否允许 UDP)
	if !isNetworkAllowed("udp", cfg.Network) {
		zlog.Warnf("[%s] 🚫 严格分流拦截: 服务端限制 Network='%s'，拒绝 MASQUE-UDP 请求 (IP: %s)", sessionID, cfg.Network, r.RemoteAddr)
		http.Error(w, "UDP traffic forbidden by server policy", http.StatusForbidden)
		return
	}

	// 2. 严格传输协议分流校验 (是否允许 MASQUE)
	if err := checkStrictTransport(r, cfg.Transport, false, false, true); err != nil {
		zlog.Warnf("[%s] 🚫 严格分流拦截: %v (IP: %s)", sessionID, err, r.RemoteAddr)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if !checkAuth(r, cfg.ExpectedToken) {
		zlog.Warnf("[%s] ❌ Authentication failed", sessionID)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	target, err := parseMasqueTarget("udp", r.URL.Path)
	if err != nil || target == "" || !checkTargetIsAvailable(target, cfg) {
		zlog.Warnf("[%s] 🚫 MASQUE-UDP target rejected or parse failed: %s", sessionID, r.URL.Path)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	tAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		zlog.Errorf("[%s] ❌ Failed to resolve UDP address: %v", sessionID, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	tConn, err := net.DialUDP("udp", nil, tAddr)
	if err != nil {
		zlog.Errorf("[%s] ❌ Failed to dial target UDP: %v", sessionID, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer tConn.Close()

	tConn.SetReadDeadline(time.Now().Add(60 * time.Second))
	zlog.Infof("[%s] 🔗 MASQUE-UDP connection ready -> %s", sessionID, target)

	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if ok {
		flusher.Flush()
		zlog.Debugf("[%s] Sent 200 OK and Flushed", sessionID)
	}

	proxyStream(sessionID, "masque-udp", tConn, r.Body, w, flusher)
}
