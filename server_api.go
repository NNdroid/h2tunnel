package h2tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/webtransport-go"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Server is an embeddable, single-lifecycle tunnel server.
type Server struct {
	cfg      serverConfig
	sessions *sessionTable
	log      *slog.Logger

	rootHandler http.Handler
	httpServer  *http.Server
	h2srv       *http2.Server
	wtServer    *webtransport.Server

	ctx        context.Context
	cancel     context.CancelFunc
	reaperStop chan struct{}
	reaperOnce sync.Once
	startOnce  sync.Once

	mu        sync.Mutex
	serving   bool
	served    bool
	closing   bool
	closed    bool
	stats     stats
	listeners Listeners
	httpConns map[net.Conn]struct{}
}

// h2 接收窗口（服务端上行方向的流控背压）。x/net 默认每流/每连接各 1MB，
// 是 CDN 高 RTT 链路上行吞吐的主要瓶颈；8MB 单流窗口在 100ms RTT 下允许
// 约 640Mbps 的在途数据。上限以服务端每会话内存为代价（SessionWindow 的
// ring 是独立的有界缓冲，不受此影响）。
const (
	h2UploadBufferPerStream     = 8 << 20  // 8MB
	h2UploadBufferPerConnection = 32 << 20 // 32MB
)

// NewServer validates options and creates a server without opening sockets or
// starting goroutines.
func NewServer(options ServerOptions) (*Server, error) {
	if options.Authenticator == nil {
		return nil, errors.New("h2tunnel: ServerOptions.Authenticator is required")
	}
	if options.Dialer == nil {
		return nil, errors.New("h2tunnel: ServerOptions.Dialer is required")
	}
	transportList, err := normalizeServerTransports(options.Transports)
	if err != nil {
		return nil, err
	}
	networkList, err := normalizeServerNetworks(options.Networks)
	if err != nil {
		return nil, err
	}
	windowKB, err := windowBytesToKB(options.Tuning.SessionWindowBytes)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	cfg := serverConfig{
		Path:               normalizeTunnelPath(options.Path),
		Transport:          transportList,
		Network:            networkList,
		SessionWindow:      windowKB,
		SessionIdleTimeout: options.Tuning.SessionIdleTimeout,
		Authenticator:      options.Authenticator,
		TargetDialer:       options.Dialer,
		ServerContext:      ctx,
	}
	if options.TLSConfig != nil {
		cfg.TLSConfig = options.TLSConfig.Clone()
		cfg.EnableTLS = true
	}
	cfg, err = prepareServerConfig(cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("h2tunnel: invalid server options: %w", err)
	}
	if cfg.EnableH3 && cfg.TLSConfig == nil {
		cancel()
		return nil, errors.New("h2tunnel: H3, WebTransport, and MASQUE require ServerOptions.TLSConfig (see h2tunnel.SelfSignedTLSConfig for development)")
	}
	if cfg.TLSConfig != nil && len(cfg.TLSConfig.Certificates) == 0 && cfg.TLSConfig.GetCertificate == nil {
		cancel()
		return nil, errors.New("h2tunnel: ServerOptions.TLSConfig has no certificate")
	}

	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		cfg:        cfg,
		log:        logger,
		ctx:        ctx,
		cancel:     cancel,
		reaperStop: make(chan struct{}),
		httpConns:  make(map[net.Conn]struct{}),
	}
	s.sessions = &sessionTable{
		sessions:    make(map[string]*tunnelSession),
		logger:      s.log,
		idleTimeout: cfg.SessionIdleTimeout,
	}
	if s.sessions.idleTimeout <= 0 {
		s.sessions.idleTimeout = sessionIdleTimeout
	}
	s.rootHandler = s.buildRootHandler()
	if cfg.EnableH3 {
		s.wtServer = newH3WTServer("", s.rootHandler, cfg.TLSConfig)
	}
	handler := s.rootHandler
	// h2 接收窗口（上行方向的流控背压）：x/net 默认每流/每连接各 1MB，
	// 在途 1MB ÷ 100ms RTT ≈ 80Mbps，是 CDN 高 RTT 链路上行吞吐的主要
	// 瓶颈。放大窗口让背压留在隧道会话层（ring 有界），而不是让 h2 流控
	// 先行卡死。客户端下行方向 x/net Transport 默认 4MB/流，无需调整。
	h2srv := &http2.Server{
		IdleTimeout:                  time.Hour,
		MaxUploadBufferPerStream:     h2UploadBufferPerStream,
		MaxUploadBufferPerConnection: h2UploadBufferPerConnection,
	}
	s.h2srv = h2srv
	if !cfg.EnableTLS {
		handler = h2c.NewHandler(handler, h2srv)
	}
	s.httpServer = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Hour,
		ConnState:         s.trackHTTPConnection,
	}
	if cfg.TLSConfig != nil {
		tlsConfig := cfg.TLSConfig.Clone()
		if !slices.Contains(tlsConfig.NextProtos, "h2") {
			tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
		}
		s.httpServer.TLSConfig = tlsConfig
		// net/http 自动装配的 http2.Server 使用默认 1MB 上行窗口；自定义
		// 窗口必须显式 ConfigureServer（必须在开始服务之前调用）。
		if err := http2.ConfigureServer(s.httpServer, h2srv); err != nil {
			cancel()
			return nil, fmt.Errorf("h2tunnel: configure HTTP/2 server: %w", err)
		}
	}
	s.cfg.stats = &s.stats.server
	return s, nil
}

func (s *Server) buildRootHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})
	mux.HandleFunc(s.cfg.Path, func(w http.ResponseWriter, r *http.Request) {
		routeTunnelRequest(w, r, s.cfg, s.wtServer, s.sessions)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fullPath := r.RequestURI
		if fullPath == "" || !strings.HasPrefix(fullPath, "/") {
			fullPath = r.URL.Path
		}
		if r.Method == http.MethodConnect {
			// MASQUE 路径基座支持自定义前缀（masquePathBase），空前缀 = 标准
			// /.well-known/masque；parseMasqueTarget 本身按段扫描，前缀无关。
			masqueBase := masquePathBase(s.cfg.Path)
			switch {
			case strings.HasPrefix(fullPath, masqueBase+"/tcp/"):
				r.URL.Path = fullPath
				routeTunnelRequest(w, r, s.cfg, s.wtServer, s.sessions)
				return
			case strings.HasPrefix(fullPath, masqueBase+"/udp/"):
				r.URL.Path = fullPath
				handleMasqueUDP(w, r, s.cfg, s.sessions)
				return
			case fullPath == s.cfg.Path:
				routeTunnelRequest(w, r, s.cfg, s.wtServer, s.sessions)
				return
			default:
				http.NotFound(w, r)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// Handler returns the tunnel handler for embedding in an existing HTTP server.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ensureRunning() {
			http.Error(w, "server shutting down", http.StatusServiceUnavailable)
			return
		}
		s.rootHandler.ServeHTTP(w, r)
	})
}

// Serve owns the supplied listeners and blocks until all enabled transports
// stop. A failure in one listener stops its sibling before Serve returns.
func (s *Server) Serve(listeners Listeners) error {
	if err := s.validateListeners(listeners); err != nil {
		return err
	}
	s.mu.Lock()
	if s.closing || s.closed {
		s.mu.Unlock()
		closeListeners(listeners)
		return net.ErrClosed
	}
	if s.serving || s.served {
		s.mu.Unlock()
		closeListeners(listeners)
		return errors.New("h2tunnel: Server.Serve called more than once")
	}
	s.serving = true
	s.served = true
	s.listeners = listeners
	s.mu.Unlock()
	s.ensureRunning()
	s.log.Debug("serving tunnel", "tcp", listeners.TCP != nil, "quic", listeners.QUIC != nil)

	type result struct {
		kind string
		err  error
	}
	count := 0
	results := make(chan result, 2)
	if listeners.TCP != nil {
		count++
		go func() {
			var err error
			if !s.cfg.EnableTLS {
				err = s.httpServer.Serve(listeners.TCP)
			} else {
				err = s.httpServer.ServeTLS(listeners.TCP, "", "")
			}
			results <- result{kind: "tcp", err: err}
		}()
	}
	if listeners.QUIC != nil {
		count++
		go func() {
			results <- result{kind: "quic", err: s.wtServer.Serve(listeners.QUIC)}
		}()
	}

	first := <-results
	_ = s.closeListenersOnly()
	for i := 1; i < count; i++ {
		<-results
	}
	s.mu.Lock()
	s.serving = false
	wasClosing := s.closing || s.closed
	s.mu.Unlock()
	if wasClosing || first.err == nil ||
		errors.Is(first.err, http.ErrServerClosed) || errors.Is(first.err, net.ErrClosed) {
		if !wasClosing {
			s.finishClose()
		}
		return nil
	}
	s.finishClose()
	s.log.Error("tunnel listener failed", "listener", first.kind, "error", first.err)
	return fmt.Errorf("h2tunnel: %s listener failed: %w", first.kind, first.err)
}

// ListenAndServe opens the listeners required by the configured transports.
// TCP and QUIC use the same numeric port, including when address uses port 0.
func (s *Server) ListenAndServe(address string) error {
	address = strings.TrimSpace(address)
	if address == "" {
		address = ":8443"
	}
	needTCP, needQUIC := s.requiredListeners()
	var listeners Listeners
	var err error
	if needTCP {
		listeners.TCP, err = net.Listen("tcp", address)
		if err != nil {
			return err
		}
	}
	if needQUIC {
		quicAddress := address
		if listeners.TCP != nil {
			host, _, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				_ = listeners.TCP.Close()
				return splitErr
			}
			_, port, splitErr := net.SplitHostPort(listeners.TCP.Addr().String())
			if splitErr != nil {
				_ = listeners.TCP.Close()
				return splitErr
			}
			quicAddress = net.JoinHostPort(host, port)
		}
		listeners.QUIC, err = net.ListenPacket("udp", quicAddress)
		if err != nil {
			closeListeners(listeners)
			return err
		}
	}
	return s.Serve(listeners)
}

// Shutdown stops new requests and waits for owned HTTP/QUIC servers to drain.
func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Debug("shutting down tunnel server")
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	s.mu.Unlock()

	var errs []error
	if s.wtServer != nil && s.wtServer.H3 != nil {
		if err := s.wtServer.H3.Shutdown(ctx); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, err)
		}
	}
	s.closeQUICListener()
	if err := s.closeTrackedHTTPConnections(); err != nil {
		errs = append(errs, err)
	}
	if ctx.Err() != nil {
		return errors.Join(append(errs, ctx.Err())...)
	}
	s.finishClose()
	return errors.Join(errs...)
}

// Close immediately terminates listeners, target connections, and sessions.
func (s *Server) Close() error {
	s.log.Debug("closing tunnel server")
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	s.mu.Unlock()
	var errs []error
	if s.wtServer != nil && s.wtServer.H3 != nil {
		if err := s.wtServer.H3.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if s.httpServer != nil {
		if err := s.httpServer.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, err)
		}
	}
	s.closeQUICListener()
	if err := s.closeTrackedHTTPConnections(); err != nil {
		errs = append(errs, err)
	}
	s.finishClose()
	return errors.Join(errs...)
}

// closeQUICListener 关闭 Serve 接收的外部 QUIC PacketConn。
// quic-go 的 H3.Close/Shutdown 不管理经 Serve(conn) 传入的外部 conn，
// 不显式关闭的话 Serve 的 QUIC goroutine 永不返回，Shutdown/Close 卡死。
// net/http 对 TCP listener 有自己的跟踪（Shutdown/Close 会关闭），无需处理。
func (s *Server) closeQUICListener() {
	s.mu.Lock()
	quic := s.listeners.QUIC
	s.mu.Unlock()
	if quic != nil {
		_ = quic.Close()
	}
}

func (s *Server) finishClose() {
	s.reaperOnce.Do(func() { close(s.reaperStop) })
	s.cancel()
	s.sessions.closeAll()
	s.mu.Lock()
	s.closed = true
	s.closing = true
	s.mu.Unlock()
}

func (s *Server) closeListenersOnly() error {
	var errs []error
	if s.wtServer != nil && s.wtServer.H3 != nil {
		if err := s.wtServer.H3.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if s.httpServer != nil {
		if err := s.httpServer.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, err)
		}
	}
	s.closeQUICListener()
	if err := s.closeTrackedHTTPConnections(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// h2c.NewHandler hijacks the accepted TCP connection before handing it to
// http2.Server. net/http deliberately stops tracking hijacked connections, so
// http.Server.Shutdown and Close cannot terminate them. Keep ownership here so
// the embeddable Server lifecycle also covers h2c tunnels.
func (s *Server) trackHTTPConnection(conn net.Conn, state http.ConnState) {
	closeNow := false
	s.mu.Lock()
	switch state {
	case http.StateClosed:
		delete(s.httpConns, conn)
	default:
		if s.closing || s.closed {
			closeNow = true
		} else {
			s.httpConns[conn] = struct{}{}
		}
	}
	s.mu.Unlock()
	if closeNow {
		_ = conn.Close()
	}
}

func (s *Server) closeTrackedHTTPConnections() error {
	s.mu.Lock()
	connections := make([]net.Conn, 0, len(s.httpConns))
	for conn := range s.httpConns {
		connections = append(connections, conn)
		delete(s.httpConns, conn)
	}
	s.mu.Unlock()

	var errs []error
	for _, conn := range connections {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Server) ensureRunning() bool {
	s.mu.Lock()
	if s.closing || s.closed {
		s.mu.Unlock()
		return false
	}
	s.mu.Unlock()
	s.startOnce.Do(func() { go s.sessions.runReaper(s.reaperStop) })
	return true
}

// Listeners 返回当前 Serve 所绑定的监听器。未调用 Serve 时两个成员为 nil；
// QUIC 成员在端口 0 场景下可通过其 LocalAddr() 读到实际端口（WT-only 服务端
// 没有 TCP listener，这是唯一的端口发现途径）。返回的是内部引用，仅供读取
// 地址，调用方不应关闭监听器（所有权归 Serve）。
func (s *Server) Listeners() Listeners {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listeners
}

func (s *Server) requiredListeners() (tcp, quic bool) {
	mask := s.cfg.routingPolicy.transports
	tcp = mask&(maskH2|maskH2C|maskGRPC) != 0
	quic = mask&(maskH3|maskWT|maskMasque) != 0
	return
}

func (s *Server) validateListeners(listeners Listeners) error {
	tcp, quic := s.requiredListeners()
	if tcp && listeners.TCP == nil {
		return errors.New("h2tunnel: TCP listener is required by enabled transports")
	}
	if quic && listeners.QUIC == nil {
		return errors.New("h2tunnel: QUIC packet listener is required by enabled transports")
	}
	if !tcp && listeners.TCP != nil {
		return errors.New("h2tunnel: TCP listener supplied but no TCP transport is enabled")
	}
	if !quic && listeners.QUIC != nil {
		return errors.New("h2tunnel: QUIC listener supplied but no QUIC transport is enabled")
	}
	if tcp && s.cfg.EnableTLS && s.cfg.TLSConfig == nil {
		return errors.New("h2tunnel: TLSConfig is required for the configured TCP transports")
	}
	return nil
}

func normalizeServerTransports(values []Transport) (string, error) {
	if len(values) == 0 {
		return transportH2, nil
	}
	seen := make(map[string]struct{}, len(values))
	parts := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.ToLower(strings.TrimSpace(string(value)))
		if name == "" || !validTransport(name, false) {
			return "", fmt.Errorf("%w: %q", ErrUnsupportedTransport, value)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		parts = append(parts, name)
	}
	return strings.Join(parts, ","), nil
}

func normalizeServerNetworks(values []Network) (string, error) {
	if len(values) == 0 {
		return networkTCP, nil
	}
	var tcp, udp bool
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(string(value))) {
		case networkTCP:
			tcp = true
		case networkUDP:
			udp = true
		default:
			return "", fmt.Errorf("%w: %q", ErrUnsupportedNetwork, value)
		}
	}
	if tcp && udp {
		return networkAll, nil
	}
	if udp {
		return networkUDP, nil
	}
	return networkTCP, nil
}

func windowBytesToKB(bytes int) (int, error) {
	if bytes < 0 || bytes > maxWindowKB*1024 {
		return 0, fmt.Errorf("h2tunnel: session window must be between 0 and %d bytes", maxWindowKB*1024)
	}
	if bytes == 0 {
		return sessionWindowDefaultKB, nil
	}
	return (bytes + 1023) / 1024, nil
}

func closeListeners(listeners Listeners) {
	if listeners.TCP != nil {
		_ = listeners.TCP.Close()
	}
	if listeners.QUIC != nil {
		_ = listeners.QUIC.Close()
	}
}
