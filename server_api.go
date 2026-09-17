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
	events    serverEventSink
	listeners Listeners
	httpConns map[net.Conn]struct{}
}

// h2 receive window (server-side uplink flow-control backpressure). x/net
// defaults to 1MB per stream and per connection — the main uplink throughput
// bottleneck on high-RTT CDN links; an 8MB per-stream window allows ~640Mbps in
// flight at 100ms RTT. The cap trades against per-session server memory (the
// SessionWindow ring is a separate bounded buffer, unaffected).
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
	padding, err := compilePaddingPolicy(options.Tuning.Padding)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	cfg := serverConfig{
		Path:                   normalizeTunnelPath(options.Path),
		Transport:              transportList,
		Network:                networkList,
		SessionWindow:          windowKB,
		SessionIdleTimeout:     options.Tuning.SessionIdleTimeout,
		SessionMax:             options.Tuning.SessionMax,
		SessionMaxPerPrincipal: options.Tuning.SessionMaxPerPrincipal,
		Padding:                padding,
		Authenticator:          options.Authenticator,
		TargetDialer:           options.Dialer,
		ServerContext:          ctx,
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
		events:          &s.events,
		sessions:        make(map[string]*tunnelSession),
		perPrincipal:    make(map[string]int),
		logger:          s.log,
		idleTimeout:     cfg.SessionIdleTimeout,
		maxSessions:     resolveSessionMax(cfg.SessionMax),
		maxPerPrincipal: resolveSessionMaxPerPrincipal(cfg.SessionMaxPerPrincipal),
		padding:         cfg.Padding,
	}
	if s.sessions.idleTimeout <= 0 {
		s.sessions.idleTimeout = sessionIdleTimeout
	}
	s.rootHandler = s.buildRootHandler()
	if cfg.EnableH3 {
		s.wtServer = newH3WTServer("", s.rootHandler, cfg.TLSConfig)
	}
	handler := s.rootHandler
	// h2 receive window (uplink flow-control backpressure): x/net defaults to 1MB
	// per stream and per connection; 1MB in flight ÷ 100ms RTT ≈ 80Mbps, the main
	// uplink bottleneck on high-RTT CDN links. Enlarging the window keeps
	// backpressure at the tunnel session layer (the ring is bounded) instead of
	// letting h2 flow control stall first. The client downlink uses x/net's
	// default 4MB/stream, no change needed.
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
		// net/http's auto-configured http2.Server uses the default 1MB uplink
		// window; a custom window requires an explicit ConfigureServer (which must
		// be called before serving starts).
		if err := http2.ConfigureServer(s.httpServer, h2srv); err != nil {
			cancel()
			return nil, fmt.Errorf("h2tunnel: configure HTTP/2 server: %w", err)
		}
	}
	s.cfg.stats = &s.stats.server
	s.cfg.events = &s.events
	if options.EventHandler != nil {
		s.SetEventHandler(options.EventHandler)
	}
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
			// CONNECT forms (MASQUE / WebTransport) all go to classifyTunnelRequest:
			// decided by the :protocol/Protocol header or the RFC 9298 URI template; non-tunnel forms 404.
			// The MASQUE URI base supports a custom prefix (masquePathBase); an empty prefix = the standard
			// /.well-known/masque。
			switch {
			case masqueURISegment(fullPath, masquePathBase(s.cfg.Path)) != "", fullPath == s.cfg.Path:
				r.URL.Path = fullPath
				routeTunnelRequest(w, r, s.cfg, s.wtServer, s.sessions)
			default:
				http.NotFound(w, r)
			}
			return
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
	listeners, err := s.listenersPlan().bind(address)
	if err != nil {
		return err
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

// closeQUICListener closes the external QUIC PacketConn that Serve was given.
// quic-go's H3.Close/Shutdown does not manage an external conn passed via
// Serve(conn); without closing it explicitly the Serve QUIC goroutine never
// returns and Shutdown/Close hang. net/http tracks its TCP listeners itself
// (Shutdown/Close close them), so those need no handling.
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

// Listeners returns the listeners currently bound by Serve. Before Serve is
// called both members are nil; the QUIC member can report its actual port via
// LocalAddr() when port 0 is used (a WT-only server has no TCP listener, so this
// is the only way to discover the port). The return value is an internal
// reference for reading addresses only; callers must not close the listeners (ownership belongs to Serve).
func (s *Server) Listeners() Listeners {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listeners
}

// requiredListeners reports which stacks to open (bind view: optional counts
// too — with MASQUE's dual carrier both TCP and QUIC are bound). SDK validation should use listenersPlan().validate.
func (s *Server) requiredListeners() (tcp, quic bool) {
	plan := s.listenersPlan()
	return plan.tcp != stackUnused, plan.quic != stackUnused
}

// stackNeed describes how strongly the enabled transports need a given stack (the listenerPlan value domain).
type stackNeed uint8

const (
	stackUnused   stackNeed = iota // no enabled transport uses this stack
	stackOptional                  // used if supplied, optional otherwise (MASQUE's dual carrier)
	stackRequired                  // required to serve the enabled transports
)

// listenerPlan is the single source of truth for "compiled transports → required
// stacks", shared by auto-bind, caller validation and the test environment. It
// replaces requiredListeners' two bools that conflated "must be provided" with
// "provided but unused" — which made MASQUE's h2 carrier (a user-supplied TCP
// listener) inexpressible.
type listenerPlan struct{ tcp, quic stackNeed }

func (p routingPolicy) listenerPlan() listenerPlan {
	plan := listenerPlan{}
	if p.transports&(maskH2|maskH2C|maskGRPC) != 0 {
		plan.tcp = stackRequired
	}
	if p.transports&(maskH3|maskWT) != 0 {
		plan.quic = stackRequired
	}
	if p.transports&maskMasque != 0 {
		// MASQUE can ride either stack: ALPN h3 (connect-udp/tcp over QUIC) or
		// extended CONNECT (:protocol over h2, see masqueConnectProtocol).
		if plan.tcp < stackOptional {
			plan.tcp = stackOptional
		}
		if plan.quic < stackOptional {
			plan.quic = stackOptional
		}
	}
	return plan
}

func (s *Server) listenersPlan() listenerPlan {
	return s.cfg.routingPolicy.listenerPlan()
}

// bind opens listeners per requirement. TCP and QUIC share the same numeric port
// (including port 0: the actual TCP port must be read, not re-randomized by the OS).
func (p listenerPlan) bind(address string) (Listeners, error) {
	var listeners Listeners
	if p.tcp != stackUnused {
		tcp, err := net.Listen("tcp", address)
		if err != nil {
			return Listeners{}, err
		}
		listeners.TCP = tcp
	}
	if p.quic != stackUnused {
		quicAddress := address
		if listeners.TCP != nil {
			var err error
			if quicAddress, err = sharedQUICAddress(address, listeners.TCP.Addr()); err != nil {
				closeListeners(listeners)
				return Listeners{}, err
			}
		}
		quic, err := net.ListenPacket("udp", quicAddress)
		if err != nil {
			closeListeners(listeners)
			return Listeners{}, err
		}
		listeners.QUIC = quic
	}
	return listeners, nil
}

// sharedQUICAddress derives the UDP address matching TCP's actual port.
func sharedQUICAddress(address string, tcpAddr net.Addr) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	_, port, err := net.SplitHostPort(tcpAddr.String())
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}

// validate checks caller-supplied listeners: required stacks must be present;
// supplying a listener for an unused stack errors (config-drift guard); a
// MASQUE-only server must supply at least one carrier stack.
func (p listenerPlan) validate(listeners Listeners) error {
	if p.tcp == stackRequired && listeners.TCP == nil {
		return errors.New("h2tunnel: TCP listener is required by enabled transports")
	}
	if p.quic == stackRequired && listeners.QUIC == nil {
		return errors.New("h2tunnel: QUIC packet listener is required by enabled transports")
	}
	if p.tcp == stackUnused && listeners.TCP != nil {
		return errors.New("h2tunnel: TCP listener supplied but no TCP transport is enabled")
	}
	if p.quic == stackUnused && listeners.QUIC != nil {
		return errors.New("h2tunnel: QUIC listener supplied but no QUIC transport is enabled")
	}
	if p.tcp == stackOptional && p.quic == stackOptional && listeners.TCP == nil && listeners.QUIC == nil {
		return errors.New("h2tunnel: MASQUE requires a TCP and/or QUIC listener")
	}
	return nil
}

func (s *Server) validateListeners(listeners Listeners) error {
	if err := s.listenersPlan().validate(listeners); err != nil {
		return err
	}
	if s.cfg.EnableTLS && s.cfg.TLSConfig == nil && listeners.TCP != nil {
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
