package h2tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
	listeners Listeners
}

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
		return nil, errors.New("h2tunnel: H3, WebTransport, and MASQUE require ServerOptions.TLSConfig")
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
	}
	s.sessions = &sessionTable{
		sessions:    make(map[string]*tunnelSession),
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
	if !cfg.EnableTLS {
		handler = h2c.NewHandler(handler, &http2.Server{IdleTimeout: time.Hour})
	}
	s.httpServer = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Hour,
	}
	if cfg.TLSConfig != nil {
		s.httpServer.TLSConfig = cfg.TLSConfig.Clone()
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
			switch {
			case strings.HasPrefix(fullPath, "/.well-known/masque/tcp/"):
				r.URL.Path = fullPath
				routeTunnelRequest(w, r, s.cfg, s.wtServer, s.sessions)
				return
			case strings.HasPrefix(fullPath, "/.well-known/masque/udp/"):
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
	if wasClosing || errors.Is(first.err, http.ErrServerClosed) || errors.Is(first.err, net.ErrClosed) {
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
	s.finishClose()
	return errors.Join(errs...)
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
