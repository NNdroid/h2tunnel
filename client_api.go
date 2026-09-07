package h2tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Client is an embeddable tunnel dialer. A Client may be used concurrently.
type Client struct {
	cfg       clientConfig
	reqURL    string
	tlsConfig *tls.Config
	log       *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	starting  bool
	started   bool
	closing   bool
	closed    bool
	startDone chan struct{}
	startErr  error
	mgr       *connectionManager
	stats     stats
	active    map[*managedConn]struct{}
	activeWG  sync.WaitGroup
}

// NewClient validates options without performing network I/O.
func NewClient(options ClientOptions) (*Client, error) {
	endpoint := strings.TrimSpace(options.Endpoint)
	if endpoint == "" {
		return nil, errors.New("h2tunnel: ClientOptions.Endpoint is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("h2tunnel: invalid endpoint %q", endpoint)
	}
	transport := strings.ToLower(strings.TrimSpace(string(options.Transport)))
	if transport == "" {
		if u.Scheme == "http" {
			transport = transportH2C
		} else {
			transport = transportH2
		}
	}
	if !validTransport(transport, false) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedTransport, transport)
	}
	if transport == transportH2C && u.Scheme != "http" {
		return nil, errors.New("h2tunnel: h2c requires an http:// endpoint")
	}
	if transport == transportH2 && u.Scheme != "https" {
		return nil, errors.New("h2tunnel: h2 requires an https:// endpoint; use h2c for cleartext")
	}
	if u.Scheme == "http" && options.TLSConfig != nil {
		return nil, errors.New("h2tunnel: TLSConfig has no effect with an http:// endpoint")
	}
	if (transport == transportH3 || transport == transportWT || transport == transportMasque) && u.Scheme != "https" {
		return nil, fmt.Errorf("h2tunnel: %s requires an https:// endpoint", transport)
	}
	if options.Tuning.StandbyConnections < 0 {
		return nil, errors.New("h2tunnel: StandbyConnections must be non-negative")
	}
	if options.Tuning.DatagramQueueSize < 0 || options.Tuning.DatagramQueueSize > 65536 {
		return nil, errors.New("h2tunnel: DatagramQueueSize must be between 0 and 65536")
	}
	if transport == transportWT && options.Tuning.StandbyConnections != 0 {
		return nil, errors.New("h2tunnel: StandbyConnections is not supported by WebTransport")
	}
	windowKB, err := windowBytesToKB(options.Tuning.SessionWindowBytes)
	if err != nil {
		return nil, err
	}
	heartbeat := options.Tuning.HeartbeatInterval
	if heartbeat == 0 {
		heartbeat = heartbeatDefault
	} else if heartbeat > 0 {
		heartbeat = clampHeartbeat(heartbeat)
	} else {
		heartbeat = 0
	}
	keepaliveSec, err := durationSeconds(options.Tuning.KeepaliveInterval, defaultKeepaliveSec, maxKeepaliveSec, "KeepaliveInterval")
	if err != nil {
		return nil, err
	}
	handshakeMs, err := durationMilliseconds(options.Tuning.HandshakeTimeout, defaultHandshakeAckMs, maxHandshakeAckMs, "HandshakeTimeout")
	if err != nil {
		return nil, err
	}

	var tlsConfig *tls.Config
	if u.Scheme == "https" {
		if options.TLSConfig != nil {
			tlsConfig = options.TLSConfig.Clone()
		} else {
			tlsConfig = &tls.Config{}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	cfg := clientConfig{
		ServerUrl:         strings.TrimRight(endpoint, "/"),
		Path:              normalizeTunnelPath(options.Path),
		CustomHost:        strings.TrimSpace(options.Host),
		Transport:         transport,
		Network:           networkAll,
		HeartbeatInterval: heartbeat,
		SessionWindow:     windowKB,
		HandshakeAckMs:    handshakeMs,
		KeepaliveSec:      keepaliveSec,
		Credentials:       options.Credentials,
		TLSConfig:         tlsConfig,
		LogicalTargets:    true,
		Dialer:            options.Dialer,
		QUICDialer:        options.QUICDialer,
		DatagramQueueSize: options.Tuning.DatagramQueueSize,
		// 探活占位：预热 lane 带 X-Resume-Role=backup（DialKindProbe），
		// 服务端不会为其拨号 —— 该值只出现在 lane 请求头里。
		TargetAddr: "__probe__",
		connectionPolicy: connectionPolicy{
			PrimaryCount:         2,
			BackupCount:          options.Tuning.StandbyConnections,
			PrimaryDialInterval:  primaryDialDefault,
			BackupDialInterval:   backupDialDefault,
			EstablishInterval:    time.Duration(defaultEstablishSec) * time.Second,
			BackoffMaxMissedAcks: defaultBackupMissedAck,
			PrimaryNetworks:      []string{networkTCP, networkUDP},
		},
	}
	if tlsConfig != nil {
		cfg.Insecure = tlsConfig.InsecureSkipVerify
		cfg.ServerName = tlsConfig.ServerName
	}
	ret := &Client{
		cfg:       cfg,
		reqURL:    cfg.ServerUrl + cfg.Path,
		tlsConfig: tlsConfig,
		log:       logger,
		ctx:       ctx,
		cancel:    cancel,
		startDone: make(chan struct{}),
		active:    make(map[*managedConn]struct{}),
	}
	cfg.stats = &ret.stats.client
	return ret, nil
}

// Start initializes and verifies the transport. It is safe to call
// concurrently and is also invoked lazily by DialContext/DialPacketContext.
// A failed Start releases all transport resources and returns the error; the
// Client may be retried (state resets so Start can run again).
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.closed || c.closing {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if c.started {
		err := c.startErr
		c.mu.Unlock()
		return err
	}
	if !c.starting {
		c.starting = true
		go c.startTransport()
	}
	done := c.startDone
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return net.ErrClosed
	case <-done:
		c.mu.Lock()
		err := c.startErr
		c.mu.Unlock()
		return err
	}
}

func (c *Client) startTransport() {
	c.log.Debug("starting tunnel transport", "transport", c.cfg.Transport)
	var err error
	var mgr *connectionManager
	if c.cfg.usesWT() {
		// WT has no reusable HTTP connection pool. The first business dial does
		// the authenticated WebTransport handshake and reports target readiness.
		err = nil
	} else {
		mgr = newConnectionManager(c.cfg.connectionPolicy, c.cfg, c.reqURL, nil, "API")
		mgr.SetClientFactory(c.newHTTPClient)
		c.mu.Lock()
		if c.closing || c.closed {
			c.mu.Unlock()
			mgr.Close()
			err = net.ErrClosed
		} else {
			c.mgr = mgr
			c.mu.Unlock()
			mgr.Start()
			_, err = mgr.WaitAnyClient(c.ctx)
		}
	}
	c.mu.Lock()
	c.startErr = err
	c.starting = false
	done := c.startDone
	if err != nil && !c.closing && !c.closed {
		// 失败即复位（单一 goroutine 串行执行，无并发写风险）：释放传输
		// 资源、换新 startDone，让下一次 Start 从头初始化实现可重试。
		if mgr != nil {
			failed := mgr
			c.mgr = nil
			go failed.Close()
		}
		c.started = false
		c.startDone = make(chan struct{})
	} else {
		c.started = true
	}
	close(done)
	c.mu.Unlock()
	if err != nil {
		c.log.Error("tunnel transport failed", "transport", c.cfg.Transport, "error", err)
	} else {
		c.log.Debug("tunnel transport ready", "transport", c.cfg.Transport)
	}
}

func (c *Client) newHTTPClient() *http.Client {
	if c.cfg.usesMasque() || c.cfg.usesH3() {
		return newH3Transport(c.cfg)
	}
	t2 := &http2.Transport{ReadIdleTimeout: 15 * time.Second, PingTimeout: 10 * time.Second}
	if strings.HasPrefix(c.reqURL, "https://") {
		if c.tlsConfig != nil {
			t2.TLSClientConfig = c.tlsConfig.Clone()
		}
		if c.cfg.Dialer != nil {
			t2.DialTLSContext = func(ctx context.Context, network, address string, tlsConfig *tls.Config) (net.Conn, error) {
				raw, err := c.cfg.Dialer(ctx, network, address)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(raw, tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = raw.Close()
					return nil, err
				}
				return tlsConn, nil
			}
		}
	} else {
		t2.AllowHTTP = true
		t2.DialTLSContext = func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
			if c.cfg.Dialer != nil {
				return c.cfg.Dialer(ctx, network, address)
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		}
	}
	return &http.Client{Transport: t2}
}

// DialContext establishes a TCP tunnel and returns only after the remote
// target and resume/2 handshake are ready.
//
// network accepts "", "tcp", "tcp4", and "tcp6"; the address family only
// governs the local side of the API contract — the server dials the target
// with its own TargetDialer and may resolve it differently.
//
// Dial errors match the exported sentinels via errors.Is:
// ErrUnauthenticated (HTTP 407/401, token rejected) and ErrForbidden
// (HTTP 403, target denied by policy).
func (c *Client) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("%w: DialContext supports tcp, tcp4, and tcp6", ErrUnsupportedNetwork)
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("h2tunnel: target is required")
	}
	if err := c.Start(ctx); err != nil {
		return nil, err
	}
	if !c.cfg.usesWT() {
		if _, err := c.mgr.WaitClient(ctx, networkTCP); err != nil {
			return nil, err
		}
	}
	c.stats.client.DialAttempts.Add(1)
	c.stats.client.ActiveDials.Add(1)

	clientSide, engineSide := net.Pipe()
	sessionCtx, sessionCancel := context.WithCancel(c.ctx)
	managed := &managedConn{Conn: clientSide, cancel: sessionCancel}
	if err := c.addActive(managed); err != nil {
		sessionCancel()
		_ = clientSide.Close()
		_ = engineSide.Close()
		return nil, err
	}
	managed.onClose = func() { c.removeActive(managed) }
	ready := make(chan error, 1)
	dialCfg := c.cfg
	dialCfg.TargetAddr = target
	dialCfg.Network = networkTCP

	go func() {
		var err error
		if dialCfg.usesWT() {
			err = executeResumeWTContext(sessionCtx, engineSide, dialCfg, c.reqURL, newClientSessionID(), ready)
		} else {
			err = executeResumableTunnelContext(sessionCtx, newClientSessionID(), engineSide, c.reqURL, dialCfg, c.mgr, ready)
		}
		_ = err
		_ = engineSide.Close()
		managed.finish()
	}()

	select {
	case err := <-ready:
		if err != nil {
			c.stats.client.DialFailures.Add(1)
			_ = managed.Close()
			return nil, err
		}
		c.log.Debug("TCP tunnel established", "target", target)
		return managed, nil
	case <-ctx.Done():
		_ = managed.Close()
		return nil, ctx.Err()
	case <-c.ctx.Done():
		_ = managed.Close()
		return nil, net.ErrClosed
	}
}

// DialPacketContext establishes a connected UDP tunnel.
func (c *Client) DialPacketContext(ctx context.Context, network, target string) (PacketConn, error) {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "", "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("%w: DialPacketContext supports udp, udp4, and udp6", ErrUnsupportedNetwork)
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("h2tunnel: target is required")
	}
	if err := c.Start(ctx); err != nil {
		return nil, err
	}
	sessionCtx, cancel := context.WithCancel(c.ctx)
	packet := newVirtualPacketConn(target, cancel)
	c.stats.client.DialAttempts.Add(1)
	c.stats.client.ActiveDials.Add(1)
	managed := &managedConn{Conn: packet, cancel: cancel}
	if err := c.addActive(managed); err != nil {
		cancel()
		_ = packet.Close()
		return nil, err
	}
	managed.onClose = func() { c.removeActive(managed) }
	packet.onClose = managed.finish
	dialCfg := c.cfg
	dialCfg.TargetAddr = target
	dialCfg.Network = networkUDP

	ready := make(chan error, 1)
	if c.cfg.usesWT() {
		// WT 走流上的 datagram 面（writeUDPPacket/readUDPPacket），
		// 服务端 handleWebTransportServer 的 datagram 路径按 X-Session-ID
		// 保持 UDP socket。建流即就绪，无 B 层握手。
		if err := c.dialPacketWT(sessionCtx, dialCfg, packet); err != nil {
			_ = packet.Close()
			return nil, err
		}
		c.log.Debug("UDP tunnel established (webtransport)", "target", target)
		return packet, nil
	}

	httpClient, err := c.mgr.WaitClient(ctx, networkUDP)
	if err != nil {
		_ = packet.Close()
		return nil, err
	}
	session := newUDPSession(newClientSessionID(), dialCfg, c.reqURL, httpClient, nil, nil)
	session.ctx = sessionCtx
	session.deliver = packet.deliver
	session.ready = ready
	session.onDone = func(err error) {
		if err == nil {
			err = io.EOF
		}
		packet.fail(err)
	}
	packet.attachUDPSession(session)
	go session.run()

	select {
	case err := <-ready:
		if err != nil {
			c.stats.client.DialFailures.Add(1)
			_ = packet.Close()
			return nil, err
		}
		c.log.Debug("UDP tunnel established", "target", target)
		return packet, nil
	case <-ctx.Done():
		_ = packet.Close()
		return nil, ctx.Err()
	case <-c.ctx.Done():
		_ = packet.Close()
		return nil, net.ErrClosed
	}
}

// dialPacketWT 通过 WebTransport 流承载 UDP 数据报（datagram 面）。
// 与 legacy 数据面一致：上行 writeUDPPacket 封帧写流，下行 readUDPPacket
// 解帧投递；无 seq 重放，流断即会话终止（由 virtualPacketConn.fail 收敛）。
func (c *Client) dialPacketWT(ctx context.Context, dialCfg clientConfig, packet *virtualPacketConn) error {
	mgr, err := newWTManagerForTunnelContext(ctx, dialCfg, c.reqURL, newClientSessionID())
	if err != nil {
		return err
	}
	session, err := mgr.GetSession(ctx)
	if err != nil {
		return err
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return err
	}

	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			close(done)
			_ = stream.Close() // FIN：通知服务端上行结束（服务端会话保留 UDP socket）
		})
	}
	upstream := make(chan []byte, dialCfg.datagramQueueSize())
	packet.attachWTTunnel(upstream, done, closeFunc(stop))

	// 上行：队列 → WT 流。
	go func() {
		for {
			select {
			case <-done:
				return
			case pkt := <-upstream:
				if err := writeUDPPacket(stream, pkt); err != nil {
					packet.fail(err)
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	// 下行：WT 流 → virtualPacketConn。
	go func() {
		defer stop()
		buf := make([]byte, 64*1024)
		for {
			n, err := readUDPPacket(stream, buf)
			if err != nil {
				return
			}
			if err := packet.deliver(buf[:n]); err != nil {
				return
			}
		}
	}()
	return nil
}

// Shutdown rejects new dials and waits for active tunnels to close naturally.
// When ctx expires the remaining tunnels keep draining in the background; call
// Close to force-close them (the internal waiter terminates once Close runs,
// since Close tears down every active tunnel).
func (c *Client) Shutdown(ctx context.Context) error {
	c.log.Debug("draining tunnel client")
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closing = true
	c.mu.Unlock()
	done := make(chan struct{})
	go func() {
		c.activeWG.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return c.Close()
	}
}

// Close immediately closes all active tunnels and transport pools.
func (c *Client) Close() error {
	c.log.Debug("closing tunnel client")
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closing = true
	c.closed = true
	c.cancel()
	mgr := c.mgr
	active := make([]*managedConn, 0, len(c.active))
	for conn := range c.active {
		active = append(active, conn)
	}
	c.mu.Unlock()
	if mgr != nil {
		mgr.Close()
	}
	for _, conn := range active {
		_ = conn.Close()
	}
	return nil
}

func (c *Client) addActive(conn *managedConn) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing || c.closed {
		return net.ErrClosed
	}
	c.active[conn] = struct{}{}
	c.activeWG.Add(1)
	return nil
}

func (c *Client) removeActive(conn *managedConn) {
	c.mu.Lock()
	if _, ok := c.active[conn]; ok {
		delete(c.active, conn)
		c.activeWG.Done()
	}
	c.mu.Unlock()
}

type managedConn struct {
	net.Conn
	cancel  context.CancelFunc
	onClose func()
	once    sync.Once
}

func (c *managedConn) Close() error {
	err := c.Conn.Close()
	c.finish()
	return err
}

func (c *managedConn) finish() {
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
}

func durationSeconds(value time.Duration, defaultValue, maxValue int, name string) (int, error) {
	if value == 0 {
		return defaultValue, nil
	}
	if value < time.Second || value > time.Duration(maxValue)*time.Second {
		return 0, fmt.Errorf("h2tunnel: %s must be between 1s and %ds", name, maxValue)
	}
	return int(value / time.Second), nil
}

func durationMilliseconds(value time.Duration, defaultValue, maxValue int, name string) (int, error) {
	if value == 0 {
		return defaultValue, nil
	}
	if value < time.Millisecond || value > time.Duration(maxValue)*time.Millisecond {
		return 0, fmt.Errorf("h2tunnel: %s must be between 1ms and %dms", name, maxValue)
	}
	return int(value / time.Millisecond), nil
}

var _ io.Closer = (*Client)(nil)
