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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// Client is an embeddable tunnel dialer. A Client may be used concurrently.
type Client struct {
	cfg       clientConfig
	reqURL    string
	tlsConfig *tls.Config
	log       *slog.Logger

	// Pin state for masque auto-carrier (shared across lanes: a lane rebuild
	// creates a new transport, but the carrier choice must stick). nil = non-auto masque.
	masquePinned *atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc

	// utls TLS fingerprint disguise (nil = native crypto/tls), parsed once in NewClient.
	utls *tlsCamouflage

	mu        sync.Mutex
	starting  bool
	started   bool
	closing   bool
	closed    bool
	startDone chan struct{}
	events    clientEventSink
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
	alpn := strings.ToLower(strings.TrimSpace(options.Tuning.MasqueALPN))
	if alpn != "" {
		if transport != transportMasque {
			return nil, errors.New("h2tunnel: MasqueALPN is only meaningful with Transport=masque")
		}
		if alpn != alpnH2 && alpn != alpnH3 {
			return nil, fmt.Errorf("h2tunnel: MasqueALPN must be %q or %q, got %q", alpnH2, alpnH3, options.Tuning.MasqueALPN)
		}
	}
	var camouflage *tlsCamouflage
	if fp := strings.ToLower(strings.TrimSpace(options.UtlxFingerprint)); fp != "" {
		if u.Scheme == "http" {
			return nil, errors.New("h2tunnel: UtlxFingerprint has no effect with an http:// endpoint (no TLS to camouflage)")
		}
		if transport == transportH3 || transport == transportWT || transport == transportMasque {
			return nil, fmt.Errorf("h2tunnel: UtlxFingerprint is not supported by %s (QUIC performs TLS internally)", transport)
		}
		cam, err := resolveUTLSFingerprint(fp)
		if err != nil {
			return nil, err
		}
		camouflage = cam
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
	padding, err := compilePaddingPolicy(options.Tuning.Padding)
	if err != nil {
		return nil, err
	}
	brutal, err := compileBrutalPolicy(options.Tuning.Brutal)
	if err != nil {
		return nil, err
	}
	warnBrutalUnavailable(options.Logger, brutal)
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
		AutoRedial:        options.Tuning.AutoRedial,
		RedialBudget:      options.Tuning.RedialBudget,
		Padding:           padding,
		MasqueALPN:        alpn,
		Brutal:            brutal,
		// One random value per Client instance, sent as X-Client-Group so every
		// lane of this client lands in the same Brutal connection group. It is
		// stable across TCP-leg migration, which is why it replaces the remote IP.
		clientGroup: newClientSessionID(),
		brutalPeer:  &brutalPeerCache{},
		// Probe placeholder: warm-up lanes carry X-Resume-Role=backup (DialKindProbe);
		// the server never dials for them — this value only appears in lane request headers.
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
	// auto carrier needs a pin bit shared across lanes (a rebuild creates a new transport).
	var masquePinned *atomic.Bool
	if transport == transportMasque && alpn == "" {
		masquePinned = &atomic.Bool{}
	}
	ret := &Client{
		cfg:          cfg,
		masquePinned: masquePinned,
		reqURL:       cfg.ServerUrl + cfg.Path,
		tlsConfig:    tlsConfig,
		log:          logger,
		ctx:          ctx,
		cancel:       cancel,
		utls:         camouflage,
		startDone:    make(chan struct{}),
		active:       make(map[*managedConn]struct{}),
	}
	ret.cfg.events = &ret.events
	if options.EventHandler != nil {
		ret.SetEventHandler(options.EventHandler)
	}
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
		// Reset on failure (single serial goroutine, no concurrent-write risk): free
		// transport resources, swap in a fresh startDone so the next Start can re-initialize.
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
	if c.cfg.usesMasque() {
		return c.newMasqueHTTPClient()
	}
	if c.cfg.usesH3() {
		return newH3Transport(c.cfg)
	}
	return c.newHTTP2Client()
}

// newMasqueHTTPClient picks the MASQUE carrier by MasqueALPN:
//   - "h3" = QUIC only; "h2" = TCP extended CONNECT (RFC 8441) only;
//   - empty = auto: prefer h3, pin h2 on any h3 dial failure (the streaming
//     CONNECT body cannot be replayed, so the failing attempt returns as-is and
//     the existing reconnect/resume loop retries it on h2).
//
// The h2 carrier requires the server to enable extended CONNECT: x/net gates it
// on the process-wide GODEBUG=http2xconnect=1 (must be set at process start; set
// it in the environment — //go:debug rejects this non-stdlib key, and os.Setenv
// after init is too late). When absent the peer advertises no
// ENABLE_CONNECT_PROTOCOL and the dial fails clearly with "extended connect not
// supported by peer" rather than hanging silently.
func (c *Client) newMasqueHTTPClient() *http.Client {
	h2Leg := http.RoundTripper(&masqueExtendedConnectTransport{base: c.newHTTP2Transport()})
	switch c.cfg.MasqueALPN {
	case alpnH3:
		return newH3Transport(c.cfg)
	case alpnH2:
		return &http.Client{Transport: h2Leg}
	default:
		grace := masqueH3ProbeGrace
		if c.cfg.RedialBudget > 0 {
			grace = c.cfg.RedialBudget
		}
		return &http.Client{Transport: &masqueAutoTransport{
			h3:     newH3Transport(c.cfg).Transport,
			h2:     h2Leg,
			pinned: c.masquePinned,
			grace:  grace,
		}}
	}
}

// brutalLocalDecision is the TCP Brutal decision for a fresh TCP leg: this
// client's own policy merged with whatever the server last told it, and a group
// id derived from the shared token plus this instance's seed. Both sides derive
// the same value independently, which is what makes grouping work without the
// token being a per-client secret: the seed is what differs. It also keeps every
// lane of this client (2 primary + N standby) in one Brutal group rather than N
// independent buckets that would let total upload scale with lane count.
func (c *Client) brutalLocalDecision() brutalDecision {
	p := c.cfg.Brutal
	p.groupID = resolveBrutalGroupID(p, c.cfg.Token, c.cfg.clientGroup)
	if peer, ok := c.cfg.brutalPeer.get(); ok {
		p = applyOffer(p, peer.rateBytes, peer.cwndGain)
	}
	return decideBrutal(p)
}

// dialTCP opens a TCP connection and enables TCP Brutal on the raw socket.
// Brutal must be applied before tls.Client / utls.UClient wrap the conn:
// tcpConnFrom follows only Unwrap chains, and tls.Conn exposes NetConn instead.
func (c *Client) dialTCP(ctx context.Context, network, address string) (net.Conn, error) {
	var (
		raw net.Conn
		err error
	)
	if c.cfg.Dialer != nil {
		raw, err = c.cfg.Dialer(ctx, network, address)
	} else {
		var dialer net.Dialer
		raw, err = dialer.DialContext(ctx, network, address)
	}
	if err != nil {
		return nil, err
	}
	if c.cfg.Brutal.enabled {
		applyBrutalBestEffort(raw, c.brutalLocalDecision(), c.log)
	}
	return raw, nil
}

// NegotiateBrutal runs one explicit TCP Brutal bandwidth exchange against the
// server (the _BrutalBwExchange sentinel) without opening a business tunnel,
// and reports the negotiated decision.
//
// It is the standalone form of the exchange that otherwise rides every resume/2
// handshake: use it to learn the agreed rate and group id before opening any
// tunnels. The sentinel session closes as soon as the server has answered, so
// the returned conn is short-lived and is closed here. The decision returned is
// the server's last answer, which is stable for the server's lifetime because
// its policy does not change between exchanges.
//
// It reports ErrBrutalUnavailable when brutal is disabled in this client's
// tuning; a non-Linux host also gets it from the platform socket layer, which
// does not stop the exchange itself.
func (c *Client) NegotiateBrutal(ctx context.Context) (BrutalTuning, error) {
	if !c.cfg.Brutal.enabled {
		return BrutalTuning{}, ErrBrutalUnavailable
	}
	conn, err := c.DialContext(ctx, networkTCP, brutalBwExchangeTarget)
	if err != nil {
		return BrutalTuning{}, err
	}
	_ = conn.Close()
	d, ok := c.cfg.brutalPeer.get()
	if !ok {
		return BrutalTuning{}, errors.New("h2tunnel: the server did not answer the brutal bandwidth exchange")
	}
	return BrutalTuning{
		Enabled:   true,
		RateBytes: d.rateBytes,
		CwndGain:  d.cwndGain,
		GroupID:   d.groupID,
		Negotiate: c.cfg.Brutal.negotiate,
	}, nil
}

// newHTTP2Transport builds the TLS HTTP/2 transport (where utls disguise and the
// custom-socket dialer converge); shared by the masque h2 leg and h2/grpc.
func (c *Client) newHTTP2Transport() *http2.Transport {
	t2 := &http2.Transport{ReadIdleTimeout: 15 * time.Second, PingTimeout: 10 * time.Second}
	if strings.HasPrefix(c.reqURL, "https://") {
		if c.tlsConfig != nil {
			tlsConfig := c.tlsConfig.Clone()
			// Explicitly ensure ALPN h2: http2.Transport negotiates on it when dialing itself.
			if !slices.Contains(tlsConfig.NextProtos, alpnH2) {
				tlsConfig.NextProtos = append(tlsConfig.NextProtos, alpnH2)
			}
			t2.TLSClientConfig = tlsConfig
		}
		if c.utls != nil {
			// utls fingerprint disguise: takes over the TLS handshake (raw socket still honors cfg.Dialer).
			t2.DialTLSContext = c.utlsDialTLSContext()
		} else if c.cfg.Dialer != nil {
			t2.DialTLSContext = func(ctx context.Context, network, address string, tlsConfig *tls.Config) (net.Conn, error) {
				raw, err := c.dialTCP(ctx, network, address)
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
		return t2
	}
	t2.AllowHTTP = true
	t2.DialTLSContext = func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
		return c.dialTCP(ctx, network, address)
	}
	return t2
}

// newHTTP2Client returns the standard h2/h2c client (the non-masque transport path).
func (c *Client) newHTTP2Client() *http.Client {
	return &http.Client{Transport: c.newHTTP2Transport()}
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
		// c.mgr is written under c.mu by the Start goroutine (and cleared on
		// failure/close), so read it under the lock to avoid a data race.
		c.mu.Lock()
		mgr := c.mgr
		c.mu.Unlock()
		if mgr == nil {
			return nil, net.ErrClosed
		}
		if _, err := mgr.WaitClient(ctx, networkTCP); err != nil {
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
	managed.done = make(chan struct{})
	managed.force = make(chan struct{}, 1)
	ready := make(chan error, 1)
	dialCfg := c.cfg
	dialCfg.TargetAddr = target
	dialCfg.Network = networkTCP

	go func() {
		var err error
		if dialCfg.usesWT() {
			err = executeResumeWTContext(sessionCtx, engineSide, dialCfg, c.reqURL, newClientSessionID(), ready, managed.force)
		} else {
			err = executeResumableTunnelContext(sessionCtx, newClientSessionID(), engineSide, c.reqURL, dialCfg, c.mgr, ready, managed.force)
		}
		// err==nil = the engine ended normally (EOF→END), a peer FIN from the other side;
		// only err!=nil is classified by context/error.
		reason, cause := tunnelDeathReason(nil, err)
		c.dispatchClientEvent(ClientEvent{
			Kind:      EventTunnelDied,
			Target:    target,
			Network:   NetworkTCP,
			Transport: dialCfg.transportValue(),
			Reason:    reason,
			Err:       cause,
		})
		_ = engineSide.Close()
		managed.finishWith(cause)
	}()

	select {
	case err := <-ready:
		if err != nil {
			c.stats.client.DialFailures.Add(1)
			if errors.Is(err, ErrForbidden) {
				c.dispatchClientEvent(ClientEvent{
					Kind:      EventTargetDenied,
					Target:    target,
					Network:   NetworkTCP,
					Transport: dialCfg.transportValue(),
					Reason:    "target denied",
					Err:       err,
				})
			}
			_ = managed.Close()
			return nil, err
		}
		c.dispatchClientEvent(ClientEvent{
			Kind:      EventTunnelEstablished,
			Target:    target,
			Network:   NetworkTCP,
			Transport: dialCfg.transportValue(),
		})
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
	managed.done = make(chan struct{})
	managed.force = make(chan struct{}, 1)
	dialCfg := c.cfg
	dialCfg.TargetAddr = target
	dialCfg.Network = networkUDP

	ready := make(chan error, 1)
	if c.cfg.usesWT() {
		// WT uses the on-stream datagram plane (writeUDPPacket/readUDPPacket); the
		// server's handleWebTransportServer datagram path keeps the UDP socket by
		// X-Session-ID. Opening the stream is "ready"; there is no layer-B handshake.
		if err := c.dialPacketWT(sessionCtx, dialCfg, packet, managed.force); err != nil {
			_ = packet.Close()
			return nil, err
		}
		c.log.Debug("UDP tunnel established (webtransport)", "target", target)
		return packet, nil
	}

	// c.mgr is written under c.mu by the Start goroutine; read it under the lock.
	c.mu.Lock()
	mgr := c.mgr
	c.mu.Unlock()
	if mgr == nil {
		_ = packet.Close()
		return nil, net.ErrClosed
	}
	httpClient, err := mgr.WaitClient(ctx, networkUDP)
	if err != nil {
		_ = packet.Close()
		return nil, err
	}
	session := newUDPSession(newClientSessionID(), dialCfg, c.reqURL, httpClient, nil, nil)
	session.ctx = sessionCtx
	session.force = managed.force
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
			if errors.Is(err, ErrForbidden) {
				c.dispatchClientEvent(ClientEvent{
					Kind:      EventTargetDenied,
					Target:    target,
					Network:   NetworkUDP,
					Transport: dialCfg.transportValue(),
					Reason:    "target denied",
					Err:       err,
				})
			}
			_ = packet.Close()
			return nil, err
		}
		c.dispatchClientEvent(ClientEvent{
			Kind:      EventTunnelEstablished,
			Target:    target,
			Network:   NetworkUDP,
			Transport: dialCfg.transportValue(),
		})
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

// dialPacketWT carries UDP datagrams over a WebTransport stream (datagram plane),
// with a reconnect loop: on a stream break / force pulse it reopens a new stream
// while the server keeps the UDP socket by X-Session-ID and continues (no seq
// replay — UDP is unordered). Redial exhaustion is governed by AutoRedial;
// RedialBudget bounds only each stream-open dial phase.
func (c *Client) dialPacketWT(ctx context.Context, dialCfg clientConfig, packet *virtualPacketConn, force <-chan struct{}) error {
	mgr, err := newWTManagerForTunnelContext(ctx, dialCfg, c.reqURL, newClientSessionID())
	if err != nil {
		return err
	}
	session, err := mgr.GetSession(ctx)
	if err != nil {
		return err
	}
	// The first stream is opened synchronously, preserving DialPacketContext's ready
	// semantics (returns write-ready) and error propagation. The budget bounds only
	// this open, canceled once the stream is up (it does not bound the data plane).
	dialCtx, dialCancel := context.WithCancel(ctx)
	if dialCfg.RedialBudget > 0 {
		dialCtx, dialCancel = context.WithTimeout(ctx, dialCfg.RedialBudget)
	}
	stream, err := session.OpenStreamSync(dialCtx)
	dialCancel()
	if err != nil {
		return err
	}

	upstream := make(chan []byte, dialCfg.datagramQueueSize())
	done := make(chan struct{}) // closed when the session terminates (local close / redial exhausted)
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(done) }) }
	packet.attachWTTunnel(upstream, done, closeFunc(stop))

	go func() {
		err := runWTUDPDatagramLoop(ctx, dialCfg, mgr, packet, session, stream, upstream, done, force)
		if err == nil || ctx.Err() != nil {
			packet.fail(net.ErrClosed)
			return
		}
		// Remote death (exhausted/unrecoverable): a TunnelDied event + conn terminal error.
		reason, cause := tunnelDeathReason(nil, err)
		c.dispatchClientEvent(ClientEvent{
			Kind:      EventTunnelDied,
			Target:    dialCfg.TargetAddr,
			Network:   NetworkUDP,
			Transport: dialCfg.transportValue(),
			Reason:    reason,
			Err:       cause,
		})
		packet.fail(err)
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

	// One signal on force = abandon the current stream and redial immediately (session/ring preserved).
	// cap 1 + non-blocking send: the signal is a one-shot pulse, not a level.
	force chan struct{}
	// Session lifecycle (context style): done is closed when the session goroutine exits.
	done    chan struct{}
	mu      sync.Mutex
	deadErr error
}

func (c *managedConn) Done() <-chan struct{} { return c.done }

func (c *managedConn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadErr
}

func (c *managedConn) finishWith(err error) {
	c.mu.Lock()
	if c.deadErr == nil {
		c.deadErr = err
	}
	c.mu.Unlock()
	select {
	case <-c.done:
	default:
		close(c.done)
	}
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
