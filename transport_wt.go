package h2tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// =========================================
// WebTransport (WT) transport adapter
//
// WT has been folded from a standalone session model into the resume/2
// engine: every business tunnel owns its own wtSessionManager (headers
// carry that tunnel's X-Session-ID + resume layer-A negotiation headers),
// and the server dispatches each business stream to the v2 session table
// (prepareResumeSession) — a peer of h2/grpc/masque: ring buffer uplink
// replay + server-side targetConn retention + A/B handshake. After a drop
// (stream dies), a new stream is opened with the same session id to resume.
//
// Because WT streams have no per-stream HTTP headers, clientDownlink
// (downlink bytes already received locally) is passed through in the data
// plane HANDSHAKE frame payload, so the server can refill the downlink gap
// from the right position.
// =========================================

type wtSessionManager struct {
	lg      *slog.Logger
	dialer  *webtransport.Transport
	reqUrl  string
	headers http.Header
	mu      sync.Mutex
	primary *webtransport.Session
	backup  *webtransport.Session
	ctx     context.Context
}

// GetSession returns a usable session: the primary if healthy, otherwise the
// backup promoted; a hit asynchronously triggers backup warmup (the same
// primary/backup + phase-offset idea as the L3 connectionManager: at any
// moment at least two usable sessions in different states, so a CDN or NAT
// hard kill cannot take both down at once).
func (m *wtSessionManager) GetSession(ctx context.Context) (*webtransport.Session, error) {
	// Fast path: primary healthy.
	m.mu.Lock()
	if m.primary != nil && m.primary.Context().Err() == nil {
		primary := m.primary
		needBackup := m.backup == nil || m.backup.Context().Err() != nil
		m.mu.Unlock()
		if needBackup {
			go m.warmupBackup()
		}
		return primary, nil
	}
	m.mu.Unlock()

	// Backup healthy: promote it.
	m.mu.Lock()
	if m.backup != nil && m.backup.Context().Err() == nil {
		m.primary = m.backup
		m.backup = nil
		primary := m.primary
		m.mu.Unlock()
		go m.warmupBackup()
		lgInfof(m.lg, "[WT Manager] 🔁 primary session dead, switched to backup session")
		return primary, nil
	}
	m.mu.Unlock()

	// Neither: dial now.
	return m.dialAndInstall(ctx)
}

func (m *wtSessionManager) warmupBackup() {
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	session, err := m.dialSession(ctx)
	if err != nil {
		lgDebugf(m.lg, "[WT Manager] ❌ backup session warmup failed: %v", err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backup != nil && m.backup.Context().Err() == nil {
		return
	}
	m.backup = session
	lgDebugf(m.lg, "[WT Manager] 🔥 backup session warmed up")
}

func (m *wtSessionManager) dialAndInstall(ctx context.Context) (*webtransport.Session, error) {
	lgDebugf(m.lg, "[WT Manager] 📡 Initiating WebTransport handshake...")
	start := time.Now()
	session, err := m.dialSession(ctx)
	if err != nil {
		lgErrorf(m.lg, "[WT Manager] ❌ WebTransport handshake failed: %v", err)
		return nil, err
	}
	m.mu.Lock()
	m.primary = session
	m.mu.Unlock()
	lgInfof(m.lg, "[WT Manager] ✅ Underlying WebTransport session established successfully (duration: %v)", time.Since(start))
	go m.warmupBackup()
	return session, nil
}

func (m *wtSessionManager) dialSession(ctx context.Context) (*webtransport.Session, error) {
	_, session, err := m.dialer.Dial(ctx, m.reqUrl, m.headers)
	return session, err
}

// newWTManagerForTunnel builds a dedicated wtSessionManager for one business
// tunnel. Each tunnel owns its own WT session (headers carry that tunnel's
// X-Session-ID and resume layer-A negotiation headers), so the server can
// distinguish multiple tunnels by session id and resume each on its own —
// the prerequisite for WT joining the resume/2 session table (one WT session
// maps to one logical session).
func newWTManagerForTunnel(cfg clientConfig, reqUrl, sessionID string) *wtSessionManager {
	mgr, _ := newWTManagerForTunnelContext(context.Background(), cfg, reqUrl, sessionID)
	return mgr
}

func newWTManagerForTunnelContext(ctx context.Context, cfg clientConfig, reqUrl, sessionID string) (*wtSessionManager, error) {
	var tlsConfig *tls.Config
	if cfg.TLSConfig != nil {
		tlsConfig = cfg.TLSConfig.Clone()
	} else {
		tlsConfig = &tls.Config{InsecureSkipVerify: cfg.Insecure}
	}
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	}
	headers := make(http.Header)
	if err := applyClientCredentials(ctx, headers, cfg); err != nil {
		return nil, err
	}
	// Anti-buffering headers consistent with other tunnel requests + camouflaged User-Agent.
	setTunnelRequestHeaders(headers)
	headers.Set("Protocol", protocolWebTransport)
	setXDst(headers, cfg)
	// resume/2 layer-A negotiation headers (X-Resume-Downlink is a per-stream
	// value passed through the data-plane HANDSHAKE frame payload, not set here).
	headers.Set("X-Tunnel-Proto", resumeFrameTypeResume)
	headers.Set("X-Session-ID", sessionID)
	headers.Set("X-Resume-Version", "2")
	headers.Set("X-Resume-Caps", clientCapabilities(cfg).String())
	headers.Set("X-Resume-Params", clientParams(cfg).String())
	if cfg.RoleBackup {
		headers.Set("X-Resume-Role", "backup")
	}
	return &wtSessionManager{
		lg: cfg.lg(),
		dialer: &webtransport.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig:      getDefaultQUICConfig(),
			DialAddr:        cfg.QUICDialer,
		},
		reqUrl:  reqUrl,
		headers: headers,
		ctx:     ctx,
	}, nil
}

// ---> client TCP: WebTransport (resume/2 integration)
// After WT joined the resume/2 engine, a drop (stream dies) reopens a new
// stream with the same session id to resume — a peer of h2/grpc/masque: ring
// buffer uplink replay + server-side targetConn retention + A/B handshake.
// clientDownlink (downlink bytes already received locally) is passed through
// the data-plane HANDSHAKE frame payload, so the server can refill the
// downlink gap from the right position.
func executeResumeWT(localConn net.Conn, cfg clientConfig, wtManager *wtSessionManager, sessionID string) {
	_ = executeResumeWTWithManagerContext(context.Background(), localConn, cfg, wtManager, sessionID, nil, nil)
}

func executeResumeWTContext(ctx context.Context, localConn net.Conn, cfg clientConfig, reqURL, sessionID string, ready chan<- error, force <-chan struct{}) error {
	wtManager, err := newWTManagerForTunnelContext(ctx, cfg, reqURL, sessionID)
	if err != nil {
		if ready != nil {
			ready <- err
		}
		return err
	}
	return executeResumeWTWithManagerContext(ctx, localConn, cfg, wtManager, sessionID, ready, force)
}

func executeResumeWTWithManagerContext(ctx context.Context, localConn net.Conn, cfg clientConfig, wtManager *wtSessionManager, sessionID string, ready chan<- error, force <-chan struct{}) error {
	defer localConn.Close()
	readyOnce := sync.Once{}
	notifyReady := func(err error) {
		if ready != nil {
			readyOnce.Do(func() { ready <- err })
		}
	}
	ringBuf := newResumeClientRingBuf(cfg.SessionWindow)
	var serverUplink uint64
	var clientDownlink uint64

	// The per-attempt budget is implemented inside runResumeWTTryContext
	// (stream setup + handshake phase, timer stopped once ready); here we
	// only pace the redials.

	for attempt := 1; ; attempt++ {
		ok, err := runResumeWTTryContext(ctx, sessionID, &serverUplink, &clientDownlink, localConn, ringBuf, cfg, wtManager, func() { notifyReady(nil) }, force)
		if ok {
			return nil // normal end (EOF / peer END)
		}
		if err != nil {
			// Fail-fast on fatal (never-recoverable) errors regardless of
			// AutoRedial (bad token / policy / protocol version mismatch).
			if ctx.Err() != nil || isFatalTunnelError(err) || (!cfg.AutoRedial && isPermanentTunnelError(err)) {
				notifyReady(err)
				return err
			}
			lgWarnf(cfg.lg(), "[Resume/WT] ❌ session unrecoverable: %v", err)
		}
		// Stream died: reopen a new stream with the same session id to resume
		// (after backoff).
		delay := time.Duration(attempt) * 200 * time.Millisecond
		if delay > resumeBackoffMax {
			delay = resumeBackoffMax
		}
		// Up to +100% jitter to desynchronize a reconnecting fleet (avoid avalanche).
		delay += time.Duration(rand.Int64N(int64(delay)))
		lgInfof(cfg.lg(), "[Resume/WT] 🔁 WT stream reopen #%d (resuming same session), waiting %v", attempt, delay)
		select {
		case <-ctx.Done():
			notifyReady(ctx.Err())
			return ctx.Err()
		case <-time.After(delay):
		}

		// Redial exhaustion handling: AutoRedial same as the TCP side.
		if attempt%resumeMaxAttempts == 0 {
			if !cfg.AutoRedial {
				break
			}
			lgWarnf(cfg.lg(), "[Resume/WT] 🔁 redial hit the %d-attempt cap, AutoRedial resets the counter and continues", resumeMaxAttempts)
		}
	}
	lgWarnf(cfg.lg(), "[Resume/WT] ❌ exceeded max retries (%d), session terminated", resumeMaxAttempts)
	err := errors.New("h2tunnel: WebTransport resume attempts exhausted")
	notifyReady(err)
	return err
}

// runResumeWTTry runs the full lifecycle of one WT stream: open stream →
// layer-B handshake (carrying clientDownlink) → uplink replay/live +
// downlink frame reading. (normalEnd, err) has the same semantics as
// runResumeAttempt.
func runResumeWTTry(sessionID string, serverUplink, clientDownlink *uint64,
	localConn net.Conn, ringBuf *resumeClientRingBuf, cfg clientConfig,
	wtManager *wtSessionManager) (bool, error) {
	return runResumeWTTryContext(context.Background(), sessionID, serverUplink, clientDownlink, localConn, ringBuf, cfg, wtManager, nil, nil)
}

func runResumeWTTryContext(parent context.Context, sessionID string, serverUplink, clientDownlink *uint64,
	localConn net.Conn, ringBuf *resumeClientRingBuf, cfg clientConfig,
	wtManager *wtSessionManager, onReady func(), force <-chan struct{},
) (bool, error) {

	// At the end of this attempt, unblock the send goroutine possibly stuck
	// in localConn.Read so the old sendLoop never reads the same connection
	// concurrently with the next attempt's sendLoop (see resumeSendLoop's
	// done parameter).
	done := make(chan struct{})
	defer func() {
		close(done)
		_ = localConn.SetReadDeadline(time.Now())
	}()
	_ = localConn.SetReadDeadline(time.Time{})

	// Per-attempt cancellation: both the RedialBudget alarm and force pulses
	// converge through it.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// RedialBudget: only constrains the stream-setup + handshake phase; the
	// timer stops once ready, so established streams are unaffected by the
	// budget (same as the TCP side).
	var budgetStop func()
	if cfg.RedialBudget > 0 {
		timer := time.AfterFunc(cfg.RedialBudget, func() {
			lgDebugf(cfg.lg(), "[Resume/WT] ⏱️ dial budget %v expired, cancelling this attempt", cfg.RedialBudget)
			cancel()
			_ = localConn.SetReadDeadline(time.Now())
		})
		budgetStop = func() { timer.Stop() }
		defer timer.Stop()
	}

	session, err := wtManager.GetSession(ctx)
	if err != nil || session == nil {
		lgWarnf(cfg.lg(), "[Resume/WT] ❌ cannot obtain WT Session: %v", err)
		return false, err
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil || stream == nil {
		lgWarnf(cfg.lg(), "[Resume/WT] ❌ WT Stream open failed: %v", err)
		return false, err
	}
	defer stream.Close()

	// force pulse → cancel the attempt ctx + close the current stream + wake
	// the sendLoop (WT stream Read does not respond to ctx cancel, it must
	// be Closed to break the recvLoop).
	if force != nil {
		go func() {
			select {
			case <-force:
				lgDebugf(cfg.lg(), "[Resume/WT] 🔌 force pulse: closing current WT stream for immediate redial")
				cancel()
				_ = stream.Close()
				_ = localConn.SetReadDeadline(time.Now())
			case <-ctx.Done():
			}
		}()
	}
	defer stream.Close()

	// ===== layer-B handshake: HANDSHAKE frame payload carries clientDownlink, wait for HANDSHAKE-ACK =====
	payload := strconv.FormatUint(*clientDownlink, 10)
	if err := writeFrame(stream, resumeFrameHandshake, 0, []byte(payload), cfg.Padding.paddingFor(resumeHeaderLen+len(payload))); err != nil {
		lgWarnf(cfg.lg(), "[Resume/WT] ❌ failed to write HANDSHAKE control frame: %v", err)
		return false, err
	}
	hsBuf := make([]byte, 64*1024)
	typ, _, _, err := readFrame(stream, hsBuf)
	if err != nil {
		lgWarnf(cfg.lg(), "[Resume/WT] ❌ failed to read HANDSHAKE-ACK: %v", err)
		return false, err
	}
	if typ != resumeFrameHandshakeAck {
		lgWarnf(cfg.lg(), "[Resume/WT] ❌ expected HANDSHAKE-ACK, got frame 0x%02x", typ)
		return false, errors.New("h2tunnel: invalid WebTransport handshake response")
	}
	lgInfof(cfg.lg(), "[Resume/WT] ✅ layer-B handshake confirmed (clientDownlink=%d)", *clientDownlink)
	if onReady != nil {
		if budgetStop != nil {
			budgetStop() // once ready the budget no longer constrains the data plane
		}
		onReady()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var recvErr error

	go func() {
		defer wg.Done()
		// uplink: replay from serverUplink in the ring, then read localConn
		// live. The stream acts as the io.Writer.
		_ = resumeSendLoop(stream, localConn, ringBuf, *serverUplink, done, cfg.HeartbeatInterval, cfg.Padding, cfg.lg(), cfg.stats)
	}()
	go func() {
		defer wg.Done()
		recvErr = resumeRecvLoopWT(stream, localConn, clientDownlink, cfg.lg(), cfg.stats)
	}()

	wg.Wait()
	if recvErr == nil {
		return true, nil
	}
	return false, nil
}

// resumeRecvLoopWT reads resume frames from the WT stream, writes localConn
// after checking seq continuity, and accumulates clientDownlink (downlink
// bytes received locally), so the next stream reopen can pass it through the
// HANDSHAKE payload and the server refills the gap from there. An END frame
// → half-close locally and return normally.
func resumeRecvLoopWT(stream io.Reader, localConn net.Conn, clientDownlink *uint64, lg *slog.Logger, st *ClientStats) error {
	payloadBuf := make([]byte, 64*1024)
	expected := *clientDownlink // the downlink coordinate space is continuous across streams: the first frame seq after reconnect must equal the bytes already received
	for {
		typ, seq, n, err := readFrame(stream, payloadBuf)
		if errors.Is(err, errResumeEndFrame) {
			if tc, ok := localConn.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			*clientDownlink = expected
			return nil
		}
		if err != nil {
			*clientDownlink = expected
			return err
		}
		if typ == resumeFrameKeepaliveAck {
			continue
		}
		if typ != resumeFrameData {
			*clientDownlink = expected
			return fmt.Errorf("resume/WT: unexpected frame type 0x%02x", typ)
		}
		if seq != expected {
			lgWarnf(lg, "[Resume/WT] ⚠️ downlink seq discontinuity: expected %d, got %d", expected, seq)
			*clientDownlink = expected
			return errGap
		}
		if _, wErr := localConn.Write(payloadBuf[:n]); wErr != nil {
			*clientDownlink = expected
			return wErr
		}
		if st != nil {
			st.DownlinkBytes.Add(int64(n))
		}
		expected += uint64(n)
		*clientDownlink = expected
	}
}

// ---> server WT: dispatch each business stream to the resume/2 session table (resumable across drops)
func handleWebTransportServer(w http.ResponseWriter, r *http.Request, sessionID string, cfg serverConfig, wtServer *webtransport.Server, sessions *sessionTable) {
	network, target := getRequestDestination(r, cfg)
	if !targetAllowedByRuntime(cfg, target) {
		lgWarnf(sessions.lg(), "[%s] 🚫 Access denied for target address: %s", sessionID, target)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// resume/2 is the only data plane: WT also goes through the resume session
	// table uniformly (resumable across drops). Layer-A negotiation headers
	// (X-Tunnel-Proto / X-Session-ID / X-Resume-Version/Caps/Params) are
	// carried by the client in the WebTransport CONNECT request and can be
	// read and validated before Upgrade.
	if r.Header.Get("X-Tunnel-Proto") != resumeFrameTypeResume {
		lgWarnf(sessions.lg(), "[%s] ❌ WT request lacks resume/2 headers, rejecting (v1 removed)", sessionID)
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
		return
	}
	if strings.TrimSpace(r.Header.Get("X-Session-ID")) == "" {
		w.Header().Set("X-Resume-Error", resumeErrInvalidParams.String())
		http.Error(w, errSessionIDRequired.Error(), http.StatusBadRequest)
		return
	}

	// ===== layer-A handshake: version / capabilities / params negotiation =====
	clientVersion := parseHeaderVersion(r.Header.Get("X-Resume-Version"))
	negotiated := negotiateVersion(clientVersion, 2)
	if negotiated == 0 {
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		lgWarnf(sessions.lg(), "[%s] ❌ version negotiation failed: client=%d server=2", sessionID, clientVersion)
		http.Error(w, "resume version unsupported", http.StatusUpgradeRequired)
		return
	}
	clientCaps := parseCaps(r.Header.Get("X-Resume-Caps"))
	serverCaps := serverCapabilities(cfg)
	caps := intersectCaps(clientCaps, serverCaps)
	params := alignParams(parseParams(r.Header.Get("X-Resume-Params")))
	// The downlink replay ring is a server-side resource; its capacity follows
	// the server config and is echoed back explicitly.
	params.windowKB = resolveSessionWindow(cfg.SessionWindow)

	// Layer-A confirmation response headers (the client reads them from the
	// WebTransport handshake response).
	w.Header().Set("X-Resume-Version", "2")
	w.Header().Set("X-Resume-Caps", caps.String())
	w.Header().Set("X-Resume-Params", params.String())
	w.Header().Set("X-Resume-Ack", "ok")

	session, err := wtServer.Upgrade(w, r)
	if err != nil {
		lgErrorf(sessions.lg(), "[%s] ❌ WebTransport upgrade failed: %v", sessionID, err)
		return
	}
	lgInfof(sessions.lg(), "[%s] ✅ WT Session established | Target: %s (%s)", sessionID, target, network)

	datagram := network == "udp"
	isBackup := r.Header.Get("X-Resume-Role") == "backup"

	for {
		stream, err := session.AcceptStream(r.Context())
		if err != nil {
			lgDebugf(sessions.lg(), "[%s] WT Session ended: %v", sessionID, err)
			break
		}

		streamID := fmt.Sprintf("%s-ST%d", sessionID, time.Now().UnixNano()%10000)

		// Each WT stream is an independent resume data plane, resumed with the
		// same X-Session-ID.
		go func(s *webtransport.Stream, sID string) {
			defer s.Close()
			// Backup (probe) line: no target dial, no business session, only
			// the A+B handshake + KEEPALIVE.
			if isBackup {
				writer := &resumeSessionWriter{w: s, padding: cfg.Padding}
				if !datagram {
					if !doServerHandshakeAck(s, writer, params.handshakeAckMs, sID, sessions.lg()) {
						return
					}
				}
				serveBackupKeepaliveOnly(s, writer, params, sID, sessions.lg())
				return
			}

			dialTarget := func() (net.Conn, error) {
				return dialTargetForRequest(r, cfg, network, target)
			}
			sess, isNew, err := sessions.prepareResumeSession(r, dialTarget, cfg.SessionWindow)
			if err != nil {
				lgErrorf(sessions.lg(), "[%s] ❌ WT Resume dial failed: %v", sID, err)
				s.CancelWrite(1)
				return
			}
			if cfg.stats != nil {
				if isNew {
					cfg.stats.SessionsCreated.Add(1)
				} else {
					cfg.stats.SessionsResumed.Add(1)
				}
			}
			if cfg.events != nil {
				kind := ServerEventSessionOpened
				if !isNew {
					kind = ServerEventSessionResumed
				}
				cfg.events.dispatch(ServerEvent{
					Kind:       kind,
					SessionID:  sID,
					Target:     target,
					Network:    Network(network),
					Transport:  TransportWebTransport,
					Principal:  requestState(r).principal,
					RemoteAddr: clientIP(r),
				})
			}
			if isNew {
				lgInfof(sessions.lg(), "[%s] 🆕 WT Resume new session established | Target: %s (%s, %s)", sID, target, network, modeLabel(datagram))
			} else {
				lgInfof(sessions.lg(), "[%s] 🔄 WT Resume existing session recovered | Target: %s (%s)", sID, target, modeLabel(datagram))
			}

			writer := &resumeSessionWriter{w: s, padding: cfg.Padding}
			// Note: mounting the activeWriter happens in serveResumeDataPlane
			// only after the layer-B handshake completes, so the downlinkPump
			// never writes DATA frames into the new stream before the
			// HANDSHAKE-ACK (the client's first frame must be HANDSHAKE-ACK).
			var clientDownlink uint64
			handshakeDone := false
			if !datagram {
				cd, ok := doWTStreamHandshake(s, writer, params.handshakeAckMs, sID, sessions.lg())
				if !ok {
					return
				}
				clientDownlink = cd
				handshakeDone = true
			}
			serveResumeDataPlane(sess, s, writer, params, clientDownlink, sID, handshakeDone, sess.clearActiveWriter)
			s.CancelRead(0)
		}(stream, streamID)
	}
}

// doWTStreamHandshake performs the layer-B handshake on a WT stream: read the
// client HANDSHAKE frame (whose payload carries this stream's downlink
// refill point clientDownlink, because WT has no per-stream HTTP headers) and
// reply HANDSHAKE-ACK. Returns the parsed clientDownlink and success. Timeout
// / non-HANDSHAKE → false.
func doWTStreamHandshake(s *webtransport.Stream, writer *resumeSessionWriter, timeoutMs int, sessionID string, lg *slog.Logger) (uint64, bool) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	type res struct {
		typ     byte
		seq     uint64
		payload []byte
		err     error
	}
	done := make(chan res, 1)
	go func() {
		payloadBuf := make([]byte, 64*1024)
		typ, seq, n, err := readFrame(s, payloadBuf)
		var pl []byte
		if n > 0 {
			pl = make([]byte, n)
			copy(pl, payloadBuf[:n])
		}
		done <- res{typ, seq, pl, err}
	}()
	var clientDownlink uint64
	select {
	case r := <-done:
		if r.err != nil {
			lgWarnf(lg, "[%s] ❌ WT HANDSHAKE read failed: %v", sessionID, r.err)
			return 0, false
		}
		if r.typ != resumeFrameHandshake {
			lgWarnf(lg, "[%s] ❌ first WT frame is not HANDSHAKE (0x%02x), handshake failed", sessionID, r.typ)
			return 0, false
		}
		// The HANDSHAKE payload carries clientDownlink (decimal string).
		if len(r.payload) > 0 {
			if v, errParse := strconv.ParseUint(string(r.payload), 10, 64); errParse == nil {
				clientDownlink = v
			}
		}
	case <-time.After(timeout):
		lgWarnf(lg, "[%s] ❌ WT HANDSHAKE timed out (%v)", sessionID, timeout)
		return 0, false
	}
	if err := writer.writeControl(resumeFrameHandshakeAck, nil); err != nil {
		lgWarnf(lg, "[%s] ❌ failed to write WT HANDSHAKE-ACK: %v", sessionID, err)
		return 0, false
	}
	lgDebugf(lg, "[%s] ✅ WT layer-B handshake confirmed (HANDSHAKE→HANDSHAKE-ACK, clientDownlink=%d)", sessionID, clientDownlink)
	return clientDownlink, true
}

// runWTUDPDatagramLoop is the redial loop for the WT-UDP datagram plane. The
// first stream is opened synchronously by the caller (DialPacketContext's
// ready semantics); this loop owns the rest of the lifecycle: after a stream
// drop or force pulse, open a new stream and the server reuses the same UDP
// socket by X-Session-ID (no seq replay — UDP is unordered; uplink packets
// arriving during the redial gap queue up). When redials are exhausted,
// AutoRedial decides revive or terminate; RedialBudget only constrains each
// stream-open's dialing phase.
func runWTUDPDatagramLoop(ctx context.Context, cfg clientConfig, mgr *wtSessionManager,
	packet *virtualPacketConn, session *webtransport.Session, firstStream *webtransport.Stream,
	upstream chan []byte, done <-chan struct{}, force <-chan struct{},
) error {
	stream := firstStream
	var current atomic.Pointer[webtransport.Stream]
	current.Store(stream)
	// force pulse → close the current stream: uplink write failure / downlink
	// read failure exit together and enter redial immediately.
	if force != nil {
		go func() {
			for {
				select {
				case <-force:
					if s := current.Load(); s != nil {
						lgDebugf(cfg.lg(), "[WT-UDP:%s] 🔌 force pulse: closing current stream for immediate redial (server UDP socket retained)", cfg.TargetAddr)
						_ = s.Close()
					}
				case <-done:
					return
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	for attempt := 1; ; attempt++ {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if stream == nil {
			// Open a new stream (session-level self-heal: when the WT session
			// dies, GetSession promotes the backup or dials now).
			if session == nil || session.Context().Err() != nil {
				session = nil
				sess, err := mgr.GetSession(ctx)
				if err != nil {
					if !backoffWTUDP(ctx, cfg, done, attempt) {
						return wtUDPTerminalErr(ctx)
					}
					continue
				}
				session = sess
			}
			dctx, dcancel := context.WithCancel(ctx)
			if cfg.RedialBudget > 0 {
				dctx, dcancel = context.WithTimeout(ctx, cfg.RedialBudget)
			}
			s, err := session.OpenStreamSync(dctx)
			dcancel()
			if err != nil {
				session = nil
				if !backoffWTUDP(ctx, cfg, done, attempt) {
					return wtUDPTerminalErr(ctx)
				}
				continue
			}
			stream = s
			current.Store(stream)
		}
		lgInfof(cfg.lg(), "[WT-UDP:%s] ✅ tunnel ready", cfg.TargetAddr)

		// attempt lifecycle: when either side fails or done/ctx fires, over()
		// closes the stream and converges; the next round starts only after
		// both goroutines exit (guaranteeing a single upstream consumer).
		attemptDone := make(chan struct{})
		var overOnce sync.Once
		over := func() {
			overOnce.Do(func() {
				close(attemptDone)
				_ = stream.Close()
			})
		}
		var upErr, downErr error
		upExited := make(chan struct{})
		downExited := make(chan struct{})
		go func() {
			defer close(upExited)
			for {
				select {
				case <-attemptDone:
					return
				case pkt := <-upstream:
					if err := writeUDPPacket(stream, pkt, cfg.Padding); err != nil {
						upErr = err
						over()
						return
					}
				}
			}
		}()
		go func() {
			defer close(downExited)
			buf := make([]byte, 64*1024)
			for {
				n, err := readUDPPacket(stream, buf)
				if err != nil {
					downErr = err
					over()
					return
				}
				// deliver failure (local side already closed) also converges;
				// when done is closed the main loop treats it as local close.
				if err := packet.deliver(buf[:n]); err != nil {
					downErr = err
					over()
					return
				}
			}
		}()

		select {
		case <-attemptDone:
		case <-done:
			over()
		case <-ctx.Done():
			over()
		}
		<-upExited
		<-downExited
		current.Store(nil)
		stream = nil

		// Local close / sessionCtx cancel: the session is final, no redial.
		select {
		case <-done:
			return nil
		default:
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if cfg.events != nil {
			cfg.events.dispatch(ClientEvent{
				Kind:      EventReconnecting,
				Target:    cfg.TargetAddr,
				Network:   NetworkUDP,
				Transport: cfg.transportValue(),
				Attempt:   attempt,
				Reason:    "datagram stream interrupted",
				Err:       firstNonNil(upErr, downErr),
			})
		}
		if cfg.stats != nil {
			cfg.stats.ResumeReconnects.Add(1)
		}
		if !backoffWTUDP(ctx, cfg, done, attempt) {
			return wtUDPTerminalErr(ctx)
		}
	}
}

// backoffWTUDP is the redial backoff; returning false means the session
// should terminate (done/ctx/exhausted). attempt increments per round; when
// AutoRedial is off, the 16th attempt is terminal.
func backoffWTUDP(ctx context.Context, cfg clientConfig, done <-chan struct{}, attempt int) bool {
	delay := time.Duration(attempt) * 200 * time.Millisecond
	if delay > resumeBackoffMax {
		delay = resumeBackoffMax
	}
	// Up to +100% jitter to desynchronize a reconnecting fleet (avoid avalanche).
	delay += time.Duration(rand.Int64N(int64(delay)))
	lgInfof(cfg.lg(), "[WT-UDP:%s] 🔁 stream died, reopen #%d (server UDP socket retained), waiting %v", cfg.TargetAddr, attempt, delay)
	select {
	case <-done:
		return false
	case <-ctx.Done():
		return false
	case <-time.After(delay):
	}
	if attempt%resumeMaxAttempts == 0 {
		if !cfg.AutoRedial {
			return false
		}
		lgWarnf(cfg.lg(), "[WT-UDP:%s] 🔁 redial hit the %d-attempt cap, AutoRedial resets the counter and continues", cfg.TargetAddr, resumeMaxAttempts)
	}
	return true
}

// wtUDPTerminalErr maps the three reasons backoff returns false into a final error.
func wtUDPTerminalErr(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errResumeAttemptsExhausted
}

// firstNonNil returns the first non-nil error (nil if all are nil).
func firstNonNil(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
