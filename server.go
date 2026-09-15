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
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/webtransport-go"
)

// setTunnelHeaders sets the response headers needed to traverse CDNs / reverse proxies.
func setTunnelHeaders(h http.Header) {
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Cache-Control", "no-store, no-transform")
	h.Set("Pragma", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	h.Set("Content-Encoding", "identity")
}

type serverRequestState struct {
	principal Principal
	transport Transport
}

type serverRequestStateKey struct{}

func authenticateServerRequest(r *http.Request, cfg serverConfig, transport Transport) (*http.Request, error) {
	var (
		principal Principal
		err       error
	)
	if cfg.Authenticator != nil {
		// Single auth entry: every server request (including probe/warm-up lanes) is validated here.
		principal, err = cfg.Authenticator(r.Context(), r)
	} else {
		// White-box tests building serverConfig directly may omit it (anonymous fallback); the SDK's NewServer enforces non-nil.
		principal = Principal{ID: "anonymous"}
	}
	if err != nil {
		return r, err
	}
	principal.ID = strings.TrimSpace(principal.ID)
	if principal.ID == "" {
		return r, fmt.Errorf("%w: authenticator returned an empty principal", ErrUnauthenticated)
	}
	state := serverRequestState{principal: principal, transport: transport}
	return r.WithContext(context.WithValue(r.Context(), serverRequestStateKey{}, state)), nil
}

func requestState(r *http.Request) serverRequestState {
	state, _ := r.Context().Value(serverRequestStateKey{}).(serverRequestState)
	return state
}

func targetAllowedByRuntime(cfg serverConfig, target string) bool {
	if strings.TrimSpace(target) == "" {
		return false
	}
	if cfg.TargetDialer != nil {
		return true
	}
	return checkTargetIsAvailable(target, cfg)
}

func dialTargetForRequest(r *http.Request, cfg serverConfig, network, target string) (net.Conn, error) {
	parent := cfg.ServerContext
	if parent == nil {
		parent = context.Background()
	}
	dialCtx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		select {
		case <-r.Context().Done():
			cancel()
		case <-parent.Done():
			cancel()
		case <-done:
		}
	}()
	defer func() {
		close(done)
		cancel()
	}()
	if cfg.TargetDialer == nil {
		if cfg.DialTarget != nil {
			return cfg.DialTarget(dialCtx, network, target)
		}
		var dialer net.Dialer
		dialer.Timeout = 10 * time.Second
		return dialer.DialContext(dialCtx, network, target)
	}
	state := requestState(r)
	// Probe lanes (X-Resume-Role: backup) never establish a real connection: Kind
	// lets TargetDialer distinguish them (and defensively refuse probe dials).
	kind := DialKindBusiness
	if r.Header.Get("X-Resume-Role") == "backup" {
		kind = DialKindProbe
	}
	return cfg.TargetDialer(dialCtx, DialRequest{
		Network:   Network(network),
		Target:    target,
		Transport: state.transport,
		Principal: state.principal,
		Kind:      kind,
	})
}

func writeTargetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		http.Error(w, "Forbidden", http.StatusForbidden)
	case errors.Is(err, ErrUnsupportedNetwork):
		http.Error(w, "Unsupported network", http.StatusBadRequest)
	default:
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
}

func serverOptionsFromConfig(cfg serverConfig) (ServerOptions, error) {
	// Single auth entry: white-box tests building serverConfig directly may omit it
	// (anonymous fallback); the real path is enforced non-nil by NewServer.
	auth := cfg.Authenticator
	if auth == nil {
		auth = Authenticator(func(_ context.Context, _ *http.Request) (Principal, error) {
			return Principal{ID: "anonymous"}, nil
		})
	}
	dialer := TargetDialer(func(ctx context.Context, request DialRequest) (net.Conn, error) {
		legacy := cfg
		if !checkTargetIsAvailable(request.Target, legacy) {
			return nil, ErrForbidden
		}
		if cfg.DialTarget != nil {
			return cfg.DialTarget(ctx, string(request.Network), request.Target)
		}
		var d net.Dialer
		d.Timeout = 10 * time.Second
		return d.DialContext(ctx, string(request.Network), request.Target)
	})
	var tlsConfig *tls.Config
	if cfg.TLSCert != "" || cfg.TLSKey != "" {
		if cfg.TLSCert == "" || cfg.TLSKey == "" {
			return ServerOptions{}, errors.New("both cert and key are required")
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return ServerOptions{}, err
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	} else if cfg.EnableTLS || cfg.EnableH3 {
		cert, _, err := generateSelfSignedCert("")
		if err != nil {
			return ServerOptions{}, err
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	transports := make([]Transport, 0, 6)
	if cfg.Transport == transportAll {
		transports = []Transport{TransportH2, TransportH3, TransportWebTransport, TransportMASQUE, TransportGRPC}
	} else {
		for _, item := range strings.Split(cfg.Transport, ",") {
			transports = append(transports, Transport(strings.TrimSpace(item)))
		}
	}
	networks := []Network{NetworkTCP}
	if cfg.Network == networkUDP {
		networks = []Network{NetworkUDP}
	} else if cfg.Network == networkAll {
		networks = []Network{NetworkTCP, NetworkUDP}
	}
	return ServerOptions{
		Path:          cfg.Path,
		Transports:    transports,
		Networks:      networks,
		TLSConfig:     tlsConfig,
		Authenticator: auth,
		Dialer:        dialer,
		Tuning: ServerTuning{
			SessionWindowBytes: cfg.SessionWindow * 1024,
			Padding:            cfg.Padding.tuning(),
		},
	}, nil
}

func routeTunnelRequest(w http.ResponseWriter, r *http.Request, cfg serverConfig, wtServer *webtransport.Server, sessions *sessionTable) {
	// CDN and reverse proxies commonly downgrade the origin hop to HTTP/1.1.
	// Go's HTTP/1 server otherwise consumes the request body before it starts a
	// response, which deadlocks a bidirectional POST stream. HTTP/2 and HTTP/3
	// are already full duplex; EnableFullDuplex is harmless there.
	_ = http.NewResponseController(w).EnableFullDuplex()

	sessionID := fmt.Sprintf("SVR-%s-%d", r.RemoteAddr, time.Now().UnixNano()%10000)
	clientPhysicalAddr := clientIP(r)
	tr := classifyTunnelRequest(r, cfg, wtServer != nil)
	lgDebugf(cfg.lg(), "[%s] === incoming request === %s %s (proto=%s, client=%s)", sessionID, r.Method, r.URL.Path, r.Proto, clientPhysicalAddr)

	var authErr error
	r, authErr = authenticateServerRequest(r, cfg, tr.transport)
	if authErr != nil {
		lgWarnf(cfg.lg(), "[%s] 🚫 authentication failed: access denied (IP: %s)", sessionID, clientPhysicalAddr)
		if cfg.events != nil {
			cfg.events.dispatch(ServerEvent{
				Kind:       ServerEventAuthRejected,
				SessionID:  sessionID,
				Network:    Network(tr.network),
				Transport:  tr.transport,
				RemoteAddr: clientPhysicalAddr,
				Reason:     "authentication rejected",
				Err:        authErr,
			})
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	policy := cfg.effectiveRoutingPolicy()
	if !policy.allowsNetwork(tr.network) {
		lgWarnf(cfg.lg(), "[%s] 🚫 strict routing policy block: server restricts Network='%s', rejecting %s request (IP: %s)", sessionID, cfg.Network, strings.ToUpper(tr.network), clientPhysicalAddr)
		http.Error(w, fmt.Sprintf("%s traffic forbidden by server policy", strings.ToUpper(tr.network)), http.StatusForbidden)
		if cfg.events != nil {
			cfg.events.dispatch(ServerEvent{
				Kind:       ServerEventTargetDenied,
				SessionID:  sessionID,
				Network:    Network(tr.network),
				Transport:  tr.transport,
				Principal:  requestState(r).principal,
				RemoteAddr: clientPhysicalAddr,
				Target:     tr.target,
				Reason:     "network policy",
			})
		}
		return
	}
	if err := checkStrictTransportPolicy(r, policy, cfg.Transport, tr.transport); err != nil {
		lgWarnf(cfg.lg(), "[%s] 🚫 strict routing policy block: %v (IP: %s)", sessionID, err, clientPhysicalAddr)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	switch tr.kind {
	case kindWebTransport:
		lgDebugf(cfg.lg(), "[%s] -> WebTransport", sessionID)
		handleWebTransportServer(w, r, sessionID, cfg, wtServer, sessions)
	case kindMasqueTCP:
		lgDebugf(cfg.lg(), "[%s] -> MASQUE-TCP", sessionID)
		handleMasqueTCPServer(w, r, sessionID, tr, cfg, sessions)
	case kindMasqueUDP:
		lgDebugf(cfg.lg(), "[%s] -> MASQUE-UDP", sessionID)
		handleMasqueUDPServer(w, r, sessionID, tr, cfg, sessions)
	case kindResume:
		lgDebugf(cfg.lg(), "[%s] -> H2-Stream RESUME", sessionID)
		handleH2StreamResumeServer(w, r, sessionID, tr, cfg, sessions)
	case kindUnsupported:
		if r.Method == http.MethodPost {
			lgDebugf(cfg.lg(), "[%s] 🚫 -> rejecting non resume/2 POST (v1 removed)", sessionID)
			w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
			http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
			return
		}
		lgWarnf(cfg.lg(), "[%s] ❌ unsupported request method or protocol combination", sessionID)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func serveResumeDataPlane(sess *tunnelSession, up io.Reader, writer *resumeSessionWriter, params resumeParams, clientDownlink uint64, sessionID string, handshakeAlreadyDone bool, clearWriter func(*resumeSessionWriter)) {
	datagram := sess.datagram

	if !datagram && !handshakeAlreadyDone {
		if !doServerHandshakeAck(up, writer, params.handshakeAckMs, sessionID, sess.lg()) {
			return
		}
	}

	defer clearWriter(writer)

	// attachAndReplay does install + replay atomically under downlinkMu: it
	// guarantees the pump's live frames don't jump ahead of replay frames (frame
	// ordering guarantee, see session.go).
	if err := sess.attachAndReplay(writer, clientDownlink); err != nil {
		lgWarnf(sess.lg(), "[%s] ⚠️ downlink replay failed (window may have been overwritten): %v", sessionID, err)
		if sess.events != nil {
			sess.events.dispatch(ServerEvent{
				Kind:      ServerEventReplayDropped,
				SessionID: sessionID,
				Network:   Network(sess.network),
				Reason:    "replay window overrun",
				Err:       err,
			})
		}
		_ = writer.writeEnd()
		return
	}

	payloadBuf := make([]byte, 64*1024)
	for {
		var (
			typ byte
			seq uint64
			n   int
			err error
		)
		if datagram {
			n, err = sess.frameR(up, payloadBuf)
		} else {
			typ, seq, n, err = readFrame(up, payloadBuf)
		}
		if errors.Is(err, errResumeEndFrame) {
			lgDebugf(sess.lg(), "[%s] resume END frame received", sessionID)
			sess.touch()
			return
		}
		if err != nil {
			lgDebugf(sess.lg(), "[%s] resume uplink read ended: %v", sessionID, err)
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
			default:
				lgWarnf(sess.lg(), "[%s] ⚠️ resume uplink got a non-data frame 0x%02x", sessionID, typ)
				return
			}
		}
		if err := sess.acceptUplinkSeq(seq, payloadBuf[:n]); err != nil {
			lgWarnf(sess.lg(), "[%s] ⚠️ resume uplink seq error: %v", sessionID, err)
			return
		}
	}
}

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

func serverCapabilities(cfg serverConfig) resumeCaps {
	return resumeCaps{
		datagram:   cfg.effectiveRoutingPolicy().allowsNetwork(networkUDP),
		backupLine: true,
	}
}

func doServerHandshakeAck(up io.Reader, writer *resumeSessionWriter, timeoutMs int, sessionID string, lg *slog.Logger) bool {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
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
			lgWarnf(lg, "[%s] ❌ HANDSHAKE read failed: %v", sessionID, res.err)
			return false
		}
		if res.typ != resumeFrameHandshake || res.n != 0 {
			lgWarnf(lg, "[%s] ❌ first frame was not HANDSHAKE (0x%02x), handshake failed", sessionID, res.typ)
			return false
		}
	case <-time.After(timeout):
		lgWarnf(lg, "[%s] ❌ HANDSHAKE timeout (%v)", sessionID, timeout)
		return false
	}
	if err := writer.writeControl(resumeFrameHandshakeAck, nil); err != nil {
		lgWarnf(lg, "[%s] ❌ failed to write HANDSHAKE-ACK: %v", sessionID, err)
		return false
	}
	lgDebugf(lg, "[%s] ✅ layer-B handshake confirmed (HANDSHAKE→HANDSHAKE-ACK)", sessionID)
	return true
}

func serveBackupKeepaliveOnly(up io.Reader, writer *resumeSessionWriter, params resumeParams, sessionID string, lg *slog.Logger) {
	keepaliveTimeout := time.Duration(params.keepaliveSec) * 3 * time.Second
	if keepaliveTimeout <= 0 {
		keepaliveTimeout = 45 * time.Second
	}
	payloadBuf := make([]byte, 64*1024)
	for {
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
				lgDebugf(lg, "[%s] backup lane stream ended: %v", sessionID, res.err)
				return
			}
			if res.typ == resumeFrameKeepalive {
				if err := writer.writeControl(resumeFrameKeepaliveAck, nil); err != nil {
					return
				}
			}
		case <-time.After(keepaliveTimeout):
			lgWarnf(lg, "[%s] ⚠️ backup lane KEEPALIVE timeout, marked dead", sessionID)
			return
		}
	}
}

func modeLabel(datagram bool) string {
	if datagram {
		return "datagram"
	}
	return "stream"
}
