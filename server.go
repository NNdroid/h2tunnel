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

// setTunnelHeaders 装配穿透 CDN / 反代所必需的响应头。
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
		// 单一鉴权入口：所有服务端请求（含探活/预热 lane）都经此校验。
		principal, err = cfg.Authenticator(r.Context(), r)
	} else {
		// 白盒测试直接构造 serverConfig 时允许匿名（SDK NewServer 强制非空）。
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
	// 探活 lane（X-Resume-Role: backup）永不建立真实连接：Kind 让
	// TargetDialer 能区分（并防御性拒绝 probe 拨号）。
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
	// 鉴权单入口：白盒测试直接构造 serverConfig 时可省略（匿名回退）；
	// 正式路径由 NewServer 强制非空。
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
	lgDebugf(cfg.lg(), "[%s] === New incoming tunnel request ===", sessionID)
	lgDebugf(cfg.lg(), "[%s] Proto: %s, Method: %s, Path: %s, Client Physical Addr: %s", sessionID, r.Proto, r.Method, r.URL.Path, clientPhysicalAddr)

	isMasqueTCP := r.Method == http.MethodConnect && r.Header.Get("Protocol") == "connect-tcp"
	isWT := wtServer != nil && r.Method == http.MethodConnect && r.Header.Get("Protocol") == "webtransport"
	transport := Transport(requestTransport(r, isWT, isMasqueTCP, false))
	var err error
	r, err = authenticateServerRequest(r, cfg, transport)
	if err != nil {
		lgWarnf(cfg.lg(), "[%s] ❌ Authentication failed: Access denied (IP: %s)", sessionID, clientIP(r))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	reqNetwork, _ := getRequestDestination(r, cfg)
	if isMasqueTCP {
		reqNetwork = "tcp"
	}

	policy := cfg.effectiveRoutingPolicy()
	if !policy.allowsNetwork(reqNetwork) {
		lgWarnf(cfg.lg(), "[%s] 🚫 严格分流拦截: 服务端限制 Network='%s'，拒绝 %s 请求 (IP: %s)", sessionID, cfg.Network, strings.ToUpper(reqNetwork), clientIP(r))
		http.Error(w, fmt.Sprintf("%s traffic forbidden by server policy", strings.ToUpper(reqNetwork)), http.StatusForbidden)
		return
	}

	if err := checkStrictTransportPolicy(r, policy, cfg.Transport, isWT, isMasqueTCP, false); err != nil {
		lgWarnf(cfg.lg(), "[%s] 🚫 严格分流拦截: %v (IP: %s)", sessionID, err, clientIP(r))
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if isWT {
		lgDebugf(cfg.lg(), "[%s] -> Dispatching to WebTransport handler", sessionID)
		handleWebTransportServer(w, r, sessionID, cfg, wtServer, sessions)
		return
	}
	if isMasqueTCP {
		lgDebugf(cfg.lg(), "[%s] -> Dispatching to MASQUE-TCP handler", sessionID)
		handleMasqueTCPServer(w, r, sessionID, cfg, sessions)
		return
	}
	if r.Method == http.MethodPost {
		if r.Header.Get("X-Tunnel-Proto") == resumeFrameTypeResume {
			lgDebugf(cfg.lg(), "[%s] -> Dispatching to H2-Stream RESUME handler", sessionID)
			handleH2StreamResumeServer(w, r, sessionID, cfg, sessions)
			return
		}
		lgDebugf(cfg.lg(), "[%s] -> 拒绝非 resume/2 的 POST（v1 已移除）", sessionID)
		w.Header().Set("X-Resume-Error", resumeErrVersionUnsupported.String())
		http.Error(w, "resume/2 required", http.StatusUpgradeRequired)
		return
	}

	lgWarnf(cfg.lg(), "[%s] ❌ Unsupported request method or protocol combination", sessionID)
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func serveResumeDataPlane(sess *tunnelSession, up io.Reader, writer *resumeSessionWriter, params resumeParams, clientDownlink uint64, sessionID string, handshakeAlreadyDone bool, clearWriter func(*resumeSessionWriter)) {
	datagram := sess.datagram

	if !datagram && !handshakeAlreadyDone {
		if !doServerHandshakeAck(up, writer, params.handshakeAckMs, sessionID, sess.lg()) {
			return
		}
	}

	defer clearWriter(writer)

	// attachAndReplay 在 downlinkMu 下原子完成挂载 + 重放：保证 pump 的
	// 实时帧不会插到重放帧之前（帧序保证，见 session.go）。
	if err := sess.attachAndReplay(writer, clientDownlink); err != nil {
		lgWarnf(sess.lg(), "[%s] ❌ 下行补发失败（可能窗口已被覆盖）: %v", sessionID, err)
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
			lgDebugf(sess.lg(), "[%s] Resume END 帧收到", sessionID)
			sess.touch()
			return
		}
		if err != nil {
			lgDebugf(sess.lg(), "[%s] Resume 上行读结束: %v", sessionID, err)
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
				lgWarnf(sess.lg(), "[%s] Resume 上行收到非业务帧 0x%02x", sessionID, typ)
				return
			}
		}
		if err := sess.acceptUplinkSeq(seq, payloadBuf[:n]); err != nil {
			lgWarnf(sess.lg(), "[%s] ❌ Resume 上行 seq 错误: %v", sessionID, err)
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
			lgWarnf(lg, "[%s] ❌ HANDSHAKE 读取失败: %v", sessionID, res.err)
			return false
		}
		if res.typ != resumeFrameHandshake || res.n != 0 {
			lgWarnf(lg, "[%s] ❌ 首个帧非 HANDSHAKE（0x%02x），握手失败", sessionID, res.typ)
			return false
		}
	case <-time.After(timeout):
		lgWarnf(lg, "[%s] ❌ HANDSHAKE 超时 (%v)", sessionID, timeout)
		return false
	}
	if err := writer.writeControl(resumeFrameHandshakeAck, nil); err != nil {
		lgWarnf(lg, "[%s] ❌ 写 HANDSHAKE-ACK 失败: %v", sessionID, err)
		return false
	}
	lgDebugf(lg, "[%s] ✅ B 层握手确认完成 (HANDSHAKE→HANDSHAKE-ACK)", sessionID)
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
				lgDebugf(lg, "[%s] 备用线路流结束: %v", sessionID, res.err)
				return
			}
			if res.typ == resumeFrameKeepalive {
				if err := writer.writeControl(resumeFrameKeepaliveAck, nil); err != nil {
					return
				}
			}
		case <-time.After(keepaliveTimeout):
			lgWarnf(lg, "[%s] 备用线路 KEEPALIVE 超时，判定失效", sessionID)
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
