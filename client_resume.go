package h2tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// =========================================
// Client session-resume tunnel executor (executeResumableTunnel).
//
// Differences from executeHTTPTunnel:
//   - requests carry X-Tunnel-Proto: resume/2 and reuse X-Session-ID
//   - frame format is a resume frame with an 8-byte seq (resumeframe.go)
//   - uplink goes into the ring before the stream; a new stream replays from the server-acked seq
//   - a stream break (write error / read error) does not close the session; it returns to the outer attempts loop
//     to reopen a stream with the same session id — disconnect -> redial -> resume
// =========================================

const (
	resumeMaxAttempts = 16              // max rebuilds within one localConn lifetime
	resumeBackoffMax  = 5 * time.Second // rebuild backoff cap
)

// seqWriter is an io.Writer that auto-increments seq — shared by uplink replay and live
// padding is applied inside Write, including ring-buffer replay writes.
type seqWriter struct {
	w       io.Writer
	seq     *atomic.Uint64
	padding paddingPolicy
}

func (s *seqWriter) Write(p []byte) (int, error) {
	seq := s.seq.Load()
	n, err := writeResumeDataFrames(s.w, seq, p, s.padding)
	if n > 0 {
		s.seq.Store(seq + uint64(n))
	}
	return n, err
}

// executeResumableTunnel is the client TCP entry when Resume is enabled.
// It establishes a logical session in the table and, after a disconnect, resumes
// on a new HTTP stream with the same session id — "never interrupted" for long
// streams like SSH (bounded by SessionWindowKB).
func executeResumableTunnel(sessionID string, localConn net.Conn, reqUrl string, cfg clientConfig, mgr *connectionManager) {
	_ = executeResumableTunnelContext(context.Background(), sessionID, localConn, reqUrl, cfg, mgr, nil, nil)
}

func executeResumableTunnelContext(ctx context.Context, sessionID string, localConn net.Conn, reqUrl string, cfg clientConfig, mgr *connectionManager, ready chan<- error, force <-chan struct{}) error {
	defer localConn.Close()
	readyOnce := sync.Once{}
	notifyReady := func(err error) {
		if ready == nil {
			return
		}
		readyOnce.Do(func() { ready <- err })
	}
	defer func() {
		if ctx.Err() != nil {
			notifyReady(ctx.Err())
		}
	}()
	ringBuf := newResumeClientRingBuf(cfg.SessionWindow)
	sessID := sessionID
	var serverUplink uint64
	var clientDownlink uint64 // local downlink bytes received; reported as X-Resume-Downlink on reconnect so the server replays the gap
	// Get the current active primary-lane http.Client via L3 (primary down -> backup promotion switches the transport pool).
	httpClient := pickClient(mgr, "tcp")
	if httpClient == nil {
		err := errors.New("h2tunnel: no ready transport connection")
		notifyReady(err)
		return err
	}

	// The per-attempt budget lives inside runResumeAttemptContext (connect + handshake
	// phase, timer stopped at ready); here we only handle the redial cadence.

	for attempt := 1; ; attempt++ {
		ok, err := runResumeAttemptContext(ctx, sessID, &serverUplink, &clientDownlink, localConn, ringBuf, reqUrl, cfg, httpClient, func() { notifyReady(nil) }, force)
		if ok {
			return nil // normal end (EOF / peer closed)
		}
		if err != nil {
			// Fail-fast on fatal (never-recoverable) errors regardless of AutoRedial:
			// bad credentials / policy rejection / protocol version mismatch are
			// configuration problems, not transient network blips, so redialing
			// forever would just storm the server. Transient-looking errors (5xx,
			// gap) still redial; with AutoRedial on they retry indefinitely (wait
			// for the network to return), with AutoRedial off they terminate.
			if ctx.Err() != nil || isFatalTunnelError(err) || (!cfg.AutoRedial && isPermanentTunnelError(err)) {
				notifyReady(err)
				return err
			}
			lgWarnf(cfg.lg(), "[Resume] ❌ session unrecoverable: %v", err)
		}
		// Stream break: re-fetch the primary-lane client before each redial (use the new transport if primary switched)
		if mgr != nil {
			httpClient = mgr.PickClient("tcp")
			if httpClient == nil {
				err := errors.New("h2tunnel: no ready transport connection")
				notifyReady(err)
				return err
			}
		}
		// try to recover after backoff (same session id, same serverUplink)
		delay := time.Duration(attempt) * 200 * time.Millisecond
		if delay > resumeBackoffMax {
			delay = resumeBackoffMax
		}
		// Add up to +100% jitter so synchronized tunnels (a fleet coming back
		// from the same outage) don't reconnect in lockstep and avalanche the
		// server.
		delay += time.Duration(rand.Int64N(int64(delay)))
		lgInfof(cfg.lg(), "[Resume] 🔁 redial #%d (same-session resume), waiting %v", attempt, delay)
		if cfg.events != nil {
			cfg.events.dispatch(ClientEvent{
				Kind:      EventReconnecting,
				Target:    cfg.TargetAddr,
				Network:   NetworkTCP,
				Transport: cfg.transportValue(),
				Attempt:   attempt,
				Reason:    "stream interrupted",
			})
		}
		if cfg.stats != nil {
			cfg.stats.ResumeReconnects.Add(1)
		}
		select {
		case <-ctx.Done():
			notifyReady(ctx.Err())
			return ctx.Err()
		case <-time.After(delay):
		}

		// Redial-exhaustion handling: with AutoRedial reset the counter for another round (infinite revival,
		// fits "disconnected, waiting for the network to return"); otherwise terminate the session.
		if attempt%resumeMaxAttempts == 0 {
			if !cfg.AutoRedial {
				break
			}
			lgWarnf(cfg.lg(), "[Resume] 🔁 redial hit the %d cap; AutoRedial resets the counter and continues", resumeMaxAttempts)
			if cfg.events != nil {
				cfg.events.dispatch(ClientEvent{
					Kind:      EventReconnecting,
					Target:    cfg.TargetAddr,
					Network:   NetworkTCP,
					Transport: cfg.transportValue(),
					Attempt:   attempt,
					Reason:    "redial cycle reset (auto-redial)",
				})
			}
		}
	}
	lgWarnf(cfg.lg(), "[Resume] ❌ exceeded max retries (%d); session terminated", resumeMaxAttempts)
	err := errResumeAttemptsExhausted
	notifyReady(err)
	return err
}

// TunnelError means the server rejected tunnel establishment with an HTTP status code.
// Beyond the public sentinels, embedders can use errors.As(*TunnelError) to recover the
// original status for fine-grained handling.
type TunnelError struct {
	status int
	// err is the mapped public sentinel (ErrUnauthenticated / ErrForbidden),
	// exposed to errors.Is via Unwrap; nil for non-auth/authz errors.
	err error
}

func (e *TunnelError) Error() string {
	return fmt.Sprintf("h2tunnel: server rejected tunnel with HTTP %d", e.status)
}

func (e *TunnelError) Unwrap() error { return e.err }

// HTTPStatus returns the HTTP status the server rejected with.
func (e *TunnelError) HTTPStatus() int { return e.status }

// newTunnelHTTPError maps a server-rejection HTTP status to a public sentinel error:
// embedders can use errors.Is(err, h2tunnel.ErrUnauthenticated) /
// errors.Is(err, h2tunnel.ErrForbidden) to distinguish "change the token" from "change the target".
func newTunnelHTTPError(status int) error {
	var sentinel error
	switch status {
	case http.StatusProxyAuthRequired, http.StatusUnauthorized:
		sentinel = ErrUnauthenticated
	case http.StatusForbidden:
		sentinel = ErrForbidden
	}
	return &TunnelError{status: status, err: sentinel}
}

func isPermanentTunnelError(err error) bool {
	var statusErr *TunnelError
	return errors.As(err, &statusErr) || errors.Is(err, errGap) || errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrForbidden)
}

// isFatalTunnelError reports errors that redialing can never recover from, so the
// tunnel must fail-fast even when AutoRedial is enabled. The only such case is a
// resume protocol version mismatch (HTTP 426): the client and server speak
// different resume versions, and a retry will never interoperate — it is a
// build/version problem, not a transient network blip.
//
// Auth / target-denied (401/403) / 5xx errors intentionally do NOT fail-fast with
// AutoRedial on: the product design keeps redialing through them because a network
// change can re-authenticate or bring the target back (see isPermanentTunnelError
// for the AutoRedial-off semantics).
func isFatalTunnelError(err error) bool {
	var statusErr *TunnelError
	if errors.As(err, &statusErr) && statusErr.status == http.StatusUpgradeRequired {
		return true // 426 resume version unsupported: never recoverable by redialing
	}
	return false
}

// buildResumeRequest builds a resume session request per transport type.
// body is the io.Pipe reader (upstream resume frames are written to pw by the send goroutine).
func buildResumeRequest(ctx context.Context, body io.Reader, sessID string, clientDownlink *uint64, ringBuf *resumeClientRingBuf, reqUrl string, cfg clientConfig) *http.Request {
	req, _ := buildResumeRequestChecked(ctx, body, sessID, clientDownlink, ringBuf, reqUrl, cfg)
	return req
}

func buildResumeRequestChecked(ctx context.Context, body io.Reader, sessID string, clientDownlink *uint64, ringBuf *resumeClientRingBuf, reqUrl string, cfg clientConfig) (*http.Request, error) {
	var method, reqURL string
	if cfg.usesMasque() {
		// MASQUE-TCP: CONNECT on the masque path; the target is carried in the path + X-Dst header
		method = http.MethodConnect
		host, port, _ := net.SplitHostPort(cfg.TargetAddr)
		if host == "" {
			host, port = cfg.TargetAddr, "22"
		}
		u, _ := url.Parse(reqUrl)
		u.Path = fmt.Sprintf("%s/tcp/%s/%s/", masquePathBase(cfg.Path), url.PathEscape(host), url.PathEscape(port))
		reqURL = u.String()
	} else {
		// h2 / h3 / grpc：POST cfg.Path
		method = http.MethodPost
		reqURL = reqUrl
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, err
	}
	if err := applyClientCredentials(ctx, req.Header, cfg); err != nil {
		return nil, err
	}
	req.Header.Set("X-Tunnel-Proto", resumeFrameTypeResume)
	req.Header.Set("X-Session-ID", sessID)
	// Downlink resume watermark: downlink bytes already delivered to the app (not the uplink ring cursor); the server replays the gap accordingly.
	req.Header.Set("X-Resume-Downlink", strconv.FormatUint(*clientDownlink, 10))
	// ===== resume/2 handshake headers: version / capabilities / parameters =====
	req.Header.Set("X-Resume-Version", "2")
	req.Header.Set("X-Resume-Caps", clientCapabilities(cfg).String())
	req.Header.Set("X-Resume-Params", clientParams(cfg).String())
	if cfg.RoleBackup {
		req.Header.Set("X-Resume-Role", "backup")
	}
	if cfg.CustomHost != "" {
		req.Host = cfg.CustomHost
	}
	setXDst(req.Header, cfg)
	setTunnelRequestHeaders(req.Header)
	// TCP Brutal exchange (piggybacked, no extra connection): the offer carries
	// this leg's local rate/gain plus a fresh nonce, and X-Client-Group carries
	// the stable per-client seed the server derives the group id from.
	setBrutalOfferHeaders(req.Header, cfg.Brutal, cfg.clientGroup)

	if cfg.usesMasque() {
		req.Header.Set("Protocol", protocolConnectTCP)
		// quic-go's http3 client treats req.Proto as the RFC 8441 :protocol value for
		// extended CONNECT (CONNECT with a non-empty, non-HTTP/1.1 Proto), so it must
		// carry the real upgrade token. The old "HTTP/3" placeholder is not a token at
		// all ('/' is illegal in token grammar): the h3 leg then stalls instead of
		// completing the CONNECT, and auto mode only gives up after masqueH3ProbeGrace.
		// The h2 leg reads the Protocol header instead (masqueExtendedConnectTransport).
		req.Proto = protocolConnectTCP
	}
	if cfg.usesGRPC() {
		// gRPC is only an outer Content-Type tag; resume frames are not wrapped in gRPC framing
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
	}
	return req, nil
}

// runResumeAttempt is one stream's full lifecycle: open -> replay/live -> receive END.
// (normalEnd=true, nil) means local EOF / peer END;
// (false, nil) means the stream was interrupted (go to the next redial);
// (false, errGap) means an unrecoverable gap (terminate the session).
func runResumeAttempt(sessID string, serverUplink *uint64, clientDownlink *uint64,
	localConn net.Conn, ringBuf *resumeClientRingBuf,
	reqUrl string, cfg clientConfig, httpClient *http.Client,
) (bool, error) {
	return runResumeAttemptContext(context.Background(), sessID, serverUplink, clientDownlink, localConn, ringBuf, reqUrl, cfg, httpClient, nil, nil)
}

func runResumeAttemptContext(parent context.Context, sessID string, serverUplink *uint64, clientDownlink *uint64,
	localConn net.Conn, ringBuf *resumeClientRingBuf,
	reqUrl string, cfg clientConfig, httpClient *http.Client, onReady func(),
	force <-chan struct{},
) (bool, error) {
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	// The send goroutine also closes pw (idempotent); this defensive close releases
	// the pipe writer on every early-return path so the request-body reader (inside
	// the http client) never blocks on pr.Read() after a failed attempt.
	defer pw.Close()

	// RedialBudget bounds only the connect+handshake phase; the timer stops at ready
	// (layer-B confirmation), so established streams are unaffected (otherwise a healthy
	// stream would be killed every budget period).
	var budgetStop func()
	if cfg.RedialBudget > 0 {
		timer := time.AfterFunc(cfg.RedialBudget, func() {
			lgDebugf(cfg.lg(), "[Resume] ⏱️ dial budget %v expired, canceling this attempt", cfg.RedialBudget)
			cancel()
			// wake a sendLoop that may be blocked in localConn.Read.
			_ = localConn.SetReadDeadline(time.Now())
		})
		budgetStop = func() { timer.Stop() }
		defer timer.Stop()
	}

	// A force signal cancels this attempt's ctx, interrupting the resp.Body reader and
	// stream setup — equivalent to a stream break, so the outer loop redials immediately
	// (session/ring preserved).
	go func() {
		select {
		case <-force:
			lgDebugf(cfg.lg(), "[Resume] 🔌 force pulse: abandoning the current stream and redialing immediately (session/recovery window preserved)")
			cancel()
			// immediately wake the sendLoop blocked in localConn.Read (a pipe read does not respond to ctx cancel).
			_ = localConn.SetReadDeadline(time.Now())
		case <-ctx.Done():
		}
	}()

	// On attempt end, interrupt the send goroutine that may be blocked in localConn.Read,
	// so the old sendLoop and the next attempt's sendLoop never read the same conn concurrently
	// (see resumeSendLoop's done parameter).
	done := make(chan struct{})
	defer func() {
		close(done)
		// make a blocked Read return immediately: this attempt's sendLoop exits on it.
		_ = localConn.SetReadDeadline(time.Now())
	}()
	// clear any stale read deadline left by the previous round, back to "wait forever".
	_ = localConn.SetReadDeadline(time.Time{})

	// Build the resume request per transport type:
	//  - h2 / h3 / grpc: POST cfg.Path, target in X-Target/X-Network headers
	//  - masque-tcp: CONNECT on the masque path, target in the URL path + X-Dst header
	// The resume frame is the shared inner data plane; each transport only supplies the outer pipe (grpc just tags Content-Type).
	req, err := buildResumeRequestChecked(ctx, pr, sessID, clientDownlink, ringBuf, reqUrl, cfg)
	if err != nil {
		return false, err
	}
	var resp *http.Response
	err = nil
	if rt, ok := httpClient.Transport.(http.RoundTripper); ok && cfg.usesMasque() {
		resp, err = rt.RoundTrip(req)
	} else {
		resp, err = httpClient.Do(req)
	}
	if err != nil {
		lgWarnf(cfg.lg(), "[Resume] ❌ failed to open stream: %v", err)
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		lgWarnf(cfg.lg(), "[Resume] ❌ server rejected: HTTP %d", resp.StatusCode)
		return false, newTunnelHTTPError(resp.StatusCode)
	}

	if v := resp.Header.Get("X-Resume-Uplink"); v != "" {
		if n, errParse := strconv.ParseUint(v, 10, 64); errParse == nil {
			*serverUplink = n
		}
	}
	// ===== layer-A confirmation check =====
	ack := resp.Header.Get("X-Resume-Ack")
	if ack != "ok" {
		if code := resp.Header.Get("X-Resume-Error"); code != "" {
			lgWarnf(cfg.lg(), "[Resume] ❌ handshake rejected: %s", code)
		} else {
			lgWarnf(cfg.lg(), "[Resume] ❌ handshake not acknowledged (X-Resume-Ack=%q), aborting", ack)
		}
		return false, errors.New("h2tunnel: resume handshake was not acknowledged")
	}
	// The server's echoed parameters win (aligned negotiation). The ring window keeps
	// the local config (dynamic resize is risky); the aligned value is only logged and used for heartbeats.
	if v := resp.Header.Get("X-Resume-Params"); v != "" {
		aligned := alignParams(parseParams(v))
		lgDebugf(cfg.lg(), "[Resume] 🔧 server-aligned params: window_kb=%d handshake_ack=%dms keepalive=%ds",
			aligned.windowKB, aligned.handshakeAckMs, aligned.keepaliveSec)
	}
	// TCP Brutal bandwidth exchange (piggybacked on this handshake): verify the
	// echoed nonce and cache the negotiated decision for the next dial. A new
	// leg re-offers on its first request, so a migrated TCP leg re-negotiates.
	handleBrutalReply(req, resp.Header.Get(brutalHeaderParams), cfg.brutalPeer, cfg.lg())
	lgInfof(cfg.lg(), "[Resume] ✅ tunnel resume ready (serverUplink=%d)", *serverUplink)

	// ===== layer-B handshake: send HANDSHAKE first, wait HANDSHAKE-ACK, zero business bytes before ack =====
	if err := writeFrame(pw, resumeFrameHandshake, 0, nil, cfg.Padding.paddingFor(resumeHeaderLen)); err != nil {
		lgWarnf(cfg.lg(), "[Resume] ❌ failed to write HANDSHAKE control frame: %v", err)
		return false, err
	}
	hsBuf := make([]byte, 64*1024)
	typ, _, _, err := readFrame(resp.Body, hsBuf)
	if err != nil {
		lgWarnf(cfg.lg(), "[Resume] ❌ failed to read HANDSHAKE-ACK: %v", err)
		return false, err
	}
	if typ != resumeFrameHandshakeAck {
		lgWarnf(cfg.lg(), "[Resume] ❌ expected HANDSHAKE-ACK, got frame 0x%02x", typ)
		return false, errors.New("h2tunnel: invalid resume handshake response")
	}
	lgDebugf(cfg.lg(), "[Resume] ✅ layer-B handshake confirmed (HANDSHAKE->HANDSHAKE-ACK)")
	if onReady != nil {
		if budgetStop != nil {
			budgetStop() // after ready the budget no longer bounds the data plane
		}
		onReady()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var sendErr, recvErr error

	go func() {
		defer wg.Done()
		defer pw.Close()
		sendErr = resumeSendLoop(pw, localConn, ringBuf, *serverUplink, done, cfg.HeartbeatInterval, cfg.Padding, cfg.lg(), cfg.stats)
	}()
	go func() {
		defer wg.Done()
		recvErr = resumeRecvLoop(resp.Body, localConn, clientDownlink, cfg.lg(), cfg.stats)
	}()

	wg.Wait()

	// Local EOF (app closed the conn) -> sendLoop already sent END and returned nil:
	// treat it as a normal end (half-close semantics win, even if recvErr is non-nil
	// from the cascading session-context cancel).
	if sendErr == nil {
		return true, nil
	}
	if recvErr == nil {
		return true, nil
	}
	_ = sendErr
	return false, nil
}

// resumeSendLoop: first replays from the ring starting at serverUplink, then switches to live mode.
// Live mode: localConn.Read -> Append ring -> seqWriter.Write.
// w is the uplink write target (h2: io.PipeWriter; wt: webtransport.Stream). The stream-mode
// half-close (END) is triggered by the caller when needed (see writeResumeEndFrame).
// done interrupts this send goroutine (possibly blocked in localConn.Read) when the attempt ends,
// so an old attempt's sendLoop and the next attempt's sendLoop never read the same localConn
// concurrently (two readers would split the byte stream unpredictably and corrupt uplink frames).
func resumeSendLoop(w io.Writer, localConn net.Conn, ringBuf *resumeClientRingBuf, startSeq uint64, done <-chan struct{}, heartbeat time.Duration, padding paddingPolicy, lg *slog.Logger, st *ClientStats) error {
	var seq atomic.Uint64
	seq.Store(startSeq)
	sw := &seqWriter{w: w, seq: &seq, padding: padding}

	// Phase A: replay from the ring
	replayed, err := ringBuf.ReplayFrom(startSeq, sw)
	if err != nil {
		if errors.Is(err, errGap) {
			return errGap
		}
		return err
	}
	if replayed > 0 {
		lgDebugf(lg, "[Resume] 🔁 replayed %d uplink bytes (seq %d..%d)", replayed, startSeq, startSeq+uint64(replayed))
	}

	// Phase B: live
	bufPtr := tcpBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer tcpBufPool.Put(bufPtr)
	for {
		// A TCP Read has no select case. A bounded read deadline lets this sole
		// writer wake during an idle period and send a resume KEEPALIVE without
		// adding a competing writer to the HTTP request body.
		if heartbeat > 0 {
			_ = localConn.SetReadDeadline(time.Now().Add(heartbeat))
		}
		n, rErr := localConn.Read(buf)
		if n > 0 {
			ringBuf.Append(buf[:n])
			if st != nil {
				st.UplinkBytes.Add(int64(n))
			}
			if _, wErr := sw.Write(buf[:n]); wErr != nil {
				return wErr
			}
		}
		if rErr != nil {
			if rErr == io.EOF {
				return writeResumeEndFrame(w, padding)
			}
			if heartbeat > 0 {
				if netErr, ok := rErr.(net.Error); ok && netErr.Timeout() {
					select {
					case <-done:
						return nil
					default:
					}
					if err := writeFrame(w, resumeFrameKeepalive, 0, nil, padding.paddingFor(resumeHeaderLen)); err != nil {
						return err
					}
					continue
				}
			}
			// On attempt end (a read timeout from SetReadDeadline), exit quietly and
			// do not treat the interrupt as a stream error that triggers a redial.
			select {
			case <-done:
				return nil
			default:
			}
			return rErr
		}
	}
}

// resumeRecvLoop reads resume DATA frames from the response stream, writes localConn after
// verifying seq continuity, and accumulates clientDownlink (local downlink bytes received) so
// the next stream reports it via X-Resume-Downlink and the server replays the gap. The downlink
// coordinate space is continuous across streams: the first frame's seq must equal *clientDownlink
// (0 for the first stream, last received count for a reconnect), otherwise the gap is unrecoverable.
// An END frame -> local half-close and normal return; a read error -> return err so the outer loop redials.
func resumeRecvLoop(body io.Reader, localConn net.Conn, clientDownlink *uint64, lg *slog.Logger, st *ClientStats) error {
	payloadBuf := make([]byte, 64*1024)
	expected := *clientDownlink
	for {
		typ, seq, n, err := readFrame(body, payloadBuf)
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
			// keepalive-ack frames for the idle primary stream are not part of the data coordinate space and are not delivered to the app.
			continue
		}
		if typ != resumeFrameData {
			*clientDownlink = expected
			return fmt.Errorf("resume: unexpected frame type 0x%02x", typ)
		}
		if seq != expected {
			lgWarnf(lg, "[Resume] ⚠️ downlink seq discontinuity: expected %d, got %d", expected, seq)
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
