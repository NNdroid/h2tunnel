package h2tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// =========================================
// Client UDP session resume (datagram resume).
//
// Differences from executeResumableTunnel (stream/TCP):
//   - UDP is a datagram model with no seq replay. After reconnecting an HTTP
//     stream with the same session id, the server reuses the same UDP socket
//     (tunnelSession.datagram=true) and continues sending/receiving subsequent
//     UDP packets on the new stream; already-sent/received packets are not replayed.
//   - Uplink: local UDP packets are wrapped into wire frames by frameW
//     (writeUDPPacket / writeUDPCapsule) and written into the stream body.
//   - Downlink: UDP packets are decoded from the stream body via frameR and written back to the local UDP socket.
//   - A stream break (read error / write failure) does not end the session; it returns to the outer attempts loop to redial with the same session id.
// =========================================

const (
	udpResumeMaxAttempts = 16              // max rebuilds within one UDP-session lifetime
	udpResumeBackoffMax  = 5 * time.Second // rebuild backoff cap
)

// udpSession is one logical UDP session carrying forwarding from a clientAddr to
// the target UDP address. Uplink data flows through the upstream channel into the
// current active stream's write goroutine; downlink is decoded by the read loop and
// written back to the local UDP socket. On a stream break it rebuilds without ending the session.
type udpSession struct {
	sessionID  string
	cfg        clientConfig
	reqUrl     string
	httpClient *http.Client
	localConn  *net.UDPConn
	clientAddr *net.UDPAddr

	// Data-plane framing: masque-udp uses capsules, the rest use datagram packets.
	frameW func(io.Writer, []byte) error
	frameR func(io.Reader, []byte) (int, error)

	// upstream is the uplink queue: the local UDP receive goroutine enqueues, the stream write goroutine consumes.
	upstream chan []byte
	// closing done signals the current stream's read/write loops to exit (session end).
	done      chan struct{}
	doneOnce  sync.Once
	ctx       context.Context
	deliver   func([]byte) error
	ready     chan<- error
	readyOnce sync.Once
	onDone    func(error)
	force     chan struct{}
}

// newUDPSession creates a logical session for one UDP clientAddr and starts the reconnect loop.
func newUDPSession(sessionID string, cfg clientConfig, reqUrl string, httpClient *http.Client, localConn *net.UDPConn, clientAddr *net.UDPAddr) *udpSession {
	s := &udpSession{
		sessionID:  sessionID,
		cfg:        cfg,
		reqUrl:     reqUrl,
		httpClient: httpClient,
		localConn:  localConn,
		clientAddr: clientAddr,
		upstream:   make(chan []byte, cfg.datagramQueueSize()),
		done:       make(chan struct{}),
	}
	if cfg.usesMasque() {
		s.frameW = func(w io.Writer, p []byte) error { return writeUDPCapsule(w, p, cfg.Padding) }
		s.frameR = readUDPCapsule
	} else {
		s.frameW = func(w io.Writer, p []byte) error { return writeUDPPacket(w, p, cfg.Padding) }
		s.frameR = readUDPPacket
	}
	return s
}

func (s *udpSession) close() {
	s.doneOnce.Do(func() { close(s.done) })
}

func (s *udpSession) notifyReady(err error) {
	if s.ready == nil {
		return
	}
	s.readyOnce.Do(func() { s.ready <- err })
}

// enqueue puts a locally received UDP packet onto the uplink queue; drops it if the session already ended.
func (s *udpSession) enqueue(pkt []byte) {
	select {
	case <-s.done:
		return
	case s.upstream <- pkt:
	default:
		lgWarnf(s.cfg.lg(), "[UDP-Resume:%s] ⚠️ uplink queue overflow, dropping packet from %s", s.sessionID, s.clientAddr)
	}
}

// run starts the session main loop: keep opening streams -> resuming, until the local socket closes or max retries are exceeded.
func (s *udpSession) run() {
	var finalErr error
	defer func() {
		s.notifyReady(finalErr)
		s.close()
		if s.onDone != nil {
			s.onDone(finalErr)
		}
	}()
	for attempt := 1; ; attempt++ {
		if s.isDone() {
			if err := s.context().Err(); err != nil {
				finalErr = err
			} else {
				finalErr = net.ErrClosed
			}
			return
		}
		err := s.runOneStream()
		if err == nil {
			return // normal end (peer closed)
		}
		finalErr = err
		// AutoRedial semantics match the TCP side: when on, even "permanent" errors
		// (auth / target denied) keep redialing — these are usually transient after a network change.
		if !s.cfg.AutoRedial && isPermanentTunnelError(err) {
			return
		}
		if s.isDone() {
			return
		}
		delay := time.Duration(attempt) * 200 * time.Millisecond
		if delay > udpResumeBackoffMax {
			delay = udpResumeBackoffMax
		}
		lgInfof(s.cfg.lg(), "[UDP-Resume:%s] 🔁 stream break, redial #%d (same-session resume), waiting %v: %v",
			s.sessionID, attempt, delay, err)
		if s.cfg.events != nil {
			s.cfg.events.dispatch(ClientEvent{
				Kind:      EventReconnecting,
				Target:    s.cfg.TargetAddr,
				Network:   NetworkUDP,
				Transport: s.cfg.transportValue(),
				Attempt:   attempt,
				Reason:    "datagram stream interrupted",
				Err:       err,
			})
		}
		if s.cfg.stats != nil {
			s.cfg.stats.ResumeReconnects.Add(1)
		}
		select {
		case <-s.done:
			return
		case <-s.context().Done():
			finalErr = s.context().Err()
			return
		case <-time.After(delay):
		}

		// Redial-exhaustion handling: AutoRedial matches the TCP side (infinite revival).
		if attempt%udpResumeMaxAttempts == 0 {
			if !s.cfg.AutoRedial {
				break
			}
			lgWarnf(s.cfg.lg(), "[UDP-Resume:%s] 🔁 redial hit the %d cap; AutoRedial resets the counter and continues", s.sessionID, udpResumeMaxAttempts)
		}
	}
	lgWarnf(s.cfg.lg(), "[UDP-Resume:%s] ❌ exceeded max retries (%d); session terminated", s.sessionID, udpResumeMaxAttempts)
}

func (s *udpSession) isDone() bool {
	select {
	case <-s.done:
		return true
	case <-s.context().Done():
		return true
	default:
		return false
	}
}

func (s *udpSession) context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *udpSession) enqueueContext(ctx context.Context, pkt []byte) error {
	select {
	case <-s.done:
		return net.ErrClosed
	case <-s.context().Done():
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case s.upstream <- pkt:
		return nil
	}
}

// runOneStream opens one HTTP stream and resumes over it. Returns nil on a normal end;
// returns err on a stream break (should redial).
func (s *udpSession) runOneStream() error {
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(s.context())
	defer cancel()
	// The uplink goroutine also closes pw (idempotent); this defensive close releases
	// the pipe writer on every early-return path.
	defer pw.Close()

	// RedialBudget bounds only the stream-open phase; the timer stops at ready, so
	// established streams are unaffected (matching the TCP/WT side).
	var budgetStop func()
	if s.cfg.RedialBudget > 0 {
		timer := time.AfterFunc(s.cfg.RedialBudget, func() {
			lgDebugf(s.cfg.lg(), "[UDP-Resume:%s] ⏱️ dial budget %v expired, canceling this stream open", s.sessionID, s.cfg.RedialBudget)
			cancel()
		})
		budgetStop = func() { timer.Stop() }
		defer timer.Stop()
	}

	// A force signal cancels this stream's ctx, interrupting the reader to trigger a redial (the server's UDP socket is preserved).
	go func() {
		select {
		case <-s.force:
			lgDebugf(s.cfg.lg(), "[UDP-Resume:%s] 🔌 force pulse: interrupting the current stream and redialing immediately (server UDP socket preserved)", s.sessionID)
			cancel()
		case <-ctx.Done():
		}
	}()

	req, err := buildResumeUDPRequestChecked(ctx, pr, s.sessionID, s.reqUrl, s.cfg)
	if err != nil {
		return err
	}
	var resp *http.Response
	err = nil
	if rt, ok := s.httpClient.Transport.(http.RoundTripper); ok && s.cfg.usesMasque() {
		resp, err = rt.RoundTrip(req)
	} else {
		resp, err = s.httpClient.Do(req)
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return newTunnelHTTPError(resp.StatusCode)
	}
	lgInfof(s.cfg.lg(), "[UDP-Resume:%s] ✅ tunnel ready", s.sessionID)
	if budgetStop != nil {
		budgetStop() // after ready the budget no longer bounds the data plane
	}
	s.notifyReady(nil)

	var wg sync.WaitGroup
	wg.Add(2)

	// Uplink: drain the upstream queue -> wrap via frameW -> write into the stream body.
	go func() {
		defer wg.Done()
		defer cancel()
		defer pw.Close()
		for {
			select {
			case <-s.done:
				return
			case <-ctx.Done():
				return
			case pkt, ok := <-s.upstream:
				if !ok {
					return
				}
				if err := s.frameW(pw, pkt); err != nil {
					lgDebugf(s.cfg.lg(), "[UDP-Resume:%s] ❌ uplink write failed: %v", s.sessionID, err)
					return
				}
			}
		}
	}()

	// Downlink: read the stream body -> decode via frameR -> write back to the local UDP socket.
	go func() {
		defer wg.Done()
		defer cancel()
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr
		defer udpBufPool.Put(bufPtr)
		for {
			n, rErr := s.frameR(resp.Body, buf)
			if rErr != nil {
				lgDebugf(s.cfg.lg(), "[UDP-Resume:%s] downlink read ended: %v", s.sessionID, rErr)
				return
			}
			var wErr error
			if s.deliver != nil {
				wErr = s.deliver(buf[:n])
			} else if s.localConn != nil {
				_, wErr = s.localConn.WriteToUDP(buf[:n], s.clientAddr)
			} else {
				wErr = errors.New("udp resume session has no delivery target")
			}
			if wErr != nil {
				lgDebugf(s.cfg.lg(), "[UDP-Resume:%s] local UDP write failed: %v", s.sessionID, wErr)
				return
			}
		}
	}()

	wg.Wait()
	return errors.New("stream closed") // stream ended -> trigger a redial
}

// buildResumeUDPRequest builds a UDP resume request:
//   - masque-udp：CONNECT /.well-known/masque/udp/<host>/<port>/, Protocol: connect-udp
//   - h2/h3/grpc：POST cfg.Path，X-Network=udp，X-Target=<target>
//
// Frame data plane: masque uses capsules, the rest use datagram packets (no seq).
func buildResumeUDPRequest(ctx context.Context, body io.Reader, sessID, reqUrl string, cfg clientConfig) *http.Request {
	req, _ := buildResumeUDPRequestChecked(ctx, body, sessID, reqUrl, cfg)
	return req
}

func buildResumeUDPRequestChecked(ctx context.Context, body io.Reader, sessID, reqUrl string, cfg clientConfig) (*http.Request, error) {
	var method, reqURL string
	if cfg.usesMasque() {
		method = http.MethodConnect
		host, port, _ := net.SplitHostPort(cfg.TargetAddr)
		if host == "" {
			host, port = cfg.TargetAddr, "53"
		}
		u, _ := url.Parse(reqUrl)
		u.Path = fmt.Sprintf("%s/udp/%s/%s/", masquePathBase(cfg.Path), url.PathEscape(host), url.PathEscape(port))
		reqURL = u.String()
	} else {
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
	// ===== resume/2 handshake headers: version / capabilities / parameters (datagram also does layer-A negotiation) =====
	req.Header.Set("X-Resume-Version", "2")
	req.Header.Set("X-Resume-Caps", clientCapabilities(cfg).String())
	req.Header.Set("X-Resume-Params", clientParams(cfg).String())
	if cfg.RoleBackup {
		req.Header.Set("X-Resume-Role", "backup")
	}
	setXNetwork(req.Header, "udp")
	setXTarget(req.Header, cfg.TargetAddr)
	if cfg.CustomHost != "" {
		req.Host = cfg.CustomHost
	}
	setTunnelRequestHeaders(req.Header)

	if cfg.usesMasque() {
		req.Header.Set("Protocol", protocolConnectUDP)
		req.Header.Set("Capsule-Protocol", "?1")
		// same as the TCP leg: quic-go reads req.Proto as the extended-CONNECT
		// :protocol value, so it must be the upgrade token, not "HTTP/3".
		req.Proto = protocolConnectUDP
	}
	if cfg.usesGRPC() {
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
	}
	return req, nil
}

// clientUDPResumeSession: one UDP session maps to one active HTTP stream.
// runStreamUDPClient / runMasqueUDPClient reuse the same reconnect logic.

// connectResumeUDP creates a new UDP resume session and returns its instance and
// enqueue function. sessionID must be generated by the caller (newClientSessionID).
// Returns nil when httpClient is empty (no available primary lane; the caller should
// drop this UDP session gracefully).
func connectResumeUDP(sessionID string, cfg clientConfig, reqUrl string, httpClient *http.Client, localConn *net.UDPConn, clientAddr *net.UDPAddr) *udpSession {
	if httpClient == nil {
		lgWarnf(cfg.lg(), "[UDP-Resume:%s] ❌ no available primary-lane client, dropping UDP session", sessionID)
		return nil
	}
	s := newUDPSession(sessionID, cfg, reqUrl, httpClient, localConn, clientAddr)
	go s.run()
	return s
}

// validateResumeUDPID lets tests/logs confirm the session id is non-empty.
func validateResumeUDPID(id string) string {
	if id == "" {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return id
}
