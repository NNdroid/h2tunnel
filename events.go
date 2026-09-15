package h2tunnel

import (
	"errors"
	"sync"
)

// =========================================
// Event callback system
//
// The essential difference from logging: logs are write-only, whereas events
// must drive the embedder's business logic (SIEM alerts, pool eviction,
// dashboards). Hence three hard dispatch constraints:
//
//	1. every handler call runs on its own goroutine — it must never block the packet loop;
//	2. a handler panic is recovered inside the dispatch goroutine — the internal engine is never affected by embedder code;
//	3. fire-and-forget: no backpressure and, beyond ordering within one source, no delivery guarantee (same-source events are still dispatched in order).
//
// =========================================

// ClientEventKind identifies a client event type.
type ClientEventKind string

const (
	// EventTunnelEstablished: the tunnel is ready (handshake done, target dialed).
	EventTunnelEstablished ClientEventKind = "tunnel_established"
	// EventTunnelDied: the tunnel died. Reason explains why (see the
	// TunnelDeath* constants and the ClientEvent.Reason docs).
	EventTunnelDied ClientEventKind = "tunnel_died"
	// EventReconnecting: after a stream break, redial the same session (resumable).
	EventReconnecting ClientEventKind = "reconnecting"
	// EventTargetDenied: the server denied the target with 403 (policy/registry lacks the service).
	EventTargetDenied ClientEventKind = "target_denied"
)

// Client tunnel death reasons (common values of ClientEvent.Reason).
const (
	// TunnelDeathMaxRetries: redials exhausted, session abandoned.
	TunnelDeathMaxRetries = "max retries"
	// TunnelDeathAuthRejected: server authentication rejected (407/401).
	TunnelDeathAuthRejected = "auth rejected"
	// TunnelDeathPeerFIN: peer ended normally (EOF/END frame).
	TunnelDeathPeerFIN = "peer FIN"
	// TunnelDeathDataGap: the downlink seq gap is unrecoverable (the server-side
	// session may have been reclaimed by idle timeout or its window overwritten).
	TunnelDeathDataGap = "data gap"
	// TunnelDeathCanceled: the caller's context was canceled or the Client closed.
	TunnelDeathCanceled = "canceled"
)

// ClientEvent is the client event payload.
type ClientEvent struct {
	Kind      ClientEventKind
	Target    string  // logical target at dial time
	Network   Network // tcp / udp
	Transport Transport
	// Attempt is meaningful only for Reconnecting events: the upcoming redial
	// ordinal (1-based).
	Attempt int
	// Reason is a human-readable cause: for TunnelDied see the TunnelDeath*
	// constants; for Reconnecting it is the underlying error text; empty otherwise.
	Reason string
	// Err is the underlying error (may be nil).
	Err error
}

// ClientEventHandler is the client event callback. It is invoked on its own
// goroutine; panics are recovered and never affect the tunnel engine. But the
// callback should return quickly — if you need blocking work (writing to a
// metrics queue, etc.), make it asynchronous yourself.
type ClientEventHandler func(ClientEvent)

// ServerEventKind identifies a server event type.
type ServerEventKind string

const (
	// ServerEventSessionOpened: a new session was established (first join of a new session id).
	ServerEventSessionOpened ServerEventKind = "session_opened"
	// ServerEventSessionResumed: an existing session reconnected and resumed.
	ServerEventSessionResumed ServerEventKind = "session_resumed"
	// ServerEventSessionClosed: the session closed (peer END, idle reclaim, or server shutdown).
	ServerEventSessionClosed ServerEventKind = "session_closed"
	// ServerEventAuthRejected: authentication failed (valuable to SIEM: possible credential brute-force).
	ServerEventAuthRejected ServerEventKind = "auth_rejected"
	// ServerEventTargetDenied: the target was denied by policy (403 / unsupported network).
	ServerEventTargetDenied ServerEventKind = "target_denied"
	// ServerEventReplayDropped: the downlink replay gap is unrecoverable (the
	// replay window was overwritten; the client was disconnected too long); the
	// session's downlink coordinate is broken and the client will reopen it.
	ServerEventReplayDropped ServerEventKind = "replay_dropped"
)

// ServerEvent is the server event payload.
type ServerEvent struct {
	Kind       ServerEventKind
	SessionID  string
	Target     string  // logical target; empty for AuthRejected events
	Network    Network // tcp / udp
	Transport  Transport
	Principal  Principal // request identity on successful auth; zero value for AuthRejected
	RemoteAddr string    // client source IP (clientIP fallback chain, spoofable, for logging only)
	Reason     string
	Err        error
}

// ServerEventHandler is the server event callback. Invocation semantics match ClientEventHandler.
type ServerEventHandler func(ServerEvent)

// clientEventSink is the client event sink: dialCfg value copies share one
// pointer, so deep data paths (resume loops, UDP sessions) can dispatch safely.
type clientEventSink struct {
	mu sync.RWMutex
	h  ClientEventHandler
}

func (s *clientEventSink) set(h ClientEventHandler) {
	s.mu.Lock()
	s.h = h
	s.mu.Unlock()
}

func (s *clientEventSink) dispatch(ev ClientEvent) {
	if s == nil {
		return
	}
	s.mu.RLock()
	h := s.h
	s.mu.RUnlock()
	if h == nil {
		return
	}
	go func() {
		defer func() { _ = recover() }() // an embedder callback panic must not kill the engine goroutine
		h(ev)
	}()
}

// serverEventSink is the server event sink: serverConfig value copies share one pointer.
type serverEventSink struct {
	mu sync.RWMutex
	h  ServerEventHandler
}

func (s *serverEventSink) set(h ServerEventHandler) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.h = h
	s.mu.Unlock()
}

func (s *serverEventSink) dispatch(ev ServerEvent) {
	if s == nil {
		return
	}
	s.mu.RLock()
	h := s.h
	s.mu.RUnlock()
	if h == nil {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		h(ev)
	}()
}

// tunnelDeathReason classifies a session-end error into a human-readable death
// reason. Priority: peer normal end (err==nil, peer FIN) > cancellation > error
// classification — closing the local conn also cancels the session context, but
// err==nil means the engine already ended via the normal path (EOF→END), so
// report peer FIN rather than canceled.
func tunnelDeathReason(ctxErr error, err error) (reason string, cause error) {
	switch {
	case err == nil:
		return TunnelDeathPeerFIN, nil
	case ctxErr != nil:
		return TunnelDeathCanceled, ctxErr
	case errors.Is(err, ErrUnauthenticated):
		return TunnelDeathAuthRejected, err
	case errors.Is(err, ErrForbidden):
		return "target denied", err
	case errors.Is(err, errGap):
		return TunnelDeathDataGap, err
	case errors.Is(err, errResumeAttemptsExhausted):
		return TunnelDeathMaxRetries, err
	}
	return "stream error", err
}

// errResumeAttemptsExhausted: a TCP/WT session exhausted its redial attempts.
var errResumeAttemptsExhausted = errors.New("h2tunnel: resume attempts exhausted")
