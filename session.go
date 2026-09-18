package h2tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =========================================
// session.go — server-side session table + resume scheduling
//
// Each resume-mode tunnel session corresponds to a bidirectional byte
// stream between the server and targetConn, kept across HTTP stream
// rebuilds:
//   - targetConn: long-lived connection to the target service (SSH etc.),
//     not closed when the HTTP stream drops
//   - downlink ring buffer: bytes read from targetConn are framed and
//     dual-written: 1) to the current active HTTP stream (if any),
//     2) to the ring buffer. When the stream dies only 1) stops, 2)
//     continues; a new stream resuming replays the gap from the ring
//   - uplink: HTTP body yields seq frames, committed to targetConn in seq
//     order; the client includes the downlink seq it received in the
//     resume request and the server replies with the uplink seq already
//     received. Resume bound: the server received uplink X, so the client
//     must continue at X (never earlier).
// =========================================

const (
	sessionIdleTimeout = 60 * time.Second // max retention without an active stream
	sessionCleanupTick = 10 * time.Second
)

// tunnelSession is a server-side session.
//
// One session table serves two data models at once:
//
//	stream   — ordered byte streams such as TCP / SSH. Cross-stream rebuild
//	           uses seq + ring replay to fill gaps; uplink is checked for
//	           seq continuity (gaps are unrecoverable).
//	datagram — datagrams such as UDP. UDP itself is unordered and lossy, so
//	           per-byte seq replay is meaningless or even harmful (it would
//	           resend already-sent packets); we only keep the targetConn
//	           socket alive across stream rebuilds — no replay.
//
// kind is decided by getXNetwork and written before dialing in
// prepareResumeSession.
type tunnelSession struct {
	id        string
	createdAt time.Time
	// lastSeen is the last-activity timestamp (unix nano) used by the idle reaper.
	// Stored atomically so the per-packet hot paths (downlinkPump, acceptUplinkSeq)
	// can update it without taking s.mu, and so the reaper can read it lock-free.
	// The previous design wrote a time.Time under s.mu: that both contended on
	// every packet and was a data race (reapIdle read it under t.mu, a different
	// lock than touch()'s s.mu).
	lastSeen atomic.Int64
	datagram bool   // true = UDP datagram mode (no seq replay)
	network  string // "tcp" / "udp" (shown in events and logs)
	events   *serverEventSink
	logger   *slog.Logger // instance logger (from Server options, nil → discard)
	binding  sessionBinding

	mu              sync.Mutex
	targetConn      net.Conn
	targetCloseOnce sync.Once
	// writeMu serializes writes to targetConn so concurrent uplink frames don't
	// interleave bytes on the target stream. It is taken WITHOUT s.mu held: the
	// seq bookkeeping in acceptUplinkSeq happens under s.mu (fast, no I/O), then
	// the actual (potentially blocking) targetConn.Write happens only under
	// writeMu. This keeps a slow/blocked target write from stalling the session's
	// control plane (downlink pump, reaper, close) which would otherwise wait on
	// s.mu.
	writeMu sync.Mutex

	// downlink: server targetConn → HTTP stream / ring buffer
	downlinkSent uint64 // bytes written to the client, cumulative
	downlinkRing *ringBuffer
	activeWriter *resumeSessionWriter // downlink writer of the current active stream; nil = no stream
	closed       bool

	// downlinkMu serializes downlink frame writes (replay vs live) so the
	// client sees strictly continuous downlink seq; frameSentSeq records
	// the end already written to the current active stream.
	// Network writes happen under this lock, never holding s.mu — avoids
	// cross-locking with the uplink (T2 split).
	downlinkMu   sync.Mutex
	frameSentSeq uint64

	// uplink: client → targetConn, accumulated in seq order (gaps are
	// unrecoverable). Unused in datagram mode (UDP has no ordering).
	uplinkRecv uint64

	// frameW / frameR data-plane wrappers: stream mode is nil (uses
	// writeResumeFrame / readResumeFrame + seq checks), datagram mode is
	// non-nil (uses writeUDPPacket / readUDPPacket, or masque's
	// writeUDPCapsule / readUDPCapsule).
	frameW func(io.Writer, []byte) error
	frameR func(io.Reader, []byte) (int, error)
}

// writeDownlink writes one downlink chunk to the active stream + ring.
//
// stream mode: write the active stream + write the ring (for disconnect
// replay), accumulating bytes.
// datagram mode: data is one complete UDP packet (targetConn.Read returns a
//
//	whole packet per call); wrapped into a wire frame by frameW and written
//	to the active stream; the ring is not written (UDP has no replay), so
//	downlinkSent degrades from "byte accumulation" to a mere counter (a
//	non-contiguous coordinate, never used for replay).
//
// With no active stream: stream mode writes the ring and waits for the next
// resume; datagram mode drops the packet (UDP packets arriving during a
// client disconnect have no recoverable meaning, and replaying them would
// corrupt the stream). Returns the bytes written.
//
// Lock order: s.mu only guards state decisions / ring appends / seq
// allocation (pure in-memory work, hold time unrelated to the network);
// network writes happen under downlinkMu — the original implementation held
// s.mu across network writes, which also froze uplink acceptUplinkSeq and
// made both directions cross-lock at full-duplex throughput.
func (s *tunnelSession) writeDownlink(data []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	writer := s.activeWriter
	datagram := s.datagram
	if datagram {
		// UDP: wrap into a wire frame and write the active stream; drop with
		// no stream (no replay across streams).
		s.downlinkSent += uint64(len(data))
		s.mu.Unlock()
		if writer == nil {
			return len(data), nil
		}
		s.downlinkMu.Lock()
		err := s.frameW(&resumeWriterAdapter{w: writer}, data)
		s.downlinkMu.Unlock()
		if err != nil {
			s.clearActiveWriter(writer)
		}
		return len(data), nil
	}
	// stream mode: append to the ring before allocating seq — guarantees
	// every byte with seq < downlinkSent is already in the ring (replay
	// reads never hit a hole). Append is a pure in-memory copy.
	s.downlinkRing.Append(data)
	seq := s.downlinkSent
	s.downlinkSent += uint64(len(data))
	s.mu.Unlock()

	if writer == nil {
		return len(data), nil
	}

	// downlinkMu serializes the frame order of "replay vs live": while the
	// replay holds the lock, live frames from the pump queue behind it; once
	// the replay finishes, frameSentSeq advances to the replay end, and
	// queued frames overlapping the replay window (seq allocated but not yet
	// written — the race window) are skipped, so the seq the client sees
	// stays strictly continuous.
	s.downlinkMu.Lock()
	if seq+uint64(len(data)) <= s.frameSentSeq {
		s.downlinkMu.Unlock()
		return len(data), nil
	}
	// This chunk's start seq = seq. Write a resume frame (the client's
	// readResumeFrame parses by seq).
	_, err := writer.writeFrame(seq, data)
	if err == nil {
		s.frameSentSeq = seq + uint64(len(data))
	}
	s.downlinkMu.Unlock()
	if err != nil {
		// A dead stream is not fatal: the ring holds the data, the next
		// stream resumes from the downlink seq.
		s.clearActiveWriter(writer)
	}
	return len(data), nil
}

// lg returns the session table logger (nil-safe).
func (t *sessionTable) lg() *slog.Logger {
	if t.logger != nil {
		return t.logger
	}
	return discardLogger
}

// lg returns the session instance logger (nil-safe, falls back to discard).
func (s *tunnelSession) lg() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return discardLogger
}

// setActiveWriter sets the downlink writer of the current active stream.
func (s *tunnelSession) setActiveWriter(w *resumeSessionWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeWriter = w
}

// clearActiveWriter clears it when the stream closes.
func (s *tunnelSession) clearActiveWriter(w *resumeSessionWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeWriter == w {
		s.activeWriter = nil
	}
}

// replayDownlink re-sends, from fromSeq, the bytes written into the ring but
// not yet delivered to the client, into the current active writer. Does not
// Append the ring again (avoids duplication). If the ring window was already
// overwritten (fromSeq < windowStart), returns errGap.
//
// The caller MUST hold downlinkMu: sharing that lock with writeDownlink's
// live frames guarantees the client sees strictly continuous downlink seq
// (replay and live frames never interleave). While the lock is held, frames
// whose seq writeDownlink already allocated queue outside the lock, and the
// part overlapping the replay window is skipped via frameSentSeq. On write
// failure, writeDownlink and the caller's defer clean up activeWriter; the
// writer never calls back into the session while holding its own lock.
func (s *tunnelSession) replayDownlinkLocked(w *resumeSessionWriter, fromSeq uint64) error {
	// downlinkSent is written inside writeDownlink's s.mu section; the replay
	// side runs under downlinkMu without s.mu, so it must snapshot first
	// (the lock order is fixed downlinkMu→s.mu, one-way, cycle-free).
	s.mu.Lock()
	target := s.downlinkSent
	s.mu.Unlock()
	if fromSeq >= target {
		return nil
	}
	tmp := make([]byte, 8192)
	seq := fromSeq
	for seq < target {
		n, err := s.downlinkRing.ReadAt(seq, tmp)
		if n > 0 {
			if _, wErr := w.writeFrame(seq, tmp[:n]); wErr != nil {
				return wErr
			}
			seq += uint64(n)
		}
		if errors.Is(err, errGap) {
			return errGap
		}
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
	}
	if s.frameSentSeq < seq {
		s.frameSentSeq = seq
	}
	return nil
}

// attachAndReplay atomically performs "attach the active writer + replay the
// downlink" under downlinkMu. Atomicity is required: if the pump grabs
// downlinkMu between setActiveWriter and the replay, live frames would cut in
// before replay frames and the client would immediately see a seq jump
// (ErrGap). The returned error only reports replay failure (gap / write
// error); attaching the writer always succeeds.
func (s *tunnelSession) attachAndReplay(writer *resumeSessionWriter, fromSeq uint64) error {
	s.downlinkMu.Lock()
	defer s.downlinkMu.Unlock()
	s.setActiveWriter(writer)
	if s.datagram {
		// datagram has no replay (UDP has no seq coordinate system).
		return nil
	}
	return s.replayDownlinkLocked(writer, fromSeq)
}

// acceptUplinkSeq accepts one uplink frame's seq+data, checks continuity,
// and — when contiguous — commits it to targetConn and advances uplinkRecv.
// datagram mode: data is an already-decoded UDP packet, committed directly
// with no seq check.
func (s *tunnelSession) acceptUplinkSeq(seq uint64, data []byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.targetConn == nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.datagram {
		// No ordering in datagram mode: validate liveness, then write under
		// writeMu (released s.mu first so the socket write can't stall s.mu).
		s.lastSeen.Store(time.Now().UnixNano())
		s.mu.Unlock()
		return s.writeTarget(data)
	}
	expected := s.uplinkRecv
	switch {
	case seq < expected:
		// The client re-sent bytes already received (early in recovery);
		// trim the duplicated head as expected.
		skip := int(expected - seq)
		if skip >= len(data) {
			s.lastSeen.Store(time.Now().UnixNano())
			s.mu.Unlock()
			return nil
		}
		data = data[skip:]
	case seq > expected:
		// The client skipped seq: the gap is unrecoverable.
		s.mu.Unlock()
		return errResumeBadSeq
	}
	s.uplinkRecv += uint64(len(data))
	s.lastSeen.Store(time.Now().UnixNano())
	s.mu.Unlock()
	return s.writeTarget(data)
}

// writeTarget serializes the (potentially blocking) targetConn.Write without
// holding s.mu, so a congested upstream cannot stall the session's control plane
// (downlink pump / reaper / close all serialize on s.mu). writeMu is taken so
// concurrent uplink frames don't interleave bytes on the target stream.
func (s *tunnelSession) writeTarget(data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if _, err := s.targetConn.Write(data); err != nil {
		return err
	}
	s.lastSeen.Store(time.Now().UnixNano())
	return nil
}

// sessionTable is the server-side session table (instance-level, owned by a
// Server; embedded libraries do not share tables across Servers).
type sessionTable struct {
	events          *serverEventSink
	logger          *slog.Logger
	padding         paddingPolicy
	mu              sync.Mutex
	sessions        map[string]*tunnelSession
	perPrincipal    map[string]int // active session count per principal (for the per-principal cap)
	idleTimeout     time.Duration
	maxSessions     int // global cap on concurrent sessions (0 = unlimited)
	maxPerPrincipal int // per-principal cap (0 = unlimited)
}

type sessionBinding struct {
	network     string
	target      string
	principalID string
}

func (b sessionBinding) matches(other sessionBinding) bool {
	return b.network == other.network && b.target == other.target && b.principalID == other.principalID
}

var errSessionIDRequired = errors.New("resume session id is required")

// errSessionIDTooLong is returned for a client-supplied X-Session-ID above
// sessionIDMaxBytes. It is rejected before the ID becomes a map key, so a
// single request cannot park megabytes of key material in the table.
var errSessionIDTooLong = errors.New("resume session id exceeds the maximum length")

// sessionIDMaxBytes bounds the client-supplied X-Session-ID. Generated IDs are
// 32 hex chars, so this leaves room for prefixed IDs without opening the door
// to a header-sized key: net/http allows a 1 MiB header, which would be
// stored verbatim in t.sessions and in every resume of it.
const sessionIDMaxBytes = 128

// validateSessionID applies the same rule everywhere an ID is accepted: the
// handlers call it before the handshake so a bad ID is answered with 400, and
// getOrCreateBound calls it as the last line of defence for library callers.
func validateSessionID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errSessionIDRequired
	}
	if len(id) > sessionIDMaxBytes {
		return errSessionIDTooLong
	}
	return nil
}

// errSessionLimitExceeded is returned when admitting a new resume session would
// exceed the configured global or per-principal cap. It is a server-side
// backpressure signal: the client should back off rather than spin redials.
var errSessionLimitExceeded = errors.New("resume session limit exceeded")

func newSessionID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// getOrCreate looks up the table: resume if it exists, open a new session
// otherwise. dialTarget is the dial function (injectable in tests).
// datagram/frameW/frameR are only used when creating a new session (the
// data-plane wrappers are set when datagram is true).
func (t *sessionTable) getOrCreate(id string, dialTarget func() (net.Conn, error), sizeKB int, datagram bool, frameW func(io.Writer, []byte) error, frameR func(io.Reader, []byte) (int, error)) (*tunnelSession, bool, error) {
	return t.getOrCreateBound(id, sessionBinding{}, dialTarget, sizeKB, datagram, frameW, frameR)
}

func (t *sessionTable) getOrCreateBound(id string, binding sessionBinding, dialTarget func() (net.Conn, error), sizeKB int, datagram bool, frameW func(io.Writer, []byte) error, frameR func(io.Reader, []byte) (int, error)) (*tunnelSession, bool, error) {
	if err := validateSessionID(id); err != nil {
		return nil, false, err
	}
	id = strings.TrimSpace(id)

	// Do not hold the table lock while dialing: a slow/unreachable target must
	// not serialize all unrelated new sessions behind its DialTimeout.
	t.mu.Lock()
	// Enforce the global / per-principal session caps *before* dialing the
	// target: a rejected new session must not waste an upstream connection, and
	// the cap bounds memory under a flood of distinct (never-resumed) session
	// IDs. Resuming an already-present session is unaffected (it does not add one).
	if !t.canAdmit(binding.principalID) {
		t.mu.Unlock()
		return nil, false, errSessionLimitExceeded
	}
	if existing, ok := t.sessions[id]; ok {
		existing.mu.Lock()
		bindingMatches := existing.binding.matches(binding)
		alive := !existing.closed && existing.targetConn != nil
		if !bindingMatches {
			existing.mu.Unlock()
			t.mu.Unlock()
			return nil, false, fmt.Errorf("%w: resume session identity changed", ErrForbidden)
		}
		if alive {
			existing.lastSeen.Store(time.Now().UnixNano())
		}
		existing.mu.Unlock()
		t.mu.Unlock()
		if alive {
			return existing, false, nil
		}
		return nil, false, errors.New("session exists but target is dead")
	}
	t.mu.Unlock()

	tconn, err := dialTarget()
	if err != nil {
		return nil, false, err
	}
	s := &tunnelSession{
		logger:       t.logger,
		id:           id,
		createdAt:    time.Now(),
		network:      binding.network,
		events:       t.events,
		targetConn:   tconn,
		datagram:     datagram,
		binding:      binding,
		frameW:       frameW,
		frameR:       frameR,
		downlinkRing: newRingBuffer(sizeKB),
	}
	s.lastSeen.Store(time.Now().UnixNano())

	// A competing request may have installed the same ID while this one dialed.
	// Keep the established session and close the losing connection immediately.
	t.mu.Lock()
	if existing, ok := t.sessions[id]; ok {
		existing.mu.Lock()
		bindingMatches := existing.binding.matches(binding)
		alive := !existing.closed && existing.targetConn != nil
		if !bindingMatches {
			existing.mu.Unlock()
			t.mu.Unlock()
			_ = tconn.Close()
			return nil, false, fmt.Errorf("%w: resume session identity changed", ErrForbidden)
		}
		if alive {
			existing.lastSeen.Store(time.Now().UnixNano())
		}
		existing.mu.Unlock()
		t.mu.Unlock()
		_ = tconn.Close()
		if alive {
			return existing, false, nil
		}
		return nil, false, errors.New("session exists but target is dead")
	}
	if t.perPrincipal == nil {
		t.perPrincipal = make(map[string]int)
	}
	t.sessions[id] = s
	t.perPrincipal[binding.principalID]++
	t.mu.Unlock()

	go s.downlinkPump()
	return s, true, nil
}

// canAdmit reports whether a new session for principalID may be admitted under
// the configured global and per-principal caps. Caller must hold t.mu.
func (t *sessionTable) canAdmit(principalID string) bool {
	if t.maxSessions > 0 && len(t.sessions) >= t.maxSessions {
		return false
	}
	if t.maxPerPrincipal > 0 && t.perPrincipal[principalID] >= t.maxPerPrincipal {
		return false
	}
	return true
}

// deleteSessionLocked removes a session from the table and keeps the
// per-principal counter in sync. Caller must hold t.mu.
func (t *sessionTable) deleteSessionLocked(id string) (*tunnelSession, bool) {
	s, ok := t.sessions[id]
	if !ok {
		return nil, false
	}
	delete(t.sessions, id)
	if s.binding.principalID != "" && t.perPrincipal != nil {
		t.perPrincipal[s.binding.principalID]--
		if t.perPrincipal[s.binding.principalID] <= 0 {
			delete(t.perPrincipal, s.binding.principalID)
		}
	}
	return s, true
}

// remove clears a session explicitly (ended or timed out).
func (t *sessionTable) remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deleteSessionLocked(id)
}

// reapIdle periodically reaps sessions that exceeded the idle timeout
// (default: 60s without an active stream).
func (t *sessionTable) reapIdle() {
	t.mu.Lock()
	now := time.Now()
	idleTimeout := t.idleTimeout
	if idleTimeout <= 0 {
		idleTimeout = sessionIdleTimeout
	}
	var toRemove []string
	for id, s := range t.sessions {
		s.mu.Lock()
		dead := s.closed || s.targetConn == nil
		s.mu.Unlock()
		idle := now.Sub(time.Unix(0, s.lastSeen.Load()))
		if dead || idle > idleTimeout {
			toRemove = append(toRemove, id)
		}
	}
	t.mu.Unlock()
	for _, id := range toRemove {
		if s := t.removeLocked(id); s != nil {
			s.close()
		}
	}
}

func (t *sessionTable) removeLocked(id string) *tunnelSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, _ := t.deleteSessionLocked(id)
	return s
}

// close closes targetConn and marks the session closed.
func (s *tunnelSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.targetCloseOnce.Do(func() {
		if s.targetConn != nil {
			_ = s.targetConn.Close()
		}
	})
}

// touch records last activity (lock-free: uses an atomic timestamp so the
// per-packet hot paths don't contend on s.mu).
func (s *tunnelSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

// downlinkPump is the background pump: it reads from targetConn and writes
// into the session buffer (+ active stream). It runs independently of any
// HTTP request goroutine and keeps working across stream rebuilds —
// targetConn is read continuously, data keeps going into the ring, and the
// next stream resumes from seq.
func (s *tunnelSession) downlinkPump() {
	bufPtr := tcpBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer tcpBufPool.Put(bufPtr)
	defer s.close()

	// Give targetConn a 5-minute read deadline backstop. The idle reaper closes
	// the session after 60s without activity, so a continuously-reading session
	// still needs a live deadline — but we only refresh it as it approaches
	// expiry rather than paying a SetReadDeadline syscall on every packet.
	readDeadline := time.Now().Add(5 * time.Minute)
	_ = s.targetConn.SetReadDeadline(readDeadline)
	for {
		// Datagram reads preserve one complete UDP message. Stream shaping is
		// centralized in resumeSessionWriter, so live and replayed bytes follow
		// the same record policy without increasing target read syscalls.
		n, err := s.targetConn.Read(buf)
		if n > 0 {
			s.writeDownlink(buf[:n])
			s.touch()
			if time.Until(readDeadline) < time.Minute {
				readDeadline = time.Now().Add(5 * time.Minute)
				_ = s.targetConn.SetReadDeadline(readDeadline)
			}
		}
		if err != nil {
			// targetConn died or timed out: stop the pump.
			// stream mode: on target EOF send an END frame to the active
			// stream, telling the client the session ended.
			// datagram mode: no END (the client's frameR only parses UDP
			// datagrams, an END frame would be parsed as an invalid packet and
			// corrupt the stream); the client reads stream EOF and reconnects.
			if !s.datagram {
				s.mu.Lock()
				writer := s.activeWriter
				closed := s.closed
				s.mu.Unlock()
				if writer != nil && !closed {
					// Try to send END (if the stream is still alive).
					_ = writer.writeEnd()
				}
			}
			return
		}
	}
}

// —— active-stream downlink writer ——
// Only one stream can write the downlink at a time; it is set when a new
// stream is established and cleared when the stream dies (write failure or
// context cancellation).
type resumeSessionWriter struct {
	// w is the active stream's downlink write target. h2/grpc/masque pass an
	// http.ResponseWriter (an io.Writer subset, flusher available); wt passes
	// a webtransport.Stream (its own streaming writer).
	w       io.Writer
	flusher http.Flusher
	mu      sync.Mutex
	closed  bool
	padding paddingPolicy
}

// resumeWriterAdapter adapts resumeSessionWriter into an io.Writer for the
// datagram data plane's frameW (writeUDPPacket / writeUDPCapsule). Uses
// writeRaw (UDP packets self-wrap, no resume frame on top).
type resumeWriterAdapter struct {
	w *resumeSessionWriter
}

func (a *resumeWriterAdapter) Write(p []byte) (int, error) {
	return a.w.writeRaw(p)
}

// writeFrame writes one resume frame on the stream (stream-mode downlink)
// and flushes. seq is this chunk's starting offset in the session's downlink
// coordinate space.
func (w *resumeSessionWriter) writeFrame(seq uint64, data []byte) (int, error) {
	written := 0
	for len(data) > 0 {
		chunkLen, padLen := w.padding.dataChunk(len(data), resumeHeaderLen)
		if err := w.writeOneFrame(seq, data[:chunkLen], padLen); err != nil {
			return written, err
		}
		written += chunkLen
		seq += uint64(chunkLen)
		data = data[chunkLen:]
	}
	return written, nil
}

func (w *resumeSessionWriter) writeOneFrame(seq uint64, data []byte, padLen int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	if err := writeResumeFrame(w.w, seq, data, padLen); err != nil {
		w.closed = true
		return err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return nil
}

// writeRaw writes raw bytes on the stream and flushes, without resume
// framing. For the datagram data plane (frameW already wrapped the UDP packet).
func (w *resumeSessionWriter) writeRaw(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, net.ErrClosed
	}
	if err := writeAll(w.w, data); err != nil {
		w.closed = true
		return 0, err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return len(data), nil
}

// writeEnd writes an END control frame on the stream.
func (w *resumeSessionWriter) writeEnd() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	if err := writeResumeEndFrame(w.w, w.padding); err != nil {
		w.closed = true
		return err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return nil
}

// writeControl writes one control frame (HANDSHAKE-ACK / KEEPALIVE-ACK etc.)
// on the stream and flushes. Used by the server handshake and backup-link
// liveness replies.
func (w *resumeSessionWriter) writeControl(typ byte, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	if err := writeFrame(w.w, typ, 0, data, w.padding.paddingFor(resumeHeaderLen+len(data))); err != nil {
		w.closed = true
		return err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return nil
}

// close marks the underlying HTTP handler as returned and forbids further
// writes (avoids the "Write called after Handler finished" panic). Called
// from the handler's defer.
func (w *resumeSessionWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}

// —— server handler entry point ——
//
// Called by server.go in routeTunnelRequest when X-Tunnel-Proto: resume/2 is
// seen. Returns (session, isNew, error); isNew=true means a new session, a
// non-nil error means the dial failed. Parameters:
//   - r: the request (carries X-Session-ID, possibly X-Resume-Downlink, X-Network)
//   - dialTarget: the function dialing the target service
//   - sessionWindowKB: the window capacity the server keeps for downlink replay
//
// In datagram mode (X-Network=udp) the data-plane wrappers are chosen from
// request headers:
//   - Protocol: connect-udp (MASQUE-UDP) → writeUDPCapsule / readUDPCapsule
//   - otherwise (H2/H3/gRPC UDP streams) → writeUDPPacket / readUDPPacket
//
// The caller owns the follow-up: 1) write X-Resume-Uplink in the response
// 2) enter the frame loop reading the uplink 3) tell the downlink pump to
// bind the active writer.
func (t *sessionTable) prepareResumeSession(r *http.Request, dialTarget func() (net.Conn, error), sessionWindowKB int) (*tunnelSession, bool, error) {
	id := r.Header.Get("X-Session-ID")
	network := getXNetwork(r)
	datagram := network == "udp"
	var frameW func(io.Writer, []byte) error
	var frameR func(io.Reader, []byte) (int, error)
	if datagram {
		padding := t.padding
		if masqueConnectProtocol(r) == protocolConnectUDP {
			frameW = func(w io.Writer, p []byte) error { return writeUDPCapsule(w, p, padding) }
			frameR = readUDPCapsule
		} else {
			frameW = func(w io.Writer, p []byte) error { return writeUDPPacket(w, p, padding) }
			frameR = readUDPPacket
		}
	}
	state := requestState(r)
	binding := sessionBinding{network: network, target: getXTarget(r), principalID: state.principal.ID}
	return t.getOrCreateBound(id, binding, dialTarget, sessionWindowKB, datagram, frameW, frameR)
}

// parseResumeDownlink parses the downlink bytes the client already received
// from the request header.
func parseResumeDownlink(r *http.Request) uint64 {
	v := r.Header.Get("X-Resume-Downlink")
	if v == "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// runReaper is the instance-level session reaper (called on Server start,
// stopped by closing stopCh).
func (t *sessionTable) runReaper(stopCh <-chan struct{}) {
	tick := time.NewTicker(sessionCleanupTick)
	defer tick.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-tick.C:
			t.reapIdle()
		}
	}
}

// len returns the current active session count (snapshot).
func (t *sessionTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// closeAll closes every session in the table (called on Server.Close/Shutdown).
func (t *sessionTable) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		s.close()
	}
	t.sessions = make(map[string]*tunnelSession)
}
