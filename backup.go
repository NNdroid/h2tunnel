package h2tunnel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// =========================================
// backup.go — backup-lane executor (hot standby / cold standby)
//
// A backup lane is a second redundant channel independent of the primary. Key design (§3.3):
//   - The backup uses its own session id (<primary>+b) and role=backup, avoiding collisions with the server session table.
//   - The backup carries no business data; it only does periodic KEEPALIVE liveness probes.
//   - Only a backup that has completed the handshake and stays KEEPALIVE-alive may be taken over;
//     an unconfirmed backup must not auto-take-over (avoid blindly failing over onto a dead line).
//
// Hot standby: while the primary is active, keep the backup stream + KEEPALIVE heartbeats alive for a fast failover.
// Cold standby: no persistent stream; the backup handshake is established only on failover.
// =========================================

// backupLineState is the backup-lane liveness state machine.
type backupLineState int

const (
	backupIdle        backupLineState = iota // not started
	backupHandshaking                        // handshake in progress
	backupAlive                              // confirmed alive (eligible for take-over)
	backupFailed                             // failed
)

func (s backupLineState) String() string {
	switch s {
	case backupIdle:
		return "idle"
	case backupHandshaking:
		return "handshaking"
	case backupAlive:
		return "alive"
	case backupFailed:
		return "failed"
	}
	return "unknown"
}

// threshold of consecutive missed heartbeats that marks the backup dead
const backupMaxMissedAcks = 3

// managedRole is the lane role: primary connection / backup connection.
type managedRole int

const (
	rolePrimary managedRole = iota
	roleBackup
)

func (r managedRole) String() string {
	if r == roleBackup {
		return "backup"
	}
	return "primary"
}

// backupLine is one backup-lane executor. It doubles as the generic liveness
// executor for connectionManager's primary/backup lanes:
//   - role=backup  -> its own session id (<primary>+b) + X-Resume-Role: backup, KEEPALIVE only
//   - role=primary -> its own session id + empty X-Resume-Role, KEEPALIVE liveness after opening the stream
//
// Both primary and backup do an A+B handshake + KEEPALIVE; only role=backup with
// state==backupAlive may be taken over (backupLine.Alive).
type backupLine struct {
	primaryID  string
	backupID   string
	role       managedRole
	netType    string // "tcp" / "udp" (the type-demux dimension)
	cfg        clientConfig
	reqUrl     string
	httpClient *http.Client // shared default client (fallback)
	client     *http.Client // this lane's dedicated client (own transport/pool, used on the real data path)

	mu            sync.Mutex
	state         backupLineState
	missedAcks    int
	maxMissedAcks int // consecutive-missed-heartbeat threshold to mark dead (0 -> default backupMaxMissedAcks)
	pipe          *io.PipeWriter
	respBody      io.ReadCloser
	closeCh       chan struct{}
	closeOnce     sync.Once
	ctxCancel     context.CancelFunc // cancels the handshake request context (called on close to tear down the keepalive stream)
	lastErr       error
	keepaliveNs   int64 // heartbeat period in nanoseconds
	handshakeMs   int   // handshake timeout in milliseconds
}

// newManagedLine creates a generic lane executor (primary or backup).
// role decides the session-id suffix and the X-Resume-Role header; netType is the type-demux label.
// client is the lane's dedicated http.Client (own transport/pool); when nil it falls back to the shared httpClient.
func newManagedLine(id string, role managedRole, netType string, cfg clientConfig, reqUrl string, httpClient, client *http.Client, maxMissedAcks int) *backupLine {
	bl := &backupLine{
		primaryID:     id,
		role:          role,
		netType:       netType,
		cfg:           cfg,
		reqUrl:        reqUrl,
		httpClient:    httpClient,
		client:        client,
		state:         backupIdle,
		maxMissedAcks: maxMissedAcks,
		keepaliveNs:   int64(resolveKeepaliveSec(cfg.KeepaliveSec)) * int64(time.Second),
		handshakeMs:   resolveHandshakeAckMs(cfg.HandshakeAckMs),
		closeCh:       make(chan struct{}),
	}
	if bl.maxMissedAcks <= 0 {
		bl.maxMissedAcks = backupMaxMissedAcks
	}
	if role == roleBackup {
		bl.backupID = id + "+b"
	} else {
		bl.backupID = id
	}
	return bl
}

// Client returns the http.Client this lane uses: its dedicated client if set, else the shared httpClient.
func (b *backupLine) Client() *http.Client {
	if b.client != nil {
		return b.client
	}
	return b.httpClient
}

func (b *backupLine) close() {
	b.closeOnce.Do(func() {
		close(b.closeCh)
		b.mu.Lock()
		if b.respBody != nil {
			_ = b.respBody.Close()
			b.respBody = nil
		}
		ctxCancel := b.ctxCancel
		b.mu.Unlock()
		if ctxCancel != nil {
			ctxCancel()
		}
		if b.client != nil && b.client.Transport != nil {
			if closer, ok := b.client.Transport.(interface{ Close() error }); ok {
				_ = closer.Close()
			} else if closer, ok := b.client.Transport.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
		}
	})
}

func (b *backupLine) setState(s backupLineState) {
	b.mu.Lock()
	b.state = s
	b.mu.Unlock()
}

func (b *backupLine) setError(err error) {
	b.mu.Lock()
	b.lastErr = err
	b.mu.Unlock()
}

func (b *backupLine) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastErr
}

// Alive reports whether the backup is confirmed alive (eligible for take-over).
func (b *backupLine) Alive() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state == backupAlive
}

func (b *backupLine) State() backupLineState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Role returns the lane role.
func (b *backupLine) Role() managedRole { return b.role }

// ID returns the lane session id.
func (b *backupLine) ID() string { return b.backupID }

// NetType returns the lane's type-demux dimension.
func (b *backupLine) NetType() string { return b.netType }

// IsClosed reports whether the lane was explicitly closed (closeCh closed).
func (b *backupLine) IsClosed() bool {
	select {
	case <-b.closeCh:
		return true
	default:
		return false
	}
}

// Start runs the backup handshake + KEEPALIVE heartbeat loop (hot standby, resident).
// It blocks until close. On handshake failure or heartbeat death it sets backupFailed and returns.
func (b *backupLine) Start() {
	b.setState(backupHandshaking)
	if !b.doHandshake() {
		b.setState(backupFailed)
		return
	}
	b.setState(backupAlive)
	b.keepaliveLoop()
}

// doHandshake completes the backup lane's A+B handshake and reports success.
// The request context is tied to the lane lifetime: do not cancel here (that would
// kill the post-handshake keepalive stream); instead store ctxCancel for close() to tear down the whole stream.
func (b *backupLine) doHandshake() bool {
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	b.mu.Lock()
	b.ctxCancel = cancel
	b.mu.Unlock()

	cfg := b.cfg
	cfg.RoleBackup = b.role == roleBackup
	req, reqErr := buildResumeRequestChecked(ctx, pr, b.backupID, new(uint64), newResumeClientRingBuf(256), b.reqUrl, cfg)
	if reqErr != nil {
		b.setError(reqErr)
		lgWarnf(b.cfg.lg(), "[Backup:%s] ❌ failed to build backup credentials: %v", b.backupID, reqErr)
		return false
	}

	var resp *http.Response
	var err error
	client := b.Client()
	if rt, ok := client.Transport.(http.RoundTripper); ok && cfg.usesMasque() {
		resp, err = rt.RoundTrip(req)
	} else {
		resp, err = client.Do(req)
	}
	if err != nil {
		b.setError(err)
		lgWarnf(b.cfg.lg(), "[Backup:%s] ❌ backup handshake stream setup failed: %v", b.backupID, err)
		return false
	}
	if resp.StatusCode != http.StatusOK {
		b.setError(newTunnelHTTPError(resp.StatusCode))
		lgWarnf(b.cfg.lg(), "[Backup:%s] ❌ backup handshake rejected: HTTP %d", b.backupID, resp.StatusCode)
		resp.Body.Close()
		return false
	}
	if resp.Header.Get("X-Resume-Ack") != "ok" {
		b.setError(errors.New("h2tunnel: transport readiness handshake was not acknowledged"))
		lgWarnf(b.cfg.lg(), "[Backup:%s] ❌ backup handshake not confirmed: %s", b.backupID, resp.Header.Get("X-Resume-Error"))
		resp.Body.Close()
		return false
	}

	// The backup carries no business data, but stream mode still needs a layer-B handshake to prove end-to-end liveness.
	if !isDatagramCap(cfg) {
		if err := writeFrame(pw, resumeFrameHandshake, 0, nil, cfg.Padding.paddingFor(resumeHeaderLen)); err != nil {
			resp.Body.Close()
			return false
		}
		buf := make([]byte, 64*1024)
		typ, _, _, err := readFrame(resp.Body, buf)
		if err != nil || typ != resumeFrameHandshakeAck {
			lgWarnf(b.cfg.lg(), "[Backup:%s] ❌ backup layer-B handshake failed: %v", b.backupID, err)
			resp.Body.Close()
			return false
		}
	}

	// save the stream reference for heartbeat read/write
	b.mu.Lock()
	b.pipe = pw
	b.respBody = resp.Body
	b.mu.Unlock()
	lgInfof(b.cfg.lg(), "[Backup:%s] ✅ backup handshake complete, entering KEEPALIVE heartbeat", b.backupID)
	return true
}

// keepaliveLoop sends periodic KEEPALIVEs and listens for KEEPALIVE-ACKs.
// N consecutive misses -> marked dead.
func (b *backupLine) keepaliveLoop() {
	interval := time.Duration(b.keepaliveNs)
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	ackCh := make(chan struct{}, 8)
	go b.listenKeepaliveAck(ackCh)

	for {
		select {
		case <-b.closeCh:
			return
		case <-ackCh:
			b.mu.Lock()
			b.missedAcks = 0
			b.state = backupAlive
			b.mu.Unlock()
		case <-ticker.C:
			b.mu.Lock()
			pw := b.pipe
			b.mu.Unlock()
			if pw == nil {
				return
			}
			if err := writeFrame(pw, resumeFrameKeepalive, 0, nil, b.cfg.Padding.paddingFor(resumeHeaderLen)); err != nil {
				lgWarnf(b.cfg.lg(), "[Backup:%s] ❌ failed to send KEEPALIVE: %v", b.backupID, err)
			}
			// each frame sent counts as one unacked; a received KEEPALIVE-ACK resets it (see listenKeepaliveAck).
			// maxMissedAcks consecutive unacked marks the lane dead (checkFailure).
			b.mu.Lock()
			b.missedAcks++
			b.mu.Unlock()
			b.checkFailure()
		}
	}
}

// checkFailure marks the lane dead when consecutive misses exceed the threshold.
func (b *backupLine) checkFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.missedAcks >= b.maxMissedAcks {
		b.state = backupFailed
		lgWarnf(b.cfg.lg(), "[Backup:%s] ⚠️ %d consecutive missed heartbeats, marking backup dead", b.backupID, b.missedAcks)
	}
}

// listenKeepaliveAck reads KEEPALIVE-ACKs and signals ackCh when one arrives.
func (b *backupLine) listenKeepaliveAck(ackCh chan struct{}) {
	buf := make([]byte, 64*1024)
	for {
		b.mu.Lock()
		body := b.respBody
		b.mu.Unlock()
		if body == nil {
			return
		}
		typ, _, _, err := readFrame(body, buf)
		if err != nil {
			return // stream ended
		}
		if typ == resumeFrameKeepaliveAck {
			select {
			case ackCh <- struct{}{}:
			default:
			}
		}
	}
}

// isDatagramCap reports whether this client transport uses datagram (UDP) mode.
// A UDP backup skips the layer-B handshake (the server skips it for datagrams), layer A only.
func isDatagramCap(cfg clientConfig) bool {
	return cfg.IsUDP() && !cfg.usesWT()
}
