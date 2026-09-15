package h2tunnel

import (
	"sync/atomic"
)

// =========================================
// Stats — lightweight statistics snapshots (optional).
//
// Embedders read cumulative counters from Client.Stats() / Server.Stats()
// (suitable for periodic scraping into Prometheus-style monitoring). All fields
// increment atomically; reading is a lock-free snapshot.
// =========================================

// ClientStats holds cumulative client statistics.
type ClientStats struct {
	// DialAttempts: number of dials initiated (TCP DialContext + UDP DialPacketContext).
	DialAttempts atomic.Int64
	// DialFailures: number of failed dials (handshake not ready, server rejected, etc.).
	DialFailures atomic.Int64
	// UplinkBytes: bytes the client sent (uplink through the tunnel).
	UplinkBytes atomic.Int64
	// DownlinkBytes: bytes the client received (downlink through the tunnel).
	DownlinkBytes atomic.Int64
	// ResumeReconnects: number of TCP/UDP session reconnects (same-session redial).
	ResumeReconnects atomic.Int64
	// ActiveDials: number of dials currently in progress.
	ActiveDials atomic.Int64
}

// ServerStats holds cumulative server statistics.
type ServerStats struct {
	// SessionsCreated: number of tunnel sessions established (new session id).
	SessionsCreated atomic.Int64
	// SessionsResumed: number of session resumptions (an existing session id rejoined).
	SessionsResumed atomic.Int64
	// SessionsActive: number of currently active sessions (approximate at read time).
	SessionsActive atomic.Int64
	// UplinkBytes: bytes the server received from clients (written to target).
	UplinkBytes atomic.Int64
	// DownlinkBytes: bytes the server sent to clients (from target).
	DownlinkBytes atomic.Int64
	// AuthFailures: number of failed-authentication requests.
	AuthFailures atomic.Int64
}

// stats is a package-level instance: Client/Server each hold a pointer
// (optionally enabled — even at the zero value the counters still do atomic
// adds, at negligible cost, so there is no conditional toggle).
type stats struct {
	client ClientStats
	server ServerStats
}

// sessionStats are the counter fields hung off sessionTable / session.
type sessionCounters struct {
	uplink   *atomic.Int64
	downlink *atomic.Int64
	created  *atomic.Int64
	resumed  *atomic.Int64
}

func clientStatsPtr(o *ClientOptions) *ClientStats {
	// dialCfg is a value copy; the stats pointer lets all copies share one set of counters.
	return nil // filled in by NewClient (avoids an options import cycle)
}

func (c *Client) Stats() *ClientStats { return &c.stats.client }

func (s *Server) Stats() *ServerStats {
	s.stats.server.SessionsActive.Store(int64(s.sessions.len()))
	return &s.stats.server
}

// SetEventHandler registers the client event callback (replacing the previous
// one; passing nil stops dispatch). The callback runs on its own goroutine and
// panics are recovered, so it never affects the tunnel engine — but it should
// return quickly. See the dispatch constraints in events.go.
func (c *Client) SetEventHandler(h ClientEventHandler) { c.cfg.events.set(h) }

// dispatchClientEvent dispatches a client event (the sink already handles goroutine + recover).
func (c *Client) dispatchClientEvent(ev ClientEvent) { c.cfg.events.dispatch(ev) }

// dispatchServerEvent dispatches a server event.
func (s *Server) dispatchServerEvent(ev ServerEvent) { s.cfg.events.dispatch(ev) }

// SetEventHandler registers the server event callback (replacing the previous one; passing nil stops dispatch).
func (s *Server) SetEventHandler(h ServerEventHandler) {
	s.cfg.events.set(h)
	s.events.set(h)
}

// ForceReconnect forces every active tunnel to abandon its current stream and
// redial immediately (session id and recovery window are preserved; the peer is
// unaware). Embedders call it proactively when a network-change event
// (NotifyAddrChange / NWPathMonitor / ConnectivityManager) arrives, skipping the
// passive latency of waiting for a heartbeat timeout. Whether a session actually
// terminates is still governed by AutoRedial / the redial cap.
func (c *Client) ForceReconnect() {
	c.mu.Lock()
	active := make([]*managedConn, 0, len(c.active))
	for conn := range c.active {
		active = append(active, conn)
	}
	c.mu.Unlock()
	for _, conn := range active {
		select {
		case conn.force <- struct{}{}:
		default:
		}
	}
	c.log.Debug("force reconnect requested", "active", len(active))
}
