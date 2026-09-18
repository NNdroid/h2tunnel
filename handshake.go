package h2tunnel

import (
	"strconv"
	"strings"
)

// =========================================
// handshake.go — negotiation (version / capabilities / parameters)
//
// The negotiation logic is pure (no I/O) for easy unit testing. Carrier: HTTP
// headers (X-Resume-Version / X-Resume-Caps / X-Resume-Params). Version is a
// hard constraint (v2 is the only one); capabilities/parameters are soft (see §2.6).
// =========================================

// Default parameters and constants
const (
	// Client capability list (a configurable subset)
	capDatagram   = "datagram"    // UDP datagram mode
	capCompress   = "compress"    // compression
	capBackupLine = "backup-line" // backup lane
	// capBrutal declares that the client understands the X-Brutal-Offer /
	// X-Brutal-Params exchange, so the server can safely answer it. It rides the
	// existing v2 capability list (parseCaps ignores unknown items), which keeps
	// older peers forward-compatible: an old server drops the offer, an old
	// client drops the reply, and nobody bumps a protocol version.
	capBrutal = "brutal"
	capReplay = "replay" // minimal baseline capability set (byte stream + seq replay)

	// Parameter keys
	paramWindowKB       = "window_kb"
	paramHandshakeAckMs = "handshake_ack_timeout" // milliseconds
	paramKeepaliveSec   = "keepalive_interval"    // seconds

	defaultWindowKB       = 256
	defaultHandshakeAckMs = 3000
	defaultKeepaliveSec   = 15
	maxWindowKB           = 65536
	maxHandshakeAckMs     = 30000
	maxKeepaliveSec       = 3600
)

// resumeCaps is the capability set (for intersection computation).
type resumeCaps struct {
	datagram   bool
	compress   bool
	backupLine bool
}

// parseCaps parses a comma-separated capability list. Unknown items are ignored
// (forward compatible).
func parseCaps(s string) resumeCaps {
	var c resumeCaps
	for _, name := range strings.Split(s, ",") {
		switch strings.TrimSpace(name) {
		case capDatagram:
			c.datagram = true
		case capCompress:
			c.compress = true
		case capBackupLine:
			c.backupLine = true
		}
	}
	return c
}

// intersectCaps returns the intersection of the client's and server's capability
// sets (client request ∩ server support). If the intersection is empty and
// neither side supports the minimal baseline set, returns empty.
func intersectCaps(client, server resumeCaps) resumeCaps {
	return resumeCaps{
		datagram:   client.datagram && server.datagram,
		compress:   client.compress && server.compress,
		backupLine: client.backupLine && server.backupLine,
	}
}

// empty reports whether the capability intersection is empty (not even the
// minimal baseline set). Note: replay is an implicit baseline — every resume
// session has byte-stream capability, so the intersection is never absolutely
// empty; this is true only if even replay fails (theoretically impossible).
func (c resumeCaps) empty() bool {
	// replay is implicit, never empty
	return false
}

// String serializes the capability list comma-separated (only enabled items).
// With no enhanced capability it returns the minimal baseline set "replay"
// (byte stream + seq replay, present on every session).
func (c resumeCaps) String() string {
	var parts []string
	if c.datagram {
		parts = append(parts, capDatagram)
	}
	if c.compress {
		parts = append(parts, capCompress)
	}
	if c.backupLine {
		parts = append(parts, capBackupLine)
	}
	if len(parts) == 0 {
		return capReplay
	}
	return strings.Join(parts, ",")
}

// resumeParams are the negotiated parameters (int ms/bytes/seconds etc.; units
// are conventionally implied by the key name).
type resumeParams struct {
	windowKB       int
	handshakeAckMs int
	keepaliveSec   int
}

func defaultParams() resumeParams {
	return resumeParams{
		windowKB:       defaultWindowKB,
		handshakeAckMs: defaultHandshakeAckMs,
		keepaliveSec:   defaultKeepaliveSec,
	}
}

// parseParams parses a `;`-separated k=v parameter list. Unknown keys are
// ignored; invalid values fall back to defaults.
func parseParams(s string) resumeParams {
	p := defaultParams()
	if s == "" {
		return p
	}
	for _, kv := range strings.Split(s, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(kv[:eq])
		val, err := strconv.Atoi(strings.TrimSpace(kv[eq+1:]))
		if err != nil {
			continue // invalid value → keep the default
		}
		switch key {
		case paramWindowKB:
			p.windowKB = val
		case paramHandshakeAckMs:
			p.handshakeAckMs = val
		case paramKeepaliveSec:
			p.keepaliveSec = val
		}
	}
	return p
}

// alignParams aligns parameters on the server: out-of-range values are clamped
// into the valid range; returns the final effective value (server wins).
func alignParams(p resumeParams) resumeParams {
	if p.windowKB <= 0 || p.windowKB > maxWindowKB {
		p.windowKB = defaultWindowKB
	}
	if p.handshakeAckMs <= 0 || p.handshakeAckMs > maxHandshakeAckMs {
		p.handshakeAckMs = defaultHandshakeAckMs
	}
	if p.keepaliveSec <= 0 || p.keepaliveSec > maxKeepaliveSec {
		p.keepaliveSec = defaultKeepaliveSec
	}
	return p
}

// String serializes the parameters as a `;`-separated k=v string.
func (p resumeParams) String() string {
	var sb strings.Builder
	sb.WriteString(paramWindowKB)
	sb.WriteString("=")
	sb.WriteString(strconv.Itoa(p.windowKB))
	sb.WriteString(";")
	sb.WriteString(paramHandshakeAckMs)
	sb.WriteString("=")
	sb.WriteString(strconv.Itoa(p.handshakeAckMs))
	sb.WriteString(";")
	sb.WriteString(paramKeepaliveSec)
	sb.WriteString("=")
	sb.WriteString(strconv.Itoa(p.keepaliveSec))
	return sb.String()
}

// negotiateVersion performs version negotiation. v2 is the only version:
// min(both) == 2 ⇒ negotiation succeeds and returns 2; otherwise returns 0 (no
// intersection, version-unsupported). The server only declares its max supported
// version; the client declares its max supported version.
func negotiateVersion(clientMax, serverMax int) int {
	v := clientMax
	if serverMax < v {
		v = serverMax
	}
	if v < 2 {
		return 0
	}
	return 2
}

// clientCapabilities is the capability set the client declares (derived from cfg).
func clientCapabilities(cfg clientConfig) resumeCaps {
	return resumeCaps{
		datagram:   cfg.IsUDP(),
		backupLine: true,
	}
}

// clientParams are the handshake parameters the client requests (derived from
// cfg; unconfigured fields use defaults).
func clientParams(cfg clientConfig) resumeParams {
	return resumeParams{
		windowKB:       resolveSessionWindow(cfg.SessionWindow),
		handshakeAckMs: resolveHandshakeAckMs(cfg.HandshakeAckMs),
		keepaliveSec:   resolveKeepaliveSec(cfg.KeepaliveSec),
	}
}
