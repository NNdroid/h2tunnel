package h2tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"
)

var buildVersion = "v1.0.0-dev"

// Version returns the build version embedded by the release workflow.
func Version() string { return buildVersion }

// discardLogger is the package-level default when no Logger is injected: when
// embedded as a library it must not spam the host's stdout. Data-plane logging
// goes through slog uniformly: clientConfig / serverConfig hold an instance
// logger derived from options.Logger (see lg()), falling back here when unset.
var discardLogger = slog.New(slog.DiscardHandler)

// lg returns the client's instance logger (nil-safe).
func (c *clientConfig) lg() *slog.Logger {
	if c.logger != nil {
		return c.logger
	}
	return discardLogger
}

// datagramQueueSize returns the UDP uplink queue depth (0 → default 200).
func (c *clientConfig) datagramQueueSize() int {
	if c.DatagramQueueSize > 0 {
		return c.DatagramQueueSize
	}
	return 200
}

// transportValue returns the transport protocol (empty = the scheme-inferred result).
func (c *clientConfig) transportValue() Transport {
	return Transport(c.Transport)
}

// lg returns the server's instance logger (nil-safe).
func (s *serverConfig) lg() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return discardLogger
}

// —— Data-plane printf log adapter: keeps the existing message format, landing on the instance slog ——

func lgDebugf(l *slog.Logger, format string, args ...any) {
	logfAt(l, slog.LevelDebug, format, args...)
}

func lgInfof(l *slog.Logger, format string, args ...any) { logfAt(l, slog.LevelInfo, format, args...) }

func lgWarnf(l *slog.Logger, format string, args ...any) { logfAt(l, slog.LevelWarn, format, args...) }

func lgErrorf(l *slog.Logger, format string, args ...any) {
	logfAt(l, slog.LevelError, format, args...)
}

func logfAt(l *slog.Logger, level slog.Level, format string, args ...any) {
	if l == nil {
		return
	}
	// Skip the allocation + format work entirely when this level is disabled.
	// The data-plane log calls fire on every record/frame, so an unconditional
	// fmt.Sprintf on a disabled level is a measurable hot-path cost.
	if !l.Enabled(context.Background(), level) {
		return
	}
	l.Log(context.Background(), level, fmt.Sprintf(format, args...))
}

// serverConfig is the server runtime configuration. It can be built
// programmatically (zero-value fields take defaults automatically).
type serverConfig struct {
	QUICReceiveWindow QUICReceiveWindowTuning `json:"-"`
	PauseDetachedRead bool                    `json:"-"`
	ListenAddr        string                  `json:"listen"`
	TLSCert           string                  `json:"cert"`
	TLSKey            string                  `json:"key"`
	EnableTLS         bool                    `json:"tls"`
	Path              string                  `json:"path"`
	LocalOnly         bool                    `json:"local_only"`
	LogLevel          string                  `json:"log_level"`
	EnableH3          bool                    `json:"-"`
	Transport         string                  `json:"transport"`
	Network           string                  `json:"network"` // "all", "tcp", "udp"
	DrainTimeout      time.Duration           `json:"-"`       // derived from drain_timeout_sec
	// SessionWindow is the recovery ring buffer size (KB); the server must
	// implement it to cooperate with client recovery.
	SessionWindow int `json:"-"`
	// Padding is the validated server-to-client record-shaping policy.
	Padding paddingPolicy `json:"-"`
	// Brutal is the validated TCP Brutal policy (brutal_linux.go applies it).
	Brutal brutalPolicy `json:"-"`
	// brutalSockets dedupes the per-connection socket configuration; nil only for
	// configs built without NewServer (white-box tests). A pointer so the
	// per-request cfg copy shares it.
	brutalSockets *brutalSockets `json:"-"`

	// DialTarget is a custom upstream dial function (for library embedding). When
	// nil, the default net.Dialer{Timeout: 10s} dials the target directly. External
	// programs can use it to route tunnel traffic into their own services (net.Pipe
	// in-memory services, unix sockets, per-target ACL filtering, etc.). The target
	// address comes from the client's X-Target header (loopback only when LocalOnly=true).
	DialTarget func(ctx context.Context, network, addr string) (net.Conn, error) `json:"-"`
	// API-only hooks. CLI construction maps its token and direct-address policy
	// to these callbacks before creating a Server.
	events             *serverEventSink `json:"-"`
	stats              *ServerStats     `json:"-"`
	logger             *slog.Logger     `json:"-"`
	Authenticator      Authenticator    `json:"-"`
	TargetDialer       TargetDialer     `json:"-"`
	TLSConfig          *tls.Config      `json:"-"`
	ServerContext      context.Context  `json:"-"`
	SessionIdleTimeout time.Duration    `json:"-"`
	// SessionMax / SessionMaxPerPrincipal are the resolved global / per-principal
	// session caps (0 from config means "use default", resolved in server_api.go).
	SessionMax             int `json:"-"`
	SessionMaxPerPrincipal int `json:"-"`

	// routingPolicy is compiled at startup so the request hot path does only
	// allocation-free bitmask checks.
	routingPolicy routingPolicy
}

// clientConfig is the client runtime configuration. It can be built
// programmatically (zero-value fields take defaults automatically).
type clientConfig struct {
	QUICReceiveWindow QUICReceiveWindowTuning `json:"-"`
	// H2StreamReceiveWindow is the client's HTTP/2 stream receive window in
	// bytes; 0 keeps the x/net 4MiB default (see resolveH2StreamReceiveWindow).
	H2StreamReceiveWindow int    `json:"-"`
	ListenAddr            string `json:"listen"`
	ServerUrl             string `json:"server"`
	Path                  string `json:"path"`
	TargetAddr            string `json:"target"`
	Insecure              bool   `json:"insecure"`
	CustomHost            string `json:"host"`
	ServerName            string `json:"sni"`
	Transport             string `json:"transport"`
	Network               string `json:"network"` // "all", "tcp", "udp"
	LogLevel              string `json:"log_level"`
	Token                 string `json:"token"`

	// The two fields below are client-side keep-alive and drain parameters, same semantics as serverConfig
	HeartbeatInterval time.Duration `json:"-"`
	DrainTimeout      time.Duration `json:"-"`
	// SessionWindow is the recovery ring buffer size (KB)
	SessionWindow int `json:"-"`
	// HandshakeAckMs is the data-plane HANDSHAKE-ACK timeout (ms); default 3000ms.
	HandshakeAckMs int `json:"handshake_ack_ms"`
	// KeepaliveSec is the backup-lane/session KEEPALIVE heartbeat interval (s); default 15s.
	KeepaliveSec int `json:"keepalive_sec"`
	// RoleBackup marks the current request as a backup lane (internal passthrough, set by backupLine).
	RoleBackup bool `json:"-"`
	// connectionPolicy is the connection-management policy (primary/backup counts, intervals, type demux).
	connectionPolicy connectionPolicy `json:"-"`
	events           *clientEventSink `json:"-"`
	stats            *ClientStats     `json:"-"`
	logger           *slog.Logger     `json:"-"`
	Credentials      CredentialProvider `json:"-"`
	TLSConfig        *tls.Config        `json:"-"`
	LogicalTargets   bool               `json:"-"`
	Dialer           ClientDialer       `json:"-"`
	QUICDialer       QUICDialer         `json:"-"`

	// DatagramQueueSize is the UDP datagram uplink queue depth (0 → default 200).
	DatagramQueueSize int `json:"-"`
	// AutoRedial resets the retry counter after redials exhaust (see ClientTuning.AutoRedial).
	AutoRedial bool `json:"-"`
	// RedialBudget is the per-attempt dial budget (see ClientTuning.RedialBudget).
	RedialBudget time.Duration `json:"-"`
	// Padding is the validated client-to-server record-shaping policy.
	Padding paddingPolicy `json:"-"`
	// MasqueALPN is the MASQUE carrier (""/h2/h3, see ClientTuning.MasqueALPN);
	// NewClient already lower-cases and trims it.
	MasqueALPN string `json:"-"`
	// Brutal is the validated TCP Brutal policy for the tunnel's TCP legs.
	Brutal brutalPolicy `json:"-"`
	// clientGroup is this Client instance's stable grouping seed, sent as
	// X-Client-Group. Generated once in NewClient so every lane of one client
	// falls in the same Brutal connection group, and stable across TCP-leg
	// migration (it is not the remote IP).
	clientGroup string `json:"-"`
	// brutalPeer caches the server's last X-Brutal-Params answer (see
	// handleBrutalReply). A pointer so copying clientConfig shares the cache.
	brutalPeer *brutalPeerCache `json:"-"`
}

func (c *clientConfig) IsUDP() bool {
	netMode := normalizeNetwork(c.Network, networkTCP)
	return netMode == networkUDP || netMode == networkAll
}

func (c *clientConfig) IsTCP() bool {
	netMode := normalizeNetwork(c.Network, networkTCP)
	return netMode == networkTCP || netMode == networkAll
}

// resolveSessionWindow returns the recovery ring buffer size; 0 or an invalid
// value → default 256KB. The cap matches the handshake negotiation so a bad
// config cannot allocate oversized memory on every session creation.
const sessionWindowDefaultKB = 256

func resolveSessionWindow(kb int) int {
	if kb <= 0 || kb > maxWindowKB {
		return sessionWindowDefaultKB
	}
	return kb
}

// H2 stream receive window bounds. 0 keeps the x/net
// transportDefaultStreamFlow default (4MiB); any explicit value is clamped
// into [64KiB, 256MiB] — the same ceiling as the QUIC receive windows. The
// floor is the HTTP/2 spec's initial window so a typo cannot strangle every
// stream.
const (
	h2StreamWindowDefault = 4 << 20
	h2StreamWindowMin     = 64 << 10
	h2StreamWindowMax     = 256 << 20
)

// resolveH2StreamReceiveWindow normalizes the client H2 stream receive window.
// 0 = keep the x/net default; otherwise clamp.
func resolveH2StreamReceiveWindow(bytes int) int {
	if bytes == 0 {
		return 0
	}
	if bytes < h2StreamWindowMin {
		return h2StreamWindowMin
	}
	if bytes > h2StreamWindowMax {
		return h2StreamWindowMax
	}
	return bytes
}

// Session-table caps: bounds memory / per-principal resource use under a flood
// of distinct (never-resumed) session IDs. 0 or an invalid value → default;
// values above the hard cap are clamped.
const (
	sessionMaxDefault             = 4096
	sessionMaxPerPrincipalDefault = 256
	sessionMaxHardCap             = 1_000_000
)

func resolveSessionMax(n int) int {
	if n <= 0 {
		return sessionMaxDefault
	}
	if n > sessionMaxHardCap {
		return sessionMaxHardCap
	}
	return n
}

func resolveSessionMaxPerPrincipal(n int) int {
	if n <= 0 {
		return sessionMaxPerPrincipalDefault
	}
	if n > sessionMaxHardCap {
		return sessionMaxHardCap
	}
	return n
}

// resolveKeepaliveSec returns the session/backup KEEPALIVE interval (s); 0 or
// invalid → default 15s.
func resolveKeepaliveSec(sec int) int {
	if sec <= 0 || sec > maxKeepaliveSec {
		return defaultKeepaliveSec
	}
	return sec
}

// resolveHandshakeAckMs returns the data-plane HANDSHAKE-ACK timeout (ms); 0 or
// invalid → default 3000ms.
func resolveHandshakeAckMs(ms int) int {
	if ms <= 0 || ms > maxHandshakeAckMs {
		return defaultHandshakeAckMs
	}
	return ms
}
