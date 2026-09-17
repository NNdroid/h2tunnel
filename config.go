package h2tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

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

type fileConfig struct {
	Mode      string `json:"mode"`       // "server" or "client"
	Listen    string `json:"listen"`     // Server listen address (e.g. ":8443") or client listen address (e.g. "127.0.0.1:2222")
	Server    string `json:"server"`     // Client upstream server URL (e.g. "https://example.com:8443")
	Target    string `json:"target"`     // Target address to forward to (e.g. "127.0.0.1:22")
	Path      string `json:"path"`       // HTTP proxy path (e.g. "/tunnel")
	Token     string `json:"token"`      // Authorization token
	Transport string `json:"transport"`  // "all", "h2", "h2c", "h3", "wt", "masque", "grpc"
	Network   string `json:"network"`    // "all", "tcp", "udp"
	TLS       bool   `json:"tls"`        // Enable TLS (auto self-signed if cert/key not provided)
	Cert      string `json:"cert"`       // TLS certificate path
	Key       string `json:"key"`        // TLS private key path
	Insecure  bool   `json:"insecure"`   // Skip TLS certificate verification (client)
	Host      string `json:"host"`       // Custom Host header (client)
	SNI       string `json:"sni"`        // Custom SNI (client)
	LocalOnly bool   `json:"local_only"` // Allow forwarding to localhost only (server)
	LogLevel  string `json:"log_level"`  // debug, info, warn, error
	// HeartbeatSec is the application-layer heartbeat interval (seconds). Behind a
	// CDN / reverse proxy it must be below their idle timeout; default 25s (just
	// under half of the 60s common denominator — ALB and Nginx default to 60s,
	// Cloudflare 100s). 0 uses the default; a negative value disables it entirely
	// (direct origin links only).
	HeartbeatSec int `json:"heartbeat_sec"`
	// DrainTimeoutSec is the upper bound (seconds) to wait for in-flight tunnels
	// to drain after SIGTERM; on timeout they are force-closed.
	DrainTimeoutSec int `json:"drain_timeout_sec"`
	// Note: the resume config field was removed — resume/2 is the only data plane
	// (always on); there is no resume:false escape hatch for TCP or UDP (v1 fully removed).
	// SessionWindowKB is the session-recovery window size (KB), which bounds the
	// recoverable outage duration (and the max bytes the server can hold/replay in
	// this window). Default 256KB.
	SessionWindowKB int `json:"session_window_kb"`
	// HandshakeAckMs is the data-plane HANDSHAKE-ACK timeout (ms); default 3000ms.
	HandshakeAckMs int `json:"handshake_ack_ms"`
	// KeepaliveSec is the backup-lane/session KEEPALIVE heartbeat interval (s); default 15s.
	KeepaliveSec int `json:"keepalive_sec"`
	// PrimaryCount is the number of primary connections; default 1. >1 enables type
	// demux (one lane per tcp/udp).
	PrimaryCount int `json:"primary_count"`
	// BackupCount is the number of backup connections; nil = default 1, 0 = disable backups.
	BackupCount *int `json:"backup_count"`
	// StandbyCount is the streamlined field the current CLI uses. The legacy
	// fileConfig is kept only for internal test tooling; real command-line parsing
	// lives in cmd/h2tunnel and rejects legacy fields such as backup_count.
	StandbyCount *int          `json:"standby_connections"`
	Padding      PaddingTuning `json:"padding"`
	// PrimaryDialIntervalSec is the primary dial interval (s); default 30s (throttles redial storms).
	PrimaryDialIntervalSec int `json:"primary_dial_interval_sec"`
	// BackupDialIntervalSec is the backup dial interval (s); default 15s (throttles redial storms).
	BackupDialIntervalSec int `json:"backup_dial_interval_sec"`
	// EstablishIntervalSec is the primary/backup establish interval (s); default
	// 100s. Primary dials first; the backup dials out of phase afterward.
	EstablishIntervalSec int `json:"establish_interval_sec"`
	// SessionMax is the global cap on concurrent resume sessions; default 4096.
	SessionMax int `json:"session_max"`
	// SessionMaxPerPrincipal is the per-principal cap on concurrent resume
	// sessions; default 256.
	SessionMaxPerPrincipal int `json:"session_max_per_principal"`
}

// applyEnvOverrides overrides fileConfig fields with H2TUNNEL_* environment variables.
func applyEnvOverrides(cfg *fileConfig) error {
	setString := func(key string, dst *string) {
		if value, ok := os.LookupEnv(key); ok {
			*dst = strings.TrimSpace(value)
		}
	}
	setBool := func(key string, dst *bool) error {
		value, ok := os.LookupEnv(key)
		if !ok {
			return nil
		}
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("%s must be a boolean: %w", key, err)
		}
		*dst = parsed
		return nil
	}
	setInt := func(key string, dst *int) error {
		value, ok := os.LookupEnv(key)
		if !ok {
			return nil
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("%s must be an integer: %w", key, err)
		}
		*dst = parsed
		return nil
	}

	setString("H2TUNNEL_MODE", &cfg.Mode)
	setString("H2TUNNEL_LISTEN", &cfg.Listen)
	setString("H2TUNNEL_SERVER", &cfg.Server)
	setString("H2TUNNEL_TARGET", &cfg.Target)
	setString("H2TUNNEL_PATH", &cfg.Path)
	setString("H2TUNNEL_TOKEN", &cfg.Token)
	setString("H2TUNNEL_TRANSPORT", &cfg.Transport)
	setString("H2TUNNEL_NETWORK", &cfg.Network)
	setString("H2TUNNEL_CERT", &cfg.Cert)
	setString("H2TUNNEL_KEY", &cfg.Key)
	setString("H2TUNNEL_HOST", &cfg.Host)
	setString("H2TUNNEL_SNI", &cfg.SNI)
	setString("H2TUNNEL_LOG_LEVEL", &cfg.LogLevel)

	for _, field := range []struct {
		key string
		dst *bool
	}{
		{"H2TUNNEL_TLS", &cfg.TLS},
		{"H2TUNNEL_INSECURE", &cfg.Insecure},
		{"H2TUNNEL_LOCAL_ONLY", &cfg.LocalOnly},
	} {
		if err := setBool(field.key, field.dst); err != nil {
			return err
		}
	}

	for _, field := range []struct {
		key string
		dst *int
	}{
		{"H2TUNNEL_HEARTBEAT_SEC", &cfg.HeartbeatSec},
		{"H2TUNNEL_DRAIN_TIMEOUT_SEC", &cfg.DrainTimeoutSec},
		{"H2TUNNEL_SESSION_WINDOW_KB", &cfg.SessionWindowKB},
		{"H2TUNNEL_HANDSHAKE_ACK_MS", &cfg.HandshakeAckMs},
		{"H2TUNNEL_KEEPALIVE_SEC", &cfg.KeepaliveSec},
		{"H2TUNNEL_PADDING_MIN_RECORD_BYTES", &cfg.Padding.MinRecordBytes},
		{"H2TUNNEL_PADDING_MAX_RECORD_BYTES", &cfg.Padding.MaxRecordBytes},
		{"H2TUNNEL_PRIMARY_COUNT", &cfg.PrimaryCount},
		{"H2TUNNEL_PRIMARY_DIAL_INTERVAL_SEC", &cfg.PrimaryDialIntervalSec},
		{"H2TUNNEL_BACKUP_DIAL_INTERVAL_SEC", &cfg.BackupDialIntervalSec},
		{"H2TUNNEL_ESTABLISH_INTERVAL_SEC", &cfg.EstablishIntervalSec},
		{"H2TUNNEL_SESSION_MAX", &cfg.SessionMax},
		{"H2TUNNEL_SESSION_MAX_PER_PRINCIPAL", &cfg.SessionMaxPerPrincipal},
	} {
		if err := setInt(field.key, field.dst); err != nil {
			return err
		}
	}
	if value, ok := os.LookupEnv("H2TUNNEL_BACKUP_COUNT"); ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("H2TUNNEL_BACKUP_COUNT must be an integer: %w", err)
		}
		cfg.BackupCount = &parsed
	}
	if value, ok := os.LookupEnv("H2TUNNEL_STANDBY_CONNECTIONS"); ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("H2TUNNEL_STANDBY_CONNECTIONS must be an integer: %w", err)
		}
		cfg.StandbyCount = &parsed
	}
	return nil
}

// validateConfig validates and normalizes a fileConfig (per mode).
func validateConfig(cfg *fileConfig) error {
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Mode == "" {
		cfg.Mode = "server"
	}
	if cfg.Mode != "server" && cfg.Mode != "client" {
		return fmt.Errorf("mode must be server or client, got %q", cfg.Mode)
	}
	cfg.Path = normalizeTunnelPath(cfg.Path)
	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unsupported log_level %q", cfg.LogLevel)
	}
	if cfg.DrainTimeoutSec < 0 {
		return fmt.Errorf("drain_timeout_sec must be >= 0")
	}
	if cfg.SessionWindowKB < 0 || cfg.SessionWindowKB > maxWindowKB {
		return fmt.Errorf("session_window_kb must be 0 or between 1 and %d", maxWindowKB)
	}
	if _, err := compilePaddingPolicy(cfg.Padding); err != nil {
		return err
	}

	if cfg.Mode == "server" {
		if cfg.Server != "" || cfg.Target != "" || cfg.Insecure || cfg.Host != "" || cfg.SNI != "" {
			return fmt.Errorf("server mode contains client-only endpoint or TLS fields")
		}
		if cfg.HeartbeatSec != 0 || cfg.HandshakeAckMs != 0 || cfg.KeepaliveSec != 0 ||
			cfg.PrimaryCount != 0 || cfg.BackupCount != nil || cfg.StandbyCount != nil || cfg.PrimaryDialIntervalSec != 0 ||
			cfg.BackupDialIntervalSec != 0 || cfg.EstablishIntervalSec != 0 {
			return fmt.Errorf("server mode contains client-only connection policy fields")
		}
		prepared, err := prepareServerConfig(serverConfig{
			EnableTLS: cfg.TLS,
			Transport: cfg.Transport,
			Network:   cfg.Network,
		})
		if err != nil {
			return err
		}
		cfg.Transport = prepared.Transport
		cfg.Network = prepared.Network
		cfg.TLS = prepared.EnableTLS
		return nil
	}

	if cfg.TLS || cfg.Cert != "" || cfg.Key != "" || cfg.LocalOnly {
		return fmt.Errorf("client mode contains server-only TLS or local_only fields")
	}
	if cfg.Server == "" {
		cfg.Server = "https://127.0.0.1:8443"
	}
	transport, err := resolveClientEndpointTransport(cfg, cfg.Server)
	if err != nil {
		return err
	}
	cfg.Transport = transport
	cfg.Network = normalizeNetwork(cfg.Network, networkTCP)
	if !validNetwork(cfg.Network) {
		return fmt.Errorf("unsupported network %q", cfg.Network)
	}
	if cfg.HeartbeatSec > 300 {
		return fmt.Errorf("heartbeat_sec must be <= 300; use a negative value to disable it")
	}
	if cfg.HandshakeAckMs < 0 || cfg.HandshakeAckMs > maxHandshakeAckMs {
		return fmt.Errorf("handshake_ack_ms must be 0 or between 1 and %d", maxHandshakeAckMs)
	}
	if cfg.KeepaliveSec < 0 || cfg.KeepaliveSec > maxKeepaliveSec {
		return fmt.Errorf("keepalive_sec must be 0 or between 1 and %d", maxKeepaliveSec)
	}
	if cfg.PrimaryCount < 0 {
		return fmt.Errorf("primary_count must be >= 0")
	}
	maxPrimary := 1
	if cfg.Network == networkAll {
		maxPrimary = 2
	}
	if cfg.PrimaryCount > maxPrimary {
		return fmt.Errorf("primary_count must not exceed enabled network count %d", maxPrimary)
	}
	if cfg.BackupCount != nil && *cfg.BackupCount < 0 {
		return fmt.Errorf("backup_count must be >= 0")
	}
	if cfg.StandbyCount != nil && *cfg.StandbyCount < 0 {
		return fmt.Errorf("standby_connections must be >= 0")
	}
	if cfg.PrimaryDialIntervalSec < 0 || cfg.BackupDialIntervalSec < 0 || cfg.EstablishIntervalSec < 0 {
		return fmt.Errorf("connection interval fields must be >= 0")
	}
	return nil
}

// serverConfig is the server runtime configuration. It can be built
// programmatically (zero-value fields take defaults automatically).
type serverConfig struct {
	ListenAddr   string        `json:"listen"`
	TLSCert      string        `json:"cert"`
	TLSKey       string        `json:"key"`
	EnableTLS    bool          `json:"tls"`
	Path         string        `json:"path"`
	LocalOnly    bool          `json:"local_only"`
	LogLevel     string        `json:"log_level"`
	EnableH3     bool          `json:"-"`
	Transport    string        `json:"transport"`
	Network      string        `json:"network"` // "all", "tcp", "udp"
	DrainTimeout time.Duration `json:"-"`       // derived from drain_timeout_sec
	// SessionWindow is the recovery ring buffer size (KB); the server must
	// implement it to cooperate with client recovery.
	SessionWindow int `json:"-"`
	// Padding is the validated server-to-client record-shaping policy.
	Padding paddingPolicy `json:"-"`

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
	ListenAddr string `json:"listen"`
	ServerUrl  string `json:"server"`
	Path       string `json:"path"`
	TargetAddr string `json:"target"`
	Insecure   bool   `json:"insecure"`
	CustomHost string `json:"host"`
	ServerName string `json:"sni"`
	Transport  string `json:"transport"`
	Network    string `json:"network"` // "all", "tcp", "udp"
	LogLevel   string `json:"log_level"`
	Token      string `json:"token"`

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
	connectionPolicy connectionPolicy   `json:"-"`
	events           *clientEventSink   `json:"-"`
	stats            *ClientStats       `json:"-"`
	logger           *slog.Logger       `json:"-"`
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
}

func (c *clientConfig) IsUDP() bool {
	netMode := normalizeNetwork(c.Network, networkTCP)
	return netMode == networkUDP || netMode == networkAll
}

func (c *clientConfig) IsTCP() bool {
	netMode := normalizeNetwork(c.Network, networkTCP)
	return netMode == networkTCP || netMode == networkAll
}

// loadConfigFile loads configuration from a JSON file (with H2TUNNEL_* environment
// overrides and validation).
func loadConfigFile(path string) (*fileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg fileConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("configuration must contain exactly one JSON object")
	}
	if err := applyEnvOverrides(&cfg); err != nil {
		return nil, err
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// resolveHeartbeat converts a seconds-based setting into a heartbeat interval.
//
//	0  → use the default (recommended, 25s)
//	<0 → disable the heartbeat (direct origin links only, no CDN/proxy in between)
//	>0 → clamp into [5s, 5min]
func resolveHeartbeat(sec int) time.Duration {
	if sec < 0 {
		return 0
	}
	if sec == 0 {
		return clampHeartbeat(0)
	}
	return clampHeartbeat(time.Duration(sec) * time.Second)
}

// resolveDrainTimeout converts a seconds-based setting into the graceful-shutdown
// drain bound; default 30s.
func resolveDrainTimeout(sec int) time.Duration {
	if sec <= 0 {
		return drainDefault
	}
	return time.Duration(sec) * time.Second
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

// buildServerConfig builds the server runtime config from a file config (applying defaults).
func buildServerConfigChecked(cfg *fileConfig) (serverConfig, error) {
	padding, err := compilePaddingPolicy(cfg.Padding)
	if err != nil {
		return serverConfig{}, err
	}
	listen := cfg.Listen
	if listen == "" {
		listen = ":8443"
	}
	path := normalizeTunnelPath(cfg.Path)
	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	netMode := normalizeNetwork(cfg.Network, networkAll)
	transport, err := normalizeTransportList(cfg.Transport)
	if err != nil {
		return serverConfig{}, err
	}
	if transport == "" {
		transport = transportH2
	}

	return serverConfig{
		ListenAddr:             listen,
		TLSCert:                cfg.Cert,
		TLSKey:                 cfg.Key,
		EnableTLS:              cfg.TLS,
		Path:                   path,
		LocalOnly:              cfg.LocalOnly,
		LogLevel:               logLevel,
		Transport:              transport,
		Network:                netMode,
		DrainTimeout:           resolveDrainTimeout(cfg.DrainTimeoutSec),
		SessionWindow:          resolveSessionWindow(cfg.SessionWindowKB),
		Padding:                padding,
		SessionMax:             resolveSessionMax(cfg.SessionMax),
		SessionMaxPerPrincipal: resolveSessionMaxPerPrincipal(cfg.SessionMaxPerPrincipal),
	}, nil
}

func buildServerConfig(cfg *fileConfig) serverConfig {
	result, err := buildServerConfigChecked(cfg)
	if err != nil {
		panic(err)
	}
	return result
}

// buildClientConfig builds the client runtime config from a file config (applying
// defaults and the connection policy).
func buildClientConfigChecked(cfg *fileConfig) (clientConfig, error) {
	padding, err := compilePaddingPolicy(cfg.Padding)
	if err != nil {
		return clientConfig{}, err
	}
	listen := cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:2222"
	}
	server := cfg.Server
	if server == "" {
		server = "https://127.0.0.1:8443"
	}
	transport, err := resolveClientEndpointTransport(cfg, server)
	if err != nil {
		return clientConfig{}, err
	}
	path := normalizeTunnelPath(cfg.Path)
	target := cfg.Target
	if target == "" {
		target = "127.0.0.1:22"
	}
	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	netMode := normalizeNetwork(cfg.Network, networkTCP)
	if !validNetwork(netMode) {
		return clientConfig{}, fmt.Errorf("unsupported network %q", cfg.Network)
	}
	primaryNetworks := []string{netMode}
	backupCount := defaultBackupCount
	if cfg.BackupCount != nil {
		if *cfg.BackupCount < 0 {
			return clientConfig{}, fmt.Errorf("backup_count must be >= 0")
		}
		backupCount = *cfg.BackupCount
	}
	if cfg.StandbyCount != nil {
		if *cfg.StandbyCount < 0 {
			return clientConfig{}, fmt.Errorf("standby_connections must be >= 0")
		}
		backupCount = *cfg.StandbyCount
	}
	policy := resolveConnectionPolicy(
		cfg.PrimaryCount, backupCount,
		cfg.PrimaryDialIntervalSec, cfg.BackupDialIntervalSec,
		cfg.EstablishIntervalSec, defaultBackupMissedAck, primaryNetworks,
	)

	return clientConfig{
		ListenAddr:        listen,
		ServerUrl:         server,
		Path:              path,
		TargetAddr:        target,
		Insecure:          cfg.Insecure,
		CustomHost:        cfg.Host,
		ServerName:        cfg.SNI,
		Transport:         transport,
		Network:           netMode,
		LogLevel:          logLevel,
		Token:             cfg.Token,
		HeartbeatInterval: resolveHeartbeat(cfg.HeartbeatSec),
		DrainTimeout:      resolveDrainTimeout(cfg.DrainTimeoutSec),
		SessionWindow:     resolveSessionWindow(cfg.SessionWindowKB),
		HandshakeAckMs:    resolveHandshakeAckMs(cfg.HandshakeAckMs),
		KeepaliveSec:      resolveKeepaliveSec(cfg.KeepaliveSec),
		Padding:           padding,
		connectionPolicy:  policy,
	}, nil
}

func buildClientConfig(cfg *fileConfig) clientConfig {
	result, err := buildClientConfigChecked(cfg)
	if err != nil {
		panic(err)
	}
	return result
}
