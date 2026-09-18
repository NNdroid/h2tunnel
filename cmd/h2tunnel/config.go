package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	h2tunnel "github.com/NNdroid/h2tunnel"
)

type config struct {
	Mode            string `json:"mode"`
	Listen          string `json:"listen"`
	Server          string `json:"server"`
	Target          string `json:"target"`
	Path            string `json:"path"`
	Token           string `json:"token"`
	Transport       string `json:"transport"`
	Network         string `json:"network"`
	TLS             bool   `json:"tls"`
	Cert            string `json:"cert"`
	Key             string `json:"key"`
	Insecure        bool   `json:"insecure"`
	Host            string `json:"host"`
	SNI             string `json:"sni"`
	UtlxFingerprint string `json:"utls"` // TLS ClientHello camouflage fingerprint: chrome/firefox/edge/safari/ios/qq (h2/grpc only)
	// Pprof starts a net/http/pprof server at the given address when non-empty
	// (server mode only; e.g. "127.0.0.1:6060"). The endpoints can dump process
	// memory, so bind only to trusted addresses.
	Pprof     string `json:"pprof"`
	LocalOnly bool   `json:"local_only"`
	LogLevel  string `json:"log_level"`

	HeartbeatSec    int           `json:"heartbeat_sec"`
	DrainTimeoutSec int           `json:"drain_timeout_sec"`
	SessionWindowKB int           `json:"session_window_kb"`
	HandshakeAckMS  int           `json:"handshake_ack_ms"`
	KeepaliveSec    int           `json:"keepalive_sec"`
	StandbyCount    int           `json:"standby_connections"`
	Padding         paddingConfig `json:"padding"`
	// MasqueALPN selects the MASQUE carrier: ""=auto (h3 first, pin h2 on
	// failure), "h2", "h3".
	MasqueALPN string `json:"masque_alpn"`
	// Brutal requests TCP Brutal on the tunnel's TCP legs (Linux only; the
	// non-Linux builds are a silent no-op).
	Brutal brutalConfig `json:"brutal"`
}

type paddingConfig struct {
	MinRecordBytes int `json:"min_record_bytes"`
	MaxRecordBytes int `json:"max_record_bytes"`
}

// brutalConfig is the config.json form of h2tunnel.BrutalTuning. Negotiate is a
// pointer so that omitting it means the documented default (true) rather than
// accidentally turning the exchange off.
type brutalConfig struct {
	Enabled   bool   `json:"enabled"`
	RateBytes uint64 `json:"rate_bytes"`
	CwndGain  uint32 `json:"cwnd_gain"`
	GroupID   uint64 `json:"group_id"`
	Negotiate *bool  `json:"negotiate"`
}

// tuning converts to the library's exported form, applying the negotiate
// default when the key was omitted.
func (b brutalConfig) tuning() h2tunnel.BrutalTuning {
	negotiate := true
	if b.Negotiate != nil {
		negotiate = *b.Negotiate
	}
	return h2tunnel.BrutalTuning{
		Enabled:   b.Enabled,
		RateBytes: b.RateBytes,
		CwndGain:  b.CwndGain,
		GroupID:   b.GroupID,
		Negotiate: negotiate,
	}
}

// brutalCwndGainMax mirrors brutalMaxCwndGain in the library. The library
// re-checks at NewClient/NewServer and fails loudly either way, so a drift here
// only weakens this early, config-load-time message.
const brutalCwndGainMax = 1000

// validate applies the same range rule the library enforces, so a bad value is
// reported at config load instead of at NewClient/NewServer.
func (b brutalConfig) validate() error {
	if b.CwndGain == 0 {
		return nil // 0 selects the 1.5x default
	}
	if b.CwndGain > brutalCwndGainMax {
		return fmt.Errorf("brutal.cwnd_gain must be between 1 and %d tenths, got %d", brutalCwndGainMax, b.CwndGain)
	}
	return nil
}

func (p paddingConfig) validate() error {
	if p.MinRecordBytes < 0 || p.MaxRecordBytes < 0 {
		return errors.New("padding record sizes must be non-negative")
	}
	if p.MinRecordBytes == 0 {
		if p.MaxRecordBytes != 0 {
			return errors.New("padding max_record_bytes requires min_record_bytes")
		}
		return nil
	}
	if p.MinRecordBytes <= 16 || p.MinRecordBytes > 65527 {
		return errors.New("padding min_record_bytes must be between 17 and 65527")
	}
	maxBytes := p.MaxRecordBytes
	if maxBytes == 0 {
		maxBytes = p.MinRecordBytes + p.MinRecordBytes/4
		if maxBytes > 65535 {
			maxBytes = 65535
		}
	}
	if maxBytes > 65535 || maxBytes-p.MinRecordBytes < 8 {
		return errors.New("padding max_record_bytes must be at least 8 bytes above min_record_bytes and not exceed 65535")
	}
	return nil
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("configuration must contain exactly one JSON object")
	}
	if err := applyEnvironment(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cfg *config) validate() error {
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Mode == "" {
		cfg.Mode = "server"
	}
	if cfg.Mode != "server" && cfg.Mode != "client" {
		return fmt.Errorf("mode must be server or client, got %q", cfg.Mode)
	}
	if cfg.Path == "" {
		cfg.Path = "/tunnel"
	} else if !strings.HasPrefix(cfg.Path, "/") {
		cfg.Path = "/" + cfg.Path
	}
	cfg.Transport = strings.ToLower(strings.TrimSpace(cfg.Transport))
	cfg.Network = strings.ToLower(strings.TrimSpace(cfg.Network))
	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unsupported log_level %q", cfg.LogLevel)
	}
	if cfg.DrainTimeoutSec < 0 || cfg.SessionWindowKB < 0 || cfg.HandshakeAckMS < 0 || cfg.KeepaliveSec < 0 || cfg.StandbyCount < 0 {
		return errors.New("duration, window, and standby fields must be non-negative")
	}
	if err := cfg.Padding.validate(); err != nil {
		return err
	}
	if err := cfg.Brutal.validate(); err != nil {
		return err
	}
	if cfg.Mode == "server" {
		if cfg.Listen == "" {
			cfg.Listen = ":8443"
		}
		if cfg.Transport == "" {
			cfg.Transport = "h2"
		}
		if cfg.Network == "" {
			cfg.Network = "tcp"
		}
		if cfg.Server != "" || cfg.Target != "" || cfg.Insecure || cfg.Host != "" || cfg.SNI != "" || cfg.UtlxFingerprint != "" || cfg.HeartbeatSec != 0 || cfg.HandshakeAckMS != 0 || cfg.KeepaliveSec != 0 || cfg.StandbyCount != 0 {
			return errors.New("server config contains client-only fields")
		}
	} else {
		if cfg.Listen == "" {
			cfg.Listen = "127.0.0.1:2222"
		}
		if cfg.Server == "" {
			return errors.New("client server URL is required")
		}
		if cfg.Target == "" {
			return errors.New("client target is required")
		}
		if cfg.Transport == "" {
			if strings.HasPrefix(strings.ToLower(cfg.Server), "http://") {
				cfg.Transport = "h2c"
			} else {
				cfg.Transport = "h2"
			}
		}
		if cfg.Network == "" {
			cfg.Network = "tcp"
		}
		if cfg.TLS || cfg.Cert != "" || cfg.Key != "" || cfg.LocalOnly || cfg.Pprof != "" {
			return errors.New("client config contains server-only fields")
		}
		endpoint, err := url.Parse(cfg.Server)
		if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
			return fmt.Errorf("client server must be a valid http:// or https:// URL")
		}
		if endpoint.Scheme == "http" && (cfg.Insecure || cfg.SNI != "" || cfg.UtlxFingerprint != "") {
			return errors.New("insecure, sni and utls have no effect with an http:// server")
		}
	}
	if !validTransportList(cfg.Transport, cfg.Mode == "server") {
		return fmt.Errorf("unsupported transport %q", cfg.Transport)
	}
	if cfg.Network != "tcp" && cfg.Network != "udp" && cfg.Network != "all" {
		return fmt.Errorf("unsupported network %q", cfg.Network)
	}
	if cfg.Mode == "server" {
		hasH2C, requiresTLS := false, false
		for _, transport := range strings.Split(cfg.Transport, ",") {
			switch strings.TrimSpace(transport) {
			case "h2c":
				hasH2C = true
			case "all", "h2", "h3", "wt", "masque":
				requiresTLS = true
			}
		}
		if (cfg.Cert == "") != (cfg.Key == "") {
			return errors.New("cert and key must be configured together")
		}
		if hasH2C && (requiresTLS || cfg.TLS || cfg.Cert != "") {
			return errors.New("h2c cannot share a listener with TLS transports or TLS fields")
		}
	} else if cfg.Transport == "wt" {
		if cfg.StandbyCount != 0 {
			return errors.New("standby_connections has no effect with wt")
		}
	}
	return nil
}

func validTransportList(value string, multiple bool) bool {
	if value == "all" {
		return multiple
	}
	parts := strings.Split(value, ",")
	if !multiple && len(parts) != 1 {
		return false
	}
	for _, part := range parts {
		switch strings.TrimSpace(part) {
		case "h2", "h2c", "h3", "wt", "masque", "grpc":
		default:
			return false
		}
	}
	return true
}

func applyEnvironment(cfg *config) error {
	stringsMap := map[string]*string{
		"H2TUNNEL_MODE": &cfg.Mode, "H2TUNNEL_LISTEN": &cfg.Listen,
		"H2TUNNEL_SERVER": &cfg.Server, "H2TUNNEL_TARGET": &cfg.Target,
		"H2TUNNEL_PATH": &cfg.Path, "H2TUNNEL_TOKEN": &cfg.Token,
		"H2TUNNEL_TRANSPORT": &cfg.Transport, "H2TUNNEL_NETWORK": &cfg.Network,
		"H2TUNNEL_CERT": &cfg.Cert, "H2TUNNEL_KEY": &cfg.Key,
		"H2TUNNEL_HOST": &cfg.Host, "H2TUNNEL_SNI": &cfg.SNI,
		"H2TUNNEL_UTLS":        &cfg.UtlxFingerprint,
		"H2TUNNEL_PPROF":       &cfg.Pprof,
		"H2TUNNEL_MASQUE_ALPN": &cfg.MasqueALPN,
		"H2TUNNEL_LOG_LEVEL":   &cfg.LogLevel,
	}
	for key, destination := range stringsMap {
		if value, ok := os.LookupEnv(key); ok {
			*destination = strings.TrimSpace(value)
		}
	}
	bools := map[string]*bool{
		"H2TUNNEL_TLS": &cfg.TLS, "H2TUNNEL_INSECURE": &cfg.Insecure,
		"H2TUNNEL_LOCAL_ONLY":     &cfg.LocalOnly,
		"H2TUNNEL_BRUTAL_ENABLED": &cfg.Brutal.Enabled,
	}
	for key, destination := range bools {
		if value, ok := os.LookupEnv(key); ok {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("%s must be a boolean: %w", key, err)
			}
			*destination = parsed
		}
	}
	// H2TUNNEL_BRUTAL_NEGOTIATE is set through a pointer so an explicit false is
	// distinguishable from unset (unset keeps the negotiate: true default).
	if value, ok := os.LookupEnv("H2TUNNEL_BRUTAL_NEGOTIATE"); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("H2TUNNEL_BRUTAL_NEGOTIATE must be a boolean: %w", err)
		}
		cfg.Brutal.Negotiate = &parsed
	}
	ints := map[string]*int{
		"H2TUNNEL_HEARTBEAT_SEC":            &cfg.HeartbeatSec,
		"H2TUNNEL_DRAIN_TIMEOUT_SEC":        &cfg.DrainTimeoutSec,
		"H2TUNNEL_SESSION_WINDOW_KB":        &cfg.SessionWindowKB,
		"H2TUNNEL_HANDSHAKE_ACK_MS":         &cfg.HandshakeAckMS,
		"H2TUNNEL_KEEPALIVE_SEC":            &cfg.KeepaliveSec,
		"H2TUNNEL_STANDBY_CONNECTIONS":      &cfg.StandbyCount,
		"H2TUNNEL_PADDING_MIN_RECORD_BYTES": &cfg.Padding.MinRecordBytes,
		"H2TUNNEL_PADDING_MAX_RECORD_BYTES": &cfg.Padding.MaxRecordBytes,
	}
	for key, destination := range ints {
		if value, ok := os.LookupEnv(key); ok {
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("%s must be an integer: %w", key, err)
			}
			*destination = parsed
		}
	}
	for key, destination := range map[string]*uint64{
		"H2TUNNEL_BRUTAL_RATE_BYTES": &cfg.Brutal.RateBytes,
		"H2TUNNEL_BRUTAL_GROUP_ID":   &cfg.Brutal.GroupID,
	} {
		if value, ok := os.LookupEnv(key); ok {
			parsed, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return fmt.Errorf("%s must be a non-negative integer: %w", key, err)
			}
			*destination = parsed
		}
	}
	if value, ok := os.LookupEnv("H2TUNNEL_BRUTAL_CWND_GAIN"); ok {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return fmt.Errorf("H2TUNNEL_BRUTAL_CWND_GAIN must be a non-negative integer: %w", err)
		}
		cfg.Brutal.CwndGain = uint32(parsed)
	}
	return nil
}
