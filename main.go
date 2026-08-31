package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Version = "1.1.0"
var zlog *zap.SugaredLogger = zap.NewNop().Sugar()

type Config struct {
	Mode      string `json:"mode"`       // "server" or "client"
	Listen    string `json:"listen"`     // Server listen address (e.g. ":8443") or client listen address (e.g. "127.0.0.1:2222")
	Server    string `json:"server"`     // Client upstream server URL (e.g. "https://example.com:8443")
	Target    string `json:"target"`     // Target address to forward to (e.g. "127.0.0.1:22")
	Path      string `json:"path"`       // HTTP proxy path (e.g. "/tunnel")
	Token     string `json:"token"`      // Authorization token
	Transport string `json:"transport"`  // "all", "h2", "h2c", "h3", "wt", "webtransport", "masque", "grpc"
	Network   string `json:"network"`    // "all" (or "tcp,udp"), "tcp", "udp"
	TLS       bool   `json:"tls"`        // Enable TLS (auto self-signed if cert/key not provided)
	Cert      string `json:"cert"`       // TLS certificate path
	Key       string `json:"key"`        // TLS private key path
	H3        bool   `json:"h3"`         // Enable HTTP/3 (QUIC)
	WT        bool   `json:"wt"`         // Enable WebTransport (client)
	Masque    bool   `json:"masque"`     // Enable MASQUE CONNECT (client)
	GRPC      bool   `json:"grpc"`       // Enable gRPC mode
	Insecure  bool   `json:"insecure"`   // Skip TLS certificate verification (client)
	Host      string `json:"host"`       // Custom Host header (client)
	SNI       string `json:"sni"`        // Custom SNI (client)
	ALPN      string `json:"alpn"`       // Custom ALPN (client)
	LocalOnly bool   `json:"local_only"` // Allow forwarding to localhost only (server)
	LogLevel  string `json:"log_level"`  // debug, info, warn, error
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias Config
	aux := struct {
		*Alias
		RawToken     interface{} `json:"token"`
		RawAuthToken interface{} `json:"auth_token"`
		RawPSK       interface{} `json:"psk"`
		RawProtocol  string      `json:"protocol"`
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	collectToken := func(v interface{}) {
		if v == nil || c.Token != "" {
			return
		}
		switch val := v.(type) {
		case string:
			c.Token = strings.TrimSpace(val)
		case []interface{}:
			var tokens []string
			for _, item := range val {
				if s, ok := item.(string); ok {
					trimmed := strings.TrimSpace(s)
					if trimmed != "" {
						tokens = append(tokens, trimmed)
					}
				}
			}
			c.Token = strings.Join(tokens, ",")
		}
	}

	collectToken(aux.RawToken)
	collectToken(aux.RawAuthToken)
	collectToken(aux.RawPSK)

	if aux.RawProtocol != "" && c.Transport == "" {
		c.Transport = aux.RawProtocol
	}

	switch strings.ToLower(c.Transport) {
	case "h3", "http3", "http/3":
		c.H3 = true
	case "wt", "webtransport":
		c.WT = true
	case "masque":
		c.Masque = true
	case "grpc":
		c.GRPC = true
	}

	return nil
}

func applyEnvOverrides(cfg *Config) {
	getEnv := func(keys ...string) string {
		for _, k := range keys {
			if v := os.Getenv(k); v != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}

	if v := getEnv("H2TUNNEL_MODE", "MODE"); v != "" {
		cfg.Mode = v
	}
	if v := getEnv("H2TUNNEL_LISTEN", "LISTEN", "PORT"); v != "" {
		if !strings.Contains(v, ":") && len(v) < 6 {
			cfg.Listen = ":" + v
		} else {
			cfg.Listen = v
		}
	}
	if v := getEnv("H2TUNNEL_SERVER", "SERVER"); v != "" {
		cfg.Server = v
	}
	if v := getEnv("H2TUNNEL_TARGET", "TARGET"); v != "" {
		cfg.Target = v
	}
	if v := getEnv("H2TUNNEL_PATH", "TUNNEL_PATH", "PROXY_PATH"); v != "" {
		cfg.Path = v
	}
	if v := getEnv("H2TUNNEL_TOKEN", "H2TUNNEL_PSK", "TOKEN", "PSK"); v != "" {
		cfg.Token = v
	}
	if v := getEnv("H2TUNNEL_TRANSPORT", "TRANSPORT"); v != "" {
		cfg.Transport = v
	}
	if v := getEnv("H2TUNNEL_NETWORK", "NETWORK"); v != "" {
		cfg.Network = v
	}
	if v := getEnv("H2TUNNEL_TLS", "TLS"); v != "" {
		cfg.TLS = (v == "1" || strings.ToLower(v) == "true")
	}
	if v := getEnv("H2TUNNEL_LOG_LEVEL", "LOG_LEVEL", "LOGLEVEL"); v != "" {
		cfg.LogLevel = v
	}
}

type ServerConfig struct {
	ListenAddr    string `json:"listen"`
	TLSCert       string `json:"cert"`
	TLSKey        string `json:"key"`
	EnableTLS     bool   `json:"tls"`
	Path          string `json:"path"`
	LocalOnly     bool   `json:"local_only"`
	LogLevel      string `json:"log_level"`
	EnableH3      bool   `json:"h3"`
	Transport     string `json:"transport"`
	Network       string `json:"network"` // "all", "tcp", "udp"
	ExpectedToken string `json:"token"`
}

type ClientConfig struct {
	ListenAddr string `json:"listen"`
	ServerUrl  string `json:"server"`
	Path       string `json:"path"`
	TargetAddr string `json:"target"`
	Insecure   bool   `json:"insecure"`
	CustomHost string `json:"host"`
	ServerName string `json:"sni"`
	Alpn       string `json:"alpn"`
	UseH3      bool   `json:"h3"`
	UseWT      bool   `json:"wt"`
	UseMasque  bool   `json:"masque"`
	UseGRPC    bool   `json:"grpc"`
	Network    string `json:"network"` // "all" / "both", "tcp", "udp"
	LogLevel   string `json:"log_level"`
	Token      string `json:"token"`
}

func (c *ClientConfig) IsUDP() bool {
	netMode := strings.ToLower(strings.TrimSpace(c.Network))
	return netMode == "udp" || netMode == "all" || netMode == "both" || netMode == "tcp+udp" || netMode == "tcp,udp"
}

func (c *ClientConfig) IsTCP() bool {
	netMode := strings.ToLower(strings.TrimSpace(c.Network))
	return netMode == "tcp" || netMode == "all" || netMode == "both" || netMode == "tcp+udp" || netMode == "tcp,udp" || netMode == ""
}

func initLogger(levelStr string) {
	var level zapcore.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		level,
	)
	zlog = zap.New(core).Sugar()
}

func loadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyEnvOverrides(&cfg)
	return &cfg, nil
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-c" || os.Args[1] == "--config" || strings.HasPrefix(os.Args[1], "-c=") || strings.HasPrefix(os.Args[1], "--config=")) {
		confPath := "config.json"
		if strings.Contains(os.Args[1], "=") {
			confPath = strings.SplitN(os.Args[1], "=", 2)[1]
		} else if len(os.Args) > 2 {
			confPath = os.Args[2]
		}
		runFromConfig(confPath)
		return
	}

	if len(os.Args) < 2 {
		if _, err := os.Stat("config.json"); err == nil {
			runFromConfig("config.json")
			return
		}
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "gen-uri":
		runGenURI(os.Args[2:])
	case "gen-systemd":
		runGenSystemd(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("h2tunnel version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown subcommand: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func runGenURI(args []string) {
	fs := flag.NewFlagSet("gen-uri", flag.ExitOnError)
	cfgPath := fs.String("c", "", "Path to configuration file")
	host := fs.String("host", "", "Server public IP or domain")
	port := fs.String("port", "", "Server listen port")
	path := fs.String("path", "", "Proxy path")
	transport := fs.String("transport", "", "Transport (h2, h3, wt, masque, grpc)")
	target := fs.String("target", "", "Forward target")
	token := fs.String("token", "", "Token")
	sni := fs.String("sni", "", "SNI disguise")
	remark := fs.String("name", "", "Node remark name")
	insecure := fs.Bool("insecure", true, "Skip TLS verify")
	pin := fs.String("pin", "", "Share PIN (6 digits). Empty = auto-generate a random PIN")
	_ = fs.Parse(args)

	// 配置优先于内置默认，但命令行 flag 可覆盖配置中的任意字段
	if *cfgPath != "" {
		if fileCfg, err := loadConfigFile(*cfgPath); err == nil {
			// 优先从 client 配置的 server URL 反解出公网 host/port
			if *host == "" && fileCfg.Server != "" {
				if u, err := url.Parse(fileCfg.Server); err == nil && u.Host != "" {
					*host = u.Hostname()
					if u.Port() != "" {
						*port = u.Port()
					}
				}
			}
			if *port == "" && fileCfg.Listen != "" {
				if _, p, err := net.SplitHostPort(fileCfg.Listen); err == nil {
					*port = p
				}
			}
			if *path == "" && fileCfg.Path != "" {
				*path = fileCfg.Path
			}
			if *target == "" && fileCfg.Target != "" {
				*target = fileCfg.Target
			}
			if *token == "" && fileCfg.Token != "" {
				*token = fileCfg.Token
			}
			if *sni == "" && fileCfg.SNI != "" {
				*sni = fileCfg.SNI
			}
			// transport 兼容 "transport":"h3" 字符串与 {"h3":true} 布尔两种写法
			if *transport == "" {
				switch {
				case fileCfg.H3:
					*transport = "h3"
				case fileCfg.WT:
					*transport = "wt"
				case fileCfg.Masque:
					*transport = "masque"
				case fileCfg.GRPC:
					*transport = "grpc"
				case fileCfg.Transport != "":
					*transport = fileCfg.Transport
				}
			}
		}
	}

	// 内置默认兜底
	if *host == "" {
		*host = "your-server-ip"
	}
	if *port == "" {
		*port = "8443"
	}
	if *path == "" {
		*path = "/tunnel"
	}
	if *transport == "" {
		*transport = "h2"
	}
	if *target == "" {
		*target = "127.0.0.1:22"
	}
	if *remark == "" {
		*remark = "H2Tunnel Node"
	}

	uri := GenerateH2TunnelURI(*transport, *host, *port, *path, *target, *token, *sni, *remark, *pin, *insecure)
	fmt.Printf("=== 📱 h2tunnel Sharing URI ===\n\n%s\n", uri)
	PrintTerminalQR(uri)
}

// loadConfigFromArgs parses only -c/--config and returns the merged Config.
// The per-parameter command-line flags have been removed; the configuration
// file is now the single source of truth. When no file is given, built-in
// defaults are applied by the build*Config helpers, and the old `-insecure`
// default (true) is preserved so a bare client run still works.
func loadConfigFromArgs(args []string) *Config {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	c := fs.String("c", "", "Path to configuration file")
	conf := fs.String("config", "", "Path to configuration file")
	_ = fs.Parse(args)

	cp := *c
	if cp == "" {
		cp = *conf
	}
	cfg := &Config{}
	if cp != "" {
		fileCfg, err := loadConfigFile(cp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config file %s: %v\n", cp, err)
			os.Exit(1)
		}
		cfg = fileCfg
	} else {
		// bare run: preserve the old `-insecure` flag default
		cfg.Insecure = true
		fmt.Fprintln(os.Stderr, "⚠️ 警告: 未指定配置文件，客户端默认跳过 TLS 证书校验 (Insecure=true)，在不可信网络中易被中间人攻击。生产环境请通过配置文件显式设置并校验证书指纹。")
	}
	applyEnvOverrides(cfg)
	return cfg
}

func buildServerConfig(cfg *Config) ServerConfig {
	listen := cfg.Listen
	if listen == "" {
		listen = ":8443"
	}
	path := cfg.Path
	if path == "" {
		path = "/tunnel"
	}
	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	netMode := strings.ToLower(strings.TrimSpace(cfg.Network))
	if netMode == "" || netMode == "both" || netMode == "tcp+udp" || netMode == "tcp,udp" {
		netMode = "all"
	}

	return ServerConfig{
		ListenAddr:    listen,
		TLSCert:       cfg.Cert,
		TLSKey:        cfg.Key,
		EnableTLS:     cfg.TLS,
		Path:          path,
		LocalOnly:     cfg.LocalOnly,
		LogLevel:      logLevel,
		EnableH3:      cfg.H3,
		Transport:     cfg.Transport,
		Network:       netMode,
		ExpectedToken: cfg.Token,
	}
}

func buildClientConfig(cfg *Config) ClientConfig {
	listen := cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:2222"
	}
	server := cfg.Server
	if server == "" {
		server = "https://127.0.0.1:8443"
	}
	path := cfg.Path
	if path == "" {
		path = "/tunnel"
	}
	target := cfg.Target
	if target == "" {
		target = "127.0.0.1:22"
	}
	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	netMode := strings.ToLower(strings.TrimSpace(cfg.Network))
	if netMode == "" {
		netMode = "tcp"
	} else if netMode == "both" || netMode == "tcp+udp" || netMode == "tcp,udp" {
		netMode = "all"
	}

	return ClientConfig{
		ListenAddr: listen,
		ServerUrl:  server,
		Path:       path,
		TargetAddr: target,
		Insecure:   cfg.Insecure,
		CustomHost: cfg.Host,
		ServerName: cfg.SNI,
		Alpn:       cfg.ALPN,
		UseH3:      cfg.H3,
		UseWT:      cfg.WT,
		UseMasque:  cfg.Masque,
		UseGRPC:    cfg.GRPC,
		Network:    netMode,
		LogLevel:   logLevel,
		Token:      cfg.Token,
	}
}

func runFromConfig(path string) {
	cfg, err := loadConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file %s: %v\n", path, err)
		os.Exit(1)
	}
	applyEnvOverrides(cfg)
	if strings.ToLower(cfg.Mode) == "client" {
		startClientDirect(buildClientConfig(cfg))
	} else {
		startServerDirect(buildServerConfig(cfg))
	}
}

func printUsage() {
	fmt.Println("Usage: h2tunnel <command> [options] or h2tunnel -c config.json")
	fmt.Println("\nCommands:")
	fmt.Println("  server       Start h2tunnel multiplexing proxy server")
	fmt.Println("  client       Start h2tunnel proxy client")
	fmt.Println("  gen-uri      Generate Stun client sharing URI link & QR Code")
	fmt.Println("  gen-systemd  Generate Linux systemd service unit")
	fmt.Println("  version      Show version information")
	fmt.Println("  help         Show help message")
}
