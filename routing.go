package h2tunnel

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	transportAll    = "all"
	transportH2     = "h2"
	transportH2C    = "h2c"
	transportH3     = "h3"
	transportWT     = "wt"
	transportMasque = "masque"
	transportGRPC   = "grpc"

	networkAll = "all"
	networkTCP = "tcp"
	networkUDP = "udp"
)

// canonicalTransport 只做大小写和空白归一；配置仅接受文档列出的正式值。
// canonicalTransport 归一传输类型名（大小写/空白）。供库用户校验输入。
func canonicalTransport(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// validTransport 校验传输类型名是否合法；allowAll 决定是否接受 "all"。
func validTransport(value string, allowAll bool) bool {
	switch value {
	case transportH2, transportH2C, transportH3, transportWT, transportMasque, transportGRPC:
		return true
	case transportAll:
		return allowAll
	default:
		return false
	}
}

// normalizeTransportList 规范服务端逗号分隔 allow-list，并稳定去重。
func normalizeTransportList(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	seen := make(map[string]struct{}, 6)
	items := make([]string, 0, 6)
	for _, raw := range strings.Split(value, ",") {
		name := canonicalTransport(raw)
		if name == "" {
			continue
		}
		if !validTransport(name, true) {
			return "", fmt.Errorf("unsupported server transport %q", strings.TrimSpace(raw))
		}
		if name == transportAll {
			return transportAll, nil
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		items = append(items, name)
	}
	if len(items) == 0 {
		return "", nil
	}
	return strings.Join(items, ","), nil
}

// resolveClientTransport 让 transport 字符串成为客户端唯一事实来源。
func resolveClientTransport(cfg *fileConfig) (string, error) {
	transport := canonicalTransport(cfg.Transport)
	if transport == "" {
		return transportH2, nil
	}
	if !validTransport(transport, false) {
		return "", fmt.Errorf("unsupported client transport %q", cfg.Transport)
	}
	return transport, nil
}

func resolveClientEndpointTransport(cfg *fileConfig, serverURL string) (string, error) {
	transport, err := resolveClientTransport(cfg)
	if err != nil {
		return "", err
	}
	lowerURL := strings.ToLower(strings.TrimSpace(serverURL))
	isHTTP := strings.HasPrefix(lowerURL, "http://")
	isHTTPS := strings.HasPrefix(lowerURL, "https://")
	switch transport {
	case transportH2:
		if isHTTP {
			return transportH2C, nil
		}
	case transportH2C:
		if !isHTTP {
			return "", fmt.Errorf("h2c requires an http:// server URL")
		}
	case transportH3, transportWT, transportMasque:
		if !isHTTPS {
			return "", fmt.Errorf("%s requires an https:// server URL", transport)
		}
	}
	return transport, nil
}

func (cfg clientConfig) transportName() string {
	transport := canonicalTransport(cfg.Transport)
	if transport != "" {
		return transport
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.ServerUrl)), "http://") {
		return transportH2C
	}
	return transportH2
}

func (cfg clientConfig) usesH3() bool     { return cfg.transportName() == transportH3 }
func (cfg clientConfig) usesWT() bool     { return cfg.transportName() == transportWT }
func (cfg clientConfig) usesMasque() bool { return cfg.transportName() == transportMasque }
func (cfg clientConfig) usesGRPC() bool   { return cfg.transportName() == transportGRPC }

func normalizeNetwork(value, fallback string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return fallback
	}
	return normalized
}

func validNetwork(value string) bool {
	return value == networkAll || value == networkTCP || value == networkUDP
}

func normalizeTunnelPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/"
	}
	if value[0] != '/' {
		return "/" + value
	}
	return value
}

type transportMask uint8

const (
	maskH2 transportMask = 1 << iota
	maskH2C
	maskH3
	maskWT
	maskMasque
	maskGRPC
	maskAllTransports = maskH2 | maskH2C | maskH3 | maskWT | maskMasque | maskGRPC
)

type networkMask uint8

const (
	maskTCP networkMask = 1 << iota
	maskUDP
	maskAllNetworks = maskTCP | maskUDP
)

type routingPolicy struct {
	transports transportMask
	networks   networkMask
	ready      bool
}

func transportMaskFor(name string) transportMask {
	switch canonicalTransport(name) {
	case transportH2:
		return maskH2
	case transportH2C:
		return maskH2C
	case transportH3:
		return maskH3
	case transportWT:
		return maskWT
	case transportMasque:
		return maskMasque
	case transportGRPC:
		return maskGRPC
	default:
		return 0
	}
}

func compileRoutingPolicy(transport, network string) routingPolicy {
	p := routingPolicy{ready: true}
	normalized, err := normalizeTransportList(transport)
	if err == nil {
		if normalized == "" || normalized == transportAll {
			p.transports = maskAllTransports
		} else {
			for _, item := range strings.Split(normalized, ",") {
				p.transports |= transportMaskFor(item)
			}
		}
	}
	switch normalizeNetwork(network, networkAll) {
	case networkAll:
		p.networks = maskAllNetworks
	case networkTCP:
		p.networks = maskTCP
	case networkUDP:
		p.networks = maskUDP
	}
	return p
}

func (p routingPolicy) allowsNetwork(network string) bool {
	switch normalizeNetwork(network, "") {
	case networkTCP:
		return p.networks&maskTCP != 0
	case networkUDP:
		return p.networks&maskUDP != 0
	default:
		return false
	}
}

func (p routingPolicy) allowsTransport(transport string) bool {
	return p.transports&transportMaskFor(transport) != 0
}

func (cfg serverConfig) effectiveRoutingPolicy() routingPolicy {
	if cfg.routingPolicy.ready {
		return cfg.routingPolicy
	}
	return compileRoutingPolicy(cfg.Transport, cfg.Network)
}

func isNetworkAllowed(reqNet, configuredNet string) bool {
	return compileRoutingPolicy("", configuredNet).allowsNetwork(reqNet)
}

// prepareServerConfig 在监听前一次性编译分流策略。请求热路径只做位运算，
// 不再为每个请求 Split 字符串、分配 map。
func prepareServerConfig(cfg serverConfig) (serverConfig, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8443"
	}
	cfg.Path = normalizeTunnelPath(cfg.Path)
	transport, err := normalizeTransportList(cfg.Transport)
	if err != nil {
		return cfg, err
	}
	if transport == "" {
		transport = transportH2
	}
	cfg.Transport = transport
	cfg.Network = normalizeNetwork(cfg.Network, networkAll)
	if !validNetwork(cfg.Network) {
		return cfg, fmt.Errorf("unsupported network %q", cfg.Network)
	}
	cfg.SessionWindow = resolveSessionWindow(cfg.SessionWindow)
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = drainDefault
	}
	cfg.routingPolicy = compileRoutingPolicy(cfg.Transport, cfg.Network)

	// allow-list 同时决定监听栈，避免放行 H3 却没有启动 QUIC。
	if cfg.Transport == transportAll {
		cfg.EnableH3 = true
		cfg.EnableTLS = true
		return cfg, nil
	}

	mask := cfg.routingPolicy.transports
	hasH2C := mask&maskH2C != 0
	requiresTLS := mask&(maskH2|maskH3|maskWT|maskMasque) != 0
	requiresH3 := mask&(maskH3|maskWT|maskMasque) != 0
	if hasH2C && (requiresTLS || cfg.EnableTLS || cfg.EnableH3) {
		return cfg, fmt.Errorf("h2c cannot share one listen address with TLS/QUIC transports")
	}
	cfg.EnableH3 = requiresH3
	if requiresTLS {
		cfg.EnableTLS = true
	} else if hasH2C {
		cfg.EnableTLS = false
	}
	return cfg, nil
}

func requestTransport(r *http.Request, isWT, isMasqueTCP, isMasqueUDP bool) string {
	switch {
	case isWT:
		return transportWT
	case isMasqueTCP || isMasqueUDP:
		return transportMasque
	case r.Method == http.MethodPost && isGRPCContentType(r.Header.Get("Content-Type")):
		return transportGRPC
	case r.Method == http.MethodPost && (r.ProtoMajor == 3 || strings.HasPrefix(r.Proto, "HTTP/3")):
		return transportH3
	case r.Method == http.MethodPost && r.ProtoMajor >= 2 && r.TLS == nil:
		return transportH2C
	case r.Method == http.MethodPost:
		// CDN 到源站可能降级为 HTTP/1.1；它仍属于 h2 POST-stream 传输族。
		return transportH2
	default:
		return ""
	}
}

func isGRPCContentType(value string) bool {
	value = strings.TrimSpace(value)
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	return strings.EqualFold(value, "application/grpc") ||
		(len(value) > len("application/grpc") && strings.EqualFold(value[:len("application/grpc")], "application/grpc") && value[len("application/grpc")] == '+')
}

func checkStrictTransportPolicy(r *http.Request, policy routingPolicy, configuredTransport string, isWT, isMasqueTCP, isMasqueUDP bool) error {
	actual := requestTransport(r, isWT, isMasqueTCP, isMasqueUDP)
	if actual != "" && policy.allowsTransport(actual) {
		return nil
	}
	if actual == "" {
		actual = "unknown"
	}
	return fmt.Errorf("transport policy violation: allowed=[%s], got=%s Method=%s Proto=%s Content-Type=%s Protocol=%s",
		configuredTransport, actual, r.Method, r.Proto, r.Header.Get("Content-Type"), r.Header.Get("Protocol"))
}

func checkStrictTransport(r *http.Request, configuredTransport string, isWT, isMasqueTCP, isMasqueUDP bool) error {
	return checkStrictTransportPolicy(r, compileRoutingPolicy(configuredTransport, networkAll), configuredTransport, isWT, isMasqueTCP, isMasqueUDP)
}
