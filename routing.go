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

// canonicalTransport only normalizes case and whitespace; config accepts only
// the canonical values listed in the docs. It normalizes a transport name
// (case/whitespace) and lets library callers validate input.
func canonicalTransport(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// validTransport checks whether a transport name is valid; allowAll decides
// whether "all" is accepted.
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

// normalizeTransportList normalizes a server comma-separated allow-list and
// dedupes it deterministically.
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

// resolveClientTransport makes the transport string the client's single source of truth.
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

// prepareServerConfig compiles the routing policy once before listening. The
// request hot path then does only bitmask math, no longer Split-ing strings or
// allocating a map per request.
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

	// The allow-list also decides which listener stacks to bind, so we never
	// allow H3 but fail to start QUIC.
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

// tunnelKind is the protocol verdict of one inbound request. classifyTunnelRequest
// computes it once per request and auth, policy, event labels and handler
// dispatch share that one value object — replacing the previous pattern where
// isWT/isMasqueTCP/isMasqueUDP booleans were re-derived in four places.
type tunnelKind uint8

const (
	kindUnsupported tunnelKind = iota
	kindWebTransport
	kindMasqueTCP
	kindMasqueUDP
	kindResume // the POST resume/2 data plane (h2/h2c/grpc/h3 sub-classified by the transport label)
)

// tunnelRequest is the classification result: kind, carrier label, network and
// target. target may be empty (a handler parses/rejects as a fallback when the
// client supplied none).
type tunnelRequest struct {
	kind      tunnelKind
	transport Transport // h2/h2c/grpc/h3/wt/masque (event and stats label)
	network   string    // networkTCP / networkUDP
	target    string
}

func classifyTunnelRequest(r *http.Request, cfg serverConfig, wtAvailable bool) tunnelRequest {
	network, target := getRequestDestination(r, cfg)
	if r.Method == http.MethodConnect {
		switch {
		case masqueConnectProtocol(r) == protocolWebTransport:
			if !wtAvailable {
				return tunnelRequest{}
			}
			return tunnelRequest{kind: kindWebTransport, transport: Transport(transportWT), network: network, target: target}
		case masqueConnectProtocol(r) == protocolConnectTCP, masqueURISegment(r.URL.Path, masquePathBase(cfg.Path)) == "tcp":
			return tunnelRequest{kind: kindMasqueTCP, transport: Transport(transportMasque), network: networkTCP, target: masqueRequestTarget("tcp", r, target)}
		case masqueConnectProtocol(r) == protocolConnectUDP, masqueURISegment(r.URL.Path, masquePathBase(cfg.Path)) == "udp":
			return tunnelRequest{kind: kindMasqueUDP, transport: Transport(transportMasque), network: networkUDP, target: masqueRequestTarget("udp", r, target)}
		default:
			return tunnelRequest{}
		}
	}
	if r.Method == http.MethodPost {
		// POST is always labeled by its resume carrier (h2/h2c/grpc/h3 sub-type);
		// whether it really is resume/2 is rejected with 426 by handleH2StreamResumeServer's
		// version hard-check, matching the historical dispatch order (auth/policy first, version last).
		return tunnelRequest{kind: kindResume, transport: resumeWireTransport(r), network: network, target: target}
	}
	return tunnelRequest{}
}

// masqueRequestTarget resolves the MASQUE target: X-Target (logical service name)
// first, then the RFC 9298 URI template, then X-Dst; if all miss it returns an
// empty string and lets the handler decide to reject.
func masqueRequestTarget(protocol string, r *http.Request, resolved string) string {
	if resolved != "" {
		return resolved
	}
	if parsed, err := parseMasqueTarget(protocol, r.URL.Path); err == nil {
		return parsed
	}
	_, dst := getXDst(r)
	return dst
}

// masqueURISegment returns the protocol segment right after the base in a MASQUE
// URI template ("tcp"/"udp"), or "" if it doesn't match — a path fallback for
// pure-RFC clients that send no header.
func masqueURISegment(path, base string) string {
	path = strings.TrimPrefix(strings.Trim(path, "/"), strings.Trim(base, "/")+"/")
	if i := strings.Index(path, "/"); i > 0 {
		if seg := strings.ToLower(path[:i]); seg == "tcp" || seg == "udp" {
			return seg
		}
	}
	return ""
}

// resumeWireTransport labels the carrier a POST resume/2 uses (h2/h2c/grpc/h3).
// A CDN→origin link may downgrade to HTTP/1.1 but still belongs to the h2 POST-stream family.
func resumeWireTransport(r *http.Request) Transport {
	switch {
	case isGRPCContentType(r.Header.Get("Content-Type")):
		return Transport(transportGRPC)
	case r.ProtoMajor == 3 || strings.HasPrefix(r.Proto, "HTTP/3"):
		return Transport(transportH3)
	case r.ProtoMajor >= 2 && r.TLS == nil:
		return Transport(transportH2C)
	default:
		return Transport(transportH2)
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

// checkStrictTransportPolicy verifies the actual carrier is within the compiled transport allow-list.
func checkStrictTransportPolicy(r *http.Request, policy routingPolicy, configuredTransport string, actual Transport) error {
	name := string(actual)
	if name != "" && policy.allowsTransport(name) {
		return nil
	}
	if name == "" {
		name = "unknown"
	}
	return fmt.Errorf("transport policy violation: allowed=[%s], got=%s Method=%s Proto=%s Content-Type=%s Protocol=%s",
		configuredTransport, name, r.Method, r.Proto, r.Header.Get("Content-Type"), masqueConnectProtocol(r))
}

// checkStrictTransport is a convenience wrapper for config validation/tests: it
// compiles a policy from configuredTransport then checks. At runtime use the
// classifyTunnelRequest result.
func checkStrictTransport(r *http.Request, configuredTransport string, actual Transport) error {
	return checkStrictTransportPolicy(r, compileRoutingPolicy(configuredTransport, networkAll), configuredTransport, actual)
}
