package h2tunnel

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/NNdroid/h2tunnel/internal/certutil"
)

// Transport identifies the HTTP transport carrying a tunnel stream.
type Transport string

const (
	TransportAuto         Transport = ""
	TransportH2           Transport = "h2"
	TransportH2C          Transport = "h2c"
	TransportH3           Transport = "h3"
	TransportWebTransport Transport = "wt"
	TransportMASQUE       Transport = "masque"
	TransportGRPC         Transport = "grpc"
)

// Network identifies the application network transported through the tunnel.
type Network string

const (
	NetworkTCP = "tcp"
	NetworkUDP = "udp"
)

var (
	ErrUnauthenticated      = errors.New("h2tunnel: unauthenticated")
	ErrForbidden            = errors.New("h2tunnel: target forbidden")
	ErrUnsupportedNetwork   = errors.New("h2tunnel: unsupported network")
	ErrUnsupportedTransport = errors.New("h2tunnel: unsupported transport")
	// ErrBrutalUnavailable means the TCP Brutal socket layer cannot apply here —
	// a non-Linux host, a kernel without the module, or a socket that is not a
	// TCP connection. A failed Brutal apply never fails a connection, so this only
	// ever shows up in logs.
	ErrBrutalUnavailable = errors.New("h2tunnel: TCP Brutal unavailable")
)

// CredentialProvider adds authentication data to one outgoing tunnel request.
// Protocol-owned headers are restored after this callback returns and therefore
// cannot be overridden by a credential provider.
type CredentialProvider func(context.Context, http.Header) error

// Principal is the authenticated identity bound to a resumable session.
type Principal struct {
	ID    string
	Roles []string
}

// Authenticator authenticates an incoming tunnel request. Implementations must
// treat request headers as read-only and return a stable, non-empty Principal.ID.
type Authenticator func(context.Context, *http.Request) (Principal, error)

// DialRequest is passed to the server's policy-aware target dialer.
type DialRequest struct {
	Network   Network
	Target    string
	Transport Transport
	Principal Principal
	// Kind distinguishes why a dial happens. DialKindProbe is the handshake of a
	// probe/warm-up lane: the server never establishes a real connection for it
	// (probe lanes never dial); Target is only for authorization logging.
	// Business tunnels are always DialKindBusiness.
	Kind DialKind
}

// DialKind classifies why the server is dialing a target.
type DialKind string

const (
	// DialKindBusiness is a client-initiated tunnel to a real target.
	DialKindBusiness DialKind = "business"
	// DialKindProbe is a keep-alive lane handshake; see DialRequest.Kind.
	DialKindProbe DialKind = "probe"
)

// TargetDialer authorizes, resolves, and connects one requested target. For
// UDP it must return a connected datagram net.Conn (normally *net.UDPConn).
//
// Probe/warm-up lanes (DialKindProbe) only appear in authorization logs; the
// server never calls Dialer for them — an implementation can skip establishing
// connections for probe-kind requests.
type TargetDialer func(context.Context, DialRequest) (net.Conn, error)

// ClientDialer and QUICDialer let embedding applications control the
// underlying sockets (for example interface binding or Android VPN protect).
// Nil values keep the standard library / quic-go dialers.
type ClientDialer func(context.Context, string, string) (net.Conn, error)
type QUICDialer func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error)

// Service describes one target in a static logical-service registry.
type Service struct {
	Network Network
	Address string
	Roles   []string
}

// ClientOptions configures an embeddable tunnel client. It intentionally has
// no local listen address or default target: callers pass the target per dial.
// ClientEventHandler is an optional client event callback (TunnelEstablished,
// TunnelDied, Reconnecting, TargetDenied), dispatched on its own goroutine with
// panics recovered. It can also be registered at runtime via Client.SetEventHandler.
type ClientOptions struct {
	// Server address (with scheme). https pairs with h2/h3/wt/masque, http with
	// h2c; when Transport is empty it is inferred from the scheme.
	Endpoint string
	// Tunnel HTTP path (default "/"). MASQUE endpoints are nested under it:
	// <path>.well-known/masque/{tcp,udp}/<host>/<port>/.
	Path string
	// Transport protocol; empty = inferred from the Endpoint scheme (https→h2, http→h2c).
	Transport Transport
	// Overrides the HTTP Host header (CDN multi-tenant origin-fetch scenarios).
	Host string
	// TLS config; used after a Clone so callers can safely reuse theirs. Not
	// allowed with an http endpoint.
	TLSConfig *tls.Config
	// UtlxFingerprint enables utls fingerprint disguise: rewrites the TLS
	// ClientHello into a real browser's shape (chrome/firefox/edge/safari/ios/qq)
	// to resist JA3/JA4-based TLS fingerprinting. Empty = Go native crypto/tls.
	// Only applies to h2/grpc (TLS over TCP): the TLS for h3/wt/masque is done
	// inside quic-go and cannot be injected, so configuring it there errors in
	// NewClient; the http endpoint (h2c) likewise.
	UtlxFingerprint string
	// Per-request authentication callback (typically from NewTokenCredentials).
	Credentials CredentialProvider
	Tuning      ClientTuning
	// Event callback (optional, injected at construction; or SetEventHandler at runtime).
	EventHandler ClientEventHandler
	Logger       *slog.Logger
	// Underlying TCP socket dialer (interface binding / VPN protect); nil = stdlib.
	Dialer ClientDialer
	// Underlying QUIC dialer (for h3/wt/masque); nil = quic-go default.
	QUICDialer QUICDialer
}

// ClientTuning contains the small set of knobs that materially affect CDN
// reliability or per-session memory. Zero values select safe defaults.
type ClientTuning struct {
	// Session-recovery ring window size (bytes). 0 = default 256KB, capped at
	// 64MB (larger errors). Outage-recovery note: outage duration × downlink rate
	// > window ⇒ the gap is unrecoverable and the session terminates. Raise it for
	// long outages or high throughput.
	SessionWindowBytes int
	// CDN two-way heartbeat interval. 0 = default 25s; negative = disable the
	// heartbeat entirely (only for direct origin links, no CDN/reverse proxy in
	// between); positive values are clamped to [5s, 5min].
	HeartbeatInterval time.Duration
	// Backup-lane KEEPALIVE interval. 0 = default 15s; valid range 1s–1h, larger errors.
	KeepaliveInterval time.Duration
	// Data-plane handshake HANDSHAKE-ACK timeout. 0 = default 3s; valid range
	// 1ms–30s, larger errors.
	HandshakeTimeout time.Duration
	// Number of hot standby connections (0 = disabled; unsupported by WT, must be 0).
	StandbyConnections int
	// UDP datagram uplink queue depth. 0 = default 200; valid range 0–65536,
	// larger errors. When full, writes block until the write deadline (CLI drops);
	// raising it absorbs bursts at the cost of memory.
	DatagramQueueSize int
	// Network-change self-heal: after redials exhaust (16), reset the retry
	// counter and keep dialing (infinite revival), fitting mobile networks where
	// "disconnected, waiting for the network to return"; false = terminate on
	// exhaustion and dispatch a TunnelDied(max retries) event for the caller to
	// decide whether to redial. Default false.
	AutoRedial bool
	// Per-attempt dial budget. 0 = unlimited (rely on the transport timeout); a
	// positive value bounds only each attempt's connect + handshake phase (the
	// timer stops once the tunnel is ready, so established streams are not
	// bounded), used to tighten the give-up cadence during an outage (e.g. 10s,
	// so 16 redials exhaust in ~3 minutes).
	RedialBudget time.Duration
	// Padding controls application-layer tunnel record shaping. Padding is
	// removed by the peer and is never forwarded to the TCP or UDP target.
	// The zero value disables padding.
	Padding PaddingTuning
	// MASQUE carrier selection (only valid with Transport=masque): "h3" = QUIC/UDP
	// only; "h2" = TCP extended CONNECT only (the server must enable extended
	// CONNECT, see the ClientTuning docs / README GODEBUG note); empty = automatic
	// (h3 first, automatically pinned to h2 if the h3 dial fails). On UDP-blocked
	// deployments, explicitly setting "h2" skips the first-connection QUIC handshake timeout.
	MasqueALPN string
	// Brutal requests TCP Brutal on the tunnel's TCP legs (h2, h2c, grpc and the
	// masque h2 carrier). UDP/QUIC legs are unaffected. It is a Linux-only,
	// best-effort optimization: on any other platform, or on a kernel without the
	// module, it degrades to a WARN and the connection proceeds unchanged.
	Brutal BrutalTuning
}

// ServerOptions configures an embeddable tunnel server. Authenticator and
// Dialer are mandatory so a library server never becomes an open proxy by
// accident. ServerEventHandler is an optional server event callback (Session*,
// AuthRejected, TargetDenied, ReplayDropped), dispatched on its own goroutine
// with panics recovered. It can also be registered at runtime via Server.SetEventHandler.
type ServerOptions struct {
	EventHandler ServerEventHandler
	// Tunnel HTTP path (default "/"). MASQUE endpoints are nested under it:
	// <path>.well-known/masque/{tcp,udp}/<host>/<port>/.
	Path          string
	Transports    []Transport
	Networks      []Network
	TLSConfig     *tls.Config
	Authenticator Authenticator
	Dialer        TargetDialer
	Tuning        ServerTuning
	Logger        *slog.Logger
}

// Server performance tuning. Zero values select safe defaults.
type ServerTuning struct {
	// Session-recovery ring window size (bytes). 0 = default 256KB, capped at
	// 64MB (larger errors).
	SessionWindowBytes int
	// Session idle reclaim time. 0 = default 60s (a session with no active stream
	// closes after this timeout).
	SessionIdleTimeout time.Duration
	// SessionMax caps the total number of concurrent resume sessions on the
	// server (0 = default 4096). A global cap bounds memory under a flood of
	// distinct (never-resumed) session IDs.
	SessionMax int
	// SessionMaxPerPrincipal caps concurrent sessions per principal (0 = default
	// 256). It stops a single principal from consuming the entire global budget.
	SessionMaxPerPrincipal int
	// Padding controls server-to-client application-layer tunnel records.
	// Configure both client and server to shape both traffic directions.
	Padding PaddingTuning
	// Brutal requests TCP Brutal on the connections the server accepts. Together
	// with ClientTuning.Brutal it turns a deployment's upload path into a shared
	// connection group, so a client's aggregate send rate is capped regardless of
	// how many connections it opens. Linux-only and best-effort, same as the
	// client side.
	Brutal BrutalTuning
}

// BrutalTuning requests TCP Brutal, a Linux TCP congestion controller driven by
// an explicit send rate. Zero values are safe: the feature is off.
type BrutalTuning struct {
	// Enabled turns the feature on. When false nothing is set on any socket and
	// no negotiation headers are sent.
	Enabled bool `json:"enabled"`
	// RateBytes is this side's declared send rate in bytes per second. 0 means
	// "no local preference": the peer's value is used instead. The negotiated
	// result is min(server, client).
	RateBytes uint64 `json:"rate_bytes"`
	// CwndGain is the congestion-window gain in tenths, so 15 = 1.5x and 20 = 2.0x.
	// The kernel cannot hold a float, hence the scaling. 0 selects the 1.5x
	// default; 1-1000 is accepted. 1.5x-2.0x is the recommended range.
	CwndGain uint32 `json:"cwnd_gain"`
	// GroupID is a static override. 0 derives it from the presented token and the
	// client's stable group seed, which is what a shared-token deployment needs.
	// A non-zero value pins the given group and is how several clients are put in
	// one shared rate bucket.
	GroupID uint64 `json:"group_id"`
	// Negotiate runs the in-band bandwidth exchange. false skips it and applies
	// this side's local values as-is.
	Negotiate bool `json:"negotiate"`
}

// PaddingTuning controls application-layer record shaping. When enabled, each
// stream record is randomly sized between MinRecordBytes and MaxRecordBytes.
// Datagram boundaries are preserved: small datagrams are padded, while a
// datagram already larger than MaxRecordBytes is sent as one intact record.
//
// This does not promise a minimum IP packet size. TLS, HTTP/2, HTTP/3, QUIC,
// TCP segmentation, acknowledgements, retransmissions, CDNs, and the path MTU
// may split or coalesce application records after h2tunnel writes them.
type PaddingTuning struct {
	// MinRecordBytes enables padding when greater than zero. It must be larger
	// than the 16-byte resume record header and leave room for the random range.
	MinRecordBytes int `json:"min_record_bytes"`
	// MaxRecordBytes is the inclusive random upper bound. Zero derives a
	// default 25% above MinRecordBytes. It must not exceed 65535.
	MaxRecordBytes int `json:"max_record_bytes"`
}

// Listeners groups the stream and QUIC listeners owned by Server.Serve.
type Listeners struct {
	TCP  net.Listener
	QUIC net.PacketConn
}

// SelfSignedTLSConfig returns a TLS config carrying a freshly generated
// self-signed certificate. The certificate is valid for host (default
// "localhost") and always for 127.0.0.1 / ::1, so clients can verify the
// connection when dialing loopback with a normal TLS config. Intended for
// development and protected origin links — use a publicly trusted
// certificate in production.
func SelfSignedTLSConfig(host string) (*tls.Config, error) {
	cert, err := certutil.GenerateSelfSigned(host)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// PacketConn is a connected datagram tunnel that can be consumed as either a
// net.Conn or net.PacketConn.
type PacketConn interface {
	net.Conn
	net.PacketConn
}

// NewTokenCredentials creates CDN-safe client token credentials.
func NewTokenCredentials(token string) (CredentialProvider, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("%w: token is empty", ErrUnauthenticated)
	}
	return func(_ context.Context, h http.Header) error {
		h.Set("X-Auth-Token", token)
		h.Set("Authorization", "Bearer "+token)
		return nil
	}, nil
}

// NewTokenAuthenticator creates a constant-time pre-shared-token
// authenticator. Both the canonical Authorization header and the CDN-safe
// X-Auth-Token header are accepted.
func NewTokenAuthenticator(token string) (Authenticator, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("%w: token is empty", ErrUnauthenticated)
	}
	return func(_ context.Context, r *http.Request) (Principal, error) {
		candidate := strings.TrimSpace(r.Header.Get("X-Auth-Token"))
		if candidate == "" {
			candidate = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		}
		if len(candidate) != len(token) || subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) != 1 {
			return Principal{}, ErrUnauthenticated
		}
		return Principal{ID: "token"}, nil
	}, nil
}

// NewStaticServiceDialer creates a closed-by-default logical service registry.
// The input map and role slices are copied. Unknown services and role failures
// return ErrForbidden without revealing whether a service exists.
func NewStaticServiceDialer(services map[string]Service, base *net.Dialer) (TargetDialer, error) {
	compiled := make(map[string]Service, len(services))
	for name, service := range services {
		name = strings.TrimSpace(name)
		service.Address = strings.TrimSpace(service.Address)
		service.Network = Network(strings.ToLower(strings.TrimSpace(string(service.Network))))
		if name == "" || service.Address == "" {
			return nil, errors.New("h2tunnel: service name and address are required")
		}
		if service.Network != NetworkTCP && service.Network != NetworkUDP {
			return nil, fmt.Errorf("%w: service %q uses %q", ErrUnsupportedNetwork, name, service.Network)
		}
		if _, _, err := net.SplitHostPort(service.Address); err != nil {
			return nil, fmt.Errorf("h2tunnel: invalid address for service %q: %w", name, err)
		}
		if _, exists := compiled[name]; exists {
			return nil, fmt.Errorf("h2tunnel: duplicate service name after trimming: %q", name)
		}
		service.Roles = append([]string(nil), service.Roles...)
		compiled[name] = service
	}
	dialer := base
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	return func(ctx context.Context, request DialRequest) (net.Conn, error) {
		service, ok := compiled[request.Target]
		if !ok || service.Network != request.Network || !principalHasAnyRole(request.Principal, service.Roles) {
			return nil, ErrForbidden
		}
		return dialer.DialContext(ctx, string(service.Network), service.Address)
	}, nil
}

func principalHasAnyRole(principal Principal, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, have := range principal.Roles {
		for _, want := range allowed {
			if subtle.ConstantTimeCompare([]byte(have), []byte(want)) == 1 && len(have) == len(want) {
				return true
			}
		}
	}
	return false
}
