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

// DialRequest is passed to the server.s policy-aware target dialer.
type DialRequest struct {
	Network   Network
	Target    string
	Transport Transport
	Principal Principal
	// Kind 区分拨号原因。DialKindProbe 是探活/预热 lane 的握手：服务端
	// 不会为其建立真实连接（探活 lane 从不拨号），Target 仅用于授权日志。
	// 业务隧道恒为 DialKindBusiness。
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
// 探活/预热 lane（DialKindProbe）只会出现在授权日志里，服务端从不为它们
// 调用 Dialer —— 实现方可以据此跳过 probe 类请求的连接建立。
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
type ClientOptions struct {
	Endpoint    string
	Path        string
	Transport   Transport
	Host        string
	TLSConfig   *tls.Config
	Credentials CredentialProvider
	Tuning      ClientTuning
	Logger      *slog.Logger
	Dialer      ClientDialer
	QUICDialer  QUICDialer
}

// ClientTuning contains the small set of knobs that materially affect CDN
// reliability or per-session memory. Zero values select safe defaults.
type ClientTuning struct {
	SessionWindowBytes int
	HeartbeatInterval  time.Duration
	KeepaliveInterval  time.Duration
	HandshakeTimeout   time.Duration
	StandbyConnections int
	// DatagramQueueSize 是 UDP 数据报上行队列深度（默认 200）。队列满时
	// 写入会阻塞至写超时（CLI 侧丢弃），调大以承载突发，代价是内存。
	DatagramQueueSize int
}

// ServerOptions configures an embeddable tunnel server. Authenticator and
// Dialer are mandatory so a library server never becomes an open proxy by
// accident.
type ServerOptions struct {
	Path          string
	Transports    []Transport
	Networks      []Network
	TLSConfig     *tls.Config
	Authenticator Authenticator
	Dialer        TargetDialer
	Tuning        ServerTuning
	Logger        *slog.Logger

	// 为空时使用标准路径 /.well-known/masque/{tcp,udp}/<host>/<port>/；
	// 设置为 "ccc" 后路径变为 /ccc/.well-known/masque/...（前段自定义，
}

type ServerTuning struct {
	SessionWindowBytes int
	SessionIdleTimeout time.Duration
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
