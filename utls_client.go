package h2tunnel

// =========================================
// TLS fingerprint disguise (utls) — applies only to the h2/grpc TCP-TLS transports.
//
// Go's native crypto/tls ClientHello (extension order / curves / compression
// combos) has a stable JA3/JA4 signature that middleboxes easily recognize and
// block. utls can rewrite the ClientHello into a real browser's shape
// (Chrome/Firefox/Safari/...).
//
// The QUIC family (h3/wt/masque) does not apply: quic-go calls crypto/tls's
// tls.QUICClient directly in its handshake layer, leaving no seam to inject a
// custom TLS implementation. NewClient rejects that combination at construction
// to avoid "thinking you're disguised when you're not".
// =========================================

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls" // the package name is tls, so it must be import-aliased
)

// utlsFingerprints maps an allowed disguise name to a utls ClientHelloID (the
// Auto variants track each browser's latest hello shape as utls upgrades).
//
// Only fingerprints that advertise h2 in ALPN are listed: the tunnel is h2-only,
// so 360 (Auto=7.5, http/1.1 only) cannot negotiate it and is excluded.
var utlsFingerprints = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"edge":    utls.HelloEdge_Auto,
	"safari":  utls.HelloSafari_Auto,
	"ios":     utls.HelloIOS_Auto,
	"qq":      utls.HelloQQ_Auto,
}

// tlsCamouflage is parsed once at construction and read-only at runtime.
type tlsCamouflage struct {
	id utls.ClientHelloID
}

// utlsDialTLSContext produces the http2.Transport DialTLSContext: raw TCP via
// rawDial (net.Dialer when nil, honoring the cfg.Dialer custom socket), then a
// utls handshake with the chosen browser fingerprint.
func (c *Client) utlsDialTLSContext(rawDial func(ctx context.Context, network, address string) (net.Conn, error)) func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	if rawDial == nil {
		var d net.Dialer
		rawDial = d.DialContext
	}
	return func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		raw, err := rawDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		uc := utls.UClient(raw, c.utlsTLSConfig(addr), c.utls.id)
		if err := uc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		// http2.Transport no longer checks ALPN (a custom dialer's conn is already
		// trusted by it), so we gate here: fail immediately if h2 wasn't negotiated,
		// to avoid later frame-protocol corruption.
		if p := uc.ConnectionState().NegotiatedProtocol; p != "h2" {
			_ = raw.Close()
			return nil, fmt.Errorf("h2tunnel: utls handshake negotiated %q, want h2", p)
		}
		return uc, nil
	}
}

// utlsTLSConfig copies every field of the user's crypto/tls.Config relevant to
// "peer trust decisions / client authentication" into utls.Config. utls carries
// its own structurally identical but distinct types (ConnectionState /
// Certificate / SignatureScheme …), so there is no whole-struct conversion — only
// field-by-field copying. Silently dropping any field about "is the peer
// trusted, how do we present a client cert" gets bypassed the moment disguise is
// enabled — the historical bug: omitting VerifyPeerCertificate disabled
// certificate fingerprint pinning, which with InsecureSkipVerify=true degraded to
// accepting any certificate (MITM).
//
// Deliberately NOT copied, with reasons below:
//   - CipherSuites / CurvePreferences: owned by the browser fingerprint preset;
//     copying them conflicts with the preset, breaking the disguise or the handshake;
//   - ClientSessionCache: sharing sessions across the native and utls configs lets a
//     resumed connection skip VerifyConnection / VerifyPeerCertificate (pinning hooks
//     run only on a full handshake) — giving up resumption on the camouflaged path is
//     the safe choice, not leaving a pinning backdoor.
func (c *Client) utlsTLSConfig(addr string) *utls.Config {
	conf := &utls.Config{NextProtos: []string{"h2"}}
	if src := c.tlsConfig; src != nil {
		conf.ServerName = src.ServerName
		conf.InsecureSkipVerify = src.InsecureSkipVerify
		conf.RootCAs = src.RootCAs
		conf.ClientCAs = src.ClientCAs
		conf.MinVersion = src.MinVersion
		conf.MaxVersion = src.MaxVersion
		conf.SessionTicketsDisabled = src.SessionTicketsDisabled
		conf.KeyLogWriter = src.KeyLogWriter
		conf.EncryptedClientHelloConfigList = src.EncryptedClientHelloConfigList
		// VerifyPeerCertificate's parameter types ([][]byte / [][]*x509.Certificate)
		// are shared across the two packages, so it can be assigned directly.
		conf.VerifyPeerCertificate = src.VerifyPeerCertificate
		conf.VerifyConnection = adaptVerifyConnection(src.VerifyConnection)
		conf.Certificates = adaptClientCerts(src.Certificates)
		conf.GetClientCertificate = adaptGetClientCertificate(src.GetClientCertificate)
	}
	if conf.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			conf.ServerName = host
		} else {
			conf.ServerName = addr
		}
	}
	return conf
}

// adaptVerifyConnection adapts a crypto/tls VerifyConnection callback to utls's
// ConnectionState type; the mapping covers every field a pinning callback reads.
func adaptVerifyConnection(fn func(tls.ConnectionState) error) func(utls.ConnectionState) error {
	if fn == nil {
		return nil
	}
	return func(cs utls.ConnectionState) error {
		return fn(tls.ConnectionState{
			Version:                     cs.Version,
			HandshakeComplete:           cs.HandshakeComplete,
			DidResume:                   cs.DidResume,
			CipherSuite:                 cs.CipherSuite,
			NegotiatedProtocol:          cs.NegotiatedProtocol,
			NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
			ServerName:                  cs.ServerName,
			PeerCertificates:            cs.PeerCertificates,
			VerifiedChains:              cs.VerifiedChains,
			SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
			OCSPResponse:                cs.OCSPResponse,
		})
	}
}

func adaptClientCerts(in []tls.Certificate) []utls.Certificate {
	if len(in) == 0 {
		return nil
	}
	out := make([]utls.Certificate, len(in))
	for i, cert := range in {
		out[i] = utls.Certificate{
			Certificate:                  cert.Certificate,
			PrivateKey:                   cert.PrivateKey,
			OCSPStaple:                   cert.OCSPStaple,
			SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
			Leaf:                         cert.Leaf,
			SupportedSignatureAlgorithms: adaptSignatureSchemes[tls.SignatureScheme, utls.SignatureScheme](cert.SupportedSignatureAlgorithms),
		}
	}
	return out
}

func adaptGetClientCertificate(fn func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) func(*utls.CertificateRequestInfo) (*utls.Certificate, error) {
	if fn == nil {
		return nil
	}
	return func(req *utls.CertificateRequestInfo) (*utls.Certificate, error) {
		cert, err := fn(&tls.CertificateRequestInfo{
			AcceptableCAs:    req.AcceptableCAs,
			SignatureSchemes: adaptSignatureSchemes[utls.SignatureScheme, tls.SignatureScheme](req.SignatureSchemes),
			Version:          req.Version,
		})
		if err != nil || cert == nil {
			return nil, err
		}
		return &utls.Certificate{
			Certificate:                 cert.Certificate,
			PrivateKey:                  cert.PrivateKey,
			OCSPStaple:                  cert.OCSPStaple,
			SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
			Leaf:                        cert.Leaf,
		}, nil
	}
}

// adaptSignatureSchemes converts between the two packages' SignatureScheme (both uint16 underneath).
func adaptSignatureSchemes[S tls.SignatureScheme | utls.SignatureScheme, D tls.SignatureScheme | utls.SignatureScheme](in []S) []D {
	if in == nil {
		return nil
	}
	out := make([]D, len(in))
	for i, s := range in {
		out[i] = D(uint16(s))
	}
	return out
}

// resolveUTLSFingerprint turns a user-configured name into a disguise plan
// (already lower-cased and trimmed). An unknown name returns the valid list.
func resolveUTLSFingerprint(name string) (*tlsCamouflage, error) {
	id, ok := utlsFingerprints[name]
	if !ok {
		names := make([]string, 0, len(utlsFingerprints))
		for k := range utlsFingerprints {
			names = append(names, k)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("h2tunnel: unknown UtlxFingerprint %q (valid: %s)", name, strings.Join(names, ", "))
	}
	return &tlsCamouflage{id: id}, nil
}
