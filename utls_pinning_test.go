package h2tunnel_test

// =========================================
// utls × certificate pinning regression tests.
//
// Attack scenario (historical bug): myssh used InsecureSkipVerify=true +
// VerifyPeerCertificate for fingerprint pinning. Once UtlxFingerprint was
// enabled, utlsTLSConfig once failed to carry over VerifyPeerCertificate →
// the camouflage path silently bypassed pinning → accepted any certificate
// (MITM). This test locks down that field (and VerifyConnection) so the
// trust decision is never swallowed by the fingerprint branch.
// =========================================

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

// startPinningServer starts an h2 tunnel server with the given TLS certificate + echo target, returns the endpoint.
func startPinningServer(t *testing.T, srvTLS *tls.Config) string {
	t.Helper()
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(echoListener)
	t.Cleanup(func() { _ = echoListener.Close() })

	auth, err := h2tunnel.NewTokenAuthenticator("pin-token")
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := h2tunnel.NewStaticServiceDialer(map[string]h2tunnel.Service{
		"echo": {Network: h2tunnel.NetworkTCP, Address: echoListener.Addr().String()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP},
		TLSConfig:     srvTLS,
		Authenticator: auth,
		Dialer:        dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(h2tunnel.Listeners{TCP: ln}) }()
	t.Cleanup(func() { _ = server.Close() })
	return "https://" + ln.Addr().String()
}

// leafFingerprint returns the SHA-256 (lowercase hex) of the leaf DER of the first certificate in the TLS config.
func leafFingerprint(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	if len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		t.Fatal("server tls.Config has no certificate")
	}
	sum := sha256.Sum256(cfg.Certificates[0].Certificate[0])
	return hex.EncodeToString(sum[:])
}

// dialPinned dials with a client that "skips chain verification + pins by fingerprint";
// a non-empty utlsFingerprint takes the camouflage path. Returns (round-trip OK, error).
func dialPinned(t *testing.T, endpoint, utlsFingerprint, pinnedFP string) (bool, error) {
	t.Helper()
	credentials, err := h2tunnel.NewTokenCredentials("pin-token")
	if err != nil {
		t.Fatal(err)
	}
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:        endpoint,
		Transport:       h2tunnel.TransportH2,
		Credentials:     credentials,
		UtlxFingerprint: utlsFingerprint,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("no peer certs")
				}
				sum := sha256.Sum256(rawCerts[0])
				if hex.EncodeToString(sum[:]) != pinnedFP {
					return errors.New("pinned fingerprint mismatch")
				}
				return nil
			},
		},
	})
	if err != nil {
		return false, err
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hi")); err != nil {
		return false, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false, err
	}
	return true, nil
}

// TestUtlsRespectsVerifyPeerCertificate — none of the three combinations may silently bypass pinning:
//   - camouflage + correct fingerprint → success;
//   - camouflage + wrong fingerprint → must fail (regression point: a dropped field would make it wrongly succeed);
//   - native TLS + wrong fingerprint → fail (control, proving consistent semantics).
func TestUtlsRespectsVerifyPeerCertificate(t *testing.T) {
	srvTLS, err := h2tunnel.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := startPinningServer(t, srvTLS)
	good := leafFingerprint(t, srvTLS)
	bad := "0000000000000000000000000000000000000000000000000000000000000000"

	if ok, err := dialPinned(t, endpoint, "chrome", good); !ok {
		t.Fatalf("utls + correct pin should succeed: %v", err)
	}
	if ok, err := dialPinned(t, endpoint, "chrome", bad); ok {
		t.Fatalf("SECURITY: utls path accepted a non-pinned certificate — VerifyPeerCertificate bypassed (err=%v)", err)
	}
	if ok, err := dialPinned(t, endpoint, "", bad); ok {
		t.Fatalf("native TLS unexpectedly accepted a non-pinned certificate (err=%v)", err)
	}
}

// TestUtlsRespectsVerifyConnection locks down the other modern pinning path
// (VerifyConnection since Go 1.15), which likewise must be carried over to
// utls.Config through the adapter function.
func TestUtlsRespectsVerifyConnection(t *testing.T) {
	srvTLS, err := h2tunnel.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := startPinningServer(t, srvTLS)

	credentials, _ := h2tunnel.NewTokenCredentials("pin-token")
	var called atomic.Bool
	client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:        endpoint,
		Transport:       h2tunnel.TransportH2,
		Credentials:     credentials,
		UtlxFingerprint: "chrome",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				called.Store(true)
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no peer certs in VerifyConnection")
				}
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !called.Load() {
		t.Fatal("SECURITY: VerifyConnection never fired on the utls path — pinning hook dropped")
	}
}
