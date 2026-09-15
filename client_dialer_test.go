package h2tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	quic "github.com/quic-go/quic-go"
)

func TestNewClientPropagatesSocketDialers(t *testing.T) {
	tcpDialer := func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	}
	quicDialer := func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
		return nil, nil
	}
	client, err := NewClient(ClientOptions{
		Endpoint:   "https://cdn.example.test",
		Transport:  TransportH3,
		TLSConfig:  &tls.Config{InsecureSkipVerify: true},
		Dialer:     tcpDialer,
		QUICDialer: quicDialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.cfg.Dialer == nil || client.cfg.QUICDialer == nil {
		t.Fatal("custom socket dialers were not propagated")
	}
}
