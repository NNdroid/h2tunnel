package h2tunnel

import (
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// =========================================
// h3 (HTTP/3 over QUIC) transport adapter
//
// h3's application-layer handler is identical to h2's (see
// handleH2StreamResumeServer in transport_h2.go) — the only difference is the
// transport: h3 runs on QUIC and needs a separate http3.Server (server) and
// http3.Transport (client), and relies on webtransport for WebTransport (h3 is
// wt's underlying transport).
//
// This file only wraps the transport-layer construction shared by h3 / WT; it
// carries no business handler.
// =========================================

// newH3WTServer builds the server-side H3/WT listener. h3 and wt share one
// http3.Server (WebTransport runs over HTTP/3), so webtransport.Server is built here.
func newH3WTServer(addr string, handler http.Handler, tlsConfig *tls.Config) *webtransport.Server {
	serverTLS := tlsConfig.Clone()
	serverTLS.NextProtos = []string{http3.NextProtoH3}
	wtServer := &webtransport.Server{
		H3: &http3.Server{
			Addr:            addr,
			Handler:         handler,
			TLSConfig:       serverTLS,
			EnableDatagrams: true,
			QUICConfig:      getDefaultQUICConfig(),
		},
	}
	webtransport.ConfigureHTTP3Server(wtServer.H3)
	return wtServer
}

// newH3Transport builds the client http.Client transport for h3 / masque (both over QUIC).
func newH3Transport(cfg clientConfig) *http.Client {
	var tlsConfig *tls.Config
	if cfg.TLSConfig != nil {
		tlsConfig = cfg.TLSConfig.Clone()
	} else {
		tlsConfig = &tls.Config{InsecureSkipVerify: cfg.Insecure}
	}
	tlsConfig.NextProtos = []string{"h3"}
	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	}
	return &http.Client{Transport: &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      getDefaultQUICConfig(),
		Dial:            cfg.QUICDialer,
	}}
}
