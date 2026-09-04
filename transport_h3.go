package h2tunnel

import (
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// =========================================
// h3（HTTP/3 over QUIC）传输层 adapter
//
// h3 的应用层 handler 与 h2 完全相同（见 transport_h2.go 的
// handleH2StreamResumeServer）——差异只在传输层：h3 走 QUIC，需要独立的
// http3.Server（服务端）与 http3.Transport（客户端），并依赖 webtransport
// 提供 WebTransport 能力（h3 是 wt 的底层传输）。
//
// 本文件只封装 h3 / WT 共用的传输层构建，不承载业务 handler。
// =========================================

// newH3WTServer 构建服务端 H3/WT 监听器。h3 与 wt 共享同一个 http3.Server
// （WebTransport 运行在 HTTP/3 之上），故统一在此构建 webtransport.Server。
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

// newH3Transport 构建客户端 h3 / masque（均走 QUIC）的 http.Client 传输层。
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
	}}
}
