module github.com/NNdroid/h2tunnel

// NOTE: keep the language version at 1.26 — do NOT bump to 1.27+ yet.
// The //go:build go1.27 release tag on x/net's "wrapping" http2
// implementation (which delegates to net/http and rejects the RFC 8441
// ":protocol" pseudo-header at its front-door validation) is gated by this
// directive; staying at 1.26 keeps x/net's original http2 implementation,
// which is required for the MASQUE-over-h2 (extended CONNECT) carrier.
// See transport_masque_client.go for details.
go 1.26.0

require (
	github.com/quic-go/quic-go v0.62.0
	github.com/quic-go/webtransport-go v0.13.0
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
)

require (
	github.com/andybalholm/brotli v1.2.4 // indirect
	github.com/dunglas/httpsfv v1.1.1 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
