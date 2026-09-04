// Package h2tunnel provides an embeddable, authenticated, resumable tunnel
// over HTTP/2, HTTP/3, WebTransport, MASQUE, and gRPC transports.
//
// A Client acts as a concurrent net.Conn dialer. A Server authenticates every
// request and delegates target authorization and connection establishment to a
// mandatory TargetDialer. NewClient and NewServer perform no network I/O.
package h2tunnel
