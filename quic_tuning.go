package h2tunnel

import (
	"fmt"

	"github.com/quic-go/quic-go"
)

// QUICReceiveWindowTuning controls stream and connection receive credit for
// H3, WebTransport, and the MASQUE H3 carrier. Zero preserves the defaults
// advertised by getDefaultQUICConfig. Configure each receiving endpoint
// separately; these are not replay buffers.
type QUICReceiveWindowTuning struct {
	InitialStreamBytes     uint64 `json:"initial_stream_bytes"`
	MaxStreamBytes         uint64 `json:"max_stream_bytes"`
	InitialConnectionBytes uint64 `json:"initial_connection_bytes"`
	MaxConnectionBytes     uint64 `json:"max_connection_bytes"`
}

// quicWindowDefaults are the effective maximum windows when the caller does
// not set them. Stream initial credit defaults to one of these rather than to
// quic-go's own 512KiB / 768KiB initial windows, which is what the inheritance
// in resolved() depends on.
var quicWindowDefaults = struct {
	Stream     uint64
	Connection uint64
}{
	Stream:     8 << 20,
	Connection: 20 << 20,
}

// resolved returns the effective windows. An unset initial window inherits the
// max rather than falling back to quic-go's 512KiB stream / 768KiB connection
// defaults: a fresh connection then starts with full credit, so the first burst
// is not throttled to initial/RTT while the window grows. That growth lag is
// what costs the most at connection start on a high-RTT link, and quic-go
// treats 0 as "use its own default", so leaving the field unset here would
// silently undo the very thing the caller asked for.
func (w QUICReceiveWindowTuning) resolved() (streamInit, streamMax, connInit, connMax uint64) {
	streamMax = w.MaxStreamBytes
	if streamMax == 0 {
		streamMax = quicWindowDefaults.Stream
	}
	connMax = w.MaxConnectionBytes
	if connMax == 0 {
		connMax = quicWindowDefaults.Connection
	}
	streamInit = w.InitialStreamBytes
	if streamInit == 0 {
		streamInit = streamMax
	}
	connInit = w.InitialConnectionBytes
	if connInit == 0 {
		connInit = connMax
	}
	return
}

// Validate rejects inconsistent or excessive receive windows at startup.
//
// Every field is bounded to 256MiB per stream or connection. Initial and
// maximum are then compared as the effective pair, so a caller who sets only
// the maximum is still checked against the initial it would inherit. Two
// shapes are refused outright. An initial window larger than the maximum the
// connection may grow it to leaves a window that cannot grow, which is not a
// tuning but a ceiling. And a connection window smaller than a single stream
// window, at either size, hands one stream enough credit to consume the whole
// connection, starving every other stream permanently.
func (w QUICReceiveWindowTuning) Validate() error {
	for _, v := range []uint64{w.InitialStreamBytes, w.MaxStreamBytes, w.InitialConnectionBytes, w.MaxConnectionBytes} {
		if v > 256<<20 {
			return fmt.Errorf("h2tunnel: QUIC receive windows must not exceed 256MiB")
		}
	}
	si, sm, ci, cm := w.resolved()
	if si > sm || ci > cm {
		return fmt.Errorf("h2tunnel: QUIC initial receive window exceeds its maximum")
	}
	if ci < si || cm < sm {
		return fmt.Errorf("h2tunnel: QUIC connection receive window must cover one stream window")
	}
	return nil
}

func (w QUICReceiveWindowTuning) config() *quic.Config {
	c := getDefaultQUICConfig()
	si, sm, ci, cm := w.resolved()
	c.InitialStreamReceiveWindow = si
	c.MaxStreamReceiveWindow = sm
	c.InitialConnectionReceiveWindow = ci
	c.MaxConnectionReceiveWindow = cm
	return c
}
