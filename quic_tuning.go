package h2tunnel

import (
	"fmt"

	"github.com/quic-go/quic-go"
)

// QUICReceiveWindowTuning controls stream and connection receive credit for
// H3, WebTransport, and the MASQUE H3 carrier. Zero preserves existing defaults.
// Configure each receiving endpoint separately; these are not replay buffers.
type QUICReceiveWindowTuning struct {
	InitialStreamBytes     uint64 `json:"initial_stream_bytes"`
	MaxStreamBytes         uint64 `json:"max_stream_bytes"`
	InitialConnectionBytes uint64 `json:"initial_connection_bytes"`
	MaxConnectionBytes     uint64 `json:"max_connection_bytes"`
}

// Validate rejects inconsistent or excessive receive windows at startup.
// Each nonzero field is bounded to 256MiB per connection / stream.
func (w QUICReceiveWindowTuning) Validate() error {
	for _, v := range []uint64{w.InitialStreamBytes, w.MaxStreamBytes, w.InitialConnectionBytes, w.MaxConnectionBytes} {
		if v > 256<<20 {
			return fmt.Errorf("h2tunnel: QUIC receive windows must not exceed 256MiB")
		}
	}
	// quic-go v0.62 defaults: initial stream 512KiB, connection 768KiB.
	si, ci := w.InitialStreamBytes, w.InitialConnectionBytes
	if si == 0 {
		si = 512 << 10
	}
	if ci == 0 {
		ci = 768 << 10
	}
	sm, cm := w.MaxStreamBytes, w.MaxConnectionBytes
	if sm == 0 {
		sm = 8 << 20
	}
	if cm == 0 {
		cm = 20 << 20
	}
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
	c.InitialStreamReceiveWindow = w.InitialStreamBytes
	c.InitialConnectionReceiveWindow = w.InitialConnectionBytes
	if w.MaxStreamBytes != 0 {
		c.MaxStreamReceiveWindow = w.MaxStreamBytes
	}
	if w.MaxConnectionBytes != 0 {
		c.MaxConnectionReceiveWindow = w.MaxConnectionBytes
	}
	return c
}
