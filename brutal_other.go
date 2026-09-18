//go:build !linux

package h2tunnel

import "net"

// TCP Brutal is a Linux kernel module, so the congestion-controller switch is
// unavailable everywhere else and the socket layer is a no-op. The config
// section is still parsed and validated, so a typo is caught before the same
// file is deployed to a Linux host.
//
// The `!linux` constraint is explicit on purpose: Go only recognises real GOOS
// suffixes, so a filename like brutal_other.go would otherwise compile on every
// platform and collide with brutal_linux.go.
func setBrutal(conn net.Conn, d brutalDecision) error {
	_ = conn
	_ = d
	return ErrBrutalUnavailable
}

func brutalAvailable() bool { return false }
