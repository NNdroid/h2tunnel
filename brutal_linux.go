//go:build linux

package h2tunnel

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
)

// Linux socket constants, defined locally instead of importing
// golang.org/x/sys/unix so that module stays an indirect dependency.
const (
	solTCP          = 6
	tcpCongestion   = 13
	tcpBrutalParams = 23301
)

const brutalAvailablePath = "/proc/net/ipv4/tcp_available"

// brutalAvailable reports whether the kernel exposes the brutal controller. It
// backs the startup WARN and the guarded Linux socket test.
func brutalAvailable() bool {
	b, err := os.ReadFile(brutalAvailablePath)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), brutalCongestionName)
}

// errBrutalGroupDropped is returned when the kernel only accepts the v1
// 12-byte struct, which has no group_id field. The algorithm still switched,
// but per-client grouping is silently lost — worth a WARN, not a failure.
var errBrutalGroupDropped = errors.New("TCP_BRUTAL_PARAMS accepted the v1 12-byte struct only; group_id was dropped")

// setBrutal performs the two-step enable: TCP_CONGESTION="brutal" then
// TCP_BRUTAL_PARAMS. Everything runs inside RawConn.Control because the fd is
// guaranteed valid only for the callback's duration.
func setBrutal(conn net.Conn, d brutalDecision) error {
	tc, ok := tcpConnFrom(conn)
	if !ok {
		return ErrBrutalUnavailable
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err = rc.Control(func(fd uintptr) {
		if inner = setsockoptCongestion(fd); inner != nil {
			return
		}
		if !d.setParams {
			return
		}
		inner = setsockoptBrutalParams(fd, d)
	}); err != nil {
		return err
	}
	return inner
}

// setsockoptCongestion switches the socket to the brutal controller.
//
// A locked brutalctl rule returns EPERM here even when the socket is already
// running brutal: the route lock covers the controller switch as well as the
// params. h2tunnel cannot override a locked route either way, so EPERM is
// accepted rather than surfaced — the operator's rule is authoritative. (The
// guide's stricter form reads getsockopt(TCP_CONGESTION) to confirm; the
// stdlib exposes no GetsockoptString, and the outcome is identical because a
// locked route is unwritable from userspace.)
func setsockoptCongestion(fd uintptr) error {
	if err := syscall.SetsockoptString(int(fd), solTCP, tcpCongestion, brutalCongestionName); err != nil {
		if errors.Is(err, syscall.EPERM) {
			return nil
		}
		return err
	}
	return nil
}

// setsockoptBrutalParams writes the v2 (20-byte) struct, falling back to the
// v1 (12-byte, no group_id) layout when the module predates groups.
func setsockoptBrutalParams(fd uintptr, d brutalDecision) error {
	var v2 = packBrutalParamsV2(d)
	if err := setsockoptBytes(fd, solTCP, tcpBrutalParams, v2[:]); err == nil {
		return nil
	} else if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOPROTOOPT) {
		var v1 = packBrutalParamsV1(d)
		if err := setsockoptBytes(fd, solTCP, tcpBrutalParams, v1[:]); err == nil {
			return errBrutalGroupDropped
		}
		return err
	} else {
		return err
	}
}

// packBrutalParamsV2 encodes
//
//	struct brutal_params { u64 rate; u32 cwnd_gain; u64 group_id; } __packed;
func packBrutalParamsV2(d brutalDecision) [20]byte {
	var b [20]byte
	binary.LittleEndian.PutUint64(b[0:], d.rateBytes)
	binary.LittleEndian.PutUint32(b[8:], d.cwndGain)
	binary.LittleEndian.PutUint64(b[12:], d.groupID)
	return b
}

// packBrutalParamsV1 is the same struct minus group_id.
func packBrutalParamsV1(d brutalDecision) [12]byte {
	var b [12]byte
	binary.LittleEndian.PutUint64(b[0:], d.rateBytes)
	binary.LittleEndian.PutUint32(b[8:], d.cwndGain)
	return b
}

// setsockoptBytes passes a packed option value. SetsockoptString is the only
// stdlib sockopt setter that takes a raw buffer: on Unix it hands len(s) over
// as optlen and does NOT append a NUL terminator, so it carries the fixed-size
// Brutal struct byte-for-byte. (A raw syscall.Syscall would be wrong here — it
// takes only three arguments on amd64 and drops the option length, and the
// socketcall-based 32-bit ABIs need the wrapper the generated setsockopt
// already selects.)
func setsockoptBytes(fd uintptr, level, opt int, val []byte) error {
	return syscall.SetsockoptString(int(fd), level, opt, string(val))
}
