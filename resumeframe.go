package h2tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// =========================================
// resumeFrame v2 codec
//
// The sole data plane of the session-recovery protocol (X-Tunnel-Proto: resume/2).
// Frame layout (16-byte header):
//
//   ┌──────┬─────┬──────────┬──────────┬──────────┬─────────┬─────────┐
//   │ type │ ver │ dataLen  │ padLen   │ seq      │ data    │ padding │
//   │ 1B   │ 1B  │ uint32BE │ uint16BE │ uint64BE │ dataLen │ padLen  │
//   └──────┴─────┴──────────┴──────────┴──────────┴─────────┴─────────┘
//
//   type: frame type (see the resumeFrameType constants). DATA carries business
//         bytes; END/ERROR/HANDSHAKE/HANDSHAKE-ACK/KEEPALIVE/KEEPALIVE-ACK are
//         control frames. Control frames share the one HTTP stream with DATA;
//         the write path is serialized by each writer's mutex
//         (resumeSessionWriter.mu). Control frames interleave between DATA
//         frames — never torn apart by the data plane and never starved
//         (downlinkPump releases the lock after each frame so control frames can
//         slip into the gaps).
//   ver : protocol version, always 0x02.
//   seq : the global byte offset where this DATA frame's data starts (accumulated
//         per direction); meaningless for control frames.
// =========================================

// Frame types
const (
	resumeFrameData         byte = 0x01 // business data frame
	resumeFrameEnd          byte = 0x02 // session end (half/full close)
	resumeFrameError        byte = 0x03 // error notification (carries a code, see resumeErrorCode)
	resumeFrameHandshake    byte = 0x10 // handshake (client→server, layer-B confirmation)
	resumeFrameHandshakeAck byte = 0x11 // handshake confirmation (server→client)
	resumeFrameKeepalive    byte = 0x12 // liveness probe (backup-lane heartbeat)
	resumeFrameKeepaliveAck byte = 0x13 // liveness confirmation
)

// Frame logical priority (design intent, not enforced at runtime): ERROR/END
// highest, handshake/heartbeat next, DATA lowest. At runtime the writer mutex
// serialization guarantees "control frames are neither torn apart nor starved";
// there is no separate priority scheduler.

// Protocol version
const (
	resumeProtoVersion    byte = 0x02
	resumeFrameTypeResume      = "resume/2"
	resumeHeaderLen            = 1 + 1 + 4 + 2 + 8 // type+ver+dataLen+padLen+seq = 16
)

// Error codes (first byte of the ERROR control-frame payload; also mapped to the
// HTTP X-Resume-Error code name).
type resumeErrorCode byte

const (
	resumeErrVersionUnsupported resumeErrorCode = 0x01
	resumeErrNoCommonCapability resumeErrorCode = 0x02
	resumeErrInvalidParams      resumeErrorCode = 0x03
	resumeErrAuthFailed         resumeErrorCode = 0x04
	resumeErrTargetUnavailable  resumeErrorCode = 0x05
	resumeErrHandshakeTimeout   resumeErrorCode = 0x06
	resumeErrBackupUnavailable  resumeErrorCode = 0x07
)

var resumeErrCodeName = map[resumeErrorCode]string{
	resumeErrVersionUnsupported: "version-unsupported",
	resumeErrNoCommonCapability: "no-common-capability",
	resumeErrInvalidParams:      "invalid-params",
	resumeErrAuthFailed:         "auth-failed",
	resumeErrTargetUnavailable:  "target-unavailable",
	resumeErrHandshakeTimeout:   "handshake-timeout",
	resumeErrBackupUnavailable:  "backup-unavailable",
}

func (c resumeErrorCode) String() string {
	if s, ok := resumeErrCodeName[c]; ok {
		return s
	}
	return "unknown-error"
}

const (
	resumeMaxDataLen uint32 = 16 * 1024 * 1024
)

var errResumeEndFrame = errors.New("resume: END frame received")
var errResumeBadSeq = errors.New("resume: out-of-order seq")

func isResumeFrameType(typ byte) bool {
	switch typ {
	case resumeFrameData, resumeFrameEnd, resumeFrameError,
		resumeFrameHandshake, resumeFrameHandshakeAck,
		resumeFrameKeepalive, resumeFrameKeepaliveAck:
		return true
	default:
		return false
	}
}

// writeAll handles the io.Writer short-write case. Network writers normally
// write the whole slice, but accepting a nil-error short write would corrupt
// every following frame on the stream.
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return fmt.Errorf("invalid write count %d for %d bytes", n, len(p))
		}
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// fillPadding repeats the pre-generated random block. padLen is allowed to be
// the full uint16 range while paddingGarbage deliberately stays small.
func fillPadding(dst []byte) {
	start := fastRand(len(paddingGarbage))
	for len(dst) > 0 {
		n := len(paddingGarbage) - start
		if n > len(dst) {
			n = len(dst)
		}
		copy(dst[:n], paddingGarbage[start:start+n])
		dst = dst[n:]
		start = 0
	}
}

func writePadding(w io.Writer, padLen int) error {
	start := fastRand(len(paddingGarbage))
	for padLen > 0 {
		n := len(paddingGarbage) - start
		if n > padLen {
			n = padLen
		}
		if err := writeAll(w, paddingGarbage[start:start+n]); err != nil {
			return err
		}
		padLen -= n
		start = 0
	}
	return nil
}

// writeFrame assembles one frame and writes it to w. typ is the frame type; seq
// is meaningful only for DATA frames; padLen sets the trailing padding (keeping
// the obfuscation property).
func writeFrame(w io.Writer, typ byte, seq uint64, data []byte, padLen int) error {
	if !isResumeFrameType(typ) {
		return fmt.Errorf("resume frame type unsupported: 0x%02x", typ)
	}
	if len(data) > int(resumeMaxDataLen) {
		return fmt.Errorf("resume frame data too large: %d", len(data))
	}
	if padLen < 0 || padLen > 0xFFFF {
		return fmt.Errorf("resume frame pad too large: %d", padLen)
	}
	if typ == resumeFrameEnd && len(data) != 0 {
		return errors.New("resume END frame must not carry data")
	}
	dataLen := uint32(len(data))

	bufPtr := paddingWritePool.Get().(*[]byte)
	buf := *bufPtr
	defer paddingWritePool.Put(bufPtr)

	totalData := resumeHeaderLen + int(dataLen) + padLen
	if totalData <= len(buf) {
		// Path A: whole frame into the pooled buffer, one write
		buf[0] = typ
		buf[1] = resumeProtoVersion
		binary.BigEndian.PutUint32(buf[2:6], dataLen)
		binary.BigEndian.PutUint16(buf[6:8], uint16(padLen))
		binary.BigEndian.PutUint64(buf[8:16], seq)
		copy(buf[16:], data)
		if padLen > 0 {
			fillPadding(buf[16+int(dataLen) : totalData])
		}
		return writeAll(w, buf[:totalData])
	}

	// Path B: oversized frame, written in three parts (header/data/padding)
	buf[0] = typ
	buf[1] = resumeProtoVersion
	binary.BigEndian.PutUint32(buf[2:6], dataLen)
	binary.BigEndian.PutUint16(buf[6:8], uint16(padLen))
	binary.BigEndian.PutUint64(buf[8:16], seq)
	if err := writeAll(w, buf[:resumeHeaderLen]); err != nil {
		return err
	}
	if err := writeAll(w, data); err != nil {
		return err
	}
	if padLen > 0 {
		if err := writePadding(w, padLen); err != nil {
			return err
		}
	}
	return nil
}

// writeResumeFrame writes a DATA frame (business data).
func writeResumeFrame(w io.Writer, seq uint64, data []byte, padLen int) error {
	return writeFrame(w, resumeFrameData, seq, data, padLen)
}

// writeResumeDataFrames writes p as one frame when shaping is disabled. When
// enabled it splits p inside the codec, so live traffic and replay traffic use
// the same record-size invariant. The returned byte count follows io.Writer
// partial-write semantics and counts payload bytes, never padding bytes.
func writeResumeDataFrames(w io.Writer, seq uint64, p []byte, policy paddingPolicy) (int, error) {
	if !policy.enabled() {
		if err := writeResumeFrame(w, seq, p, 0); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	written := 0
	for len(p) > 0 {
		chunkLen, padLen := policy.dataChunk(len(p), resumeHeaderLen)
		if err := writeResumeFrame(w, seq, p[:chunkLen], padLen); err != nil {
			return written, err
		}
		written += chunkLen
		seq += uint64(chunkLen)
		p = p[chunkLen:]
	}
	return written, nil
}

// writeResumeEndFrame writes the session-end control frame (END).
func writeResumeEndFrame(w io.Writer, policy paddingPolicy) error {
	return writeFrame(w, resumeFrameEnd, 0, nil, policy.paddingFor(resumeHeaderLen))
}

// writeResumeErrorFrame writes the error control frame (ERROR).
func writeResumeErrorFrame(w io.Writer, code resumeErrorCode, policy paddingPolicy) error {
	data := []byte{byte(code)}
	return writeFrame(w, resumeFrameError, 0, data, policy.paddingFor(resumeHeaderLen+len(data)))
}

// readFrame reads one frame, returning its type, seq and data copy (into
// payloadBuf). Padding is already discarded inside. errResumeEndFrame signals an
// END control frame.
func readFrame(r io.Reader, payloadBuf []byte) (typ byte, seq uint64, n int, err error) {
	// Read the header into the front of payloadBuf first (data overwrites it
	// next): a local stack buffer passed via the io.Reader interface escapes to
	// the heap, costing one extra allocation per frame on the DATA hot path. If
	// payloadBuf is too small (rare: callers that only read control frames) fall
	// back to a heap allocation, keeping the old contract no tighter.
	var hdr []byte
	if len(payloadBuf) >= resumeHeaderLen {
		hdr = payloadBuf[:resumeHeaderLen]
	} else {
		hdr = make([]byte, resumeHeaderLen)
	}
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, 0, 0, err
	}
	typ = hdr[0]
	ver := hdr[1]
	dataLen := binary.BigEndian.Uint32(hdr[2:6])
	padLen := binary.BigEndian.Uint16(hdr[6:8])
	seq = binary.BigEndian.Uint64(hdr[8:16])

	if ver != resumeProtoVersion {
		return 0, 0, 0, fmt.Errorf("resume frame version mismatch: %d", ver)
	}
	if !isResumeFrameType(typ) {
		return 0, 0, 0, fmt.Errorf("resume frame type unsupported: 0x%02x", typ)
	}
	if typ == resumeFrameEnd {
		if dataLen != 0 {
			return 0, 0, 0, errors.New("resume END frame must not carry data")
		}
		if padLen > 0 {
			if _, err = io.CopyN(io.Discard, r, int64(padLen)); err != nil {
				return 0, 0, 0, err
			}
		}
		return typ, seq, 0, errResumeEndFrame
	}
	if dataLen > resumeMaxDataLen {
		return 0, 0, 0, fmt.Errorf("resume frame data too large: %d", dataLen)
	}
	if uint32(len(payloadBuf)) < dataLen {
		return 0, 0, 0, fmt.Errorf("payloadBuf too small: need %d have %d", dataLen, len(payloadBuf))
	}
	if _, err = io.ReadFull(r, payloadBuf[:dataLen]); err != nil {
		return 0, 0, 0, err
	}
	if padLen > 0 {
		if _, err = io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return 0, 0, 0, err
		}
	}
	return typ, seq, int(dataLen), nil
}

// readResumeFrame reads one DATA frame; a non-DATA frame returns an error.
func readResumeFrame(r io.Reader, payloadBuf []byte) (seq uint64, n int, err error) {
	typ, seq, n, err := readFrame(r, payloadBuf)
	if err != nil {
		return 0, 0, err
	}
	if typ != resumeFrameData {
		return 0, 0, fmt.Errorf("resume: unexpected frame type 0x%02x", typ)
	}
	return seq, n, nil
}

// resumeClientRingBuf is the client-side uplink buffer (bytes are fallen back
// here when writing an uplink frame fails; on recovery they are re-sent from the
// seq the server acked).
type resumeClientRingBuf struct {
	rb *ringBuffer
}

func newResumeClientRingBuf(sizeKB int) *resumeClientRingBuf {
	return &resumeClientRingBuf{rb: newRingBuffer(sizeKB)}
}

// Append writes a run of uplink data (seq is advanced by the caller externally).
func (b *resumeClientRingBuf) Append(data []byte) { b.rb.Append(data) }

// WindowEnd returns the current write position seq (ringBuf.WindowStart + bytes
// written).
func (b *resumeClientRingBuf) WindowEnd() uint64 { return b.rb.WindowEnd() }

// ReplayFrom reads all data from the given seq and writes it to w. Returns the
// total bytes written and any error encountered (errGap means the gap is
// unrecoverable).
func (b *resumeClientRingBuf) ReplayFrom(seq uint64, w io.Writer) (int64, error) {
	tmp := make([]byte, 8192)
	var total int64
	for {
		n, err := b.rb.ReadAt(seq, tmp)
		if n > 0 {
			if _, wErr := w.Write(tmp[:n]); wErr != nil {
				return total, wErr
			}
			seq += uint64(n)
			total += int64(n)
		}
		if errors.Is(err, errGap) {
			return total, errGap
		}
		if err != nil || n == 0 {
			return total, nil
		}
	}
}
