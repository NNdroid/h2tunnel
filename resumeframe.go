package h2tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// =========================================
// resumeFrame v2 编解码
//
// 会话恢复协议唯一数据面（X-Tunnel-Proto: resume/2）。
// 帧格式（16B 头）：
//
//   ┌──────┬─────┬──────────┬──────────┬──────────┬─────────┬─────────┐
//   │ type │ ver │ dataLen  │ padLen   │ seq      │ data    │ padding │
//   │ 1B   │ 1B  │ uint32BE │ uint16BE │ uint64BE │ dataLen │ padLen  │
//   └──────┴─────┴──────────┴──────────┴──────────┴─────────┴─────────┘
//
//   type：帧类型（见 resumeFrameType 常量）。DATA 为业务数据，
//         END/ERROR/HANDSHAKE/HANDSHAKE-ACK/KEEPALIVE/KEEPALIVE-ACK
//         为控制帧。控制帧与 DATA 共用同一条 HTTP 流，写路径由各自
//         writer 的互斥锁（resumeSessionWriter.mu）串行化；控制帧在 DATA
//         帧之间穿插写入，既不会被数据面拆裂，也不会被饿死（downlinkPump
//         每写出一帧即释放锁，控制帧得以在帧间隙插入）。
//   ver ：协议版本，恒为 0x02。
//   seq ：DATA 帧内 data 的起始全局字节偏移（按方向累计）；控制帧无意义。
// =========================================

// 帧类型
const (
	resumeFrameData         byte = 0x01 // 业务数据帧
	resumeFrameEnd          byte = 0x02 // 会话结束（半关闭/全关闭）
	resumeFrameError        byte = 0x03 // 错误通知（携带错误码，见 resumeErrorCode）
	resumeFrameHandshake    byte = 0x10 // 握手（客户端→服务端，B 层确认）
	resumeFrameHandshakeAck byte = 0x11 // 握手确认（服务端→客户端）
	resumeFrameKeepalive    byte = 0x12 // 存活探测（备用线路心跳）
	resumeFrameKeepaliveAck byte = 0x13 // 存活确认
)

// 帧逻辑优先级（设计意图，非运行时强制）：ERROR/END 最高，握手/心跳次之，
// DATA 最低。运行时由 writer 互斥锁串行化保证「控制帧不拆裂、不饿死」，
// 不依赖独立的优先级调度器。

// 协议版本
const (
	resumeProtoVersion    byte = 0x02
	resumeFrameTypeResume      = "resume/2"
	resumeHeaderLen            = 1 + 1 + 4 + 2 + 8 // type+ver+dataLen+padLen+seq = 16
)

// 错误码（ERROR 控制帧 payload 首字节；同时映射到 HTTP X-Resume-Error 码名）
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
	for len(dst) > 0 {
		n := len(dst)
		if n > len(paddingGarbage) {
			n = len(paddingGarbage)
		}
		copy(dst[:n], paddingGarbage[:n])
		dst = dst[n:]
	}
}

func writePadding(w io.Writer, padLen int) error {
	for padLen > 0 {
		n := padLen
		if n > len(paddingGarbage) {
			n = len(paddingGarbage)
		}
		if err := writeAll(w, paddingGarbage[:n]); err != nil {
			return err
		}
		padLen -= n
	}
	return nil
}

// writeFrame 组装一帧并写入 w。
// type 为帧类型；seq 仅 DATA 帧有意义；padLen 决定尾部填充（保持混淆特征）。
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
	if typ == resumeFrameEnd && (len(data) != 0 || padLen != 0) {
		return errors.New("resume END frame must not carry data or padding")
	}
	dataLen := uint32(len(data))

	bufPtr := paddingWritePool.Get().(*[]byte)
	buf := *bufPtr
	defer paddingWritePool.Put(bufPtr)

	totalData := resumeHeaderLen + int(dataLen) + padLen
	if totalData <= len(buf) {
		// 路径 A：整帧入池缓冲一次性写入
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

	// 路径 B：超大帧，分三次写（头/数据/填充）
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

// writeResumeFrame 写一个 DATA 帧（业务数据）。
func writeResumeFrame(w io.Writer, seq uint64, data []byte, padLen int) error {
	return writeFrame(w, resumeFrameData, seq, data, padLen)
}

// writeResumeEndFrame 写入会话结束控制帧（END）。
func writeResumeEndFrame(w io.Writer) error {
	return writeFrame(w, resumeFrameEnd, 0, nil, 0)
}

// writeResumeErrorFrame 写入错误控制帧（ERROR）。
func writeResumeErrorFrame(w io.Writer, code resumeErrorCode) error {
	return writeFrame(w, resumeFrameError, 0, []byte{byte(code)}, 0)
}

// readFrame 读一帧，返回帧类型、seq、data 拷贝（写入 payloadBuf）。
// 填充已在函数内丢弃。返回 errResumeEndFrame 表示 END 控制帧。
func readFrame(r io.Reader, payloadBuf []byte) (typ byte, seq uint64, n int, err error) {
	var hdr [resumeHeaderLen]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
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
		if dataLen != 0 || padLen != 0 {
			return 0, 0, 0, errors.New("resume END frame must not carry data or padding")
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

// readResumeFrame 读一个 DATA 帧；非 DATA 帧返回错误。
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

// resumeClientRingBuf 上行客户端缓冲（写入上行帧失败时回退到此 buf，
// 恢复时按服务端 ack 的 seq 续发）
type resumeClientRingBuf struct {
	rb *ringBuffer
}

func newResumeClientRingBuf(sizeKB int) *resumeClientRingBuf {
	return &resumeClientRingBuf{rb: newRingBuffer(sizeKB)}
}

// Append 写入一段上行数据（seq 由调用方外部递增）
func (b *resumeClientRingBuf) Append(data []byte) { b.rb.Append(data) }

// WindowEnd 返回当前写入位置 seq（ringBuf.WindowStart + 已写入字节数）
func (b *resumeClientRingBuf) WindowEnd() uint64 { return b.rb.WindowEnd() }

// ReplayFrom 从给定 seq 起读出所有数据，写入 w。
// 返回写入总字节数与遇到的错误（errGap 表示缺口不可恢复）。
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
