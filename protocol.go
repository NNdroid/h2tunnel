package h2tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// paddingGarbage is a pre-generated random byte array used for ultra-fast
// padding fill, avoiding runtime computation and allocation.
var paddingGarbage [4096]byte

// Idle-timeout ceiling across common reverse proxies behind a CDN (a practical
// common denominator):
//
//	AWS ALB idle_timeout        default 60s
//	Nginx proxy_read_timeout    default 60s
//	Cloudflare origin read      100s (returns 524 on timeout)
//
// The default heartbeat is under half of the 60s minimum, leaving room for
// retransmission and jitter.
const (
	heartbeatDefault = 25 * time.Second
	heartbeatMin     = 5 * time.Second
	heartbeatMax     = 5 * time.Minute
	// Upper bound for draining in-flight tunnels during graceful shutdown.
	drainDefault = 30 * time.Second
)

// clampHeartbeat clamps a user-configured heartbeat interval into a safe range.
// Returning 0 disables the heartbeat (recommended only for direct origin links
// with no middleboxes).
func clampHeartbeat(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return heartbeatDefault
	case d < heartbeatMin:
		return heartbeatMin
	case d > heartbeatMax:
		return heartbeatMax
	}
	return d
}

// maxCapsuleLen bounds the length of a MASQUE/QUIC UDP capsule we are willing to
// consume. capsuleLen comes from the (attacker-controlled) wire, so without this
// cap a malicious peer could force the server to read an unbounded amount of
// stream data — a trivial DoS. 4 MiB is far above any legitimate UDP payload.
const maxCapsuleLen = 1 << 22

var paddingWritePool = sync.Pool{
	New: func() interface{} {
		// All shaped records are capped below 64 KiB. Larger unshaped payloads
		// use writeFrame's header/data/padding scatter path instead of retaining
		// a 1 MiB object per concurrently active writer.
		buf := make([]byte, 64*1024)
		return &buf
	},
}

func init() {
	rand.Read(paddingGarbage[:])
}

// fastRand returns a non-cryptographic random int in [0, max). It is used only
// for traffic-obfuscation padding (never for secrets/nonces), so a fast PRNG is
// both safe and dramatically cheaper than crypto/rand per call.
//
// It uses math/rand/v2's top-level functions, which draw from a lock-free
// runtime source (unlike math/rand/v1's global locked source). This matters on
// the padding hot path: fillPadding is called once per frame, so a locked
// global PRNG would serialize every concurrently active tunnel's framing.
func fastRand(max int) int {
	if max <= 1 {
		return 0
	}
	return mrand.IntN(max)
}

// normalizeTargetAddr normalizes a target address (supports IP:Port and
// Domain:Port).
func normalizeTargetAddr(addr, defaultPort string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		p, errP := strconv.Atoi(port)
		if errP == nil && p >= 1 && p <= 65535 && host != "" {
			return net.JoinHostPort(host, port)
		}
	}
	// If no port was given, try to append the default port.
	if defaultPort != "" && !strings.Contains(addr, ":") {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
}

// isValidTargetAddr validates a target address (supports IPv4 / IPv6 / hostname
// + port).
func isValidTargetAddr(addr string) bool {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	return true
}

func checkTargetIsAvailable(target string, cfg serverConfig) bool {
	if target == "" {
		return false
	}
	// In "local only" mode, perform a host check.
	if cfg.LocalOnly {
		host, _, err := net.SplitHostPort(target)
		if err != nil {
			host = target
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
		if ip := net.ParseIP(host); ip != nil {
			return ip.IsLoopback()
		}
		// Keep the conventional local hostname for user-friendly configs, but do
		// not accept lookalike names such as localhost.example.com.
		return host == "localhost"
	}
	return true
}

func getDefaultQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
		// Out-of-order bytes allowed. Must be large for high throughput, or
		// congestion control stalls the stream.
		MaxStreamReceiveWindow:     8 * 1024 * 1024,  // 8 MB (default is usually 512KB)
		MaxConnectionReceiveWindow: 20 * 1024 * 1024, // 20 MB
		// Max concurrent bidirectional streams the client may open, so mux doesn't
		// block once streams run out.
		MaxIncomingStreams: 1000,
		// In a pure-proxy setup you can disable KeepAlive or lengthen it to cut
		// control-frame overhead.
		KeepAlivePeriod:       9 * time.Second,
		MaxIdleTimeout:        30 * time.Second, // bound the idle timeout
		MaxIncomingUniStreams: 10000,            // raise the unidirectional-stream limit
	}
}

func getXNetwork(r *http.Request) string {
	network := r.Header.Get("X-Network")
	if network != "udp" {
		network = "tcp"
	}
	return network
}

func getXTarget(r *http.Request) string {
	target := r.Header.Get("X-Target")
	return target
}

// getRequestDestination resolves the routing target for the legacy (non-MASQUE)
// data plane: the X-Network / X-Target headers verbatim. It is fail-closed like
// the MASQUE resolver (see masqueRequestTarget): the historical default
// substitution — the server's own localhost SSH (127.0.0.1:22) or DNS
// (127.0.0.1:53) for an empty or invalid X-Target — is gone, because those
// substitutes cleared checkTargetIsAvailable and, over loopback, the local_only
// check too. An unusable target now reaches the runtime policy as-is and is
// rejected with 403.
func getRequestDestination(r *http.Request, _ serverConfig) (string, string) {
	return getXNetwork(r), strings.TrimSpace(getXTarget(r))
}

func setXNetwork(h http.Header, network string) {
	h.Set("X-Network", network)
}

func setXTarget(h http.Header, target string) {
	h.Set("X-Target", target)
}

func setXDst(h http.Header, cfg clientConfig) (string, string) {
	network := "tcp"
	if normalizeNetwork(cfg.Network, networkTCP) == networkUDP {
		network = "udp"
	}
	defaultPort := "22"
	if network == "udp" {
		defaultPort = "53"
	}
	if cfg.LogicalTargets {
		target := strings.TrimSpace(cfg.TargetAddr)
		setXNetwork(h, network)
		setXTarget(h, target)
		return network, target
	}

	target := normalizeTargetAddr(cfg.TargetAddr, defaultPort)
	if !isValidTargetAddr(target) {
		if network == "udp" {
			target = "127.0.0.1:53"
		} else {
			target = "127.0.0.1:22"
		}
	}
	setXNetwork(h, network)
	setXTarget(h, target)
	return network, target
}

func setXAuth(h http.Header, cfg clientConfig) {
	if cfg.Token == "" {
		return
	}
	// Both the custom header and standard Authorization survive common CDNs / reverse proxies.
	h.Set("X-Auth-Token", cfg.Token)
	h.Set("Authorization", "Bearer "+cfg.Token)
}

func applyClientCredentials(ctx context.Context, h http.Header, cfg clientConfig) error {
	if cfg.Credentials != nil {
		return cfg.Credentials(ctx, h)
	}
	setXAuth(h, cfg)
	return nil
}

// clientUserAgent is the User-Agent used uniformly across every tunnel request
// (TCP/UDP resume, backup lanes, WT CONNECT). It must be set explicitly: Go's
// HTTP/2 transport injects "Go-http-client/2.0" when a request has no UA —
// after utls disguises the handshake as Chrome, that header immediately makes
// the TLS fingerprint and the HTTP fingerprint contradict each other, undoing
// all the camouflage work.
const clientUserAgent = "Mozilla/5.0 (Linux; Android 15; SM-A057G Build/AP3A.240905.015.A2; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.7922.202 Mobile Safari/537.36 w2n/Android"

// setTunnelRequestHeaders sets the tunnel request-side anti-buffering headers,
// pairing with the server's setTunnelHeaders:
//
//	User-Agent: clientUserAgent — suppresses the Go-http-client default (see above).
//	Accept-Encoding: identity — Go's transport otherwise auto-adds gzip and promises
//	  to decompress; a middlebox seeing Accept-Encoding: gzip may compress-buffer the
//	  response. Explicit identity blocks both the auto-added header and CDN compression.
//	Cache-Control: no-store, no-transform — requires the CDN not to cache or rewrite.
func setTunnelRequestHeaders(h http.Header) {
	h.Set("User-Agent", clientUserAgent)
	h.Set("Accept-Encoding", "identity")
	h.Set("Cache-Control", "no-store, no-transform")
}

// clientIP recovers the real client IP.
//
// Behind a CDN / reverse proxy r.RemoteAddr is always the edge node's address;
// using it directly for logs and audit records nothing useful. Fall back through
// the common conventions in order.
//
// ⚠️ Security constraint: these headers can all be spoofed by the client, so the
// return value is for logging / rate-limit stats only and MUST NEVER be used for
// authentication or access control. To gate by IP, validate at the outermost
// reverse proxy or configure a trusted-proxy hop count and take the Nth-from-last.
func clientIP(r *http.Request) string {
	for _, h := range []string{"CF-Connecting-IP", "True-Client-IP", "X-Real-IP"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return v
		}
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	return r.RemoteAddr
}

// masquePathBase returns the MASQUE path base, nested under the tunnel path and
// reusing the same path config (path=/tunnel → /tunnel/.well-known/masque;
// path=/ → /.well-known/masque). A reverse proxy / CDN only needs to allow one
// prefix and both ends stay consistent automatically.
func masquePathBase(tunnelPath string) string {
	p := strings.TrimRight(strings.TrimSpace(tunnelPath), "/")
	if p == "" {
		return "/.well-known/masque"
	}
	return p + "/.well-known/masque"
}

// parseMasqueTarget parses the URI template per RFC 9298.
func parseMasqueTarget(protocol, reqPath string) (string, error) {
	protocol = strings.ToLower(protocol)
	if protocol != "tcp" && protocol != "udp" {
		lgErrorf(discardLogger, "[Protocol] ❌ URI parse failed: unsupported base protocol '%s'", protocol)
		return "", fmt.Errorf("unsupported protocol: %s", protocol)
	}
	cleanPath := strings.Trim(reqPath, "/")
	parts := strings.Split(cleanPath, "/")

	udpIdx := -1
	for i, p := range parts {
		if strings.EqualFold(p, protocol) {
			udpIdx = i
			break
		}
	}

	if udpIdx == -1 || len(parts) < udpIdx+3 {
		return "", fmt.Errorf("invalid masque path: %s", reqPath)
	}

	host, err1 := url.PathUnescape(parts[udpIdx+1])
	port, err2 := url.PathUnescape(parts[udpIdx+2])
	if err1 != nil || err2 != nil || host == "" || port == "" {
		lgErrorf(discardLogger, "[Protocol] ❌ URI decode failed: hostErr=%v, portErr=%v", err1, err2)
		return "", fmt.Errorf("failed to unescape host/port")
	}

	target := net.JoinHostPort(host, port)
	if !isValidTargetAddr(target) {
		return "", fmt.Errorf("invalid parsed masque target: %s", target)
	}
	lgDebugf(discardLogger, "[Protocol] ✅ MASQUE URI parsed OK -> target: %s", target)
	return target, nil
}

// --- QUIC VarInt (called extremely often; keep only severe error logs) ---

// putVarInt encodes val into dst (which must have room for 8 bytes) and
// returns the encoded length. writeUDPCapsule uses it to batch several varints
// into one Write; writeVarInt is its writer-facing form.
func putVarInt(dst []byte, val uint64) int {
	switch {
	case val <= 0x3f:
		dst[0] = byte(val)
		return 1
	case val <= 0x3fff:
		binary.BigEndian.PutUint16(dst[:2], uint16(val)|0x4000)
		return 2
	case val <= 0x3fffffff:
		binary.BigEndian.PutUint32(dst[:4], uint32(val)|0x80000000)
		return 4
	default:
		binary.BigEndian.PutUint64(dst[:8], val|0xc000000000000000)
		return 8
	}
}

func writeVarInt(w io.Writer, val uint64) error {
	var buf [8]byte
	return writeAll(w, buf[:putVarInt(buf[:], val)])
}

func varIntLen(val uint64) int {
	switch {
	case val < 1<<6:
		return 1
	case val < 1<<14:
		return 2
	case val < 1<<30:
		return 4
	default:
		return 8
	}
}

// udpDecodeScratch pools the byte scratch and LimitedReader used while
// decoding UDP capsules and packets: one warm-pool object per datagram loop
// instead of a LimitedReader plus 2-4 escaping varint buffers per packet.
// The old make-per-varint and hdr-array both escaped to the heap because the
// buffers cross an io.Reader interface call.
type udpDecodeScratch struct {
	scratch [8]byte
	lr      io.LimitedReader
}

var udpDecodeScratchPool = sync.Pool{New: func() any { return new(udpDecodeScratch) }}

func getUDPDecodeScratch() *udpDecodeScratch {
	return udpDecodeScratchPool.Get().(*udpDecodeScratch)
}

func putUDPDecodeScratch(s *udpDecodeScratch) {
	s.lr.R = nil // drop the body reference before recycle
	udpDecodeScratchPool.Put(s)
}

// readVarInt reads a QUIC varint through scratch (at least 8 bytes, caller
// owned) so the hot decode loops allocate nothing.
func readVarInt(r io.Reader, scratch []byte) (uint64, error) {
	if _, err := io.ReadFull(r, scratch[:1]); err != nil {
		return 0, err
	}
	prefix := scratch[0] >> 6
	length := 1 << prefix
	val := uint64(scratch[0] & 0x3f)

	if length > 1 {
		if _, err := io.ReadFull(r, scratch[1:length]); err != nil {
			return 0, err
		}
		for _, v := range scratch[1:length] {
			val = (val << 8) | uint64(v)
		}
	}
	return val, nil
}

// :protocol values for MASQUE / WebTransport (tunnel protocol-shape identifiers,
// independent of carrier).
const (
	protocolWebTransport = "webtransport"
	protocolConnectTCP   = "connect-tcp"
	protocolConnectUDP   = "connect-udp"
)

// masqueConnectProtocol returns the MASQUE CONNECT protocol name. It tolerates
// both exposures: quic-go h3 uses a regular "Protocol" header, while x/net h2
// extended CONNECT places the :protocol pseudo-header into r.Header(":protocol").
func masqueConnectProtocol(r *http.Request) string {
	if p := r.Header.Get("Protocol"); p != "" {
		return p
	}
	return r.Header.Get(":protocol")
}

// --- MASQUE UDP Capsule ---
const (
	paddingCapsuleType         = 0x1F23
	maxPaddingCapsuleHeaderLen = 6 // type(2) + length varint (up to 4 for uint16-sized padding)
	maxTunnelUDPPayload        = 65532
)

func udpCapsuleDataWireLen(payloadLen int) int {
	// DATAGRAM capsule type + capsule length + context ID + payload.
	return 1 + varIntLen(uint64(1+payloadLen)) + 1 + payloadLen
}

func paddingCapsuleWireLen(padLen int) int {
	return varIntLen(paddingCapsuleType) + varIntLen(uint64(padLen)) + padLen
}

func capsulePaddingForTarget(dataWireLen, target int) int {
	padLen := target - dataWireLen - maxPaddingCapsuleHeaderLen
	if padLen < 0 {
		padLen = 0
	}
	for dataWireLen+paddingCapsuleWireLen(padLen) < target {
		padLen++
	}
	return padLen
}

// writeUDPCapsule emits one CONNECT-UDP datagram plus its optional padding
// capsule. Wire order: [padding capsule][DATAGRAM capsule].
//
// Small datagrams (DNS, DHCP, game ticks — the hot case) assemble header,
// padding and payload into one pooled buffer so the whole emission rides ONE
// w.Write: on the h2 carrier every Write is a DATA frame (plus a flush/syscall
// on the pipe path), and the old per-varint writes turned one datagram into
// 4-7 frames. Only datagrams too big for the pool fall back to separate
// header/payload writes, sparing the 64KB memcpy.
func writeUDPCapsule(w io.Writer, p []byte, padding paddingPolicy) error {
	if len(p) > maxTunnelUDPPayload {
		return fmt.Errorf("UDP payload > %d", maxTunnelUDPPayload)
	}
	dataWireLen := udpCapsuleDataWireLen(len(p))
	target := padding.targetAtLeast(dataWireLen, maxPaddingCapsuleHeaderLen)
	addPadding := target > dataWireLen
	padLen := 0
	if addPadding {
		padLen = capsulePaddingForTarget(dataWireLen, target)
	}

	// Unknown capsule types are ignored by the peer. Keeping padding in its own
	// capsule preserves the CONNECT-UDP datagram payload exactly.
	var hdr [16]byte
	hdrLen := 0
	hdrLen += putVarInt(hdr[hdrLen:], 0x00)             // DATAGRAM capsule type
	hdrLen += putVarInt(hdr[hdrLen:], uint64(1+len(p))) // capsule length = context ID + payload
	hdrLen += putVarInt(hdr[hdrLen:], 0x00)             // context ID
	total := hdrLen + len(p)
	if addPadding {
		total += varIntLen(paddingCapsuleType) + varIntLen(uint64(padLen)) + padLen
	}

	if total <= udpBufPoolLen {
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr
		n := 0
		if addPadding {
			n += putVarInt(buf[n:], paddingCapsuleType)
			n += putVarInt(buf[n:], uint64(padLen))
			fillPadding(buf[n : n+padLen])
			n += padLen
		}
		copy(buf[n:], hdr[:hdrLen])
		n += hdrLen
		copy(buf[n:], p)
		err := writeAll(w, buf[:n+len(p)])
		udpBufPool.Put(bufPtr)
		return err
	}

	// Oversized datagram: padding capsule then datagram, headers batched where
	// they are adjacent. Two-to-three writes instead of the old four-to-seven.
	if addPadding {
		var padHdr [8]byte
		n := putVarInt(padHdr[:], paddingCapsuleType)
		n += putVarInt(padHdr[n:], uint64(padLen))
		if err := writeAll(w, padHdr[:n]); err != nil {
			return err
		}
		if err := writePadding(w, padLen); err != nil {
			return err
		}
	}
	if err := writeAll(w, hdr[:hdrLen]); err != nil {
		return err
	}
	return writeAll(w, p)
}

func readUDPCapsule(r io.Reader, payloadBuf []byte) (int, error) {
	s := getUDPDecodeScratch()
	defer putUDPDecodeScratch(s)
	s.lr.R = r
	for {
		capsuleType, err := readVarInt(r, s.scratch[:])
		if err != nil {
			return 0, err
		}
		capsuleLen, err := readVarInt(r, s.scratch[:])
		if err != nil {
			return 0, err
		}
		if capsuleLen > maxCapsuleLen {
			return 0, fmt.Errorf("UDP capsule length %d exceeds limit %d", capsuleLen, maxCapsuleLen)
		}

		s.lr.N = int64(capsuleLen)
		if capsuleType == 0x00 {
			contextID, err := readVarInt(&s.lr, s.scratch[:])
			if err != nil {
				return 0, err
			}
			if contextID == 0 {
				if s.lr.N > int64(len(payloadBuf)) {
					return 0, fmt.Errorf("UDP capsule too large for buffer")
				}
				n, err := io.ReadFull(&s.lr, payloadBuf[:s.lr.N]) // read straight into the pooled buffer, no GC
				return n, err
			}
		}
		if s.lr.N > 0 {
			io.Copy(io.Discard, &s.lr)
		}
	}
}

// --- Stream UDP Packets ---
// writeUDPPacket preserves one target UDP datagram per tunnel record.
func writeUDPPacket(w io.Writer, p []byte, padding paddingPolicy) error {
	if len(p) > maxTunnelUDPPayload {
		return fmt.Errorf("UDP payload > %d", maxTunnelUDPPayload)
	}

	padLen := padding.paddingFor(4 + len(p))
	totalLen := 4 + len(p) + padLen

	bufPtr := udpBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer udpBufPool.Put(bufPtr)

	// Assemble the header.
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(p)))
	binary.BigEndian.PutUint16(buf[2:4], uint16(padLen))

	// Concatenate payload and padding.
	copy(buf[4:], p)
	if padLen > 0 {
		fillPadding(buf[4+len(p) : totalLen])
	}

	return writeAll(w, buf[:totalLen])
}

func readUDPPacket(r io.Reader, payloadBuf []byte) (int, error) {
	s := getUDPDecodeScratch()
	defer putUDPDecodeScratch(s)
	if _, err := io.ReadFull(r, s.scratch[:4]); err != nil {
		return 0, err
	}

	length := binary.BigEndian.Uint16(s.scratch[0:2])
	padLen := binary.BigEndian.Uint16(s.scratch[2:4])

	if int(length) > len(payloadBuf) {
		return 0, fmt.Errorf("UDP packet too large for buffer: %d", length)
	}

	if _, err := io.ReadFull(r, payloadBuf[:length]); err != nil {
		return 0, err
	}

	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return 0, err
		}
	}
	return int(length), nil
}
