package h2tunnel

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
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
func fastRand(max int) int {
	if max <= 1 {
		return 0
	}
	return mrand.Intn(max)
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

func getXDst(r *http.Request) (string, string) {
	network := getXNetwork(r)
	target := getXTarget(r)

	if target == "" || !isValidTargetAddr(target) { // fall back to a default when empty/invalid
		switch network {
		case "udp":
			target = "127.0.0.1:53" // DNS
		default:
			target = "127.0.0.1:22" // SSH
		}
	}

	return network, target
}

func getRequestDestination(r *http.Request, cfg serverConfig) (string, string) {
	if cfg.TargetDialer != nil {
		return getXNetwork(r), strings.TrimSpace(getXTarget(r))
	}
	return getXDst(r)
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

// secureEqual is a constant-time string comparison (run to completion even on a
// length mismatch, to avoid a length side channel).
func secureEqual(a, b string) bool {
	if a == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
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
func writeVarInt(w io.Writer, val uint64) error {
	var buf [8]byte
	if val <= 0x3f {
		buf[0] = byte(val)
		return writeAll(w, buf[:1])
	} else if val <= 0x3fff {
		binary.BigEndian.PutUint16(buf[:2], uint16(val)|0x4000)
		return writeAll(w, buf[:2])
	} else if val <= 0x3fffffff {
		binary.BigEndian.PutUint32(buf[:4], uint32(val)|0x80000000)
		return writeAll(w, buf[:4])
	}
	binary.BigEndian.PutUint64(buf[:], val|0xc000000000000000)
	return writeAll(w, buf[:])
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

func readVarInt(r io.Reader) (uint64, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	val := uint64(b[0] & 0x3f)

	if length > 1 {
		buf := make([]byte, length-1)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		for _, v := range buf {
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
	if addPadding {
		if err := writeVarInt(w, paddingCapsuleType); err != nil {
			return err
		}
		if err := writeVarInt(w, uint64(padLen)); err != nil {
			return err
		}
		if err := writePadding(w, padLen); err != nil {
			return err
		}
	}

	// Write the Datagram capsule (type 0x00).
	if err := writeVarInt(w, 0x00); err != nil {
		return err
	}
	if err := writeVarInt(w, uint64(1+len(p))); err != nil {
		return err
	}
	if err := writeVarInt(w, 0x00); err != nil {
		return err
	}
	return writeAll(w, p)
}

func readUDPCapsule(r io.Reader, payloadBuf []byte) (int, error) {
	for {
		capsuleType, err := readVarInt(r)
		if err != nil {
			return 0, err
		}
		capsuleLen, err := readVarInt(r)
		if err != nil {
			return 0, err
		}
		if capsuleLen > maxCapsuleLen {
			return 0, fmt.Errorf("UDP capsule length %d exceeds limit %d", capsuleLen, maxCapsuleLen)
		}

		lr := &io.LimitedReader{R: r, N: int64(capsuleLen)}
		if capsuleType == 0x00 {
			contextID, err := readVarInt(lr)
			if err != nil {
				return 0, err
			}
			if contextID == 0 {
				if lr.N > int64(len(payloadBuf)) {
					return 0, fmt.Errorf("UDP capsule too large for buffer")
				}
				n, err := io.ReadFull(lr, payloadBuf[:lr.N]) // read straight into the pooled buffer, no GC
				return n, err
			}
		}
		if lr.N > 0 {
			io.Copy(io.Discard, lr)
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
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}

	length := binary.BigEndian.Uint16(hdr[0:2])
	padLen := binary.BigEndian.Uint16(hdr[2:4])

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
