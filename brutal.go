package h2tunnel

// =========================================
// brutal.go — TCP Brutal congestion control: policy, group identity, negotiation
//
// TCP Brutal is a Linux kernel module replacing the TCP congestion controller
// with an explicit send-rate controller. Enabling it on a socket is a two-step
// setsockopt: TCP_CONGESTION="brutal" switches the algorithm, TCP_BRUTAL_PARAMS
// (23301) supplies {rate bytes/s, cwnd_gain tenths, group_id}. It is Linux-only
// and opt-in: elsewhere it is a silent no-op, and on a kernel without the module
// it degrades with a single WARN — a broken option must never break a tunnel.
//
// Connection groups are the part that matters to a proxy: every socket on one
// host carrying the same non-zero group_id shares `rate` as a TOTAL, so one
// group caps a client's aggregate upload regardless of how many connections it
// opens. Group IDs are therefore derived, never typed by hand:
//
//	group_id = u64le(HMAC-SHA256(token, seed)[:8]) | 1
//
// The token is the HMAC key — identical for every client of a shared-token
// deployment, which is why it cannot be the identity on its own — and `seed`
// supplies the per-client difference. `| 1` keeps the result non-zero, since 0
// means "no group". The seed is X-Client-Group when the client sends it (one
// random value per Client instance, stable across TCP-leg migration) and falls
// back to X-Session-ID. Neither is the remote IP, so NAT rebind and connection
// migration do not split a client into fresh buckets. Both sides derive the
// same value independently, so the group_id the server echoes back is a
// cross-check, not a dependency.
//
// Why the exchange exists: Brutal needs the path bandwidth, and proxy protocols
// carry no place for it. The client offers its local rate/gain on X-Brutal-Offer,
// the server answers on X-Brutal-Params with the negotiated value. Values merge
// with min() and 0 means "no local preference", so either side may stay silent
// and the other wins.
//
// The exchange is deliberately NOT version-gated and adds no capability flag:
// the offer must be sent on the first request of a leg, before the client has
// seen any server capabilities, so a cap could never gate it. The wire stays
// inert without versioning because an older peer simply ignores the unknown
// headers — it neither echoes nor acts on them. The sentinel target
// _BrutalBwExchange is the explicit form of the same exchange for callers that
// want to negotiate without opening a business tunnel.
//
// Nonce: a fresh random value per exchange on X-Brutal-Offer, echoed back on
// X-Brutal-Params; the client applies the decision only on a match, so a cached
// or reordered response cannot be applied to the wrong socket. The nonce never
// enters the HMAC input — group_id must be stable for a client, not per exchange.
// =========================================

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	brutalCongestionName = "brutal"

	// brutalBwExchangeTarget is the sentinel target carrying the explicit bandwidth
	// exchange. An underscore-leading label is not a valid DNS name (RFC 952/1123),
	// so it can never resolve to a real upstream even if the short-circuit were
	// bypassed; it also fails isValidTargetAddr, which is why it must be matched
	// before the legacy getXDst default-substitution runs.
	brutalBwExchangeTarget = "_BrutalBwExchange"

	brutalDefaultCwndGain = 15 // tenths: 1.5x
	brutalMaxCwndGain     = 1000
	brutalNonceBytes      = 16

	// Header names. X-Brutal-Offer is request→server (the client's local
	// preference); X-Brutal-Params is server→client (the negotiated decision).
	brutalHeaderOffer     = "X-Brutal-Offer"
	brutalHeaderParams    = "X-Brutal-Params"
	brutalHeaderClientGrp = "X-Client-Group"

	paramBrutalRate  = "rate"
	paramBrutalGain  = "gain"
	paramBrutalGroup = "group_id"
	paramBrutalNonce = "nonce"
)

// brutalPolicy is the compiled, validated form of BrutalTuning. cwndGain is
// always non-zero (0 selects the default), so callers never re-check it.
type brutalPolicy struct {
	enabled   bool
	rateBytes uint64
	cwndGain  uint32
	groupID   uint64 // 0 = derive from the presented token
	negotiate bool
}

// brutalDecision is what setBrutal puts into the socket. setParams reports
// whether TCP_BRUTAL_PARAMS should be written at all.
type brutalDecision struct {
	rateBytes uint64
	cwndGain  uint32
	groupID   uint64
	setParams bool
	// nonce is the peer's echoed exchange nonce; it is never sent to the kernel.
	nonce string
}

// brutalUnwrapDepth bounds the wrapper chain followed by tcpConnFrom. A user
// supplied ClientDialer may hand back its own wrapper; one that unwraps into a
// cycle must not be able to hang a dial, so the walk stops after this many hops
// rather than following the chain forever. Two hops covers every wrapper this
// package produces.
const brutalUnwrapDepth = 32

// tcpConnFrom unwraps a connection to its underlying *net.TCPConn. Only plain
// Unwrap chains are followed — tls.Conn exposes NetConn instead, which is why
// every call site applies Brutal before wrapping the raw socket.
func tcpConnFrom(conn net.Conn) (*net.TCPConn, bool) {
	for depth := 0; depth < brutalUnwrapDepth; {
		switch c := conn.(type) {
		case *net.TCPConn:
			return c, true
		case interface{ Unwrap() net.Conn }:
			conn = c.Unwrap()
			depth++
		default:
			return nil, false
		}
	}
	return nil, false
}

// tuning converts back to the exported form, mirroring paddingPolicy.tuning so
// a serverConfig can be reflected into ServerOptions. cwndGain is already
// normalized to the 1.5x default, so the round trip is not identity on a
// zero-value config: it reports what will actually be applied.
func (p brutalPolicy) tuning() BrutalTuning {
	return BrutalTuning{
		Enabled:   p.enabled,
		RateBytes: p.rateBytes,
		CwndGain:  p.cwndGain,
		GroupID:   p.groupID,
		Negotiate: p.negotiate,
	}
}

// compileBrutalPolicy validates and normalizes a BrutalTuning. The only rule is
// on cwnd_gain: 0 selects the 1.5x default, any non-zero value must stay within
// a sane range. Everything else is accepted, so a zero-value BrutalTuning is
// always valid and a disabled feature can never fail a client.
func compileBrutalPolicy(t BrutalTuning) (brutalPolicy, error) {
	gain := t.CwndGain
	if gain == 0 {
		gain = brutalDefaultCwndGain
	}
	if gain > brutalMaxCwndGain {
		return brutalPolicy{}, fmt.Errorf("h2tunnel: Brutal.CwndGain must be at most %d tenths (got %d)", brutalMaxCwndGain, gain)
	}
	return brutalPolicy{
		enabled:   t.Enabled,
		rateBytes: t.RateBytes,
		cwndGain:  gain,
		groupID:   t.GroupID,
		negotiate: t.Negotiate,
	}, nil
}

// brutalOffer builds the X-Brutal-Offer value for one exchange attempt, or "" to
// keep the wire clean when there is nothing to offer (disabled, or negotiation
// turned off). The nonce inside it is what the client checks the answer against.
func brutalOffer(p brutalPolicy) string {
	if !p.enabled || !p.negotiate {
		return ""
	}
	nonce := newBrutalNonce()
	return formatBrutalKV(map[string]string{
		paramBrutalRate:  strconv.FormatUint(p.rateBytes, 10),
		paramBrutalGain:  strconv.FormatUint(uint64(p.cwndGain), 10),
		paramBrutalNonce: nonce,
	})
}

// setBrutalOfferHeaders puts the exchange request on one outgoing tunnel request:
// the local preference plus this client's stable grouping seed. The seed travels
// only with an offer — the server derives a group id solely to answer an exchange,
// so an unsolicited header would be dead weight on every tunnel request.
func setBrutalOfferHeaders(h http.Header, p brutalPolicy, group string) {
	offer := brutalOffer(p)
	if offer == "" {
		return
	}
	h.Set(brutalHeaderOffer, offer)
	if group != "" {
		h.Set(brutalHeaderClientGrp, group)
	}
}

// clampPeerGain bounds a peer-declared gain to the range this side would accept
// for its own config. Both parsers read a remote header, and an absurd value must
// not reach the peer cache, the decision NegotiateBrutal reports, or the kernel —
// the socket is already bounded by min() against a locally validated policy, this
// closes the rest of the path. 0 keeps its "no local preference" meaning.
func clampPeerGain(gain uint32) uint32 {
	if gain == 0 || gain <= brutalMaxCwndGain {
		return gain
	}
	return 0
}

// parseBrutalOffer reads a peer's X-Brutal-Offer. Missing or malformed keys read
// as zero (no preference), which is the intended lenient shape for a header.
func parseBrutalOffer(s string) (rateBytes uint64, cwndGain uint32, nonce string) {
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case paramBrutalRate:
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				rateBytes = n
			}
		case paramBrutalGain:
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				cwndGain = clampPeerGain(uint32(n))
			}
		case paramBrutalNonce:
			nonce = v
		}
	}
	return rateBytes, cwndGain, nonce
}

// applyOffer merges a peer's declared values into the local policy with min()
// semantics, axis by axis: either side may declare 0 ("no local preference") and
// the other side's value wins for that axis. The axes are independent, so a peer
// that declares a gain but no rate still contributes its gain.
func applyOffer(local brutalPolicy, peerRate uint64, peerGain uint32) brutalPolicy {
	if peerRate != 0 && (local.rateBytes == 0 || peerRate < local.rateBytes) {
		local.rateBytes = peerRate
	}
	if peerGain != 0 && peerGain < local.cwndGain {
		local.cwndGain = peerGain
	}
	return local
}

// decideBrutal turns the effective policy into what actually goes into the
// socket. setParams is false when neither side declared a rate: switch the
// algorithm, but leave the module's own defaults in force rather than pushing a
// zero rate that would starve the connection.
func decideBrutal(p brutalPolicy) brutalDecision {
	return brutalDecision{
		rateBytes: p.rateBytes,
		cwndGain:  p.cwndGain,
		groupID:   p.groupID,
		setParams: p.rateBytes > 0,
	}
}

// resolveBrutalExchange is the server side of one exchange: merge the client's
// offer into the local policy with min() semantics, then resolve the group id
// from the presented token and client seed. It returns the effective policy
// together with the nonce the client sent, so the caller can both configure the
// socket and render the X-Brutal-Params value from the same computation.
//
// Resolving the group needs the token, which is why it runs after
// authentication. A request that never authenticates never produces a group.
func resolveBrutalExchange(p brutalPolicy, r *http.Request) (brutalPolicy, string) {
	offer := strings.TrimSpace(r.Header.Get(brutalHeaderOffer))
	if offer == "" {
		return p, ""
	}
	peerRate, peerGain, nonce := parseBrutalOffer(offer)
	if peerRate != 0 || peerGain != 0 {
		p = applyOffer(p, peerRate, peerGain)
	}
	p.groupID = resolveBrutalGroupID(p, brutalTokenFromHeaders(r.Header), brutalGroupSeed(r))
	return p, nonce
}

// brutalReply renders the X-Brutal-Params value for one exchange, echoing the
// client's nonce so it can verify the answer belongs to this exchange.
func brutalReply(p brutalPolicy, r *http.Request) string {
	if !p.enabled || !p.negotiate {
		return ""
	}
	eff, nonce := resolveBrutalExchange(p, r)
	if nonce == "" {
		return ""
	}
	return formatBrutalReply(decideBrutal(eff), nonce)
}

// handleBrutalReply processes the server's answer on the client: a reply whose
// echoed nonce does not match the one this request offered belongs to a different
// exchange (a cached or reordered response, or one answered to another leg) and
// is discarded rather than trusted. On a match the decision is recorded for the
// next dial.
//
// http2 keeps no reference to the dialer's conn, so the socket carrying this
// stream cannot be reached from here and the reply does not reconfigure it. The
// server applies the same decision to its own accepted socket in
// routeTunnelRequest, so this cache only affects the client's side. The cache is
// what makes negotiation still take effect: negotiation only ever lowers the
// rate, so recording the server's value and merging it at the next dial is
// monotone, and every later leg (standby lanes, migrations, reconnects) starts
// already bounded by the negotiated value.
func handleBrutalReply(req *http.Request, reply string, peer *brutalPeerCache, lg *slog.Logger) {
	if reply == "" {
		return
	}
	_, _, sent := parseBrutalOffer(req.Header.Get(brutalHeaderOffer))
	if sent == "" {
		return
	}
	d, echoed := parseBrutalReply(reply)
	if !sameBrutalNonce(sent, echoed) {
		lgWarnf(lg, "[Brutal] ⚠️ reply nonce mismatch, ignoring the answer to this exchange")
		return
	}
	if peer != nil {
		peer.set(d)
	}
	lgDebugf(lg, "[Brutal] ✅ negotiated rate=%d gain=%d group_id=%d", d.rateBytes, d.cwndGain, d.groupID)
}

// brutalPeerCache remembers the last X-Brutal-Params decision seen from the
// server so dials that come after the first exchange start from the negotiated
// value rather than the client's own preference.
type brutalPeerCache struct {
	mu   sync.Mutex
	seen bool
	dec  brutalDecision
}

func (b *brutalPeerCache) get() (brutalDecision, bool) {
	if b == nil {
		return brutalDecision{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dec, b.seen
}

func (b *brutalPeerCache) set(d brutalDecision) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.dec = d
	b.seen = true
	b.mu.Unlock()
}

// formatBrutalReply builds the X-Brutal-Params response value.
func formatBrutalReply(d brutalDecision, nonce string) string {
	kv := map[string]string{
		paramBrutalRate: strconv.FormatUint(d.rateBytes, 10),
		paramBrutalGain: strconv.FormatUint(uint64(d.cwndGain), 10),
	}
	if d.groupID != 0 {
		kv[paramBrutalGroup] = strconv.FormatUint(d.groupID, 10)
	}
	if nonce != "" {
		kv[paramBrutalNonce] = nonce
	}
	return formatBrutalKV(kv)
}

// parseBrutalReply reads a server's X-Brutal-Params. It returns the nonce
// separately because the caller has to verify it before trusting the decision.
func parseBrutalReply(s string) (brutalDecision, string) {
	d := brutalDecision{}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case paramBrutalRate:
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				d.rateBytes = n
				d.setParams = true
			}
		case paramBrutalGain:
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				d.cwndGain = clampPeerGain(uint32(n))
			}
		case paramBrutalGroup:
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				d.groupID = n
			}
		case paramBrutalNonce:
			d.nonce = v
		}
	}
	return d, d.nonce
}

// formatBrutalKV renders a key set in a fixed order so the header value is
// deterministic and diffable in logs and tests.
func formatBrutalKV(kv map[string]string) string {
	order := []string{paramBrutalRate, paramBrutalGain, paramBrutalGroup, paramBrutalNonce}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		if v, ok := kv[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, ",")
}

// resolveBrutalGroupID picks the group id for one request: the operator's static
// override wins, otherwise it is derived from the presented token and the client
// seed. A missing token or seed yields 0, i.e. no grouping — an honest no-op
// rather than a guess.
func resolveBrutalGroupID(p brutalPolicy, token, seed string) uint64 {
	if p.groupID != 0 {
		return p.groupID
	}
	if token == "" || seed == "" {
		return 0
	}
	return deriveBrutalGroupID(token, seed)
}

// deriveBrutalGroupID is the derivation described at the top of this file. It is
// pure so it can be unit-tested and shared by both sides.
func deriveBrutalGroupID(token, seed string) uint64 {
	mac := hmac.New(sha256.New, []byte(token))
	io.WriteString(mac, seed)
	sum := mac.Sum(nil)
	return binary.LittleEndian.Uint64(sum[:8]) | 1
}

// brutalGroupSeed is the per-client value mixed into the group-id derivation:
// X-Client-Group when the client sends it, else the resume session id.
func brutalGroupSeed(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get(brutalHeaderClientGrp)); v != "" {
		return v
	}
	return strings.TrimSpace(r.Header.Get("X-Session-ID"))
}

// brutalTokenFromHeaders reads the presented token, mirroring the sources
// NewTokenAuthenticator accepts: X-Auth-Token, then "Authorization: Bearer ".
func brutalTokenFromHeaders(h http.Header) string {
	if v := strings.TrimSpace(h.Get("X-Auth-Token")); v != "" {
		return v
	}
	auth := strings.TrimSpace(h.Get("Authorization"))
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return strings.TrimSpace(auth[len(prefix):])
	}
	return ""
}

func newBrutalNonce() string {
	b := make([]byte, brutalNonceBytes)
	if _, err := rand.Read(b); err != nil {
		// rand.Read fails only on a broken entropy source. Fall back to a time
		// based nonce so the exchange still completes; it just loses entropy.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func sameBrutalNonce(sent, echoed string) bool {
	s, e := strings.TrimSpace(sent), strings.TrimSpace(echoed)
	if s == "" || e == "" {
		return false
	}
	return hmac.Equal([]byte(s), []byte(e))
}

// applyBrutalToConn is dispatched by setBrutal, which is defined per platform
// (brutal_linux.go does the setsockopt pair; everywhere else returns
// ErrBrutalUnavailable).
func applyBrutalToConn(conn net.Conn, d brutalDecision) error {
	return setBrutal(conn, d)
}

// applyBrutalBestEffort is the call shape used at every dial and accept site:
// Brutal is an optimization, so a failure never fails the connection. Platform
// unavailability (non-Linux) is already announced at startup and is not repeated
// per connection.
func applyBrutalBestEffort(conn net.Conn, d brutalDecision, lg *slog.Logger) {
	if err := applyBrutalToConn(conn, d); err != nil {
		if !errors.Is(err, ErrBrutalUnavailable) {
			warnBrutalDegraded(lg, err.Error())
		}
	}
}

// applyBrutalOnce applies a decision to the server's accepted socket at most once
// per connection. A resume session runs many requests over one TCP leg, and the
// decision does not change between them, so configuring the socket per request
// would be pure syscall cost. The first request to see the conn wins.
func applyBrutalOnce(done *brutalSockets, conn net.Conn, d brutalDecision, lg *slog.Logger) {
	if conn == nil || !done.mark(conn) {
		return
	}
	applyBrutalBestEffort(conn, d, lg)
}

// brutalSockets remembers which accepted connections already had their socket
// configured. Connections are tracked for the lifetime of the Server that owns
// the set, which is one extra interface-sized entry per live TCP leg — bounded
// by the session table anyway.
type brutalSockets struct {
	applied sync.Map // net.Conn -> struct{}
}

func (b *brutalSockets) mark(c net.Conn) bool {
	if b == nil {
		return false
	}
	_, dup := b.applied.LoadOrStore(c, struct{}{})
	return !dup
}

func (b *brutalSockets) forget(c net.Conn) {
	if b == nil {
		return
	}
	b.applied.Delete(c)
}

// brutalConnKey carries the accepted socket into the request context so the
// handler can configure it.
type brutalConnKey struct{}

// brutalConnFromRequest returns the accepted socket attached by the server's
// ConnContext. It is nil when Brutal is disabled, when the request did not come
// in over the tracked HTTP listener, or when a handler rebuilt the request
// without copying its context.
func brutalConnFromRequest(r *http.Request) net.Conn {
	if r == nil {
		return nil
	}
	c, _ := r.Context().Value(brutalConnKey{}).(net.Conn)
	return c
}

// warnBrutalDegraded reports a degraded Brutal outcome at most once per process,
// so a busy server does not turn every connection into a log line.
var warnBrutalDegradedOnce sync.Once

func warnBrutalDegraded(l *slog.Logger, reason string) {
	warnBrutalDegradedOnce.Do(func() {
		lgWarnf(l, "[Brutal] ⚠️ TCP Brutal requested but not fully active: %s (traffic continues on the default congestion controller)", reason)
	})
}

// warnBrutalUnavailable announces once, at NewClient/NewServer time, that Brutal
// was requested but this host cannot apply it — a non-Linux build, or a Linux
// kernel whose tcp_available list has no brutal entry. Without it a busy
// deployment would find out only by reading per-connection logs.
var warnBrutalUnavailableOnce sync.Once

func warnBrutalUnavailable(lg *slog.Logger, p brutalPolicy) {
	if !p.enabled || brutalAvailable() {
		return
	}
	if lg == nil {
		lg = discardLogger
	}
	warnBrutalUnavailableOnce.Do(func() {
		lgWarnf(lg, "[Brutal] ⚠️ TCP Brutal requested but unavailable on this host (non-Linux build, or no 'brutal' in /proc/net/ipv4/tcp_available) — traffic uses the default congestion controller; the config stays valid so the same file still works once the kernel supports it")
	})
}
