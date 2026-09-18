package h2tunnel

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompileBrutalPolicy(t *testing.T) {
	cases := []struct {
		name string
		gain uint32
		want uint32
		err  bool
	}{
		{name: "zero selects the 1.5x default", gain: 0, want: brutalDefaultCwndGain},
		{name: "one tenth is accepted", gain: 1, want: 1},
		{name: "upper bound is inclusive", gain: brutalMaxCwndGain, want: brutalMaxCwndGain},
		{name: "above the bound is rejected", gain: brutalMaxCwndGain + 1, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := compileBrutalPolicy(BrutalTuning{Enabled: true, CwndGain: tc.gain, RateBytes: 42, GroupID: 7, Negotiate: true})
			if tc.err {
				if err == nil {
					t.Fatalf("compileBrutalPolicy(gain=%d) = %v, want an error", tc.gain, p)
				}
				return
			}
			if err != nil {
				t.Fatalf("compileBrutalPolicy: %v", err)
			}
			if p.cwndGain != tc.want {
				t.Fatalf("cwndGain = %d, want %d", p.cwndGain, tc.want)
			}
			if !p.enabled || p.rateBytes != 42 || p.groupID != 7 || !p.negotiate {
				t.Fatalf("policy not copied: %+v", p)
			}
		})
	}

	// A zero-value tuning is always valid: the feature is opt-in, and a
	// disabled feature must never fail a client.
	if _, err := compileBrutalPolicy(BrutalTuning{}); err != nil {
		t.Fatalf("zero-value BrutalTuning must compile: %v", err)
	}
}

func TestApplyOfferTakesTheMinimum(t *testing.T) {
	base := func(rate uint64, gain uint32) brutalPolicy {
		return brutalPolicy{enabled: true, rateBytes: rate, cwndGain: gain, negotiate: true}
	}

	// 0 from the peer means "no local preference" and leaves the local value alone.
	if got := applyOffer(base(100, 20), 0, 0); got.rateBytes != 100 || got.cwndGain != 20 {
		t.Fatalf("peer offered nothing, policy changed: %+v", got)
	}
	if got := applyOffer(base(100, 20), 100, 20); got.rateBytes != 100 || got.cwndGain != 20 {
		t.Fatalf("equal values changed the policy: %+v", got)
	}
	if got := applyOffer(base(100, 20), 40, 25); got.rateBytes != 40 || got.cwndGain != 20 {
		t.Fatalf("lower rate / higher gain: got %+v, want rate 40 gain 20", got)
	}
	if got := applyOffer(base(100, 20), 400, 5); got.rateBytes != 100 || got.cwndGain != 5 {
		t.Fatalf("higher rate / lower gain: got %+v, want rate 100 gain 5", got)
	}

	// A local rate of 0 adopts whatever the peer declares.
	if got := applyOffer(base(0, 20), 40, 20); got.rateBytes != 40 {
		t.Fatalf("local rate 0 did not adopt the peer's: %+v", got)
	}
	// But a peer rate of 0 with a local rate of 0 leaves both at 0 — nothing is
	// invented, and decideBrutal turns that into "switch the algorithm only".
	if got := applyOffer(base(0, 20), 0, 20); got.rateBytes != 0 {
		t.Fatalf("both silent must stay at rate 0: %+v", got)
	}
}

func TestDecideBrutalOnlyPushesParamsWhenARateExists(t *testing.T) {
	d := decideBrutal(brutalPolicy{rateBytes: 123, cwndGain: 15, groupID: 9})
	if !d.setParams || d.rateBytes != 123 || d.cwndGain != 15 || d.groupID != 9 {
		t.Fatalf("decision = %+v", d)
	}

	d = decideBrutal(brutalPolicy{rateBytes: 0, cwndGain: 15, groupID: 9})
	if d.setParams {
		t.Fatalf("a zero rate must not be pushed to the kernel: %+v", d)
	}
	if d.groupID != 9 || d.cwndGain != 15 {
		t.Fatalf("the algorithm switch still carries gain and group: %+v", d)
	}
}

func TestDeriveBrutalGroupID(t *testing.T) {
	const token = "shared-token"
	// The token is shared by every client, so the seed is what separates them;
	// bit 0 is forced so a collision with the reserved 0 is structurally
	// impossible, not merely unlikely.
	for _, seed := range []string{"seed-a", "seed-b", "session-01", "client-group-ffffffff"} {
		if id := deriveBrutalGroupID(token, seed); id == 0 || id&1 == 0 {
			t.Fatalf("group id %d from seed %q is 0 or lost the forced bit", id, seed)
		}
	}
	if a := deriveBrutalGroupID(token, "seed-a"); a != deriveBrutalGroupID(token, "seed-a") {
		t.Fatal("the derivation is not deterministic")
	}
	if a, b := deriveBrutalGroupID(token, "seed-a"), deriveBrutalGroupID(token, "seed-b"); a == b {
		t.Fatalf("two clients of one shared token must not share a group id (both %d)", a)
	}
	if a, b := deriveBrutalGroupID("token-1", "seed-a"), deriveBrutalGroupID("token-2", "seed-a"); a == b {
		t.Fatal("the token must take part in the derivation")
	}
}

func TestResolveBrutalGroupID(t *testing.T) {
	if id := resolveBrutalGroupID(brutalPolicy{groupID: 77}, "", ""); id != 77 {
		t.Fatalf("the operator's static override must win, got %d", id)
	}
	if id := resolveBrutalGroupID(brutalPolicy{}, "token", "seed"); id == 0 {
		t.Fatal("token+seed must produce a group id")
	}
	if id := resolveBrutalGroupID(brutalPolicy{}, "", "seed"); id != 0 {
		t.Fatalf("a missing token must yield no group, got %d", id)
	}
	if id := resolveBrutalGroupID(brutalPolicy{}, "token", ""); id != 0 {
		t.Fatalf("a missing seed must yield no group, got %d", id)
	}
}

func TestBrutalOfferNeedsEnabledAndNegotiate(t *testing.T) {
	p := brutalPolicy{enabled: true, rateBytes: 1000, cwndGain: 15, negotiate: true}
	offer := brutalOffer(p)
	_, _, nonce := parseBrutalOffer(offer)
	if nonce == "" {
		t.Fatalf("the offer must carry a nonce for the echo check: %q", offer)
	}
	_, _, fresh := parseBrutalOffer(brutalOffer(p))
	if fresh == nonce {
		t.Fatal("two offers must not share a nonce")
	}

	if offer := brutalOffer(brutalPolicy{enabled: false, rateBytes: 1, negotiate: true}); offer != "" {
		t.Fatalf("a disabled policy must stay silent: %q", offer)
	}
	if offer := brutalOffer(brutalPolicy{enabled: true, rateBytes: 1, negotiate: false}); offer != "" {
		t.Fatalf("negotiate=false must stay silent: %q", offer)
	}
}

func TestSetBrutalOfferHeaders(t *testing.T) {
	p := brutalPolicy{enabled: true, rateBytes: 1000, cwndGain: 15, negotiate: true}

	h := make(http.Header)
	setBrutalOfferHeaders(h, p, "group-seed-1")
	if h.Get(brutalHeaderOffer) == "" || h.Get(brutalHeaderClientGrp) != "group-seed-1" {
		t.Fatalf("offer + seed headers missing: %v", h)
	}

	// An empty seed must not ship an empty header: the server falls back to the
	// session id, and a blank value would look deliberate.
	h = make(http.Header)
	setBrutalOfferHeaders(h, p, "")
	if h.Get(brutalHeaderClientGrp) != "" {
		t.Fatalf("an empty seed must not be sent: %v", h)
	}
	if h.Get(brutalHeaderOffer) == "" {
		t.Fatal("the offer itself must still be sent")
	}

	h = make(http.Header)
	setBrutalOfferHeaders(h, brutalPolicy{enabled: false}, "group-seed-1")
	if len(h) != 0 {
		t.Fatalf("a disabled policy must write no headers: %v", h)
	}
}

func TestParseBrutalOfferToleratesMalformedInput(t *testing.T) {
	rate, gain, nonce := parseBrutalOffer("rate=250,gain=12,nonce=abc")
	if rate != 250 || gain != 12 || nonce != "abc" {
		t.Fatalf("parsed (%d,%d,%q)", rate, gain, nonce)
	}

	// Spaces, missing keys, and junk all degrade to zero instead of erroring:
	// a header must never take the tunnel down.
	rate, gain, nonce = parseBrutalOffer("  rate = 77 , gain=bad, junk, =5 ,nonce=x ")
	if rate != 77 || gain != 0 || nonce != "x" {
		t.Fatalf("tolerant parse gave (%d,%d,%q)", rate, gain, nonce)
	}
	if rate, gain, nonce = parseBrutalOffer(""); rate != 0 || gain != 0 || nonce != "" {
		t.Fatalf("empty offer must read as zero: (%d,%d,%q)", rate, gain, nonce)
	}
	if rate, _, _ = parseBrutalOffer("rate=-1"); rate != 0 {
		t.Fatalf("a negative rate must read as zero, got %d", rate)
	}
}

func TestFormatAndParseBrutalReplyRoundTrip(t *testing.T) {
	d := brutalDecision{rateBytes: 555, cwndGain: 18, groupID: 0x0102, setParams: true}
	if got := formatBrutalReply(d, "nonce-1"); got != "rate=555,gain=18,group_id=258,nonce=nonce-1" {
		t.Fatalf("rendered reply is not in the fixed order: %q", got)
	}

	back, echoed := parseBrutalReply(formatBrutalReply(d, "nonce-1"))
	if echoed != "nonce-1" || back.rateBytes != 555 || back.cwndGain != 18 || back.groupID != 0x0102 || !back.setParams {
		t.Fatalf("round trip mismatch: %+v echoed=%q", back, echoed)
	}

	// An ungrouped decision omits group_id, so an absent value cannot be
	// confused with a real 0.
	if got := formatBrutalReply(brutalDecision{rateBytes: 1, cwndGain: 15}, ""); got != "rate=1,gain=15" {
		t.Fatalf("ungrouped reply: %q", got)
	}
	if d, _ := parseBrutalReply("rate=1,gain=15"); d.groupID != 0 || !d.setParams {
		t.Fatalf("absent group_id must read as 0: %+v", d)
	}
}

func TestSameBrutalNonce(t *testing.T) {
	if !sameBrutalNonce("abc", "abc") || !sameBrutalNonce("  abc  ", "abc") {
		t.Fatal("an echoed nonce must match")
	}
	if sameBrutalNonce("abc", "abd") || sameBrutalNonce("abc", "abcd") {
		t.Fatal("a different nonce must not match")
	}
	if sameBrutalNonce("", "abc") || sameBrutalNonce("abc", "") || sameBrutalNonce("", "") {
		t.Fatal("an empty nonce must never match")
	}
}

func TestNewBrutalNonceHasEntropy(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		n := newBrutalNonce()
		if len(n) != brutalNonceBytes*2 {
			t.Fatalf("nonce %q is %d chars, want %d (hex-encoded 16 bytes)", n, len(n), brutalNonceBytes*2)
		}
		if seen[n] {
			t.Fatalf("nonce repeated: %s", n)
		}
		seen[n] = true
	}
}

func TestBrutalGroupSeedPrefersTheClientGroup(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/tunnel", nil)
	req.Header.Set(brutalHeaderClientGrp, "  client-group-1 ")
	req.Header.Set("X-Session-ID", "session-1")
	if seed := brutalGroupSeed(req); seed != "client-group-1" {
		t.Fatalf("seed = %q, want the client group (trimmed)", seed)
	}

	// Old clients do not send X-Client-Group; the session id keeps the exchange
	// working, at per-session granularity instead of per-client.
	req = httptest.NewRequest(http.MethodPost, "/tunnel", nil)
	req.Header.Set("X-Session-ID", "session-1")
	if seed := brutalGroupSeed(req); seed != "session-1" {
		t.Fatalf("fallback seed = %q, want the session id", seed)
	}

	req = httptest.NewRequest(http.MethodPost, "/tunnel", nil)
	if seed := brutalGroupSeed(req); seed != "" {
		t.Fatalf("no group and no session id must yield an empty seed, got %q", seed)
	}
}

func TestBrutalTokenFromHeaders(t *testing.T) {
	h := make(http.Header)
	h.Set("X-Auth-Token", "  token-a  ")
	if got := brutalTokenFromHeaders(h); got != "token-a" {
		t.Fatalf("X-Auth-Token = %q", got)
	}

	h = make(http.Header)
	h.Set("Authorization", "Bearer token-b")
	if got := brutalTokenFromHeaders(h); got != "token-b" {
		t.Fatalf("Bearer = %q", got)
	}
	h.Set("Authorization", "bearer token-c")
	if got := brutalTokenFromHeaders(h); got != "token-c" {
		t.Fatalf("the Bearer scheme must match case-insensitively: %q", got)
	}

	h = make(http.Header)
	h.Set("X-Auth-Token", "token-a")
	h.Set("Authorization", "Bearer token-b")
	if got := brutalTokenFromHeaders(h); got != "token-a" {
		t.Fatalf("X-Auth-Token must win, got %q", got)
	}

	h = make(http.Header)
	h.Set("Authorization", "Basic dXNlcjpwYXNz")
	if got := brutalTokenFromHeaders(h); got != "" {
		t.Fatalf("a non-Bearer scheme must not be read as a token: %q", got)
	}
	if got := brutalTokenFromHeaders(make(http.Header)); got != "" {
		t.Fatalf("no credentials must yield an empty token, got %q", got)
	}
}

func TestHandleBrutalReplyChecksTheNonceEcho(t *testing.T) {
	lg := slog.New(slog.DiscardHandler)
	mkReq := func(nonce string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/tunnel", nil)
		req.Header.Set(brutalHeaderOffer, "rate=100,gain=15,nonce="+nonce)
		return req
	}
	reply := func(nonce string) string {
		return formatBrutalReply(brutalDecision{rateBytes: 80, cwndGain: 12, groupID: 3, setParams: true}, nonce)
	}

	peer := &brutalPeerCache{}
	handleBrutalReply(mkReq("sent-1"), reply("sent-1"), peer, lg)
	d, ok := peer.get()
	if !ok || d.rateBytes != 80 || d.cwndGain != 12 || d.groupID != 3 {
		t.Fatalf("a matching nonce must record the decision: ok=%v %+v", ok, d)
	}

	// A reply that answers a different exchange is discarded, and must not
	// overwrite a decision already recorded.
	handleBrutalReply(mkReq("sent-2"), reply("sent-3"), peer, lg)
	if d, _ = peer.get(); d.rateBytes != 80 || d.cwndGain != 12 {
		t.Fatalf("a nonce mismatch changed the cached decision: %+v", d)
	}

	// No offer on the request means the client never started an exchange, so
	// nothing is trusted.
	peer = &brutalPeerCache{}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", nil)
	handleBrutalReply(req, reply("whatever"), peer, lg)
	if _, ok := peer.get(); ok {
		t.Fatal("a reply without a matching offer must be ignored")
	}

	// An empty reply and a nil cache are both harmless.
	peer = &brutalPeerCache{}
	handleBrutalReply(mkReq("sent-1"), "", peer, lg)
	if _, ok := peer.get(); ok {
		t.Fatal("an empty reply must not record anything")
	}
	handleBrutalReply(mkReq("sent-1"), reply("sent-1"), nil, lg)
}

func TestBrutalPeerCache(t *testing.T) {
	var peer *brutalPeerCache
	if _, ok := peer.get(); ok {
		t.Fatal("a nil cache must report not-seen")
	}
	peer.set(brutalDecision{rateBytes: 1}) // must not panic
	if _, ok := peer.get(); ok {
		t.Fatal("writing through a nil cache must be a no-op")
	}

	cache := &brutalPeerCache{}
	if _, ok := cache.get(); ok {
		t.Fatal("a fresh cache must report not-seen")
	}
	want := brutalDecision{rateBytes: 5, cwndGain: 11, groupID: 2}
	cache.set(want)
	got, ok := cache.get()
	if !ok || got != want {
		t.Fatalf("cache round trip: ok=%v %+v", ok, got)
	}
}

func TestBrutalReplyNegotiatesAndEchoes(t *testing.T) {
	policy := brutalPolicy{
		enabled:   true,
		rateBytes: 200000000,
		cwndGain:  20,
		negotiate: true,
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", nil)
	req.RemoteAddr = "203.0.113.5:40000"
	req.Header.Set("X-Auth-Token", "shared-token")
	req.Header.Set(brutalHeaderClientGrp, "client-group-1")
	req.Header.Set(brutalHeaderOffer, "rate=100000000,gain=15,nonce=echo-me")

	reply := brutalReply(policy, req)
	if reply == "" {
		t.Fatal("the server must answer an offer")
	}
	d, echoed := parseBrutalReply(reply)
	if echoed != "echo-me" {
		t.Fatalf("the nonce was not echoed back: %q", reply)
	}
	if d.rateBytes != 100000000 || d.cwndGain != 15 {
		t.Fatalf("the reply is not min(server, client): rate=%d gain=%d", d.rateBytes, d.cwndGain)
	}
	want := deriveBrutalGroupID("shared-token", "client-group-1")
	if d.groupID != want {
		t.Fatalf("group_id = %d, want the client's own derivation %d", d.groupID, want)
	}
	if d.groupID == 0 {
		t.Fatal("the reply carries no group")
	}
}

func TestBrutalGroupSeedIsStableAcrossConnectionMigration(t *testing.T) {
	policy := brutalPolicy{enabled: true, rateBytes: 100, cwndGain: 15, negotiate: true}
	groupOf := func(remoteAddr, seed string) uint64 {
		req := httptest.NewRequest(http.MethodPost, "/tunnel", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Auth-Token", "shared-token")
		req.Header.Set(brutalHeaderClientGrp, seed)
		req.Header.Set(brutalHeaderOffer, "rate=0,gain=0,nonce=n")
		d, _ := parseBrutalReply(brutalReply(policy, req))
		return d.groupID
	}

	// The egress IP changes when a client's line migrates; the group id must
	// not follow it, or the client would get a fresh bucket on every migration.
	first := groupOf("203.0.113.5:40000", "client-group-1")
	second := groupOf("198.51.100.9:51000", "client-group-1")
	if first == 0 || first != second {
		t.Fatalf("group id changed across migration: %d -> %d", first, second)
	}
	if third := groupOf("203.0.113.5:40000", "client-group-2"); third == first {
		t.Fatalf("a different client must not share a group: %d", third)
	}
}

func TestBrutalReplyStaysSilentWithoutAnOffer(t *testing.T) {
	mk := func(p brutalPolicy, offer string) string {
		req := httptest.NewRequest(http.MethodPost, "/tunnel", nil)
		if offer != "" {
			req.Header.Set(brutalHeaderOffer, offer)
		}
		req.Header.Set("X-Auth-Token", "token")
		req.Header.Set(brutalHeaderClientGrp, "seed")
		return brutalReply(p, req)
	}

	p := brutalPolicy{enabled: true, rateBytes: 100, cwndGain: 15, negotiate: true}
	if got := mk(p, ""); got != "" {
		t.Fatalf("no offer must produce no reply: %q", got)
	}
	if got := mk(brutalPolicy{enabled: false, negotiate: true}, "rate=1,gain=1,nonce=n"); got != "" {
		t.Fatalf("a disabled server must not reply: %q", got)
	}
	if got := mk(brutalPolicy{enabled: true, negotiate: false}, "rate=1,gain=1,nonce=n"); got != "" {
		t.Fatalf("negotiate=false must not reply: %q", got)
	}
	if got := mk(p, "  "); got != "" {
		t.Fatalf("a blank offer must produce no reply: %q", got)
	}
}

func TestFormatBrutalKVIsDeterministic(t *testing.T) {
	kv := map[string]string{
		paramBrutalNonce: "n",
		paramBrutalRate:  "1",
		paramBrutalGain:  "2",
		paramBrutalGroup: "3",
	}
	if got := formatBrutalKV(kv); got != "rate=1,gain=2,group_id=3,nonce=n" {
		t.Fatalf("kv = %q", got)
	}
	if got := formatBrutalKV(map[string]string{paramBrutalRate: "1"}); got != "rate=1" {
		t.Fatalf("single key: %q", got)
	}
	if got := formatBrutalKV(nil); got != "" {
		t.Fatalf("empty kv: %q", got)
	}
	if got := formatBrutalKV(map[string]string{"unknown": "1"}); got != "" {
		t.Fatalf("an unknown key must be dropped: %q", got)
	}
}
