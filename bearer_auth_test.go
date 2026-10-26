package h2tunnel

import (
	"context"
	"net/http"
	"testing"
)

// TestBearerTokenSchemeIsCaseInsensitive pins the scheme-name rule: RFC 6750
// section 2.1 says the auth scheme token is case-insensitive, so "bearer" and
// "BEARER" must authenticate exactly as "Bearer" does. This matters because the
// authenticator and the Brutal exchange both read the presented token, and they
// previously disagreed -- the Brutal path matched case-insensitively while
// NewTokenAuthenticator used a case-sensitive TrimPrefix, so a client sending
// "bearer ..." failed authentication with the Brutal side still reading its
// token.
func TestBearerTokenSchemeIsCaseInsensitive(t *testing.T) {
	for _, tc := range []struct {
		auth string
		want string
	}{
		{auth: "Bearer tok", want: "tok"},
		{auth: "bearer tok", want: "tok"},
		{auth: "BEARER tok", want: "tok"},
		{auth: "BearEr tok", want: "tok"},
		{auth: "  Bearer   tok  ", want: "tok"},
		{auth: "", want: ""},
		{auth: "Bearer", want: ""},
		{auth: "Bearer ", want: ""},
		{auth: "bearer\ttok", want: ""},
		{auth: "BearerX tok", want: ""},
		{auth: "Basic tok", want: ""},
		{auth: "Token tok", want: ""},
	} {
		if got := bearerToken(tc.auth); got != tc.want {
			t.Errorf("bearerToken(%q) = %q, want %q", tc.auth, got, tc.want)
		}
	}
}

// TestTokenAuthenticatorAcceptsCaseVariedScheme is the end-to-end half of the
// same rule: the authenticator must accept a case-varied scheme name and still
// refuse a different scheme.
func TestTokenAuthenticatorAcceptsCaseVariedScheme(t *testing.T) {
	auth, err := NewTokenAuthenticator("secret-token")
	if err != nil {
		t.Fatalf("NewTokenAuthenticator: %v", err)
	}
	for _, tc := range []struct {
		name   string
		header string
		wantOK bool
	}{
		{name: "canonical", header: "Bearer secret-token", wantOK: true},
		{name: "lowercase scheme", header: "bearer secret-token", wantOK: true},
		{name: "uppercase scheme", header: "BEARER secret-token", wantOK: true},
		{name: "wrong scheme", header: "Basic secret-token", wantOK: false},
		{name: "wrong token", header: "Bearer other-token", wantOK: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Header: http.Header{"Authorization": []string{tc.header}}}
			p, aerr := auth(context.Background(), req)
			got := aerr == nil
			if got != tc.wantOK {
				t.Fatalf("auth = %v (%v), want accepted=%v", p, aerr, tc.wantOK)
			}
		})
	}
}
