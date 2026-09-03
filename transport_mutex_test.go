package main

import (
	"testing"
)

func TestClientTransportValidation(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "default", want: transportH2},
		{name: "h2", value: transportH2, want: transportH2},
		{name: "h2c", value: transportH2C, want: transportH2C},
		{name: "h3", value: transportH3, want: transportH3},
		{name: "wt", value: transportWT, want: transportWT},
		{name: "masque", value: transportMasque, want: transportMasque},
		{name: "grpc", value: transportGRPC, want: transportGRPC},
		{name: "server-only all", value: transportAll, wantErr: true},
		{name: "removed alias", value: "http3", wantErr: true},
		{name: "unknown", value: "websocket", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveClientTransport(&Config{Transport: tc.value})
			if (err != nil) != tc.wantErr {
				t.Fatalf("resolveClientTransport(%q) error = %v, wantErr %v", tc.value, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("resolveClientTransport(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}
