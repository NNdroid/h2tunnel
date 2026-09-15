package h2tunnel_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

// TestPaddingAllProtocolsTCPAndUDP proves that record shaping is wired through
// every carrier in both directions without changing target-visible TCP bytes or
// UDP datagram boundaries. Exact record-size bounds are asserted by the codec
// tests; transport stacks may split or coalesce records below this layer.
func TestPaddingAllProtocolsTCPAndUDP(t *testing.T) {
	padding := h2tunnel.PaddingTuning{MinRecordBytes: 600, MaxRecordBytes: 1200}
	env := newProtocolEnvWithPadding(t, padding)
	transports := []h2tunnel.Transport{
		h2tunnel.TransportH2,
		h2tunnel.TransportH2C,
		h2tunnel.TransportGRPC,
		h2tunnel.TransportH3,
		h2tunnel.TransportWebTransport,
		h2tunnel.TransportMASQUE,
	}

	for _, transport := range transports {
		transport := transport
		t.Run(string(transport)+"/TCP", func(t *testing.T) {
			client := newProtocolClientWithPadding(t, env, transport, padding)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "bench-tcp")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			payload := make([]byte, 8192)
			for i := range payload {
				payload[i] = byte(i)
			}
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("TCP target-visible payload changed by padding")
			}
		})

		t.Run(string(transport)+"/UDP", func(t *testing.T) {
			client := newProtocolClientWithPadding(t, env, transport, padding)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, err := client.DialPacketContext(ctx, h2tunnel.NetworkUDP, "bench-udp")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			payload := []byte(fmt.Sprintf("padding-%s-udp", transport))
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 2048)
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := conn.Read(got)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got[:n], payload) {
				t.Fatalf("UDP datagram changed by padding: got %q want %q", got[:n], payload)
			}
		})
	}
}

func TestPaddingPublicAPIValidation(t *testing.T) {
	credentials, err := h2tunnel.NewTokenCredentials("token")
	if err != nil {
		t.Fatal(err)
	}
	_, err = h2tunnel.NewClient(h2tunnel.ClientOptions{
		Endpoint:    "https://example.test",
		Transport:   h2tunnel.TransportH2,
		Credentials: credentials,
		Tuning: h2tunnel.ClientTuning{Padding: h2tunnel.PaddingTuning{
			MinRecordBytes: 600,
			MaxRecordBytes: 607,
		}},
	})
	if err == nil {
		t.Fatal("NewClient accepted a padding range with no useful jitter")
	}
}
