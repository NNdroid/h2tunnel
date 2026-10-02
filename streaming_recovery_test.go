package h2tunnel_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NNdroid/h2tunnel"
)

func TestWTAuthenticationFailureStopsAutoRedial(t *testing.T) {
	env := newProtocolEnv(t)
	credentials, _ := h2tunnel.NewTokenCredentials("wrong-token")
	for _, network := range []h2tunnel.Network{h2tunnel.NetworkTCP, h2tunnel.NetworkUDP} {
		t.Run(string(network), func(t *testing.T) {
			client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{Endpoint: env.tlsURL, Transport: h2tunnel.TransportWebTransport, TLSConfig: &tls.Config{InsecureSkipVerify: true}, Credentials: credentials, Tuning: h2tunnel.ClientTuning{AutoRedial: true}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if network == h2tunnel.NetworkTCP {
				_, err = client.DialContext(ctx, string(network), "bench-tcp")
			} else {
				_, err = client.DialPacketContext(ctx, string(network), "echo-udp")
			}
			if !errors.Is(err, h2tunnel.ErrUnauthenticated) && !errors.Is(err, h2tunnel.ErrForbidden) {
				t.Fatalf("authentication rejection: %v", err)
			}
		})
	}
}

func TestProtocolRecoveryDuringContinuousTraffic(t *testing.T) {
	padding := h2tunnel.PaddingTuning{MinRecordBytes: 600, MaxRecordBytes: 1200}
	windows := h2tunnel.QUICReceiveWindowTuning{InitialStreamBytes: 1 << 20, InitialConnectionBytes: 2 << 20, MaxStreamBytes: 16 << 20, MaxConnectionBytes: 32 << 20}
	env := newProtocolEnvWithServerTuning(t, h2tunnel.ServerTuning{Padding: padding, PauseDetachedRead: true, SessionWindowBytes: 4 << 20, QUICReceiveWindow: windows})
	for _, carrier := range []struct {
		transport h2tunnel.Transport
		alpn      string
	}{
		{h2tunnel.TransportH2, ""}, {h2tunnel.TransportH2C, ""}, {h2tunnel.TransportGRPC, ""},
		{h2tunnel.TransportH3, ""}, {h2tunnel.TransportWebTransport, ""},
		{h2tunnel.TransportMASQUE, "h2"}, {h2tunnel.TransportMASQUE, "h3"},
	} {
		transport := carrier.transport
		name := string(transport)
		if carrier.alpn != "" {
			name += "_" + carrier.alpn
		}
		t.Run(name, func(t *testing.T) {
			if carrier.alpn == "h2" && !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
				t.Skip("MASQUE H2 requires GODEBUG=http2xconnect=1")
			}
			reconnecting := make(chan struct{}, 1)
			credentials, _ := h2tunnel.NewTokenCredentials(protocolMatrixToken)
			endpoint := env.tlsURL
			tlsConfig := &tls.Config{InsecureSkipVerify: true}
			if transport == h2tunnel.TransportH2C {
				endpoint = env.h2cURL
				tlsConfig = nil
			}
			client, err := h2tunnel.NewClient(h2tunnel.ClientOptions{Endpoint: endpoint, Transport: transport, TLSConfig: tlsConfig, Credentials: credentials, EventHandler: func(ev h2tunnel.ClientEvent) {
				if ev.Kind == h2tunnel.EventReconnecting {
					select {
					case reconnecting <- struct{}{}:
					default:
					}
				}
			}, Tuning: h2tunnel.ClientTuning{Padding: padding, SessionWindowBytes: 4 << 20, AutoRedial: true, QUICReceiveWindow: windows, MasqueALPN: carrier.alpn}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "bench-tcp")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(30 * time.Second))
			want := make([]byte, 2<<20)
			for i := range want {
				want[i] = byte(i*17 + (i >> 10))
			}
			writer := make(chan error, 1)
			resume := make(chan struct{})
			var resumeOnce sync.Once
			releaseWriter := func() { resumeOnce.Do(func() { close(resume) }) }
			defer releaseWriter()
			go func() {
				for off := 0; off < len(want); off += 32 << 10 {
					if off == 128<<10 {
						<-resume
					}
					if _, err := c.Write(want[off : off+32<<10]); err != nil {
						writer <- err
						return
					}
				}
				writer <- nil
			}()
			got := make([]byte, len(want))
			if _, err := io.ReadFull(c, got[:64<<10]); err != nil {
				t.Fatal(err)
			}
			client.ForceReconnect()
			reader := make(chan error, 1)
			go func() { _, err := io.ReadFull(c, got[64<<10:]); reader <- err }()
			select {
			case <-reconnecting:
				releaseWriter()
			case <-ctx.Done():
				t.Fatal("recovery not triggered", ctx.Err())
			}
			if err := <-reader; err != nil {
				t.Fatal(err)
			}
			if err := <-writer; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("continuous payload changed across recovery")
			}
			if client.Stats().ResumeReconnects.Load() == 0 {
				t.Fatal("test did not exercise recovery")
			}
		})
	}
}

func TestPaddedContinuousTrafficThroughDelayedCDN(t *testing.T) {
	padding := h2tunnel.PaddingTuning{MinRecordBytes: 600, MaxRecordBytes: 1200}
	client, headers := newPublicAPICDNEnvironmentWithPadding(t, 2*time.Millisecond, padding)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c, err := client.DialContext(ctx, h2tunnel.NetworkTCP, "echo")
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(30 * time.Second))
			if err := checkStreamingEcho(c); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if !headers.Load() {
		t.Fatal("CDN headers lost")
	}
}

func checkStreamingEcho(c net.Conn) error {
	want := make([]byte, 512<<10)
	for i := range want {
		want[i] = byte(i*7 + (i >> 10))
	}
	done := make(chan error, 1)
	go func() { _, err := io.Copy(c, bytes.NewReader(want)); done <- err }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if err := <-done; err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
