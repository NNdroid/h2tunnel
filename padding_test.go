package h2tunnel

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

var testPadding = paddingPolicy{min: 600, max: 1200}

func TestCompilePaddingPolicy(t *testing.T) {
	tests := []struct {
		name    string
		tuning  PaddingTuning
		want    paddingPolicy
		wantErr bool
	}{
		{name: "disabled"},
		{name: "derived max", tuning: PaddingTuning{MinRecordBytes: 600}, want: paddingPolicy{min: 600, max: 750}},
		{name: "explicit range", tuning: PaddingTuning{MinRecordBytes: 600, MaxRecordBytes: 1200}, want: testPadding},
		{name: "max without min", tuning: PaddingTuning{MaxRecordBytes: 1200}, wantErr: true},
		{name: "negative min", tuning: PaddingTuning{MinRecordBytes: -1}, wantErr: true},
		{name: "header too small", tuning: PaddingTuning{MinRecordBytes: resumeHeaderLen}, wantErr: true},
		{name: "range too narrow", tuning: PaddingTuning{MinRecordBytes: 600, MaxRecordBytes: 607}, wantErr: true},
		{name: "min leaves no jitter room", tuning: PaddingTuning{MinRecordBytes: 65528}, wantErr: true},
		{name: "max too large", tuning: PaddingTuning{MinRecordBytes: 600, MaxRecordBytes: 65536}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := compilePaddingPolicy(tc.tuning)
			if (err != nil) != tc.wantErr {
				t.Fatalf("compilePaddingPolicy() error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("compilePaddingPolicy() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestResumeDataFramesRangeAndRoundTrip(t *testing.T) {
	payload := make([]byte, 8192)
	for i := range payload {
		payload[i] = byte(i)
	}
	var wire bytes.Buffer
	n, err := writeResumeDataFrames(&wire, 42, payload, testPadding)
	if err != nil || n != len(payload) {
		t.Fatalf("writeResumeDataFrames() = %d, %v", n, err)
	}

	var got bytes.Buffer
	seq := uint64(42)
	records := 0
	decodeBuf := make([]byte, 64*1024)
	for wire.Len() > 0 {
		before := wire.Len()
		typ, frameSeq, frameLen, readErr := readFrame(&wire, decodeBuf)
		if readErr != nil {
			t.Fatal(readErr)
		}
		recordLen := before - wire.Len()
		if recordLen < testPadding.min || recordLen > testPadding.max {
			t.Fatalf("record %d has size %d outside [%d,%d]", records, recordLen, testPadding.min, testPadding.max)
		}
		if typ != resumeFrameData || frameSeq != seq {
			t.Fatalf("record %d typ=%d seq=%d, want DATA seq=%d", records, typ, frameSeq, seq)
		}
		got.Write(decodeBuf[:frameLen])
		seq += uint64(frameLen)
		records++
	}
	if records < 2 {
		t.Fatalf("8192-byte payload was not split: %d record", records)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatal("decoded payload differs from input")
	}
}

func TestResumeControlFramesArePadded(t *testing.T) {
	t.Run("END", func(t *testing.T) {
		var wire bytes.Buffer
		if err := writeResumeEndFrame(&wire, testPadding); err != nil {
			t.Fatal(err)
		}
		if wire.Len() < testPadding.min || wire.Len() > testPadding.max {
			t.Fatalf("END record size = %d", wire.Len())
		}
		_, _, _, err := readFrame(&wire, make([]byte, 64))
		if !errors.Is(err, errResumeEndFrame) {
			t.Fatalf("read END = %v", err)
		}
	})

	t.Run("ERROR", func(t *testing.T) {
		var wire bytes.Buffer
		if err := writeResumeErrorFrame(&wire, resumeErrTargetUnavailable, testPadding); err != nil {
			t.Fatal(err)
		}
		if wire.Len() < testPadding.min || wire.Len() > testPadding.max {
			t.Fatalf("ERROR record size = %d", wire.Len())
		}
		typ, _, n, err := readFrame(&wire, make([]byte, 64))
		if err != nil || typ != resumeFrameError || n != 1 {
			t.Fatalf("read ERROR typ=%d n=%d err=%v", typ, n, err)
		}
	})
}

func TestDatagramPaddingRangeAndRoundTrip(t *testing.T) {
	writers := []struct {
		name  string
		write func(io.Writer, []byte, paddingPolicy) error
		read  func(io.Reader, []byte) (int, error)
	}{
		{name: "packet", write: writeUDPPacket, read: readUDPPacket},
		{name: "capsule", write: writeUDPCapsule, read: readUDPCapsule},
	}
	for _, writer := range writers {
		writer := writer
		for _, size := range []int{0, 1, 62, 63, 64, 511, 1190, 1400} {
			t.Run(fmt.Sprintf("%s/size=%d", writer.name, size), func(t *testing.T) {
				payload := make([]byte, size)
				for i := range payload {
					payload[i] = byte(i)
				}
				var wire bytes.Buffer
				if err := writer.write(&wire, payload, testPadding); err != nil {
					t.Fatal(err)
				}
				if size < testPadding.min && (wire.Len() < testPadding.min || wire.Len() > testPadding.max) {
					t.Fatalf("wire size %d outside [%d,%d]", wire.Len(), testPadding.min, testPadding.max)
				}
				decoded := make([]byte, maxTunnelUDPPayload)
				n, err := writer.read(&wire, decoded)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(decoded[:n], payload) {
					t.Fatalf("decoded %d bytes differ from %d-byte payload", n, size)
				}
			})
		}
	}
}

func TestMASQUECapsuleNeverFallsBelowFloor(t *testing.T) {
	seenSizes := make(map[int]struct{})
	for i := 0; i < 2000; i++ {
		var wire bytes.Buffer
		if err := writeUDPCapsule(&wire, []byte("dns-query-small"), testPadding); err != nil {
			t.Fatal(err)
		}
		if wire.Len() < testPadding.min || wire.Len() > testPadding.max {
			t.Fatalf("iteration %d: capsule size %d outside [%d,%d]", i, wire.Len(), testPadding.min, testPadding.max)
		}
		seenSizes[wire.Len()] = struct{}{}
	}
	if len(seenSizes) < 2 {
		t.Fatalf("padding did not vary across 2000 records: %v", seenSizes)
	}
}

func TestDatagramPaddingDisabledAndOversize(t *testing.T) {
	payload := []byte("hi")
	var packet bytes.Buffer
	if err := writeUDPPacket(&packet, payload, paddingPolicy{}); err != nil {
		t.Fatal(err)
	}
	if packet.Len() != 4+len(payload) {
		t.Fatalf("disabled packet size = %d, want %d", packet.Len(), 4+len(payload))
	}

	var capsule bytes.Buffer
	if err := writeUDPCapsule(&capsule, payload, paddingPolicy{}); err != nil {
		t.Fatal(err)
	}
	if capsule.Len() != udpCapsuleDataWireLen(len(payload)) {
		t.Fatalf("disabled capsule size = %d, want %d", capsule.Len(), udpCapsuleDataWireLen(len(payload)))
	}

	tooLarge := make([]byte, maxTunnelUDPPayload+1)
	if err := writeUDPPacket(io.Discard, tooLarge, testPadding); err == nil {
		t.Fatal("writeUDPPacket accepted an oversized payload")
	}
	if err := writeUDPCapsule(io.Discard, tooLarge, testPadding); err == nil {
		t.Fatal("writeUDPCapsule accepted an oversized payload")
	}

	conn := newVirtualPacketConn("dns", func() {})
	defer conn.Close()
	if n, err := conn.Write(tooLarge); err == nil || n != 0 {
		t.Fatalf("PacketConn.Write(oversize) = %d, %v; want 0, error", n, err)
	}
}
