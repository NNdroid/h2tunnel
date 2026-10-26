package h2tunnel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestResumeAttemptReportsUnrecoverableGap guards that runResumeAttemptContext
// returns the (false, errGap) its contract promises, on both paths that can
// produce one.
//
// The contract exists so the caller can abandon the lane and reconnect instead
// of handing the application a truncated stream: (false, errGap) is what it
// reports as TunnelDeathDataGap, whereas (true, nil) is a clean end and
// (false, context.Canceled) is a routine redial signal. Both masking paths
// collapsed errGap into one of those two:
//
//   - recv side: a downlink seq discontinuity triggers cancel() inside
//     runResumeAttemptContext, so the following context check reported
//     context.Canceled, indistinguishable from the cancel the caller itself
//     issues.
//   - send side: a Phase-A replay gap returns before any live byte moves, while
//     a peer that ended its stream with an END frame leaves recvErr nil; the
//     old fall-through then returned (true, nil), so "my recovery window was
//     overrun" looked like a successful stream.
//
// Each subtest fails on the pre-fix code: the first reports context.Canceled,
// the second reports true.
func TestResumeAttemptReportsUnrecoverableGap(t *testing.T) {
	// recv side: the server sends a downlink frame whose seq is ahead of the
	// client's watermark, so resumeRecvLoop returns errGap.
	t.Run("recv side", func(t *testing.T) {
		ok, err := runResumeAttemptGap(t, true, 0)
		if ok {
			t.Fatal("recv-side gap reported as a normal end of stream")
		}
		if !errors.Is(err, errGap) {
			t.Fatalf("recv-side gap returned %v, want errGap", err)
		}
	})

	// send side: the ring has rolled past serverUplink, so the Phase-A replay
	// returns errGap before any live byte. The server answers with an END frame
	// rather than tearing the connection, so recvErr comes back nil -- which is
	// exactly the branch that used to hand a replay gap out as a successful
	// stream. A bare close would return io.EOF, a read error, and the context
	// would already be canceled, so it could never reach that branch.
	t.Run("send side", func(t *testing.T) {
		ok, err := runResumeAttemptGap(t, false, 1000)
		if ok {
			t.Fatal("send-side replay gap reported as a normal end of stream")
		}
		if !errors.Is(err, errGap) {
			t.Fatalf("send-side replay gap returned %v, want errGap", err)
		}
	})
}

// runResumeAttemptGap drives one full resume attempt against a handler that
// completes the handshake and then either sends an out-of-order downlink frame
// (sendGap) or ends the stream cleanly. serverUplink is the offset the server
// claims; anything below the ring's window start is an unrecoverable gap.
func runResumeAttemptGap(t *testing.T, sendGap bool, serverUplinkValue uint64) (bool, error) {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// Layer-A: acknowledge immediately. The client's Do does not return until
		// these headers arrive, and only then does it write the HANDSHAKE below --
		// so they must be flushed out before the body is read, or the two sides
		// deadlock.
		rw.Header().Set("X-Resume-Ack", "ok")
		rw.WriteHeader(http.StatusOK)
		rw.(http.Flusher).Flush()

		// Layer-B: read the client's HANDSHAKE, answer it, then deliver either the
		// gap frame or nothing.
		typ, _, _, err := readFrame(r.Body, make([]byte, 64*1024))
		if err != nil || typ != resumeFrameHandshake {
			return
		}
		if err := writeFrame(rw, resumeFrameHandshakeAck, 0, nil, 0); err != nil {
			return
		}
		rw.(http.Flusher).Flush()
		if sendGap {
			// seq 500 against a watermark of 0: the first byte the client expects
			// never arrives, so the gap is unrecoverable.
			if err := writeFrame(rw, resumeFrameData, 500, []byte("gap"), 0); err != nil {
				return
			}
			return
		}
		// Otherwise close the stream the way a peer does: an END frame, not a
		// torn connection. An END frame leaves recvErr nil, which is the branch
		// that used to swallow a replay gap as a successful stream; a bare close
		// returns io.EOF, which is a read error and would have cancelled the
		// context instead.
		if err := writeFrame(rw, resumeFrameEnd, 0, nil, 0); err != nil {
			return
		}
	}))
	// HTTP/2 is what the resume data plane actually runs on, and it matters here:
	// a plain HTTP/1.1 client does not surface the response until its chunked
	// upload completes, so a streaming resume request would deadlock waiting for
	// the layer-A ack that the server only sends after reading the HANDSHAKE.
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	// The 1 KiB ring holds the last 1024 uplink bytes, so a serverUplink below
	// the offset the replay appends past is the "window rolled away" case.
	ring := newResumeClientRingBuf(1)
	ring.Append(make([]byte, 8*1024)) // rolls the window to seq 7168
	serverUplink := serverUplinkValue
	var clientDownlink uint64

	// The application conn is closed on the far end before the attempt, so a send
	// loop that reaches live mode reads EOF, writes its END frame and returns:
	// the local-EOF path. Without that a send loop parked in Read would never
	// wake, since net.Pipe honours no read deadline, and the attempt's
	// wg.Wait would hang the test.
	localConn, farEnd := net.Pipe()
	defer localConn.Close()
	_ = farEnd.Close()

	// A zero heartbeat keeps the send loop from setting a read deadline, which a
	// net.Pipe end cannot honour.
	cfg := clientConfig{
		ServerUrl:     srv.URL,
		Path:          "/tunnel",
		TargetAddr:    "127.0.0.1:80",
		Token:         "resume-gap-token",
		SessionWindow: 1,
	}
	const sessID = "sess-gap"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ok, err := runResumeAttemptContext(ctx, sessID, &serverUplink, &clientDownlink, localConn, ring, srv.URL+"/tunnel", cfg, srv.Client(), nil, nil)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("attempt did not terminate (ok=%v err=%v)", ok, err)
	}
	return ok, err
}
