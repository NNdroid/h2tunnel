# WT Integration with resume/2: Design Notes

> Goal: fold WebTransport (wt) from its standalone WTSessionManager session model into the resume v2
> engine, achieving the same **resume-after-disconnect data continuation** as h2/grpc/masque
> (ring buffer + seq replay + layer-A/B handshake + server-side target-connection retention),
> rather than stopping at session-layer failover.

## Background and gap

The current wt data plane (`handleWTTCPClientConn` / `proxyWTStreamV2`):
- For each TCP connection, `OpenStreamSync` opens one stream; the local variable `seq` runs bare, and
  the moment the stream breaks, `closeBoth()` terminates the whole connection.
- No ring buffer / no seq replay / no layer-A+B handshake / no session-table continuation; for every
  new stream the server re-runs `net.DialTimeout` to a fresh target connection.
- Conclusion: wt only achieves "session-layer failover" (`WTSessionManager` primary/backup switching,
  guaranteeing the next hop uses a live session); it **does not recover in-flight business data**.

## Key facts (confirmed in source)

1. The resume v2 frame codec `writeFrame(w io.Writer, ...)` / `readFrame(r io.Reader, ...)`
   **does not depend on HTTP** — it works purely at the `io.Writer`/`io.Reader` layer (resumeframe.go).
2. `webtransport.Stream` is an `io.ReadWriteCloser` (it has Read/Write/Close/SetDeadline),
   so it can naturally serve as the resume data channel.
3. `Session.OpenStreamSync` can open multiple streams on the same WT session → "open a new
   stream on the same session after a stream breaks and resume" is viable.
4. `webtransport.Dialer.Dial(ctx, url, reqHdr)` sends `reqHdr` as HTTP CONNECT request
   headers, and the server's `wtServer.Upgrade(w, r)` can read them via `r.Header` → **layer-A
   negotiation headers can be passed through `wtManager.headers`**, letting the server complete
   version/capability/parameter negotiation and session recovery accordingly.

## Core changes

### Server side (server.go / session.go)

1. **Abstract `resumeSessionWriter`**: field `w http.ResponseWriter` → `w io.Writer`.
   `http.ResponseWriter` is a subset of `io.Writer`, so the existing h2/grpc/masque call
   sites `&resumeSessionWriter{w: w}` need no changes — backward compatible. `flusher` stays
   optional (WT streams write in streaming fashion on their own, so flusher is passed nil).
2. **Rework `handleWebTransportServer`**: every business stream goes through the session table based on `r.Header`:
   - Verify `X-Tunnel-Proto == resume/2` (anything but 2 → reject)
   - `prepareResumeSession` → layer-A negotiation → layer-B HANDSHAKE handshake → downlink catch-up → uplink frame loop
   - stream breaks → the session (targetConn) is kept, waiting for a new stream with the same session id to resume
   - Reuse the h2 handler's handshake and frame-loop logic (extract a shared `serveResumeDataPlane` to avoid a dual implementation)
3. **Pass `clientDownlink` through the layer-B HANDSHAKE frame payload**: a WT stream cannot carry
   per-stream HTTP headers (unlike h2's `X-Resume-Downlink` request header), so the client puts the
   uplink resume starting point (a decimal string) into the payload of the first data-plane HANDSHAKE
   frame; `doWTStreamHandshake` reads that first frame, replies with HANDSHAKE-ACK, and returns `clientDownlink`.
4. **`activeWriter` attachment timing**: `setActiveWriter` must happen only after the layer-B handshake
   completes (HANDSHAKE-ACK written out) (`serveResumeDataPlane` owns this uniformly for both h2 and wt).
   Otherwise downlinkPump might write DATA frames into the new stream before HANDSHAKE-ACK, and the
   client would read DATA as its first frame instead of HANDSHAKE-ACK, failing the handshake.

### Client side (client.go / client_resume.go)

1. `newWTManagerForTunnel`: builds a dedicated `WTSessionManager` for a single tunnel, with
   headers carrying the resume layer-A negotiation headers (`X-Tunnel-Proto`, `X-Session-ID`, `X-Resume-Version/Caps/Params`,
   `X-Target`/`X-Network`, `X-Auth`) + `Protocol: webtransport`.
2. `executeResumeWT` / `runResumeWTTry` / `resumeRecvLoopWT`: each attempt calls
   `OpenStreamSync` to get a stream as the data channel (a stream is an `io.ReadWriteCloser`); after a
   break, reopen a new stream under the same session id to resume. The `resumeSendLoop` signature is
   widened from `*io.PipeWriter` to `io.Writer` so a WT stream can serve directly as the uplink write target.

## Verification

- The existing h2/grpc/masque/masque-udp transport matrix regression stays fully green (the abstraction change does not affect it)
- `TestWTResumeReconnect`: stream1 closes after reading the first 25×200B; stream2 resumes
  5×200B from `clientDownlink=5000` under the same session id; the overall sequence is continuous, with no gap and no duplication
- build / vet / gofmt / cross-compilation (linux/amd64, linux/arm64, darwin/arm64, windows/amd64) all green
