# Throughput and recovery tuning

Padding retains the same application record sizes and sequence format. The server now flushes once per input chunk rather than after every padded record. Small writes and handshake/heartbeat/END controls still flush immediately; there is no batching timer that delays interactive traffic. A lower transport may split or combine records, as before.

UDP sessions no longer allocate TCP replay rings. Both UDP queue directions use 2/4/8/16/32/64 KiB buffer classes and return buffers after consumption, cancellation, or shutdown. The queue retains at most its configured packet count; `sync.Pool` may retain unused buffers until GC, so this is not a strict process RSS limit. Nonblocking enqueue overflow logs are aggregated to at most once per second and counted by `ClientStats.DatagramDrops`. The public PacketConn's writes still block when full and honor write deadlines.

The session limits now include target dials in progress. Existing sessions can resume at capacity. Failed dials release their reservations, and a dial completing after server shutdown cannot install a new session.

Recovery uses a snapshot-bound replay and the current stream writer. An upload watermark advances only after the target accepts those bytes, including partial writes. Attempt cancellation interrupts a sender even when a heartbeat is updating its read deadline. TCP, UDP and WT retry with jitter and reset the cadence after 30 seconds of established operation. HTTP 401/403/407/426 and the authentication/policy sentinels stop even with AutoRedial; transient network errors and 5xx may retry. This intentionally changes the old behavior of retrying rejected credentials/policy indefinitely.

## Choosing recovery capacity

`SessionWindowBytes` (SDK) / `session_window_kb` (CLI) is a replay buffer, not a QUIC flow-control window. It keeps the 256 KiB default and 64 MiB cap. Under the default overwrite policy, a continuously producing target can overrun 256 KiB in about 21 ms at 100 Mbps. Budget the window from observed undelivered bytes and the expected outage; also budget per-session memory and configure global/per-principal limits.

For TCP services that tolerate target-side backpressure, enable `ServerTuning.PauseDetachedRead` / `pause_detached_read`. The server pauses target reads until a new stream attaches and replays. This propagates pressure into the target's socket buffers and eventually the producer. One target read already in flight can append a chunk after detachment; keep enough replay capacity for unacknowledged traffic plus that chunk. This is not an unlimited outage guarantee: the idle retention timeout still applies, active-stream failures must first be detected, and the upstream service may have its own write timeout. UDP retains its packet-drop/no-replay semantics. The option is off by default for compatibility.

## Choosing QUIC receive credit

`ClientTuning.QUICReceiveWindow` and `ServerTuning.QUICReceiveWindow` accept `QUICReceiveWindowTuning`. Configure the receiver of the traffic you want to improve (client for downloads, server for uploads). This applies to H3, WT, and MASQUE H3, on every rebuilt transport. H2's existing windows are unchanged.

Zero fields preserve the pinned quic-go v0.62 defaults: initial stream 512 KiB, initial connection 768 KiB, maximum stream 8 MiB, maximum connection 20 MiB. Initial windows must fit their maxima, and connection credit must cover a stream's credit. Every explicit field is capped at 256 MiB. QUIC auto-tunes up to those maxima; increasing them is useful only when actual receiver flow-control credit limits a measured workload.

A configurable example for a high-bandwidth path (not a universal preset):

```json
{
  "session_window_kb": 4096,
  "pause_detached_read": true,
  "quic_receive_window": {
    "initial_stream_bytes": 1048576,
    "initial_connection_bytes": 2097152,
    "max_stream_bytes": 16777216,
    "max_connection_bytes": 33554432
  }
}
```

`pause_detached_read` is server-only; omit it on clients. The other fields work on either receiving endpoint. Environment overrides are `H2TUNNEL_PAUSE_DETACHED_READ`, `H2TUNNEL_QUIC_INITIAL_STREAM_BYTES`, `H2TUNNEL_QUIC_INITIAL_CONNECTION_BYTES`, `H2TUNNEL_QUIC_MAX_STREAM_BYTES`, and `H2TUNNEL_QUIC_MAX_CONNECTION_BYTES`.

## Reproducing measurements

### Local before/after sample (2026-10-02)

Baseline source was exported from `9fdad70` and given the same continuous-transfer benchmark and real target helper. Both builds ran sequentially on Windows/amd64, Go 1.26.4, i9-13900K, GOMAXPROCS=32, with `GODEBUG=http2xconnect=1`, padding enabled, default receive windows, 1 second per case and three samples. The table reports median completed payload MB/s, including both directions for duplex.

| Protocol / direction | Sessions | Baseline MB/s | Changed MB/s |
| --- | ---: | ---: | ---: |
| H2 download | 1 | 51.71 | 235.10 |
| H2 download | 8 | 162.97 | 289.52 |
| H2 duplex | 1 | 74.30 | 103.13 |
| H2 duplex | 8 | 85.83 | 147.29 |
| H3 download | 1 | 123.21 | 168.25 |
| H3 download | 8 | 187.40 | 266.88 |
| H3 duplex | 1 | 159.36 | 226.76 |
| H3 duplex | 8 | 268.04 | 297.38 |

The actual PacketConn enqueue/consume benchmark changed from one allocation to zero allocations per operation in both measured sizes: 1200-byte packets went from 325.2 to 194.6 ns/op (1280 to 0 B/op), and 16384-byte packets from 2353 to 243.9 ns/op (16384 to 0 B/op). These are warm-pool results; cold pools and GC can allocate.

These samples establish local workload results, not production speed guarantees or statistical confidence. Earlier runs on the same desktop varied substantially; even this changed H3 eight-session download ranged from 261.66 to 311.22 MB/s. CPU scheduling, GC and the loopback network affect the numbers. Use longer repeated runs on the deployment host before choosing window sizes. The deterministic batching test separately proves one flush per input chunk while retaining immediate small/control writes.

`BenchmarkProtocolStreaming` runs continuous upload, download, and duplex through a real TCP target. Each operation represents a 32 KiB chunk per session; duplex reports the sum of both directions. There are 1 and 8-session cases, padding off/on, and explicit MASQUE H2/H3 carriers. Completion is acknowledged by the target so bytes merely queued locally are not reported as completed transfers. It is a closed-loop bulk benchmark, not an open-loop tail-latency or network-loss test.

```sh
GODEBUG=http2xconnect=1 go test -run '^$' -bench '^BenchmarkProtocolStreaming$' -benchmem -count=5 .
go test -run '^$' -bench '^BenchmarkPacketConnQueueWrite$' -benchmem -count=5 .
GODEBUG=http2xconnect=1 go test -run 'TestProtocolRecoveryDuringContinuousTraffic|TestPaddedContinuousTrafficThroughDelayedCDN|TestLargeUDPDatagramsAllProtocols' -count=5 .
```

On PowerShell, set `$env:GODEBUG='http2xconnect=1'` before invoking `go test`. Run baseline and changed binaries sequentially on an otherwise idle host. Profiles now include continuous H2/H3 workloads plus allocation, mutex and block reports in CI.

The traffic tests compare complete upload/download payloads, exercise multiple simultaneous sessions, verify forced recovery with data still in flight, traverse an HTTP/2-to-HTTP/1.1 CDN model with delayed forwarding, and check 48 KB UDP packets across the protocol matrix. Deterministic tests separately cover admission reservations, shutdown during dialing, snapshot-bounded replay, partial target writes, detached-read backpressure and queue ownership during close.

Actual packet loss, a public CDN, and Linux production behavior require separate runtime measurements. For QUIC, check CPU and kernel UDP receive drops as well as flow-control credit; window increases cannot fix CPU saturation or socket-buffer drops. Local race coverage depends on a working C toolchain; CI already runs race checks on Linux/macOS.

## Validation of this change

All 84 continuous-stream benchmark cases completed in a 100 ms smoke run: seven carriers, upload/download/duplex, one/eight sessions, and padding off/on. That short run verifies harness coverage; use the repeated longer measurements above for performance comparisons.

The final local `GODEBUG=http2xconnect=1 go test ./... -count=1` passed (root package 60.932 s), as did `go vet ./...`, `git diff --check`, and CGO-disabled Linux builds for amd64, 386 and ARMv6. Recovery cases passed five repeated runs earlier, and WT TCP/UDP rejected-credential tests cover AutoRedial explicitly. Linux builds establish compilation only. The local Windows race run was blocked by the C toolchain's missing `windows.h`; the updated remote CI has not been executed for this working-tree patch.

A final padded H2 single-download profile also completed with CPU, allocation, mutex and block data. Its largest CPU entry was Windows `runtime.cgocall` (37.29% flat); the largest sampled allocation entries were HTTP/2 frame writing and frame-cache handling. This profile includes client, server and target in one process. Cumulative blocked goroutine time is not a latency measurement, and these Windows samples do not establish the dominant resource on Linux.
