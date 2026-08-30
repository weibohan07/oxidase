# Transport and Cluster soak campaigns

`oxidase-soak` is a bounded, reproducible validation tool for the v0.3 data
plane. It is a workspace member so that ordinary Clippy and test gates compile
it, but it is not a default member or a production binary. Its fixtures use
ephemeral `127.0.0.1:0` listeners, generated test-only certificates, and no
external server, Docker daemon, Internet connection, or fixed port.

The tool is evidence for a specific command, build, host, and duration. A clean
short run is not a claim of long-term stability.

## Modes

`combined` exercises:

- TLS 1.2/1.3 ingress with both HTTP/1.1 and HTTP/2 ALPN;
- weighted resilient-cluster selection, active health transitions, passive
  state, status retry, and bounded admission;
- periodic Service snapshot reload and test-only certificate rotation;
- completed streaming bodies and deliberate downstream cancellation; and
- the management metrics used to report retries, health transitions, and body
  termination.

`protocol` exercises:

- a reusable downstream HTTP/2 connection carrying transparent gRPC DATA and
  `grpc-status` trailers;
- TLS HTTP/1.1 WebSocket-style Upgrade tunnels with repeated bidirectional byte
  exchange;
- deliberate gRPC stream cancellation; and
- periodic snapshot reload and certificate rotation while existing H2
  connections and tunnels remain active.

The protocol workload reuses an H2 connection per worker, reconnecting after a
bounded number of requests. Each Upgrade tunnel carries multiple exchanges and
is deliberately paced. This makes the measured workload exercise multiplexing
and long-lived tunnels instead of exhausting the client's ephemeral ports with
artificial connection churn.

## Invocation

Build the exact locked workspace sources before a campaign:

```bash
cargo build -p oxidase-soak --release --locked
```

Run a combined campaign:

```bash
target/release/oxidase-soak \
  --mode combined \
  --duration 5m \
  --concurrency 8 \
  --reload-interval 5s \
  --payload-size 32768 \
  --seed 219765221
```

Run a protocol-focused campaign:

```bash
target/release/oxidase-soak \
  --mode protocol \
  --duration 2m \
  --concurrency 6 \
  --reload-interval 5s \
  --payload-size 16384 \
  --seed 3237998081
```

`duration` and `reload-interval` accept explicit `ms`, `s`, or `m` units.
`concurrency` and `payload-size` must be greater than zero. The seed controls
the deterministic protocol/cancellation choice made by each worker.

## Output contract

Successful runs write one JSON object to stdout with schema
`oxidase.soak/v1`. It contains the exact input parameters, actual elapsed time,
request/success/error counts, retries, health transitions, body cancellations,
bytes, reload and certificate-rotation counts, and per-protocol counts. A fatal
control-plane failure writes a JSON error envelope to stderr and exits non-zero.
The first few per-request errors may also be printed to stderr to preserve a
diagnostic cause without creating an unbounded log.

On Linux, the tool samples `/proc/self/status` and `/proc/self/fd` after warm-up
and records baseline, peak, and final RSS/FD observations. On hosts without
those interfaces, including macOS, these fields are JSON `null`; absence of a
measurement must not be reported as stable memory or descriptor usage. There
is intentionally no absolute CI threshold because allocator and runner behavior
varies. Manual review should look for unexplained monotonic growth and should
also require a clean process exit.

## CI smoke and campaign review

`cargo test -p oxidase-soak --locked` runs sub-second bounded versions of both
modes with real loopback sockets. Ordinary CI does not run multi-minute soak
campaigns.

For a manual campaign, record:

1. the exact Git commit and whether the tree was clean;
2. the full command and JSON output;
3. host OS/architecture and whether RSS/FD sampling was available;
4. non-zero error samples from stderr;
5. whether the process exited on its own; and
6. any follow-up fix and a clean rerun at the fixed commit.

The checked-in short records under `crates/oxidase-soak/campaigns/` demonstrate
the format. The 60-second combined record was run at `876cd4a`; the 10-second
protocol record was run with the contents committed as `a5e7b34`. The initial
30-second protocol attempt before `a5e7b34` exhausted macOS ephemeral client
ports because the tool opened one connection per operation. It was a failed
campaign, not a gateway qualification result. The follow-up introduced reusable
H2 connections and paced multi-exchange tunnels, then completed the recorded
protocol rerun with zero errors.

