# ADR 0014: Observable upstream phases and one logical request budget

Status: accepted design; phase 6A implementation in progress.

## Verified legacy contract

On main `ebfb754`, `connect_timeout` configures HttpConnector's TCP/DNS behavior.
After Cluster admission and optional bounded replay buffering, each Hyper request
attempt gets `connect_timeout + response_timeout`, including connect, TLS, upload
and head waiting. Retry can repeat that per-attempt budget. `response_timeout`
also independently controls upstream response-body idle. Defaults are therefore
35 seconds per attempt and 30-second body idle, not a 30-second logical deadline.
Queue and replay buffering are outside that legacy attempt clock.

Old source and Bundle timing remain an explicit legacy mode, with a precise
migration warning. A nonrenewing aggregate legacy upper bound is derived from
maximum attempts and configured retry queue waits after initial queue/buffering;
this bounds previously renewable retry waiting without pretending it is the new
entry-to-head contract. New and old source fields together are rejected.

## New phased policy

The strict `timeouts` policy has positive durations:

| Field | Default | Observable start → end |
| --- | --- | --- |
| connect | 5s | aggregate cold validated-address selection, or fixed-target reconnect → TCP completion |
| tls_handshake | 5s | TCP completion → authenticated TLS/ALPN completion |
| request_body_idle | 30s | demanded request body Pending → DATA/trailers/EOS/error |
| response_header | 10s | pool-ready dispatch for empty input, or local input EOS → head |
| response_body_idle | 30s | demanded upstream body Pending → DATA/trailers/EOS/error |
| pre_response_total | 60s | Proxy entry before queue/buffer → final chosen response head |

The total deadline is one monotonic absolute Instant. Queue, buffering, every
attempt, DNS/address acquisition and retry retarget/wait are capped by it. Retry
and discovery generation cannot refresh it. A retryable intermediate head does
not end the total budget. The final head does; long streaming/gRPC bodies then
retain only their applicable idle limits and admission lifecycle.

Local EOS means the last body frame was handed to Hyper, not that the remote peer
received all bytes. Pool-ready is Hyper's captured connection metadata boundary,
not a remote receipt timestamp. Always poll the response concurrently with upload:
early 200/413 and bidirectional H2 are valid and must not wait for local input EOS.
New TCP/TLS timers belong to an immutable connector, not one waiter's total budget,
so cancelling a request does not destroy another waiter's shared connecting work.

Idle is demand-relative and cooperative at the Body polling boundary. Timers arm
on Pending, clear on DATA/trailer/EOS/error, and latch a terminal error. Unpolled
backpressure time is not represented as measured remote inactivity. Request and
response legs share attempt ownership: premature response EOS/HEAD cannot release
an upload's permit, and response cancellation signals unfinished upload cancellation.

## Failure provenance and compatibility

Closed timeout phases are queue/connect/tls/request_body/response_header/
response_body/total. Local overload maps to safe 503; demanded downstream upload
idle to pre-head 408; upstream/total pre-head timeout to safe 504. Post-head faults
remain stream errors/reset, never another head or retry. Total expiry, downstream
fault and cancellation do not manufacture endpoint passive failures. TCP/TLS/head
failure retries still require explicit method, cause, replay, attempts, untried
endpoint and retry-storm admission. Certificate failure never downgrades trust.

A status retry reserves a replacement endpoint while holding the original attempt
and one Cluster permit. Only admitted replacement allows cancellation and closure
of the old upload before permit retargeting. If no replacement can be admitted,
the original response/upload remain untouched. Reservation drop, cancellation or
a foreign Cluster reservation cannot mutate the original admission.

Cold TCP address attempts consume one aggregate connect deadline. The temporarily
remaining TCP duration is restored to the configured connector policy before pool
storage; TLS has its own immutable limit. All transport and queue deadline
arithmetic is checked, so an unrepresentable legacy duration fails closed rather
than panicking or becoming an infinite deadline.

An old portable plan without `timeouts` reconstructs legacy mode. New phased
plans declare required feature `upstream-deadlines`; missing capability declarations
are rejected as well as unsupported required features. Source spans and migration
warnings survive reconstruction. No discovery fields are exposed by 6A.

References: [locked Hyper connection capture](https://docs.rs/hyper-util/0.1.20/hyper_util/client/legacy/connect/fn.capture_connection.html),
[locked Hyper Client retry controls](https://docs.rs/hyper-util/0.1.20/hyper_util/client/legacy/struct.Builder.html#method.retry_canceled_requests).
These observable boundaries were verified against the locked library implementation.
