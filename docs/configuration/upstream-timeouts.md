# Upstream transport and deadlines

Phase 6A supports static Cluster endpoints and an explicit timing policy on the
existing streaming Proxy. It does not expose dynamic A/AAAA or SRV configuration.
The workspace remains `0.3.0-alpha.1`; all APIs remain alpha.

```yaml
resources:
  clusters:
    api:
      endpoints:
        - name: origin
          url: https://api.internal.example:8443/base
      timeouts:
        connect: 5s
        tls_handshake: 5s
        request_body_idle: 30s
        response_header: 10s
        response_body_idle: 30s
        pre_response_total: 60s
```

Each duration must be positive and at most 24 hours. The values above are the
defaults within a declared `timeouts` block; omitting that entire block selects
the legacy mode described below. Unknown fields, null policy/values, zero values,
and new/legacy fields together fail with exact source diagnostics.

## Observable clocks

| Field | Start → finish | Failure boundary |
| --- | --- | --- |
| `connect` | cold validated-address selection → connected socket, or one fixed-target pool reconnect → connected socket | pre-head upstream failure; a pooled hit does not create a TCP clock |
| `tls_handshake` | TCP completion → authenticated TLS and ALPN | pre-head TLS failure; no trust bypass or downgrade |
| `request_body_idle` | demanded body poll becomes Pending → DATA/trailers/EOS/error | safe 408 before a final head, stream cancellation afterwards |
| `response_header` | pool-ready dispatch for empty input, or local body EOS for non-empty input → upstream head | safe 504 before the final head |
| `response_body_idle` | demanded upstream body poll becomes Pending → DATA/trailers/EOS/error | body error/reset, never a replacement 504 |
| `pre_response_total` | Proxy entry before admission and buffering → final chosen response head | one absolute monotonic deadline across all attempts |

Queue waits, explicit replay buffering, name resolution, address fallback, TCP/TLS,
upload and status/error retry all consume the same `pre_response_total` budget.
Neither retry nor a refreshed address view creates a new deadline. An intermediate
head selected for retry does not end that budget; the final chosen head does.
Long H2/gRPC bodies then retain idle/admission lifecycle protections rather than a
new total-transfer clock.

Local EOS means Hyper received the final request-body frame or observed its end,
not that the upstream received every byte. Pool-ready dispatch is Hyper's captured
connection boundary, including a reused connection. It is not a measured remote
receipt timestamp. Responses are polled concurrently with uploads: early 200/413
and bidirectional H2 do not wait for the upload to end.

Body idle timers are cooperative demand timers, not raw socket-progress sensors.
They arm on Pending, clear on progress, and latch a terminal error. No timer is
created solely to count unpolled downstream/upstream backpressure as remote idle.
TCP/TLS limits are transport policy, never a caller's absolute request deadline.

## Logical origin, physical dial and pools

The URL's scheme, authority and base path remain the logical HTTP origin. DNS IPs
do not become Host, H2 authority or TLS verification/SNI names. Existing prepared
Trust and client-certificate policy still controls authentication.

Each Client owns an immutable connector to one validated SocketAddr. Its internal
SHA-256 pool identity includes the logical origin, Cluster/endpoint, actual address
and port, effective protocol, prepared TLS security identity and TCP/TLS policy.
The connector does not resolve a hostname again. Registry entries are bounded to
1,024, prefer idle/LRU eviction, and hold resource owners weakly. Compatible
policy-only reload can reuse transport; origin/address/protocol/security changes
cannot borrow an incompatible pool. Retired requests may finish privately without
repopulating a global retired-resource cache.

Static native-name results have an internal 90-second freshness window, not a DNS
TTL claim. Fresh hits do not perform a name lookup. Native resolution failures may
reuse a previously validated answer for a further fixed 90 seconds; errors do not
extend that bound, and failure retries are suppressed for five seconds. Invalid or
oversized answers cannot use stale fallback. The cache is bounded to 1,024 entries
and coalesces a name's in-flight work. At most 32 native worker jobs are admitted;
the actual blocking job retains its permit after a caller cancels.

Each answer is bounded to 32 distinct physical targets. Existing candidate pools
are checked first. Cold TCP failure/timeout may try the next validated target
before any request body is dispatched. All cold fallback TCP attempts share one
aggregate `connect` budget, rather than resetting it for each address. The winning
connector restores the original configured policy before being stored for future
pool reconnects. TLS authentication/ALPN failure stops
immediately. The winning connection is handed to Hyper exactly once, with no
synthetic request or fake origin. An unused warm socket expires after 90 seconds;
its expiry task ends on consumption/drop. Cold preconnection and actual pool
reconnect share a 1,024-slot transport gate without double charging. These local
quotas are overload, not passive endpoint failure or a retryable connect fault.

A Client with no live pooled connection still reconnects only to its immutable
target. A typed physical TCP reconnect failure retires that exact Client from the
registry, without closing already-issued streams or evicting a newer replacement.
A subsequent logical request may select among the still validated static answers.
This is not same-attempt request-body replay or hidden business retry.

This static native cache cannot report authoritative NXDOMAIN/NODATA or record
TTLs. Those contracts belong to subsequent dynamic-discovery delivery, not to
the native platform name-service interface.

## Health and retry ownership

Health uses the same validated targets and TLS identity, with its own network
deadline and a fair 64-probe global gate. A Cluster creates at most 32 probe futures
at a time and advances through its complete endpoint set. Local admission waiting
does not consume a physical endpoint's network deadline; resolver/local-capacity
failures do not eject a physical endpoint. Business admission and retry permits
are not used by health checks.

Retry remains opt-in and pre-head only. A status retry first reserves a different
endpoint while retaining its one Cluster slot. When no replacement is admitted,
the original response and upload remain untouched. Only after reservation may the
old upload be cancelled and closed and the replacement permit committed. Upload,
response and trusted-tunnel guards release on actual completion/cancellation, not
merely because an early response head or EOS appeared.

Cold Hyper connection acquisition has a separate 1,024-slot retirement budget.
Normal requests create no additional retirement task. Cancellation of a started
cold dispatch retains its original connecting future only until pool-ready/error
or a fixed transport-derived cap, so valid concurrent H2 waiters do not lose the
shared acquisition. Never-polled requests are dropped without starting work;
owner shutdown cancels cleanup. These workers do not hold a snapshot/publisher or
grant another business attempt. Hyper may queue HEADERS in the same poll that
exposes connection metadata: cancellation suppresses DATA but cannot retract an
already-queued head or undo peer-side effects.

## Legacy migration and Bundle capability

Old YAML and old Bundle fields remain accepted:

```yaml
connect_timeout: 5s
response_timeout: 30s
```

The published baseline gives each attempt a `connect_timeout + response_timeout`
envelope after initial queue/replay buffering, and separately uses
`response_timeout` for response-body idle. Default legacy timing is therefore
35 seconds per attempt plus 30-second body idle, not a 30-second entry-to-head
deadline. An aggregate upper bound over permitted attempts and retry queue waits
is fixed once after that initial buffering; it cannot be renewed by retry.
Explicit legacy fields produce migration diagnostics describing this distinction.
Use `timeouts` to cover the initial queue and buffering as well.

Native address fallback is explicit and sequential; the former connector's
automatic Happy Eyeballs behavior is not claimed. A shared connector never stores
a request-specific deadline. Unrepresentable legacy transport or queue deadlines
fail closed instead of panicking or becoming infinite.

Old portable plans without `timeouts` reconstruct legacy mode. New plans declare
required feature `upstream-deadlines`; missing declarations and unsupported
required features are rejected. Inspected artifacts carry policy, not name-service
answers, pool pointers or runtime state. No execution timeout or operational target update
changes PublishedRuntime ETag/origin or Admin publication authority.

Executed regression and final-head Hosted receipts are recorded in
[discovery acceptance](../verification/discovery-acceptance.md). Local checks are
not substituted for final PR-head or merged-main CI.
