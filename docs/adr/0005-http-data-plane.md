# ADR 0005: Hyper data plane

- Status: Accepted
- Date: 2026-08-23

## Context

Oxidase needs arbitrary Service composition, bidirectional response wrapping,
streaming request and response bodies, reusable upstream connections, graceful
listener lifecycle, and a path to HTTP/2, TLS, WebSocket, SSE, gRPC, trailers, and
`100-continue`.

Pingora offers a production proxy stack but centers extension around proxy phases.
Mapping every terminal and wrapper Service into those phases would either privilege
Proxy again or put the Service interpreter inside one large proxy hook. Hyper is a
lower-level protocol implementation: it fits arbitrary Service execution and body
types naturally, but Oxidase must explicitly own pooling, header policy, timeouts,
TLS, upgrades, and lifecycle.

## Decision

Use Tokio + Hyper as the sole initial data plane. Keep the compiler, core IR,
Oxista, and runtime executor independent of Hyper through a narrow leaf-execution
boundary. `oxidase-server` owns listeners, streaming body adaptation, one reusable
upstream client per prepared cluster set, and protocol lifecycle.

The first production slice was HTTP/1.1. TLS and HTTP/2 were added to this same data
plane: cleartext ingress remains HTTP/1.1, while HTTPS selects H2 or HTTP/1.1 with
ALPN. HTTP/3 is out of scope.

The Proxy implementation uses long-lived Hyper pools backed by rustls connectors
for `auto`, forced HTTP/1.1, and forced H2 policies. Pools are reused across requests
and reconciled on snapshot publication. Incoming request and upstream response
bodies remain Hyper streams; timeout and telemetry adapters preserve DATA, trailers,
end of stream, and errors without collecting the normal path.

The initial forwarding policy replaces untrusted incoming Forwarded/X-Forwarded
fields with connection-derived peer, scheme, and host values, sends the upstream
origin as Host, removes Connection-nominated and standard hop-by-hop headers, and
retains the raw request path/query representation.

Listener sockets and immutable transport plans are separate. Reload prepares
Certificates, Sites, Clusters, and sockets before atomic publication. Retained
sockets load the current TLS/HTTP plan for each new connection; each request or H2
stream independently pins the current runtime snapshot. Retirement sends HTTP/1
graceful shutdown or H2 GOAWAY and aborts only after the drain deadline.

`PreparedCluster` adds selection, health, passive ejection, bounded admission, and
explicit pre-head retry behind the same Proxy leaf and pools. Candidate preparation
does not start active health tasks; commit activation does. Normal bodies remain
streaming. Only an explicitly configured replay mode may collect a bounded request
body before the first attempt.

HTTP/1 Upgrade is capability-gated inside the server. A validated Proxy handshake
may preserve the required Connection/Upgrade fields and transfer upgraded I/O to a
connection-owned tunnel; ordinary Service output cannot construct that capability.
H2 trailers remain frames and enable opaque gRPC forwarding without a protobuf
layer.

## Current boundaries

Cleartext h2c, HTTP/2 extended CONNECT/WebSocket, arbitrary CONNECT, gRPC-Web,
HTTP/3, custom `100-continue` policy, dynamic Cluster discovery, and unbounded or
implicit replay remain out of scope. The response-header timeout currently bounds
connect plus request upload/header latency as one deadline rather than exposing
separate per-phase timers.
