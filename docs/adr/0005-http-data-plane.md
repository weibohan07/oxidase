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

The first production slice is HTTP/1.1 without TLS. HTTP/2 and TLS are additive
work, not a second data plane. HTTP/3 is out of scope.

The Proxy implementation uses one shared Hyper client backed by a Rustls
HTTP-or-HTTPS connector. The pool is reused across requests and negotiates upstream
HTTP/2 with ALPN. Incoming request and upstream response bodies remain Hyper streams;
response-body idle timeouts are enforced by a body adapter.

The initial forwarding policy replaces untrusted incoming Forwarded/X-Forwarded
fields with connection-derived peer, scheme, and host values, sends the upstream
origin as Host, removes Connection-nominated and standard hop-by-hop headers, and
retains the raw request path/query representation.

## Required follow-up

Before listener reload is called complete, implement prepare, atomic commit, drain,
and partial-bind rollback. Proxy hardening still needs explicit disconnect and slow
client cancellation tests, endpoint health state, and policy configuration beyond
the secure default.
