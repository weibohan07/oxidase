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

## Required follow-up

Before Proxy is called complete, add hop-by-hop header removal, explicit Host and
Forwarded policy, finite connect/response timeouts, cancellation tests, and bounded
streaming tests. Before listener reload is called complete, implement prepare,
atomic commit, drain, and partial-bind rollback.

