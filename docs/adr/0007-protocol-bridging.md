# ADR 0007: Protocol bridging, trailers, gRPC, and HTTP/1 Upgrade

- Status: Accepted
- Date: 2026-08-30

## Context

Oxidase has one streaming Hyper data plane for cleartext HTTP/1.1 and TLS
ALPN-selected HTTP/1.1 or HTTP/2. Proxy bodies already carry `http_body::Frame`,
but the existing hop-by-hop Header policy was intentionally conservative: it
removed `TE`, `Trailer`, `Connection`, and `Upgrade` in every direction. That policy
cannot express HTTP/2 trailers or a trusted HTTP/1 Upgrade tunnel.

This change must preserve the existing Service algebra. Trailers, gRPC, and Upgrade
are data-plane protocol behavior of Proxy; they are not new Services. Ordinary
Respond, Transform, Site, and Oxista responses must not gain the ability to forge
hop-by-hop framing or an Upgrade capability.

## Decision

### Frame-preserving bodies

Every request and response adapter forwards complete body frames:

- DATA is forwarded without collection;
- trailer fields remain trailer frames and are never rewritten into initial
  Headers;
- end-of-stream and body errors remain observable;
- body telemetry counts DATA octets only;
- timeout and instrumentation wrappers do not discard trailers.

The normal Proxy and Asset paths remain streaming. No bridging path may use
`into_data_stream()` or collect a complete body merely to discover future trailers.

### Wire-protocol-aware Header policy

`oxidase-server` owns a small `WireProtocol` model for HTTP/1 and HTTP/2. Hyper
types and transport policy do not enter `oxidase-core`, Oxista, expressions, or the
Service graph.

For HTTP/1, the sanitizer parses `Connection` tokens, removes every nominated
field, and removes standard hop-by-hop fields. `TE` is hop-by-hop. `Connection` and
`Upgrade` are reconstructed only by the trusted Proxy Upgrade path.

For HTTP/2, the sanitizer removes `Connection`, `Keep-Alive`,
`Proxy-Connection`, `Transfer-Encoding`, and `Upgrade`. `TE` is retained only when
its parsed value is exactly `trailers`; any other or combined value is removed.

`Trailer` declarations remain forbidden in user DSL/OXR/Transform policies. A Proxy
may preserve or generate a validated declaration as trusted runtime metadata.
The Response Finalizer receives the downstream wire protocol and a private trusted
Upgrade capability; ordinary responses continue through the strict framing policy.

### Upstream protocol policy and pools

Cluster Resources compile one of:

```text
auto
http1
h2
```

`auto` uses ALPN for HTTPS and HTTP/1 for cleartext. `http1` forces HTTP/1.1.
`h2` requires H2 for HTTPS and uses H2 prior knowledge for cleartext upstreams.
Each policy has a long-lived pool owned by the server runtime; no request creates a
new client.

Transparent gRPC requires a Cluster explicitly configured as `protocol: h2`.
Oxidase does not parse protobuf or gRPC message frames, does not translate
`grpc-status` into an HTTP status, and does not implement gRPC-Web.

### Trailer bridging contract

HTTP/2 to HTTP/2 forwards validated DATA and trailers in both directions.
HTTP/1 chunked request trailers may be forwarded to H2 after protocol-aware Header
sanitation.

For H2 response trailers sent to an HTTP/1 client, Hyper requires trailer names in
the initial response `Trailer` declaration and the downstream request must have
accepted trailers. A streaming gateway cannot discover undeclared future names
after the response head is sent. Oxidase therefore forwards only declared,
validated trailer names in this direction. If an undeclared or otherwise unsafe
trailer arrives after the head, the body terminates with a protocol error; it is
never silently dropped and cannot be changed into a synthetic 502 after the head
was sent.

### Trusted HTTP/1 Upgrade

Only HTTP/1.1 Proxy supports generic Upgrade, including WebSocket. H2 extended
CONNECT, arbitrary CONNECT tunneling, and WebTransport are rejected.

The server extracts the downstream `OnUpgrade` capability before decomposing the
request and keeps it in a server-local request payload. A Proxy Upgrade candidate
must have a syntactically valid single Upgrade protocol and a `Connection` token
that names `upgrade`. The upstream request is forced through the HTTP/1 pool; the
gateway removes client-nominated hop fields and reconstructs only the validated
`Connection: upgrade` and `Upgrade` values.

An upstream 101 is trusted only when its Connection/Upgrade fields are valid and
match the requested protocol. The Proxy then constructs a private
`TrustedUpgradeResponse` containing both `OnUpgrade` futures and the pinned runtime
snapshot. No configuration value or non-Proxy leaf can construct this type.

The HTTP/1 connection driver enables Hyper upgrades and owns the tunnel task. It
uses bidirectional asynchronous copy without application buffering, records bytes
and a fixed termination reason, and never detaches a task beyond the owning
connection lifecycle. A reload that retains the Listener does not cut an active
tunnel. Listener retirement lets it continue during the drain window; expiry aborts
the connection and tunnel.

### Errors and observation

A failure before a downstream response head maps through the existing safe Proxy
error response. A request/response body failure, gRPC reset, or tunnel failure after
the head is emitted terminates that stream or connection and records body/tunnel
telemetry; it cannot be rewritten into an HTTP status.

Metric labels remain bounded: configured Listener/Cluster names plus fixed protocol,
direction, and termination enums. Paths, SNI, peer addresses, Upgrade protocol
values, gRPC messages, and Header contents are never labels.

## Consequences

- One Service graph and one Response Finalizer remain authoritative across H1/H2.
- Basic unary and streaming gRPC work by transparent H2 frame forwarding rather
  than a gRPC-specific execution path.
- H2-to-H1 undeclared trailers fail explicitly instead of being silently lost.
- Upgrade is a capability carried by trusted server-local types, not a relaxation
  of public Header policy.
- Active tunnels pin their original snapshot and participate in Listener drain.

## Rejected alternatives

- Collecting bodies to learn trailer names violates the streaming invariant.
- Passing all hop-by-hop Headers through Proxy would let untrusted configuration or
  clients control connection framing.
- Treating every upstream as `auto` cannot prove the H2 contract required by gRPC.
- Detaching tunnel tasks would break reload drain, active counters, and file
  descriptor lifecycle.
- Adding gRPC or WebSocket Service types would duplicate the Proxy execution model.

## Current non-goals

Inbound h2c, RFC 8441 HTTP/2 WebSocket, arbitrary CONNECT, WebTransport, gRPC-Web,
HTTP/3, QUIC, and protobuf-aware processing remain unsupported.
