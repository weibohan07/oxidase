# Protocol boundaries

Oxidase has one HTTP data plane, but each wire transition has a distinct validation
contract. This document records what may cross each boundary and which component is
authoritative.

## Downstream bytes to HTTP request

Hyper and rustls are trusted parsers. Raw downstream bytes never enter the Service
algebra. A request reaches a `RequestFrame` only after:

- TLS and ALPN selection, when applicable;
- HTTP/1 or HTTP/2 parser/state-machine validation;
- a valid method, URI, version, and `HeaderMap` exist; and
- connection-derived scheme, peer address, TLS, SNI, and protocol metadata are
  attached independently of client forwarding headers.

HTTP/1 requests require an unambiguous target/authority as enforced by Hyper and
the server boundary. CONNECT and authority-form are not a generic tunnel facility.
HTTP/2 pseudo-headers are consumed by Hyper and cannot be reconstructed from normal
configured Headers.

## Source configuration to runtime Headers

Gateway, Oxista defaults/profiles/OXR, and Transform share one source Header policy.
They cannot set:

```text
Connection
Content-Length
Keep-Alive
Proxy-Connection
TE
Trailer
Transfer-Encoding
Upgrade
```

Dynamic values must parse as `HeaderValue`, so CR/LF response splitting fails. The
response finalizer owns final status/body suppression and framing.

## Proxy request and response heads

Runtime sanitization first captures and removes `Connection`-nominated fields, then
removes standard hop-by-hop/framing fields. HTTP/2 additionally rejects connection
semantics and retains `TE` only when the complete value is exactly `trailers`.
Forwarded scheme and peer fields are derived from accepted connection metadata.

An upstream response head is not trusted framing. Proxy creates a streaming body
plan, then the same root response finalizer used by Respond, Site, and Redirect
derives downstream framing.

## Body frames and trailers

Every adapter must preserve DATA, trailer frames, end-of-stream, and errors. Byte
telemetry counts DATA only. Trailer fields cannot contain framing, routing,
authentication-hop, or `Connection`-nominated names.

Cross-version trailers are allowed only when the HTTP/1 side knows the complete
field-name set from the initial `Trailer` declaration. For requests, an H2 client
that sends undeclared trailers through an H1 upstream Cluster receives a body/
protocol error rather than having Hyper silently discard the frame. For responses,
HTTP/1 client acceptance and the trusted upstream declaration must both make the
field set knowable before the response head. Late forwarding identity fields
(`Forwarded` and `X-Forwarded-*`) are forbidden alongside routing, authentication,
representation, framing, and connection metadata. An unsafe late trailer produces
a stream error; it is never silently converted to a Header or dropped.

## Trusted Upgrade

Ordinary source values cannot construct `UpgradeCandidate`, `PendingUpgrade`,
`TrustedUpgrade`, or `TunnelPlan`. The capability path is:

```text
validated HTTP/1 downstream request
  -> one-shot PendingUpgrade next to Incoming body
  -> Proxy consumes and pins it to the RuntimeSnapshot
  -> validated matching upstream 101
  -> ResponseFinalizer emits trusted 101 and TunnelPlan
```

Any mismatch, duplicate token, non-HTTP/1 path, or non-101 response destroys the
capability. A normal `101` is bodyless and loses Upgrade headers. Arbitrary CONNECT
and H2 extended CONNECT are not supported.

## gRPC

`application/grpc` is opaque HTTP/2 traffic. Oxidase does not parse protobuf,
translate `grpc-status`, or infer retry safety from gRPC method names. Terminal
`grpc-status` and `grpc-message` remain trailers. Once the downstream response head
is committed, a reset or body error cannot be converted into an HTTP error or
retry.

## Reload and drain

The transport plan selected by a TLS handshake is immutable for that connection.
Each HTTP request or H2 stream independently pins the current runtime snapshot.
Therefore a retained H2 connection may carry old and new snapshot streams without
mixing state within one stream. Retirement stops accepts, requests graceful
HTTP/1/H2 shutdown, allows already accepted work through the drain deadline, then
aborts remaining connections and tunnels.

## External conformance interpretation

The pinned suites under `tools/conformance` exercise the public wire boundary, not
the Service algebra. h2spec's RFC 7540 expectations require interpretation where
Hyper implements newer HTTP/2 errata. Autobahn evaluates the bytes of the proxied
WebSocket tunnel, not a WebSocket application endpoint in Oxidase. HTTPWookiee can
run in reverse-proxy mode only against loopback fixtures it controls. Tool output is
uploaded verbatim and is not a release pass until each finding is triaged.
