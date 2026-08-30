# ADR 0006: Inbound TLS and HTTP/2

- Status: Accepted
- Date: 2026-08-30

## Context

Oxidase already owns one Tokio + Hyper HTTP/1 data plane, atomic snapshot
publication, prebind-before-commit listener changes, and graceful connection drain.
Inbound TLS and HTTP/2 must extend that path without moving transport concepts into
the Service algebra or pinning a whole multiplexed connection to one stale runtime
snapshot.

Certificate replacement also differs from a socket change. Rebinding an unchanged
address interrupts acceptance and can fail even though the existing socket is valid;
new TLS handshakes only need a new immutable transport plan.

## Decision

### Dependencies and cryptography

Use rustls 0.23, tokio-rustls 0.26, and rustls-pki-types 1. The latter's maintained
`PemObject` API parses PEM directly; the archived `rustls-pemfile` compatibility
crate is intentionally excluded. The ring provider is selected explicitly with TLS
1.2, TLS 1.3, and logging support.
The upstream Hyper-Rustls connector uses the same provider. This avoids OpenSSL and
the default AWS-LC/CMake build path. No external `openssl` command is required by
tests or runtime.

Certificate and private-key parsing is synchronous preparation work and remains on
the existing single-concurrency blocking compiler worker during reload.

### Resource model

`CertificateSpec` is a compiled Resource containing resolved certificate-chain and
private-key paths plus exact source spans. `PreparedCertificate` owns an immutable
rustls `CertifiedKey`, a content digest, and non-secret metadata. The preparation
pipeline:

1. reads both declared files and records them as candidate dependencies;
2. parses a non-empty X.509 chain;
3. rejects encrypted keys explicitly;
4. accepts exactly one PKCS#8, PKCS#1 RSA, or SEC1 key;
5. asks the selected rustls provider to parse the key;
6. verifies that the leaf certificate and private key match;
7. computes a domain-separated digest over the public certificate-chain DER.

Private-key bytes are never placed in diagnostics, Debug output, inspection
manifests, tracing, metrics, or a separately exposed key fingerprint. The candidate
private key is reparsed and positively matched on every preparation; only after that
check may a matching public-chain digest reuse the prior opaque signing resource.
Certificate/key paths and their parent directories remain in the reload dependency
set on success and failure.

### SNI and ALPN

An HTTPS listener names one default Certificate resource and may add exact ASCII DNS
rules or one leftmost wildcard rule such as `*.example.com`. Rules are normalized to
lowercase. Exact rules win, then the longest matching wildcard suffix, then the
default certificate. A wildcard matches exactly one leftmost label before its
suffix and never an IP address.

Preparation verifies exact rules against the leaf certificate with rustls name
verification. Wildcard rules require a correspondingly normalized wildcard DNS SAN;
an incompatible declaration fails the candidate. The default certificate has no
implicit hostname contract.

The listener's configured HTTP-version preference produces rustls ALPN protocols in
the same order (`h2`, `http/1.1`). No ALPN or `http/1.1` selects HTTP/1 only when that
version is enabled. `h2` selects the HTTP/2 driver only when H2 is enabled. Any other
result fails closed.

### Listener and snapshot lifecycle

`PreparedListenerPlan` separates listener identity/address from immutable transport
and HTTP settings. The accept loop owns the socket. For every newly accepted TCP
connection it reads the current plan for its listener from `SnapshotStore`; existing
connections retain the plan with which they started.

Consequences:

- certificate, SNI, ALPN, HTTP-version, and per-protocol setting changes do not
  rebind an unchanged listener address;
- an invalid candidate never publishes and the last-known-good certificate remains;
- certificate and Service changes publish in one snapshot transaction;
- a bind/name/address change still prepares every new socket before commit;
- no failed candidate starts a persistent accept, TLS, or health task.

Each HTTP request pins the current `RuntimeSnapshot` when the request/stream begins.
An HTTP/2 connection therefore may serve old in-flight streams and new post-reload
streams simultaneously; it is not itself pinned to one snapshot.

### Connection drivers and drain

Plaintext listeners support HTTP/1.1 only. Configuring H2 on plaintext fails with an
explicit h2c-not-implemented diagnostic. HTTPS connections perform a bounded TLS
handshake and then select exactly one Hyper driver from negotiated ALPN.

HTTP/1 retains the timer-backed header-read timeout and existing graceful shutdown.
HTTP/2 uses Hyper's Tokio executor/timer and explicit maximum concurrent streams,
maximum header-list size, keepalive interval, and keepalive timeout.

On listener retirement or process shutdown, acceptance stops first. Every HTTP/1
connection receives graceful shutdown; every HTTP/2 connection sends GOAWAY through
Hyper's graceful-shutdown API and stops accepting new streams. Accepted requests may
finish within the drain window, after which the connection task is aborted.

### Request metadata and observation

Protocol-neutral request metadata exposes `request.http_version` and a read-only
`request.tls` namespace containing enabled, server name, ALPN, and TLS version.
Forwarded/X-Forwarded-Proto continues to derive scheme from this trusted connection
metadata, never from an incoming Header.

Transport metrics use fixed protocol/result enums; existing Observe metrics use only
configured Observe names and fixed result enums. SNI, certificate paths, client
addresses, and request data are not labels. SNI may appear as a controlled tracing
field.

## Rejected alternatives

- A second TLS/H2 server stack would duplicate finalization, Service execution, and
  lifecycle semantics.
- Pinning one snapshot per HTTP/2 connection would hide reloads from new streams.
- Rebinding on every certificate change would introduce avoidable downtime and bind
  failure.
- Dynamic certificate I/O inside the rustls resolver would move blocking work into
  the handshake path.
- OpenSSL/native-tls would add a system dependency and a second TLS behavior model.

## Current non-goals

Inbound h2c, client certificates/mTLS, ACME, OCSP stapling, TLS 1.0/1.1, custom
cipher-suite configuration, HTTP/3, QUIC, RFC 8441 extended CONNECT, WebSocket, and
gRPC are not part of this decision. Protocol trailers and Upgrade are handled by the
next protocol-bridging ADR.
