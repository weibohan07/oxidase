# Changelog

All notable changes are recorded here. Oxidase remains alpha software; neither
the configuration schema nor the diagnostics schema is a stable compatibility
contract yet.

## [Unreleased]

## [0.3.0-alpha.1] - 2026-08-30

### Added

- versioned human and JSON diagnostics with exact source spans and cross-file
  reference chains;
- pure-Rust inbound TLS 1.2/1.3, SNI certificate selection, atomic certificate
  reload, ALPN-selected HTTP/1.1 and HTTP/2, and graceful H2 drain;
- frame-preserving request/response trailers, transparent H2 gRPC forwarding,
  and capability-gated HTTP/1 Upgrade/WebSocket proxying;
- prepared resilient Clusters with named weighted endpoints, round-robin,
  weighted-round-robin and least-requests selection, active health checks,
  passive ejection, bounded admission, explicit replay policy, and safe
  pre-response-head retries;
- read-only Cluster status at `/api/v1/clusters` and bounded Cluster metrics;
- a reproducible secure/resilient example using clearly marked, publicly known
  test-only certificate material.

### Changed

- workspace version advanced to `0.3.0-alpha.1`; Gateway remains
  `oxidase.dev/v1alpha1` and Oxista remains v1;
- Proxy keeps one streaming data plane and long-lived protocol pools while
  selecting prepared endpoint runtime state;
- listener sockets, immutable transport plans, and request-pinned snapshots now
  have independent reload lifetimes.

### Security

- private keys are parsed and matched before publication and are never rendered
  in diagnostics, manifests, logs, metrics, or admin output;
- retry remains disabled by default, never occurs after a downstream response
  head, and buffers request bodies only under an explicit byte limit;
- user source cannot construct trusted Upgrade responses or control dangerous
  framing and hop-by-hop headers.

### Known limits

- no h2c, mTLS, ACME, OCSP stapling, HTTP/3, H2 extended CONNECT, gRPC-Web,
  arbitrary CONNECT proxy, dynamic service discovery, or cross-process health
  state;
- the release is not production-ready and does not claim long-term soak or API
  stability beyond the evidence recorded for this milestone.

## [0.2.0-alpha.1] - 2026-08-23

- introduced the compiled Service algebra, Oxista, streaming HTTP/1 data plane,
  immutable snapshot reload, production observation, content identity, and strict
  source compilation that form the v0.3 foundation.
