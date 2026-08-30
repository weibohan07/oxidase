# Security policy

Oxidase is alpha software. Its security model is defined by explicit protocol,
resource, compilation, and publication boundaries rather than an assumption that
the process is hidden behind a firewall. The implemented and residual boundaries
are documented in:

- [`docs/security/threat-model.md`](docs/security/threat-model.md);
- [`docs/security/protocol-boundaries.md`](docs/security/protocol-boundaries.md);
- [`docs/security/resource-exhaustion.md`](docs/security/resource-exhaustion.md);
- [`docs/security/conformance-audit.md`](docs/security/conformance-audit.md);
- [`docs/implementation-status.md`](docs/implementation-status.md).

The v0.3 data plane supports TLS 1.2/1.3, HTTP/1.1, HTTP/2, streaming Proxy/Site
bodies, trailers, basic transparent gRPC, trusted HTTP/1 Upgrade, and resilient
Clusters. The v0.4 line is hardening those capabilities; it is not a declaration
of production readiness or a stable API.

## Reporting a vulnerability

Use GitHub private vulnerability reporting or a private Security Advisory for this
repository. Include the affected commit, configuration, reproduction, and impact.
Do not open a public issue containing an active exploit, Secret, private path,
certificate key, bearer token, or upstream credential.

The project will acknowledge a complete report, reproduce it on a supported commit,
and coordinate a fix and disclosure. No fixed response-time SLA is promised for an
alpha release.

## Current security invariants

- Configuration, Patterns, Expressions, OXR, OXT, Certificates, Sites, and Cluster
  plans are prepared and validated before publication. Failed candidates preserve
  last-known-good.
- Unknown or duplicate configuration keys, dependency cycles, and missing Resource
  references fail closed.
- Request overlays and lexical bindings are transactional. `Fallback` advances only
  on `Declined`; an error response is a handled response.
- Request and response bodies stream by default. Request-body replay exists only
  behind explicit bounded retry configuration.
- Hyper owns HTTP parsing. Oxidase rejects or removes unsafe framing and hop-by-hop
  metadata at every source and protocol boundary; source configuration cannot create
  a trusted Upgrade capability.
- Each request or HTTP/2 stream pins one immutable runtime snapshot. Publication,
  listener preparation, Cluster activation, and graceful retirement have distinct
  lifetimes.
- Site source, backing, dot/private, denied, traversal, double-encoded, and symlink
  escape paths are not public assets.
- OXT has no filesystem, network, database, shell, plugin, or arbitrary-code
  capability. HTML interpolation autoescapes and render budgets are shared across
  includes.
- Redirect locations are restricted to local absolute paths; network-path and
  response-splitting forms fail.
- Forwarded scheme and peer metadata come from the accepted connection, not
  client-supplied forwarding Headers.
- Private keys are prepared as opaque rustls signing material and never rendered in
  diagnostics, manifests, logs, metrics, or client errors.
- Metrics use configured names and fixed enums only. Paths, queries, peer addresses,
  SNI values, Header values, and error strings are not labels.
- Client-facing errors do not contain internal paths, source text, template names,
  certificate material, or upstream diagnostic details.

## Deployment obligations

The current read-only management listener is disabled unless `--admin-bind` is
provided. Bind it only to loopback or a separately protected management network;
v0.3 does not provide management authentication. Configure finite TLS, HTTP, body,
Cluster, and drain deadlines appropriate to the workload. Run the process with a
dedicated account, read-only configuration where practical, and operating-system
resource limits. These controls supplement, but do not replace, Oxidase's protocol
validation.

## Explicitly unsupported security claims

Oxidase currently provides Trust-Store-backed inbound `none`/`optional`/`required`
client-certificate verification and upstream TLS with system/custom roots, a fixed
verification identity, and an optional client Certificate Resource. Only bounded,
rustls-verified client metadata reaches the request model. mTLS does not assign an
application role or authorize a request, and upstream certificate verification
cannot be disabled.

Oxidase does not currently provide CRL/OCSP revocation, certificate pinning, a
SPIFFE policy engine, automatic certificate-to-role mapping, bearer-token
administration, ACME, a WAF, arbitrary CONNECT, HTTP/3, h2c ingress, H2 WebSocket,
gRPC-Web, dynamic service discovery, or a distributed control plane. It has not
completed a long-duration Linux resource qualification. Do not infer these
properties from the presence of related TLS, Proxy, Cluster, or soak code.
