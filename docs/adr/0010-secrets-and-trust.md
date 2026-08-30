# ADR 0010: Secrets, trust stores, and mutual TLS

- Status: Accepted
- Date: 2026-08-30

## Context

Oxidase already prepares server certificates before publishing a runtime snapshot,
but not every sensitive value is a certificate key and not every CA set should come
from the host operating system. Inbound client-certificate authentication and
upstream private PKI both need an explicit trust boundary that participates in the
same prepare-before-commit transaction as Services, Listeners, and Clusters.

The design must not place secret bytes in the compiled source program, diagnostics,
inspection output, metrics, or logs. It must also keep rustls types out of the core
Service algebra and preserve the existing separation between an immutable snapshot,
a retained listener socket, and long-lived upstream connection pools.

This decision supersedes only the client-certificate/mTLS non-goal recorded by
ADR 0006. Its h2c, ACME, OCSP, legacy-TLS, cipher-suite, HTTP/3, and extended-CONNECT
non-goals remain unchanged.

## Decision

### File-backed Secret resources

The first Secret provider is a bounded regular file:

```yaml
resources:
  secrets:
    admin-token:
      file: /run/secrets/oxidase-admin-token
      max_bytes: 64KiB
```

Inline secret values are not accepted. `max_bytes` defaults to 64 KiB and must be
nonzero. The resolved file path enters the candidate dependency graph, but Secret
bytes never enter compiler IR. Runtime preparation rejects a missing path, a
non-regular file, a read failure, and a file that is larger than the configured
limit. The file is read as exact bytes: Oxidase performs no newline trimming,
Unicode decoding, or other normalization.

File-backed resources are type-checked before and after open. On Unix the open is
nonblocking, so a FIFO/device path or a regular-file-to-FIFO race is rejected rather
than wedging the single preparation worker. Symlink-based atomic rotation remains
supported and the opened descriptor is still checked as a regular file.

Prepared bytes are held in `SecretBytes`. Its Debug, Display, and Serialize
implementations emit only `<redacted>`, and callers compare a candidate through a
constant-time operation for equal-length inputs. Secret length remains observable.
Clones share one allocation; the final owner zeroizes that allocation on drop.
Partial read buffers are zeroizing from their first byte.

This is best-effort process-memory hygiene, not a claim that every copy is erased.
The operating system, filesystem cache, allocator, crash dump, swap, and copies made
outside `SecretBytes` are outside this guarantee. On Unix, group- or other-readable
permissions produce a warning; they do not fail preparation because portable
permission models differ. Mode `0600` or a stricter equivalent is recommended.

Secret contents have a private preparation fingerprint for in-process reuse, but
that deterministic value is excluded from exported identities. The live runtime
activation `ConfigVersion` incorporates an opaque random token that remains stable
only while the prepared Secret is reused, so a rotation changes live state without
exposing a useful offline oracle for a low-entropy Secret. The deterministic
compile/inspection identity excludes both Secret contents and that random token;
repeated manifests are byte-stable and intentionally cannot identify Secret
rotations.

This ADR establishes the Secret Resource boundary. It does not make arbitrary
Secret values available to expressions, templates, Headers, or metrics. Consumers
must use a purpose-built interface that cannot accidentally stringify the bytes.

### Trust-store resources

A Trust Store is public CA material rather than a Secret:

```yaml
resources:
  trust_stores:
    internal-ca:
      ca_bundle: ./pki/internal-ca.pem
```

Preparation accepts a regular ASCII PEM file of at most 16 MiB containing one or
more `CERTIFICATE` sections and whitespace only. Empty bundles, malformed PEM,
private keys, and annotated non-PEM text are rejected. Certificate DER is sorted and
deduplicated before building the rustls root store and content digest, so source
order and duplicate sections do not change the prepared identity.

The CA path remains a reload dependency. A changed, missing, or invalid bundle makes
the candidate fail while the current snapshot remains active. Because CA
certificates are public trust anchors, their path and normalized content digest are
not treated as Secret material.

### Inbound client authentication

An HTTPS Listener may select one of three client-authentication modes:

```yaml
listeners:
  - name: internal
    bind: 0.0.0.0:8443
    protocol: https
    tls:
      default_certificate: gateway
      client_auth:
        mode: required
        trust_store: internal-ca
    service:
      ref: internal-api
```

- `none` is the default and forbids `trust_store`;
- `optional` permits an anonymous client, but a certificate that is offered must
  validate against the named Trust Store;
- `required` requires a certificate chain that validates against the named Trust
  Store.

`optional` and `required` both require a Trust Store reference. An invalid or
untrusted presented certificate fails the TLS handshake and never reaches the
Service graph.

Only metadata derived after rustls verification crosses into the protocol-neutral
request model. The read-only expression/template namespace exposes:

```text
request.tls.client.verified
request.tls.client.sha256
request.tls.client.subject
request.tls.client.dns_sans
request.tls.client.uri_sans
```

The SHA-256 value fingerprints the verified leaf DER. DNS and URI SAN lists are
sorted, deduplicated, and bounded; the subject and aggregate SAN text are also
bounded. Anonymous connections expose `verified: false`, null fingerprint/subject,
and empty SAN lists. `subject` is informational and must not be treated as a stable
principal. Authorization policy should use an explicitly selected verified SAN or
leaf fingerprint and should define rotation behavior.

Client identity values are not metric labels. Debug output records only presence and
counts, not the fingerprint, subject, or SAN values. mTLS authenticates a certificate
chain; it does not automatically assign application roles or authorize a request.

Client-auth policy is part of the immutable Listener transport digest. A retained
socket loads the current transport plan for each new accept, so a valid CA rotation
does not rebind the Listener. Existing TLS connections retain their old handshake
and identity; new connections use the new Trust Store. An invalid rotation never
publishes.

### Upstream TLS and client identity

HTTPS Clusters may use host roots, a custom Trust Store, or their union, and may
present an existing Certificate Resource as a client certificate:

```yaml
resources:
  clusters:
    api:
      endpoints:
        - name: api-a
          url: https://10.0.0.10:8443
      tls:
        server_name: api.internal.example
        trust:
          system_roots: false
          trust_store: internal-ca
        client_certificate: upstream-client
```

`system_roots` defaults to true. At least one trust source must remain enabled. If
`server_name` is absent, the endpoint URL host is the TLS verification identity. A
fixed DNS `server_name` is used for verification and SNI; a fixed IP value is used as
the verification identity and does not manufacture a DNS SNI name. Wildcards,
userinfo, and arbitrary verification bypasses are not accepted.

`client_certificate` refers to the existing Certificate Resource, whose chain,
private key, validity, issuer links, and key match have already been prepared. The
same upstream TLS policy is used by normal Proxy traffic and active health checks.

The prepared upstream TLS digest covers the complete accepted system-root set, the
custom Trust Store digest, the client certificate's public-chain digest, the fixed
server name, and the Cluster identity. Proxy and health-check pool identities include
that digest. A trust, client-certificate, or verification-name change therefore
cannot reuse an incompatible connection pool. Old pinned work may finish on an old
pool; new work from the published snapshot uses the new policy. Compatible policies
can continue to reuse their long-lived pools.

Candidate TLS construction happens before commit and starts no persistent work.
Missing native roots, an empty trust policy, an invalid Trust Store, or an invalid
client certificate prevents publication and preserves last-known-good.

## Consequences

- Secret bytes have one narrow, redacting runtime representation instead of becoming
  general configuration values.
- One normalized Trust Store Resource serves inbound verification and upstream TLS.
- Verified client-certificate facts are available to the existing expression system
  without exposing rustls or X.509 parser types to the Service algebra.
- Trust and client-identity changes are atomic and become part of listener or pool
  compatibility, while existing pinned connections retain their original policy.
- Operators must still define authorization, certificate issuance, revocation, and
  safe file delivery outside Oxidase.

## Rejected alternatives

- Inline Secrets would place sensitive values in YAML, diagnostics context, shell
  history, and source-control workflows.
- Exposing Secret bytes as ordinary strings would make logging, interpolation, and
  serialization leaks too easy.
- `dangerous_skip_verify` would turn a source typo or incident workaround into an
  unauthenticated upstream transport; no such DSL exists.
- Treating the certificate subject DN as a canonical principal would create an
  unstable and ambiguous authorization boundary.
- Reusing pools only by endpoint URL would let a connection authenticated under an
  old trust/client-identity policy serve work from a new policy.

## Current limitations

The current alpha supports only file-backed Secrets and PEM Trust Stores. It has no
cloud/KMS Secret provider, encrypted-at-rest Secret format, CRL or OCSP revocation,
certificate pin set, SPIFFE policy engine, automatic certificate issuance, ACME, or
automatic certificate-to-role mapping. Upstream verification cannot be disabled.
Secret zeroization is best effort within the documented process-memory boundary.
