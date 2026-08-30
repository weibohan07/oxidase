# Inbound TLS

Oxidase supports inbound HTTPS with rustls TLS 1.2/1.3, certificate Resources,
bounded handshakes, SNI selection, and ALPN. This remains an alpha interface and is
not a claim of production readiness.

## Certificate resources

Certificates are Resources, not Services:

```yaml
resources:
  certificates:
    public:
      cert_chain: ./certs/public.pem
      private_key: ./certs/public-key.pem

    api:
      cert_chain: ./certs/api.pem
      private_key: ./certs/api-key.pem
```

Paths are resolved relative to the source file that declares the Resource. `check`,
initial `serve`, and every reload prepare the certificate before publication:

- both paths must exist and be regular files;
- the chain must contain at least one parseable X.509 `CERTIFICATE` section;
- the key file must contain exactly one PKCS#8, PKCS#1, or SEC1 private key;
- encrypted private keys are rejected with a diagnostic that recommends an
  unencrypted supported key file;
- the private key must positively match the leaf certificate;
- each SNI mapping must reference an existing Certificate Resource and the selected
  leaf certificate must be valid for that declared DNS name.

Oxidase does not emit private-key contents or fingerprints through diagnostics,
Debug output, the compilation manifest, logs, or metrics. Certificate-chain and key
paths are reload dependencies. Certificate reuse identity covers the public chain;
the candidate private key is still reparsed and checked on every preparation before
old opaque signing state can be reused.

## HTTPS listener

```yaml
listeners:
  - name: public-https
    bind: 0.0.0.0:8443
    protocol: https

    tls:
      default_certificate: public
      sni:
        api.example.com: api
        "*.internal.example.com": internal
      handshake_timeout: 5s

    http:
      versions: [h2, http1]

    service:
      ref: public
```

`protocol: https` requires `tls`; `protocol: http` rejects it. The default handshake
timeout is `5s`. A timed-out or invalid handshake closes that connection without
publishing request data or changing the active snapshot.

Each Listener also has a fixed internal limit of 128 concurrent TLS handshakes.
Oxidase acquires that permit immediately after accept; when all permits are occupied,
the new socket is closed instead of creating an unbounded queue of handshake tasks.
The rejection is reported as the fixed `overloaded` transport result. This limit is
not user-configurable in the current alpha.

Oxidase uses rustls safe TLS 1.2/1.3 defaults with the pure-Rust-facing ring provider.
Cipher suites and protocol versions are not user configurable in this alpha.

## SNI selection

SNI mapping keys accept two forms:

- an ASCII DNS name such as `api.example.com`;
- one complete left-most wildcard label such as `*.internal.example.com`.

Names are compared case-insensitively after compilation. Selection order is exact
name, then a matching wildcard, then `default_certificate`. A wildcard matches
exactly one label: `a.internal.example.com` matches, while
`a.b.internal.example.com` and `internal.example.com` do not. Multiple or embedded
wildcards, wildcard IP addresses, trailing dots, empty labels, and invalid DNS
characters fail compilation. The certificate used by a wildcard rule must contain
that literal wildcard DNS subjectAltName.

Raw SNI is never a metric label. It can appear as a controlled tracing field and as
read-only request metadata.

## Atomic rotation

Certificate and Service changes participate in one prepare-before-commit
transaction. When listener name and bind are unchanged, Oxidase keeps the socket
bound. Each new accepted connection reads the newly published TLS/HTTP plan; existing
TLS connections retain the certificate and protocol state selected during their old
handshake. A malformed, encrypted, mismatched, or SNI-incompatible candidate is not
published, and last-known-good continues serving.

The request expression namespace exposes connection-derived values:

```text
request.scheme
request.http_version
request.tls.enabled
request.tls.server_name
request.tls.alpn
request.tls.version
```

Forwarded scheme metadata is derived from this accepted connection state rather than
trusted from client-supplied forwarding Headers.

## Not implemented

Inbound client-certificate authentication and custom Trust Stores are documented in
[`mtls.md`](mtls.md). This alpha does not implement ACME, CRL/OCSP revocation,
TLS 1.0/1.1, user-configurable cipher suites, QUIC/HTTP/3, automatic certificate
issuance, or certificate-to-role mapping. Do not configure publicly known test keys
for a real service.
