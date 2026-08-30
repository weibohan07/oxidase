# Mutual TLS and custom trust

Oxidase supports custom PEM Trust Store Resources, inbound client-certificate
verification, and upstream server/client authentication over rustls TLS 1.2/1.3.
These remain alpha contracts and are not a complete certificate lifecycle or
authorization system.

## Trust Store resources

```yaml
resources:
  trust_stores:
    clients:
      ca_bundle: ./pki/client-ca.pem

    internal-upstreams:
      ca_bundle: ./pki/internal-ca.pem
```

The bundle path resolves relative to the declaring source file. It must be a regular
ASCII PEM file no larger than 16 MiB and contain at least one `CERTIFICATE` section.
Only certificate sections and whitespace are accepted; private keys, comments, and
other PEM objects fail preparation. Duplicate certificate DER is removed and source
order does not affect the prepared digest.

Trust Stores are public CA material, not Secret Resources. Their paths participate
in dependency watching. A missing or invalid rotation rejects the candidate and
leaves last-known-good active.

## Inbound client authentication

Client authentication is configured under an HTTPS Listener:

```yaml
resources:
  certificates:
    gateway:
      cert_chain: ./pki/gateway.pem
      private_key: ./pki/gateway-key.pem
  trust_stores:
    clients:
      ca_bundle: ./pki/client-ca.pem

listeners:
  - name: internal-api
    bind: 0.0.0.0:8443
    protocol: https
    tls:
      default_certificate: gateway
      client_auth:
        mode: required
        trust_store: clients
    http:
      versions: [h2, http1]
    service:
      ref: internal-api
```

The modes are:

| Mode | Trust Store | Anonymous client | Invalid presented certificate |
| --- | --- | --- | --- |
| `none` | forbidden | accepted | certificate is not requested |
| `optional` | required | accepted | handshake fails |
| `required` | required | handshake fails | handshake fails |

`none` is the default. Client authentication is available for both TLS HTTP/1.1 and
HTTP/2 because it is completed before ALPN selects the HTTP connection driver.

Only a certificate chain accepted by rustls becomes request metadata. An anonymous
optional-auth connection receives the empty identity. The read-only request
namespace contains:

| Field | Meaning |
| --- | --- |
| `request.tls.client.verified` | `true` only after successful certificate verification |
| `request.tls.client.sha256` | `sha256:<64 lowercase hex>` fingerprint of leaf DER, otherwise null |
| `request.tls.client.subject` | informational rendered subject, otherwise null |
| `request.tls.client.dns_sans` | sorted, deduplicated verified DNS SAN strings |
| `request.tls.client.uri_sans` | sorted, deduplicated verified URI SAN strings |

Identity extraction is bounded to 64 DNS/URI SAN entries and 4 KiB of subject or
aggregate SAN text. Other GeneralName kinds are not exported. These fields are
available to existing expressions and templates, but they are not metric labels.

mTLS performs transport authentication only. It does not grant a role. Do not use
the subject DN as a stable principal; choose a verified SAN or leaf fingerprint and
define how certificate rotation affects authorization. In `optional` mode, always
test `verified` before using any identity field.

### Inbound rotation

Client-auth mode and Trust Store digest are part of the immutable Listener transport
plan. When Listener name and bind are unchanged, a successful trust rotation keeps
the socket bound. Existing connections retain the old completed handshake and
identity; new connections use the newly published Trust Store. A malformed or empty
CA bundle is not published.

## Upstream TLS and mTLS

An HTTPS Cluster may select system roots, one custom Trust Store, or both:

```yaml
resources:
  certificates:
    upstream-client:
      cert_chain: ./pki/upstream-client.pem
      private_key: ./pki/upstream-client-key.pem

  trust_stores:
    internal-upstreams:
      ca_bundle: ./pki/internal-ca.pem

  clusters:
    api:
      protocol: h2
      endpoints:
        - name: api-a
          url: https://10.0.0.10:8443
      tls:
        server_name: api.internal.example
        trust:
          system_roots: false
          trust_store: internal-upstreams
        client_certificate: upstream-client
```

`tls` is rejected when every endpoint is cleartext HTTP. For a Cluster with HTTPS
endpoints:

- omitting `tls` uses system roots;
- `trust.system_roots` defaults to `true`;
- `trust.trust_store` adds the named custom CA set;
- setting `system_roots: false` selects custom roots only;
- disabling system roots without a custom Trust Store is invalid;
- `client_certificate` sends a prepared Certificate Resource as the upstream client
  identity.

When `server_name` is absent, each HTTPS endpoint's URL host is its verification
identity. A configured DNS name is used for both verification and SNI. A configured
IPv4 or unbracketed IPv6 address is used as an IP verification identity and does not
create a DNS SNI value. The field accepts one exact ASCII DNS name or IP address;
wildcards and verification bypasses are rejected.

The same prepared TLS policy is used by Proxy requests and active health checks.
The Cluster's existing `auto`, `http1`, or `h2` protocol policy still determines the
upstream HTTP connection behavior.

### Pool identity and reload

Proxy and health-check pool keys include a digest of the effective upstream TLS
policy. That digest includes the accepted system roots, custom Trust Store,
client-certificate public chain, fixed verification name, and Cluster identity.
A change to any of these cannot reuse an incompatible connection pool.

New snapshot work uses the new pool. Work pinned to an older snapshot may complete
on the old pool, after which weakly retained incompatible pools can be released.
Compatible policy reloads continue to use long-lived pools. TLS preparation occurs
before commit; an unavailable native root set, invalid Trust Store, missing client
certificate, or invalid verification name preserves last-known-good.

## Security limitations

There is no `dangerous_skip_verify` or equivalent source option. This alpha does not
implement CRL/OCSP revocation, certificate pin sets, SPIFFE-aware policy, automatic
certificate-to-role mapping, client-certificate forwarding, ACME, or automatic
certificate issuance. Private keys remain file-backed Certificate Resources; use
the existing certificate-file permission and rotation guidance.
