# DNS address and SRV discovery (phases 6B–6C)

Phase 6B adds A/AAAA address discovery; phase 6C adds SRV target groups to the
same existing Cluster/Proxy data plane.
This is alpha policy, not a DNS resolver product or a stable configuration API.
The implementation and its final Hosted/qualification evidence are tracked
separately in [the acceptance ledger](../verification/discovery-acceptance.md).
The selection contract is also recorded in
[ADR 0015](../adr/0015-srv-target-selection.md). Code and local tests are not a
substitute for the separate final-head Hosted checks or phase-6D campaigns.

## Configuration

Choose exactly one of `endpoints` and `discovery` for each Cluster. Do not leave
an empty `endpoints` field beside discovery. The logical origin is explicit:

```yaml
resources:
  clusters:
    api:
      protocol: h2
      discovery:
        dns:
          name: api.internal.example
          record: a_aaaa
          port: 8443
          origin: https://api.internal.example/base/
          resolver:
            nameservers:
              - 10.0.0.53:53
            query_timeout: 2s
          refresh:
            min_interval: 1s
            max_interval: 1m
            jitter_percent: 10
            stale_if_error: 30s
          limits:
            max_endpoints: 256
            max_targets: 32
          address_policy:
            allow_private: true
            allow_loopback: false
            allow_link_local: false
      tls:
        server_name: api.internal.example
        trust:
          system_roots: true
      timeouts:
        connect: 5s
        tls_handshake: 5s
        request_body_idle: 30s
        response_header: 10s
        response_body_idle: 30s
        pre_response_total: 60s
```

For `record: a_aaaa` (the default), `name` is an ASCII hostname, canonicalized to
lower case with a final DNS dot. An optional single input trailing dot is accepted;
IP literals, wildcards, underscores, empty labels and IPv6 zone identifiers are
not accepted. `port` is required and is `1..=65535`.

For `record: srv`, use the separate `_service._tcp.hostname` query grammar and
omit `port` entirely, including null. The port comes from each SRV record:

```yaml
discovery:
  dns:
    name: _https._tcp.api.internal.example
    record: srv
    origin: https://api.internal.example/base/
    resolver:
      nameservers: [10.0.0.53:53]
```

The SRV service/transport labels do not become TLS names. The service label is
nonempty ASCII letters/digits/hyphens with a leading underscore; `_tcp` is the
only accepted transport because the data plane dials TCP. `_udp`, wildcard/IP
suffixes, empty labels and multiple final dots fail at the name's source span.
Input case normalizes to a lower-case FQDN. Unknown record types are rejected.

`origin` is a fixed HTTP(S) logical authority and optional base path, without
credentials, query, fragment or control characters. Its authority port and the
physical A/AAAA dial `port` or SRV record port may differ deliberately. DNS answers
do not choose the scheme, HTTP Host/H2 authority, base path, SNI/verification name, Trust Store or
client certificate. Existing [upstream TLS/mTLS policy](mtls.md) applies to
HTTPS discovery origins even before any addresses are resolved.

## Resolver policy and limits

Omit `resolver.system` and `resolver.nameservers` to use local system resolver
configuration, or explicitly choose `system: true`. Otherwise provide 1–4
explicit IP:port `nameservers`, with no `system` field. Hostnames as nameserver
addresses, `system: false`, null/empty lists and mixed selectors fail compilation.
Mapped IPv4 nameserver addresses normalize to IPv4; nameservers are canonicalized,
sorted and deduplicated. Query timeout defaults to 2 seconds.

The maintained asynchronous stub resolver handles DNS wire parsing, UDP and TCP
fallback for truncated UDP replies. No public DNS, Docker or external binary is
needed by the regression fixtures. This is not recursive resolution, DNSSEC
validation, DoH, DoT, mDNS or a service registry.

Per candidate, at most 128 discovery Clusters are accepted. Each policy permits
`max_endpoints` in `1..=256` (default 256), a cap on physical members across both
families, and `max_targets` in `1..=32` (default 32), a cap on distinct logical
query/CNAME names including the initial service name and distinct SRV targets—not
IP address count. Resolver
responses additionally have fixed limits: 512 aggregate records, 65,535 encoded
bytes and CNAME depth 8. Parallel work, query coalescing and retained state are
bounded by the owned runtime; application requests do not start ad-hoc lookups.

`query_timeout`, `min_interval` and `max_interval` are positive and at most 24h.
`max_interval` cannot be smaller than `min_interval`. `stale_if_error` may be zero
to disable stale use, otherwise is bounded to 24h. `jitter_percent` is `0..=100`.
The defaults are 1s / 1m / 10% / 30s respectively.

## Expiration is not refresh scheduling

A and AAAA observations keep separate absolute monotonic expirations. CNAME
edges constrain the final address lifetime; a later answer cannot restart an
earlier edge's TTL. Refresh can occur earlier than expiry, but `min_interval`,
backoff or jitter never turn an expired address into a fresh member. No second
completed-answer cache restarts TTL at each read.

TTL zero is not reusable fresh membership. It does not cause a zero-delay busy
loop. A short TTL can expire before the next permitted refresh; new leases then
observe unavailability rather than an artificially extended TTL. Stale use is
explicit and anchored at the last successful expiration, never at the latest
failed refresh.

| Resolver observation | Membership / stale behavior |
| --- | --- |
| Positive A or AAAA | Reconcile that family's permitted, deduplicated addresses with their original expirations |
| NXDOMAIN | Withdraw the name; do not preserve revoked addresses as stale |
| NODATA | Withdraw only that record family; a valid other family remains independent |
| Timeout, network failure, SERVFAIL, REFUSED | May use the previously accepted family within its original expiration plus fixed finite `stale_if_error` window |
| Policy rejection, malformed answer, record/target/depth limit | Reject the affected result without stale-resurrecting unsafe addresses |

Valid SOA-derived negative lifetimes control bounded retry scheduling, with CNAME
lifetime bounds where applicable. Failure backoff and response-order changes do
not renew positive or stale deadlines. A query is coalesced per committed owner,
not multiplied by concurrent business requests.

REFUSED is treated as temporary refusal by the configured resolver, not as
authoritative name withdrawal. This project allowlist only retains previously
approved addresses under the unchanged address/identity policy and original
expiration plus finite grace; it does not accept a new unsafe address or extend
the grace on repeated refusal. NXDOMAIN/NODATA remain explicit withdrawal.
Production refresh jitter mixes OS-seeded randomness with the static Cluster
identity; deterministic schedule tests inject a seed. Jitter changes scheduling,
never record freshness or the stale deadline.

## SRV target selection and address expansion

An SRV record keeps its canonical target, port, priority, full `0..=65535` weight
and original expiry. Target selection first uses the lowest numeric priority
that has a health-eligible target, then applies RFC-2782-style weighting
at that priority. Zero weights participate in the inclusive zero draw with
randomized ordering; an all-zero priority selects uniformly. Tests inject seeds;
production does not allocate an array proportional to the weight sum.

Configured `round_robin`, `weighted_round_robin` or `least_requests` applies only
to physical addresses within the selected target. Those address weights are one:
three A/AAAA addresses do not triple that SRV target's weight. Admission
saturation may try another eligible target at the same priority; it is not a
health failure and cannot silently send traffic to a backup priority. A fully
saturated eligible priority returns `UpstreamOverloaded`/503.

Identical target/port/priority/weight records deduplicate using the smallest
expiry. Different weights for the same target/port/priority are an invalid
answer, independent of response order. The same target at different ports or
priorities retains the distinct record policies. Weight/priority-only changes
do not change physical health/pool identity; remove/re-add does create a fresh
incarnation. The logical target is resolved once per A/AAAA family, not once per
port or priority. The original target remains identity through a bounded CNAME
lookup. Accepting a target alias is explicit Oxidase interoperability policy;
operators should publish non-alias targets, and this is not a claim of strict
RFC-2782 non-alias conformance.

A sole logical SRV record with target `.` withdraws the service immediately and
sends no target address queries. Identical dot/port/priority/weight tuples
deduplicate even if their TTLs differ; distinct all-dot tuples or a response
mixing `.` and ordinary targets are invalid. Missing,
withdrawn, malformed or policy-rejected targets cannot be stale-resurrected.
Successful SRV resolution preserves each target family's structured result:
one slow target does not discard another target's already received addresses.
Pending work at the one whole-round query deadline becomes a bounded timeout.
The attempt expiry is the minimum of the SRV record, final address and every
CNAME edge's original absolute expiry—not the time all children finish.

The same closed transient-error allowlist may retain previously approved
membership only until its original expiry plus finite grace. A failed whole
service lookup and a failed individual target are distinct observations; neither
renews TTL, stale lifetime or a business request's pre-response deadline.
DNS wire record counts and encoded retained-result size are bounded across the
round. Hickory enforces the physical 65,535-byte packet bound; raw negative/error
EDNS bytes that the resolver discards are not falsely counted as observable
aggregate result bytes. There is no second DNS parser to intercept those packets.

## Address policy and actual dialing

Private IPv4 RFC1918 ranges and IPv6 ULA are allowed by default for internal
gateway use. Loopback and link-local are independently denied by default.
Unspecified, multicast and broadcast addresses are always rejected as business
targets. IPv4-mapped IPv6 normalizes before applying the same rules. IPv6 zone
identifiers are unsupported.

Mixed replies filter forbidden addresses; a permitted address is never replaced
by a forbidden fallback. An entirely rejected family is policy-unavailable. An
attempt lease fixes the validated SocketAddr and authentication identity, and
the existing connector dials that exact address without resolving the logical
name again. Health checks use the same boundary with independent probe quotas.

## Publication, streams and observation

Preparation/check/Bundle verification validate static contracts and local resolver
inputs without relying on current DNS reachability, sending a query or starting a
long-lived refresh supervisor. Local system resolver configuration is read-only
input validation; pre-commit prepared discovery ownership freezes the actual
resolver inputs before activation. Reusing the same compatible owner does not
reread OS DNS configuration on each refresh or request. A policy replacement or
process restart is required to adopt changed local system resolver settings.
Publication starts initial resolution. Cold or
expired membership fails only that Cluster with safe `UpstreamUnavailable`/503;
it does not redefine the gateway's existing readiness contract.

DNS generation is operational Resource state. It never changes
PublishedRuntime's ETag, revision, RuntimeOrigin, source authority, CandidateStore
current/history, recovery-required state or fixed Admin bootstrap. A DNS refresh
cannot reopen drained listeners. Existing conditional Admin operations keep the
same publication preconditions.

Lease issuance and membership removal share a linearization boundary. Already
issued streams/attempts may finish; removed members receive no new leases, and
new requests cannot borrow their old H2 pools. Order-only or TTL-only updates keep
compatible member identities. A removed-then-added address has a fresh incarnation
so late health/DNS callbacks cannot resurrect it. Retired idle pools and query
tasks release owned state without cancelling an already leased stream.

Retries stay in the request's pinned configuration policy, with bounded attempt
history and the same absolute pre-response deadline across generation changes.
They do not gain time or implicit replay merely because DNS changed.

The authenticated read-only `/api/v1/clusters` view can report bounded configured
policy, resolution state, generation, eligibility, expirations and closed error
codes. DNS IPs, targets, generation and error messages are not Prometheus labels;
dynamic metrics aggregate under configured Cluster names and closed result enums.
Offline Explain describes the policy, not an invented current address.

## Bundles and current boundary

Portable plans serialize only fixed discovery/resolver/origin/address/timeout
policy and source provenance, never current answers, health, pools, generation or
expiration timestamps. Discovery requires both `dns-address-discovery` and
`upstream-deadlines` manifest capabilities. SRV additionally requires
`dns-srv-discovery`; an address-only runtime rejects that required feature before
preparation. Stripping the declaration while keeping an SRV plan also fails
before activation. Missing declarations and unsupported features are rejected;
old static and A/AAAA Bundles remain compatible, including their numeric `port`
encoding. SRV plans omit the port; explicit null is never equivalent to absence.

Active Linux qualification and phase-six fuzz campaigns are not implied by this
document. Their actual execution belongs to the separately gated phase-6D stage
recorded in the acceptance ledger. There is no new
DNS-cache mutation API, DNSSEC claim or change to fifth-stage Admin authority.
