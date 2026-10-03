# ADR 0013: Upstream transport identity and operational discovery

Status: accepted design; delivery is split across phase 6A–6D.

## Context and trust boundary

Phase five's PublishedRuntime remains the sole configuration publication
authority. DNS observations are operational Resource state, not configuration,
Trust material, an Admin bootstrap update, or an activation receipt. Discovery
must not alter runtime ETag/revision/origin, reopen drained listeners, clear a
recovery-required journal, or restore Source authority over a Bundle.

## Identity and connection

The server separates a canonical logical origin (scheme, HTTP authority and base
path), the prepared TLS verification/SNI/Trust/client identity, and a validated
SocketAddr DialTarget. A per-attempt lease fixes these identities and admission.
The connector dials that exact SocketAddr; it never resolves the logical origin a
second time. Request URI, Host and H2 authority remain logical, not a fabricated
pool-key host or metadata Header. IPv6 authority uses typed URL host formatting.

Long-lived pools use unambiguous SHA-256 identity encoding over logical origin,
selected endpoint/address/port, protocol, prepared TLS security identity and
connection timing policy. Different endpoint selections cannot borrow an old H2
connection to a different address. Proxy and health checks share the connector
implementation and authenticated peer identity; health probes keep their own
budget and admission. Hyper's automatic unstarted-request retry is disabled so
explicit Cluster attempts remain the retry authority.

Registry removal releases idle pool ownership, not existing streams/tunnels.
Bounded pool retention and weak resource ownership prevent a permanently growing
generation-key cache. A removed-then-added discovered endpoint gets a fresh
incarnation; an old callback cannot mutate or reactivate the new member.

## Operational membership (6B/6C)

Prepare validates only static discovery/resolver policy. Commit starts one bounded
supervisor per committed Resource; cold unresolved Cluster traffic is a safe 503,
not a failure to start the gateway/Admin. An immutable EndpointSet and generation
are atomically observed. Lease issuance/removal share a linearization boundary:
already issued attempts may finish, but removed members receive no new leases.
Identical RR order-independent membership and TTL-only refresh reuse identities.

A/AAAA observations retain separate expiration and failure state. Expiration is
monotonic; refresh scheduling never extends freshness. Explicit deletion,
NXDOMAIN, policy rejection, invalid/limited answers and SRV target-dot withdrawal
do not resurrect stale members. Only documented transient failures may use the
fixed stale-if-error window anchored at the last successful expiration. TTL zero
is not a reusable fresh membership and cannot produce a busy refresh loop.

SRV first selects the lowest eligible priority, then a logical target using RFC
2782 zero-inclusive weights, then a valid address within that target. Address
expansion does not multiply target weight. Ordinary saturation is overload, not
permission to bypass priority or admission. DNS does not choose scheme, arbitrary
path, TLS authentication name, credentials or trust policy.

## Delivery boundary

6A exposes only fixed endpoints and upstream timing. 6B opens A/AAAA after its
runtime is implemented and rejects SRV. 6C opens SRV. 6D qualifies ownership,
Bundle/Admin/drain integration, resource reclamation and Linux campaigns. None
changes the workspace version or implements stage seven.

The exact resolver release, limits and executable acceptance evidence are recorded
when their stages are implemented. DNS wire parsing is delegated to a maintained
library, not a parallel protocol stack.

References: [locked Hyper connector boundary](https://docs.rs/hyper-util/0.1.20/hyper_util/client/legacy/connect/index.html),
[RFC 2782](https://www.rfc-editor.org/rfc/rfc2782.html),
[RFC 2308](https://www.rfc-editor.org/rfc/rfc2308.html),
[RFC 9520](https://www.rfc-editor.org/rfc/rfc9520.html).
Oxidase's Resource state/publication model is a project decision, not an RFC claim.
