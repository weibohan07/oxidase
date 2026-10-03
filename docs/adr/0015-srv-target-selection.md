# ADR 0015: SRV target groups and bounded address expansion

Status: phase 6C design, implementation and acceptance tracked separately in
[the phase-six ledger](../verification/discovery-acceptance.md).

## Boundary

SRV is operational discovery in the existing prepared Cluster resource, not a
new Service or publisher. It cannot change HTTP scheme/authority/base path,
verification/SNI name, Trust/client identity, ConfigVersion, PublishedRuntime,
CandidateStore, source authority or drain permissions. `record: srv` additionally
requires the `dns-srv-discovery` Bundle capability. Its physical port comes only
from SRV; a declared static discovery port, including null, is rejected.

The source name is a canonical ASCII `_service._tcp.hostname.` DNS query name.
UDP service labels are rejected because this runtime connects TCP. That query
name is never an HTTP Host or TLS authentication name. Existing fixed `origin`
and TLS override policies still control those identities.

## Selection is two-level

An SRV record retains target, priority, full zero-inclusive 16-bit weight, port
and original expiry. First find the smallest numeric priority with a currently
health-eligible target. At that priority, choose a logical target using RFC 2782
weighting. Zero-weight targets participate at the inclusive zero draw; their
order is randomized so mixed zero weights are not permanently shadowed. An
all-zero level chooses uniformly rather than treating every target as disabled.
Tests inject a seed and use deterministic boundaries/wide distribution bounds.

Only after target selection does configured round_robin,
weighted_round_robin or least_requests choose a physical address within that
target. Address weights are one. Three addresses therefore do not triple an
SRV target's weight. There is no array proportional to the sum of weights.

Health eligibility and admission are different. Saturation may try another
eligible target at the same priority, but cannot silently use a higher numeric
backup priority or reinterpret saturation as unhealthy. If that entire priority
is saturated, return overload. Backup priority is available only after lower
priorities have no eligible targets. Retry attempt/queue/history/semaphore
limits and one logical absolute pre-response deadline still apply.

## Identity and reconciliation

Physical membership identifies configured Cluster, canonical original logical
target, actual address and SRV port. Priority and weight are selection metadata,
not pool/health identity. Weight/priority-only and order/TTL-only changes preserve
compatible health, admission, incarnation and connection pools. Identical records
deduplicate with the smallest expiry; conflicting weights for identical
target/port/priority are rejected instead of depending on packet order. The same
target at different ports or priorities keeps those record policies distinct.

One canonical target is resolved once per A/AAAA family even when records mention
multiple ports or priorities. The original target remains group identity if its
address lookup follows a bounded CNAME. Supporting such aliases is an explicit
interoperability choice, not a claim of strict RFC 2782 non-alias target adherence;
operators should publish non-alias targets. Every CNAME expiry narrows the result.

The lease gate and current-member checks remain the 6B linearization boundary.
Removal ends new lease/pool eligibility; issued streams may finish. Remove/readd
uses a new incarnation and fresh health while preserving any nonzero physical
admission safely. Every callback/query/queue/retry is fenced to its committed
owner session. A retired session cannot obtain leases after an explicit resume.

## Lifetimes and failures

DialTarget validity is constrained by the SRV record, target A/AAAA record and
every CNAME edge's original absolute monotonic expiry, never by time of joining
all child lookups. Expiry and refresh scheduling remain distinct. A failed query
does not restart any positive/stale lifetime or a business request deadline.

NXDOMAIN/NODATA withdraw the corresponding service or family. Sole target `.`
withdraws the service immediately, sends no target address queries and cannot use
stale. Mixing `.` with ordinary targets is invalid rather than ambiguous. Policy,
malformed and limit failures cannot justify stale resurrection. Only the same
fixed 6B transient allowlist may use finite grace anchored at original expiries.

Partial target/family failures are retained as structured observations. When the
SRV query succeeds, a slow target cannot discard already received valid results
from another target; pending work at the single round deadline becomes an explicit
bounded timeout and is cancelled. An already-expired result stays expired. Whole
service lookup failure is distinct from an individual target failure.

A valid service RRset with an independently failed target/family remains a
positive partial round for scheduling and metrics. Only rejection of the complete
positive input enters whole-service failure backoff. Original positive deadlines
and the earliest target retry deadline still bound the next refresh.

The owner-local target failure memo contains at most two family entries per
configured target cap and is pruned on target withdrawal. Negative SOA/CNAME
expiry is retained as an original observation, but query suppression is capped
at `max_interval` just like whole-service negative scheduling. Re-reading the
memo does not slide either deadline. This deliberate early requery ceiling avoids
a one-day target outage under a sixty-second configured refresh maximum; it
neither extends positive freshness nor authorizes stale data.

## Resolver work and observation

The pinned raw Hickory pool remains the only DNS wire implementation. The full
round uses one absolute query deadline, bounded target futures, 64 global query
permits, 512 aggregate observable records, 65,535 encoded result bytes, eight CNAME edges, 32 distinct
logical query names and 256 physical members. A parent does not retain a query
permit while waiting for its admitted children. No implicit completed-answer
cache, second DNS lookup or per-business-request discovery is added. Hickory
enforces the 65,535-byte physical packet bound. The aggregate result budget charges
positive response buffers and re-encoded retained negative authority/glue data;
the raw pool does not expose discarded negative/error EDNS payload bytes, so this
budget is not falsely described as measuring every error packet's original wire
bytes. No parallel DNS wire parser/interceptor is introduced to manufacture that
observation. Oversized retained negative data still fails closed without stale.

Dynamic target/IP/port/priority/weight/incarnation values never become metric
labels. Bounded authenticated Cluster status may describe selection metadata;
Prometheus series remain configured Cluster names and fixed enums. Explain
describes the policy and explicitly leaves endpoint choice to runtime state.

Reference: [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782.html).
The resource/session/admission and failure choices above are Oxidase alpha policy,
not a claim of a complete general-purpose DNS or RFC conformance implementation.
