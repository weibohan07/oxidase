# ADR 0016: passive resource lifecycle census

Status: accepted design; phase 7A.1 implementation and execution have separate
acceptance receipts. Workspace/API versions do not change.

## Decision and authority boundary

Add a process-local `ResourceCensus` in runtime, usable by server ownership units.
It observes creation, retirement/cancellation request, and actual final Drop.
It does not own a snapshot, endpoint, pool, socket, future, publisher or journal.
`PublishedRuntime` remains the only publication authority. Census state is never
consulted to admit traffic, choose an endpoint, refresh DNS, retire a transport,
change an ETag, grant an Admin permission or release a permit.

The authenticated read-only `/api/v1/resources` route uses existing `read`
permission. `/api/v1/runtime` retains its identity schema. Scrapes do not take a
mutation gate, sweep weak references, expire DNS members, recover health state,
close connections, delete artifacts or restart work. Maintenance remains in the
existing request/owner/publication paths. Existing pool inspection is separated
from explicit pool pruning; a registry entry count is not a live Client count.

## Units and ownership

| Unit | Creation and owner | Retirement / final release | Running expectation |
| --- | --- | --- | --- |
| preparation work | entering actual preparation | worker/future ends, including failed candidate | finite active preparation, never mislabeled as a constructed snapshot |
| snapshot instance | completed preparation or direct value Clone | successful replacement marks retired; actual last Arc releases fields and token | one current publication; old held bodies/tunnels may retain retired instances |
| Cluster / endpoint object | actual constructor, shared Resource graph | owner/member replacement; last owning Arc | current configured members remain; withdrawn leased objects may finish |
| admission family and permits | actual shared counter / successful issued permit | actual counter / RAII permit Drop | shared counters can serve current and old generations; no per-endpoint double counting |
| supervisor | scheduled before spawn | cancel requested differs from future Drop | committed owners only; old owner work must stop even while an old request survives |
| probe / resolver query | entering logical work, waiting then admitted | logical future Drop | quota wait is distinct from executing; this is not a count of Hickory's private tasks |
| pool entry | actual registry insertion | eviction/reconciliation/removal Drop | bounded registry ownership only |
| Client family | actual Client build, token shared through connector clones | final family token Drop, including Hyper's internal Client clones | registry retirement may precede final held-body/driver release |
| TCP / authenticated TLS IO | actual successful physical connection / handshake | socket-owning IO Drop, including warm/Upgrade ownership | current idle connections are legal; retirement is not an EOF assertion |
| warm slot / expiry task | actual accepted warm transport / scheduled expiry | consume, expiry, owner Drop / actual task exit | finite warm lifetime; cancelling timer is not completing it |
| executor / upload / dispatch cleanup future | captured scheduled guard before spawn | actual future completion/Drop | executor unbound work is mixed, not falsely labeled as a specific H1/H2 driver |
| response adapter / tunnel | actual owned adapter / trusted tunnel | terminal shell Drop / actual tunnel future Drop | completed body shell and pinned snapshot have different release boundaries |

Tokens are non-Clone ownership guards. Arc cloning shares a guard only for a real
clone family. Direct snapshot value cloning creates another instance in the same
census and remains a candidate until published. Successful publication bookkeeping
runs outside ArcSwap's retry closure. Snapshot roles are monotonic; delayed
publication bookkeeping cannot revive an already-retired snapshot. Draining is a
serving-state change, not a new snapshot or a retirement of the current publication.

Cancellation metadata is weak and cannot extend a future's lifetime. Guards are
captured before spawn, even when the runtime cancels a never-polled task. First
poll marks Running; cancellation already requested is not overwritten by that
mark. Destruction, not abort invocation or registry deletion, decrements live.

## Observation bounds and consistency

Metric labels are fixed resource-kind and lifecycle-state enums, never epochs,
digests, IPs, incarnation IDs, tokens, URLs or request data. Cumulative counts are
created/destroyed/published; live and state counts use checked updates. Underflow
or overflow increments a visible invariant-failure count, never a saturated fake
zero. Exact conservation is asserted only at controlled barriers/quiescence.

Samples declare their capture interval and update sequence and are not globally
atomic. Bounded details store only weak scalar metadata for selected long-lived
units, with 4096 entries. Actual guard Drop removes the record; reading never
performs GC. If that diagnostic capacity is exceeded, aggregate counts remain
available but oldest retired age becomes unavailable and untracked-live is
reported. Hot per-request units do not enter that detail table.

Hyper's private PoolInner allocations, checkout/connecting internals, and Hickory's
provider-internal tasks are not exhaustively observable. Client family, owned
executor futures and actual physical IO are separate auditable boundaries, not
a fabricated count of every allocation or all Tokio tasks. OS RSS/PSS/FD samples
remain independent evidence, not derivable from these counters.

The validation-only `OXIDASE_RESOURCE_OBSERVATION=off` switch disables process
observation; unavailable data must remain unavailable rather than reported zero.
It changes no admission, lifetime or publication policy. Enabled/disabled and
zero/low/high scrape experiments measure observer overhead and non-retention,
not production performance promises.

## Qualification boundary

Phase 7A.2 must separately verify sustained healthy traffic and explicitly bounded
fault windows, all started operation outcomes, complete DATA/trailers and Running
recovery before drain. Phase 7A.3 compares actual object and OS curves before any
retention change. No leak or allocator explanation is presumed. Missing mandatory
observations, unknown growth attribution or incomplete campaigns remain
INCONCLUSIVE/FAIL; merging observation code is not memory qualification.
