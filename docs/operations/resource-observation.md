# Resource observations (phase 7A.1)

The authenticated `GET /api/v1/resources` (also HEAD) uses the existing Admin
`read` permission. It is not another publication API. `/api/v1/runtime` keeps its
existing identity document; DNS, observation and scrapes do not change ETag,
RuntimeOrigin, serving state, permission, journal or CandidateStore history.

The alpha envelope is `oxidase.resources/v1`. `resources` contains fixed units
and states, with created/destroyed/published totals and live gauges. A live count
means a real ownership guard has not reached final Drop, not that a registry
contains that many names. Arc clones count once; a snapshot value Clone counts
as another candidate instance sharing its graph/resources.

## Read correctly

- `health_supervisor` counts scheduled and running owned supervisor futures, not
  manager map entries. `health_probe` separately counts logical probe futures,
  including global-quota waiting. Probe completion does not prove that every
  associated Hyper task or pooled socket closed.
- `proxy_pool_family` / `health_pool_family` count actual Client builds. Connector
  clones, including Hyper's internal Client clones, share the same family token.
  `*_pool_entry` instead counts registry ownership. Eviction marks the family
  retired but a held response/driver may retain it. A Current family means owned
  by a current registry entry, not proof that its endpoint is currently eligible.
- `upstream_tcp_connection` and `upstream_tls_connection` count actual socket IO
  and authenticated TLS IO ownership separately. Warm slots, timers, connect/
  handshake work, captured executor futures and upload pipes are separate units.
  Unbound Hyper executor work mixes connection/pool background futures; it is not
  falsely described as a complete count of H1/H2 drivers.
- `snapshot` Retired counts real replaced snapshot instances still retained.
  Body EOS/error/cancellation releases a snapshot pin. The response adapter shell
  can survive EOS and still count as `response_body` until its actual Drop.
  Trusted tunnel plans count Scheduled before execution and Running afterward;
  their natural completion/cancellation releases the existing snapshot/permits.
- `snapshot_preparation` covers runtime Resource preparation only, not earlier
  compiler/YAML work, Bundle verification or Asset spooling. A failed preparation
  is not mislabeled as a successfully constructed snapshot.
- `endpoint_admission` counts shared physical admission-counter families. Multiple
  endpoint objects/generations can share one family. `cluster_runtime` counts its
  shared container; outstanding Cluster/endpoint/retry permits are separate actual
  ownership units. Do not add endpoint-instance counts to infer permits.
- Supervisor/query/probe units cover Oxidase-owned work, not every private Tokio,
  Hickory, native resolver, Admin worker or allocator object. Existing downstream
  connection/stream/tunnel metrics remain separate. Uncovered internals are not
  fabricated zero measurements.

Snapshot Current/Retired roles are passive lifecycle markers. The production
manager serializes preparation from its current publication. Arbitrary library
users constructing multiple stores or republishing old shared Resource graphs
cannot interpret a single Cluster role as a multi-store authority/refcount; actual
created/destroyed/live ownership counts remain independent. Observation state is
never used to authorize publication or choose a lease.

The Cluster read view preserves `retired_admission_counters` as physical families
with outstanding admission and no current member. The separate
`stored_admission_tombstones` counts stored noncurrent weak slots, including dead
or inactive metadata. These are different units: observing a dead slot cannot
delete it or pretend it still owns a resource. Original owner/lease maintenance
still performs its bounded cleanup.

## Consistency and bounded detail

Samples report `capture_start_ms`, `capture_end_ms`, update sequence at each end,
in-flight mutations at each end and `globally_atomic: false`. Prometheus exports
those flags alongside fixed kind/state series. Different atomics can be observed
mid-update. Assert exact `created - destroyed == live` only at a controlled
quiescent barrier, not unconditionally on a busy scrape.

Underflow/overflow increments `invariant_failures`; it is a test/qualification
failure, not a saturated fake zero. No sample resets totals. Retired and Exiting
ages are distinct: requesting cancellation is not completing a future.

Selected long-lived units have weak scalar detail, capacity 4096. Drop removes
detail immediately; reads never sweep, evict, refresh or mutate resources. If
capacity/identity is exhausted, `detail_untracked_live` is nonzero and required
age observations become null. `age_supported: false` similarly means unknown,
not zero age. Fixed metric labels never contain object IDs, epochs, digest,
addresses, target names, tokens, URL/query, Header values or request identifiers.

For validation only, `OXIDASE_RESOURCE_OBSERVATION=off` disables process
observation. Disabled hot guards allocate no scalar record; responses then report
`enabled: false` and no resource rows, and resource-specific metrics are absent.
That is unavailable data and cannot qualify required resource observations.
Admission, TTL, lease, timeouts and publication are identical in both modes.

## Running is not Drained

Current snapshot, configured resources, health/DNS supervisors, reusable pools,
idle current connections and bounded Admin artifacts/history are legal while
Running. Old issued streams may retain retired objects until their actual terminal
event. Removing/replacing an owner nevertheless stops its background work without
waiting for an old stream to release its snapshot.

Pool registry bounds remain 1024 per Proxy/Health registry; DNS owners 128, members
256 per owner, DNS global query quota 64, active probes global/per-Cluster 64/32.
Current configuration fixes admission limits. Admin candidates/history/receipts
retain their existing independent configured count/byte bounds; they are not
cleared just to produce a pretty resource sample. The fixed weak-detail capacity
is a diagnostic bound, not a bound on legal active request ownership.

The phase-six soak monitor now fills `health_tasks` from actual supervisor tokens,
`pools` from the two actual Client-family gauges and `old_snapshots` from Retired
instances. It still retains null when any required series is missing/disabled.
This does not retroactively qualify the older phase-six null samples.

Phase 7A.2 separately adds healthy/fault workload accounting and an independent
analyzer. Phase 7A.3 must obtain attribution before changing retention policy and
must validate Running recovery separately from explicit drain. At this point
Linux resource/memory qualification remains NOT RUN/INCONCLUSIVE, not implied by
unit tests, an interface or a configured workflow.
