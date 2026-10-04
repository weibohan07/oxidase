# Resource retention attribution: 7A.3

The protected starting main for this evidence stage is
`54b0fc65be52b72f3354791674905b9205277f3a` (PR #21). Its independent push run
`37197386244` passed all four required jobs, after final PR head `98c5de6` passed
`37196664266`. These are implementation checks, not a memory qualification.

This stage must not change publication authority, Admin authentication, DNS
membership/leases, verified dial identity, pool reuse, logical request deadlines,
streaming frames or current version. There is no assumption of a leak. No
allocator replacement, trim, forced connection close, cache/history purge or
restarting gateway is a permitted production fix.

## Falsifiable hypotheses

| Hypothesis | Predicted independent evidence | Counter-experiment | Current conclusion |
| --- | --- | --- | --- |
| unnecessary old snapshot pin | retired snapshot/age follows publications after old flows finish | freeze publication, continue traffic, then Quiet Running; controlled old-flow release | INCONCLUSIVE until raw Linux measurements are analyzed |
| pool/physical connection retirement incomplete | registry entries and live family/IO diverge beyond relevant maintenance windows | delete/re-add targets, finish issued work, compare Running and post-drain separately | local registry cap is proven, process-wide family/IO bound is not |
| health/DNS task retained | running/exiting task count accumulates with owners/generations | retirement barrier, delayed callback, fixed healthy Recovery | implementation barriers pass; runtime curves pending |
| bounded cache filling | entry/byte growth saturates at declared owner capacity | bounded-scale saturation, no-scrape and background-only controls | capacity varies by owner; no peak-derived bounds permitted |
| legitimate Admin receipts/audit/history | growth follows successful mutations, stays within existing retention rules | fixed DNS/no publication and existing count/byte eviction tests | CandidateStore history is metadata, not retained RuntimeSnapshot; volatile recovery container global bound unproven |
| allocator retention/fragmentation | object/allocation evidence stable while resident private pages remain | external allocation stacks plus RSS/PSS/Private_Dirty, separate profiled and normal release runs | NOT ATTRIBUTED; a positive/flat RSS line alone proves neither hypothesis |
| observation itself changes growth | growth follows scrape rate with otherwise matched full-success load | pure reads, low/high/zero periodic scrape and observation-disabled comparison | three actual matched Respond controls completed; all positive drift remains INCONCLUSIVE, cross-machine values do not identify causation |

## Proven local boundaries are not global bounds

- Proxy/Health registries each have 1024 entries; evicted issued clones, response
  shells, connector/executor ownership and physical IO are distinct units. That
  limit cannot bound every live Client family or established connection.
- Health network admission is 64, but waiting probe futures count too; each live
  supervisor enters at most 32 probes. The manager map length is not task count.
- Discovery owners are capped at 128; one round per owner, at most two A/AAAA or
  four SRV target query futures per owner, with 64 network admissions. Hickory
  private tasks/queues/sockets are outside this census.
- SRV failure memo storage is at most twice configured max targets (max 64 per
  resolver). Expired `not_before` stops a hit, not necessarily entry retention;
  positive/replacement/owner Drop maintenance is separate.
- hyper-util 0.1.20 checks idle age greater than 90 seconds on a 90-second sweep.
  Its current IdleTask is legitimate in Quiet Running; this is not a guaranteed
  90-second actual IO/driver destruction time. The fixture observation budget
  was corrected from 120 to 210 seconds before formal measurement, based on that
  locked source plus fixture body/head/scheduling margins, not observed peaks.
- Warm slots have an independent 90-second weak expiry. Each surviving connector
  has at most one slot; the total is not inferred from preconnect admission.
- Compile gate 1 and control channel 8 do not bound every prepared candidate:
  callers awaiting send may hold candidates. Current SnapshotStore has one
  published owner; old pins and value-cloned candidates are additional objects.
- A response adapter may release request/snapshot ownership at EOS while its
  shell remains alive. A live body-object count is not the active-request count.

Library-private buffers, TLS caches, downstream IO, site/certificate/Secret byte
storage, and retained allocation stacks need their own evidence. None is filled
with zero because the census cannot expose it.

## Evidence and permitted conclusions

Short baseline `37197630141` uses exact main `54b0fc6`, normal locked release,
independent H/C runners, seed 700211, 30/300/120/60/60-second phases, concurrency
8 plus separate cancellation/Upgrade lanes, 32768-byte responses, 1 MiB uploads,
and actual 1-second OS/Admin sampling. Both original jobs finished FAIL, with
archive checksums and byte-identical independent replay preserved.
Its durations do not satisfy H-final/C-final minima. Raw failures must remain.

| Original load | Offered / received | Complete success / intentional cancel / Upgrade / transport error | Actual stopping/result boundary |
| --- | ---: | ---: | --- |
| H | 112763 / 112763 | 111796 / 427 / 432 / 108 | all five short phases complete; every transport error follows the configured 1000-request connection retirement |
| C | 12346 / 12346 | 12264 / 37 / 37 / 8 | canonical SRV target comparison failed about 11.155 s into steady; Recovery/Quiet/drain never began |

H's actual phase durations were 30.1051/300.1080/120.0841/60.0018/60.0065 s.
Steady RSS baseline/peak/final was 27660/30872/30448 KiB, with full-phase slope
+8.773 KiB/s; PSS was 25310/28446/27238 KiB from 29 actual smaps captures.
Recovery RSS was 30448/30972/30080; Quiet Running 29708/29708/28324. FD was
33/35/33 steady, 33/35/33 recovery, 24/24/22 quiet and 21/21/21 post-drain.
This is positive resident drift, not proven retained allocation or a leak. Its
memory attribution remains INCONCLUSIVE and its traffic validation remains FAIL.

Snapshots peaked at one with no retired instance in this fixed H load; final
created/destroyed/current was 10/9/1. Health/discovery supervisors were each one
while Running and zero post-drain. Proxy families peaked at four (retired peak
one, max observed retirement age 1196 ms) and ended at zero; current health
families and physical TCP/TLS each ended at two, with six upstream executor
futures. Upload/response/tunnel/warm/expiry ended at actual zero. Current health
pool/idle executor retention is a distinct legal owner, not a failure to make
every gauge zero. C's incomplete 41-second record proves no memory recovery.

Confirmed **validation**, not production-retention, repairs:

- Admin SRV targets are canonical `a.discovery.test.` / `b.discovery.test.`.
  Exact weight/priority/identity validation now uses those actual bytes; no
  deadline extension, name-policy change or relaxed weight check is involved.
- Normal downstream connections retire after the fixture's explicit unchanged
  1000-request budget. A client must actually close/join at that boundary before
  submitting a new logical operation; it must not reuse the already-retired
  sender, silently replay a POST/gRPC operation or whitelist healthy errors.
  Separate retirement Started/Terminal records and per-worker histogram flush
  prove the old completion → actual driver join → next admission ordering.
  Existing errors remain recorded, and missing acknowledgement is fatal.

Original archives: H artifact `11302070528`, SHA-256
`ce1103790ee750d713d32686d563b4aa19893c750758f9c5f551fa409a46c95b`;
C artifact `11301424456`, SHA-256
`11540e78491b8e8016d8cde6cc67dccad0dd8d06a8b060d39f5a3dbbbe859c70`.
Original per-file manifests verified 33 H / 35 C files; repeated independent
analysis equals the uploaded original reports. New repairs require new runs.

The first repair repeat, normal release `37199862567` at `6ccab8e`, seed 700212,
kept the same phase/load parameters. Both sealed originals remain **FAIL**;
[their verified source/binary/PID/phase/counter/curve index](artifacts/resource-7a-6ccab8e-hosted-failures.json)
records 34 H / 36 C checked files and identical independent replay. H conserved
111263 operations and 105 actual connection-retirement pairs, but retained three
unexpected replies: one warmup HTTP/1 transport failure and two complete safe
503s in healthy steady traffic. These are **not** whitelisted or explained by the
quota repair. Their causal investigation is separate from resident attribution.

C conserved 69828 operations and 53 retirement pairs before stopping at
`resource.control_not_triggered:positive_aaaa_counter`. The same-window probe
actually completed 200, all 32768 bytes and EOF through `[::1]`; the fixture's
AAAA answer counter increased by three. This configuration resolves **SRV**:
the supervisor's round metric has `family="srv"`, not a top-level `aaaa` plan.
The validation repair requires all of the original raw fixture AAAA delta,
complete physical IPv6 response, actual SRV positive-round increase and fresh
canonical SRV membership generation in a predeclared 30-second window. It does
not relabel production metrics, change DNS leases, extend request deadlines or
accept an unrelated global counter. Original C lacks Recovery/Quiet evidence.

An external allocation-stack experiment is deliberately separate: fixed
heaptrack 1.5.0 source/checksum, dependency/license/permission inventory and
own-process PID/start/binary validation; no allocator replacement or Yama bypass.
`allocation-launch` / `allocation-attach` on the registered manual workflow use
`{"duration_seconds":60,"concurrency":4}`. The separate release-with-debug
fixture is HTTP/1 Proxy/Asset, not TLS/H2 H/C qualification. `CAPTURED` means
only a bounded trace was actually collected and parsed; unfreed-at-exit values
are not proof of a leak. Late/unjoined sampler, full-response deadline and PID
ownership negative tests must reject false capture. Actual attempts and their
failures are preserved separately; completion of the native build does not
prove collection, parsing or source attribution.

### Subsequent original failures and matched controls

[The original failure index](artifacts/resource-7a-876dbdb-097c6ec-hosted-failures.json)
preserves C run `37201451796` at `876dbdb` (seed 700213) and formal C run
`37204003262` at `097c6ec` (seed 700214), including exact binary/PID identities,
provider archive hashes, all per-file checks, and identical frozen-analyzer
replay. Neither completed Recovery Running or Quiet Running; those missing
measurements remain null.

The first hit the unchanged 64-MiB error-journal cap: unwindowed TTL-zero
withdrawal had generated tens of thousands of complete 503s. The repair defines
TTL zero as its own finite physical fault/restore window, not a new production
lease rule. A bounded contiguous-range journal now preserves only individually
received, identical complete safe 503s inside a single allowed C window; it
never compresses healthy errors, transport failures, cancellation or partial
bodies. Independent negative tests reject lost, overlapping, cross-window or
incorrectly fingerprinted ranges. The original truncated file remains FAIL.

Formal C then conserved all 88364 offered/terminal operations and its compact
record stayed within capacity, but stopped after 54.465 seconds of steady with
`resource.control_peer_recovery_unproven:dns_readd`. Raw probes already proved
a complete fresh B followed by a complete fresh A inside the same original
12-second recovery deadline. The sequential A-then-B helper discarded B while
looking for A. Its repair retains a shared physical-peer witness set, verifies
each full body/metadata/EOF, and applies one unchanged deadline measured from
the actual window end. It neither changes load balancing nor retries business
requests. A fixed finite probe cap is additional to, not a replacement for,
that common deadline. The eight new B streams in the original held-flow proof
remain mandatory.

That original also contains an unacknowledged warmup body cancellation and
eleven H2 large-upload response-head transport errors inside an NXDOMAIN
window allowing **only complete 503s**. Those facts are not excused by the
controller repair, safe root error mapping, or a gateway cancellation metric.
Their upstream physical Drop/reset causes remain unproven; no broader fault
allowance or production protocol change is justified by this coarse evidence.

[Three actual Respond-only scrape controls](artifacts/7a3-097-respond-scrape-controls.md)
ran at the same frozen source/seed/phase recipe on independent Linux runners:
first/final-only, 1-Hz and 4-Hz Admin sampling, with independent 1-Hz OS capture.
All 170467 / 170443 / 170522 operations were fully verified 16-byte responses,
with no abandoned or unexpected workload terminals. Steady RSS increments were
676 / 620 / 480 KiB, respectively. These controls do not exercise upstream
pools, health or DNS; absent periodic Admin cannot prove Running lifetimes.
They do not establish a scrape-rate effect or assign those pages to an
allocator. All three independent reports remain INCONCLUSIVE.

### Complete formal healthy load (H), still INCONCLUSIVE

[The sealed H index](artifacts/resource-7a-097c6ec-formal-h.json) records source
`097c6ec`, run `37204003262`, artifact `11305298669`, all 35 verified files
and exact frozen-original-analyzer replay. Actual phase seconds were
180.088 / 3600.031 / 900.071 / 300.019 / 300.005. The normal release remained
Running through recovery and Quiet; explicit drain came only afterward.

All 1185958 offered operations were received: 1176872 complete ordinary/gRPC
responses, 4463 actual acknowledged cancellations, 4623 complete Upgrade
exchanges. All 1178 deliberate connection retirements had actual join receipts.
No unexpected workload outcome or FAIL finding was observed in this exact H
capture. This conclusion applies to that source/configuration/platform/seed,
not every protocol behavior or the later C tools.

| Phase | RSS baseline / peak / final KiB | FD baseline / peak / final |
| --- | --- | --- |
| 60-minute steady | 29636 / 32976 / 31404 | 33 / 35 / 33 |
| Recovery Running | 31228 / 32420 / 29528 | see original time series |
| Quiet Running | 28632 / 29748 / 29120 | 24 / 24 / 22 |
| Post-drain | 29120 / 29120 / 29120 | 21 to 19 |

Steady PSS had 339 actual observations, 27505/29788/28324 KiB; Private_Dirty
was 12192/14476/13012. Full-phase RSS slope was +0.58315 KiB/s, while the
fixed final-half slope was -0.25747: both remain visible rather than choosing
the favorable window. Five-minute RSS medians were 29774, 29622, 29754,
29926, 30084, 30464, 29832, 30080, 31140, 31208, 31664, 31260 KiB.
Recovery declined, but Quiet gained 488 KiB; no retained-allocation proof
assigns either increment to an allocator or leak.

Actual snapshot instances stayed current=1/retired=0 in steady Running; health
and discovery supervisor owners stayed one each. During **Quiet Running**,
physical TCP dropped four to two, executor futures twelve to eight, and bodies
and tunnels reached zero. Only afterward did drain retire supervisor owners;
TCP later reached zero, tasks eight to four. The current Proxy/Health Client
families (four/two) still have legal current ownership and must not be forced
to zero. These are real reclamation intervals, not registry lengths or a
scrape-triggered sweep, but fixed H does not prove churn-generation bounds.

The original report remains INCONCLUSIVE and its Hosted job non-green:
4625 `RL_GRACEFUL_TLS_CLOSE`, 21 `RL_CAPACITY_UNPROVEN`, two
`RL_MEMORY_ATTRIBUTION` findings, zero FAIL. Only the first 200 repeated TLS
notices fit in its detail list. The sealed index retains all actual code counts;
the analyzer now also emits bounded per-code counts before detail truncation.
That additive visibility change does not alter verdicts, thresholds, or the
original report. A complete hour is not whole-resource or memory qualification.

Formal H/C must preserve original minima and complete operation conservation,
full content/trailer validation, finite faults with fresh affected-peer recovery,
old A held/Upgrade proof, and Running-only reclamation before drain. Missing
capacities or allocation attribution remain INCONCLUSIVE even after a green PR.
The phase-six `ca0ffc9` UNKNOWN and old positive RSS drift are not retrospectively
explained by new counters or repaired validation tools.

### Actual allocation capture, not a normal-release verdict

[The allocation-attempt index](artifacts/resource-7a-allocation-attempts.json)
preserves five actual attempts plus a failed checkout caused by a mistyped
source SHA (NOT RUN). The earlier failures were stable-library identity
comparison incorrectly including ASLR addresses, readiness matching the wrong
protocol text, accessing the closed fd after the 1000th complete reply, and
using SIGTERM where the existing CLI's normal shutdown accepts SIGINT. Each
repair has a bounded regression; no production allocator, retirement interval,
pool policy or signal contract was changed.

Run `37206022587`, exact source `5fda7f7545bb082df7c57e21d30c5945b97abd51`,
actually collected and parsed heaptrack 1.5.0 stacks. The separate debug-enabled
release H1 Proxy/Asset fixture ran 60.035 seconds, four clients, 1-MiB public
payloads: 9910 offered/full replies, zero errors, 12 actual connections all
joined. Gateway PID/start/binary identity was rechecked at the end; 118 actual
Running samples are distinct from the profiler interpreter's samples.

Gateway RSS first/peak/last was 34320/44192/44192 KiB; PSS
30374/40246/40246; Private_Dirty 29732/37116/24744; FD 20/26/23.
An additional stopped-load but still Running final capture was
41184/37238/21736 KiB RSS/PSS/Private_Dirty, FD 18. The external interpreter's
RSS was 260924/272048/272048 KiB, not gateway residency. Collector injection
also changes the gateway, so this is not an unprofiled counterfactual.

The native parser printed 3004406 allocations, peak heap `7.49M`, peak RSS
`45.25M`, and unfreed-at-end `195.64K` in its original units. Actual Oxidase
Rust symbols/source lines occur alongside Bytes/Hyper I/O, connection-state,
upstream-handshake and runtime/tracing stacks. Non-merged peak stack groups
are not additive retained-byte totals; unfreed-at-exit is not a leak verdict,
and Rust v0 symbols were not fully demangled. This narrows one isolated H1
case but does **not** assign normal TLS/H2 H/C resident drift to a category.
Those retained-allocation/allocator hypotheses remain INCONCLUSIVE.

### Retry witness stopping point

Formal C repeat `37205968672`, exact `60ca74f`, seed 700216, conserved all
111955 offered/terminal operations and all 100 explicit retirement pairs,
but stopped at `resource.control_retry_not_triggered` after 89.638 seconds
of steady. Its 180.095-second warmup cannot count toward 60-minute steady.
[The original checked index](artifacts/resource-7a-60ca74f-hosted-failure.json)
contains provider hashes, all 37 verified files and identical frozen replay.
The resource fixture dispatch bypassed the legacy branch implementing
`retry_a`: all 16 control probes returned 200 without that trigger. This proves
a fixture wiring defect, not a production retry failure.

It also retains nineteen H2 upload transport failures in status-only DNS
windows and one actual cancellation whose fixture Drop was only observed
3.118 seconds after client cancellation, following connection retirement.
None is accepted inside the original three-second ACK deadline. The source
predates typed H2-reason capture, so those causes cannot be reconstructed.
Controlled tests now capture actual REFUSED_STREAM, perform 512 empty and
512 1-MiB uploads with complete safe 503s on the same TLS/H2 connections,
and obtain eight operation-bound upstream Drop ACKs while the original H2
connection remains open. They did not reproduce those campaign anomalies and
do not close the original failure or its scheduling/propagation attribution.

### Final implementation repeat and delivery boundary

Final implementation `c0db6cde862b3101ed3939e5c7dfa1d68fe6a891` ran C
`37211766238`, seed 700218, with the original formal 180/3600/900/300/300-second
recipe and unchanged concurrency/payload/fault rules. It actually stopped after
180.124 seconds warmup and 13.136 seconds steady, not after a completed hour.
[The final original index](artifacts/resource-7a-c0db6cd-hosted-failure.json)
retains artifact `11306813903`, all 36 verified files and exact frozen replay.

All 62870 offered operations were received. Independent supplementary wire-only
replay verified 62513 complete ordinary responses, 180 complete Upgrade echoes
and 171 acknowledged cancellations. It separately retained **five unwindowed
worker 504s**, one missing cancellation ACK, and the failed normal IPv6 control
probe. That probe received a complete safe 504 after 5.001 seconds; correctness
of the safe error body is not correctness of the healthy operation. It must not
be excused as a named fault or attributed to a controller mistake. Twenty-two
other complete IPv6 replies do not cancel that failure. No claimed counter
zero, private-library cause, shortened deadline, enlarged limit or new failure
allowance closes it. Running recovery/Quiet never began and remain unavailable.

The total/header witness now requires full safe response bytes/EOF plus a real
delta in the corresponding phase counter. It retains the original eight new
probes and nine-second per-probe budget; it does not retry business operations.
Counter attribution is explicitly the same physical fault window, **not** that
specific probe. Header-only 504 cannot prove total timeout. That repair cannot
explain the final normal IPv6 failure, which occurred before that scenario.

Hosted implementation run `37208987135` at `3822a49` also had an independent
Stable failure in the existing IPv6 pool-reuse test: its test sender called
`send_request` while the dispatcher was not ready. The original log is retained;
a real gated first-poll regression fails the old helper and passes an explicit
`ready().await` on the same sender. All body/query/authority/pool assertions
remain intact, with one send and actual driver join, no retry/reconnection.
Final implementation `c0db6cd` passed all nine local gates and four required
Hosted checks (`37211727753`). That green build does not relabel any campaign.

The final 61-second local ASan `discovery_runtime` campaign at `c0db6cd`, seed
600401, executed 4012 inputs, added 511 corpus units and ended with 487 files:
no crash/timeout/OOM. Peak 507 MiB belongs to the **fuzzer**, not the gateway.
Source and both lockfiles were unchanged. All 14 example commands passed.

**7A has not fully passed.** Implementation/evidence delivery is allowed to
retain FAIL/INCONCLUSIVE; it is not a production-readiness claim. Still-open
work is exact-load IPv6 timeout attribution, H2 GOAWAY/cancellation propagation,
normal TLS/H2 retained-allocation attribution and the 21 unproven structural
capacities. No speculative production retention change was made in PR #22.
