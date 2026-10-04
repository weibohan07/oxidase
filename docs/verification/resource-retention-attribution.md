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
| observation itself changes growth | growth follows scrape rate with otherwise matched full-success load | pure reads, low/high/zero periodic scrape and observation-disabled comparison | pure-read regressions pass; actual rate-matched memory experiment pending |

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

Formal H/C must preserve original minima and complete operation conservation,
full content/trailer validation, finite faults with fresh affected-peer recovery,
old A held/Upgrade proof, and Running-only reclamation before drain. Missing
capacities or allocation attribution remain INCONCLUSIVE even after a green PR.
The phase-six `ca0ffc9` UNKNOWN and old positive RSS drift are not retrospectively
explained by new counters or repaired validation tools.
