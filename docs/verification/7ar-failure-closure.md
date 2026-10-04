# 7A-R failure closure

Starting protected main: `41a21ac836688b5698638ac8354753c6b8e44d5a`.
Baseline worktree: `c0db6cde862b3101ed3939e5c7dfa1d68fe6a891`.
Candidate production files, fixtures, lockfiles and analyzer are initially identical
to that baseline; the four intervening changed files are evidence/documents only.
Workspace and APIs remain unchanged. No later product phase belongs to this task.

## Frozen questions before experiments

| Case | Original fact | First falsifiable question | Status |
| --- | --- | --- | --- |
| R-504-CONTROL | C 37211766238 / control-1-15, full safe 504 at ~5.001 s | Does the operation reach the intended upstream; which operation-bound timer fires, and which await cannot progress? | UNRESOLVED |
| R-504-WORKER | Same C, five ordinary worker 504s | Do physical connection/dispatch times overlap the control failure, or are different uploads/heads waiting? | UNRESOLVED |
| R-CANCEL | Same C / 8:172, required upstream Drop ACK missing | Does the held response remain alive on the same upstream operation after downstream cancellation; does its healthy sibling finish? | UNRESOLVED |
| R-H2 | Earlier C 37209014444, GOAWAY/enhance and unknown causes | Which hop initiates GOAWAY and what locked h2 source condition triggers it? | UNRESOLVED |
| R-TLS-CLOSE | H 37204003262, 4625 notices | Distinguish unique closure operations from duplicate analysis; test real per-hop shutdown and incomplete-message negatives. | UNRESOLVED |
| R-CAPACITY | Frozen H, 21 actual kinds lack proofs | Which ownership/admission inputs bound current plus retired generations before construction? | UNRESOLVED |
| R-ALLOCATION | Only separate debug H1 trace exists | What remains allocated at comparable Running checkpoints in actual TLS/H2 Proxy/gRPC? | UNRESOLVED |

## First registered focused baseline

Use exact original C implementation/fixture/analyzer, seed 700218, Linux normal
release, TLS H1/H2, IPv6, original eight workers plus cancel/Upgrade lanes,
32768-byte responses, 1048576-byte uploads, unchanged 1000-request retirement
and all original deadlines/fault order. Preserve the original 180-second warmup.
Only the measured steady duration is limited to the first 90 seconds for diagnosis;
60/30/30-second recovery/quiet/post-drain are not formal qualification minima.
This is a focused reproduction, never a one-hour qualification PASS.

Prediction: the first control sequence reaches positive AAAA and the original
failure region. A non-reproduction refutes deterministic-seed sufficiency, not
the original failure. At most three same-recipe attempts are allowed before a
new distinguishing barrier/experiment; all results are retained. No load reduction,
business retry, timeout extension, feature disablement or new error allowance.

## Original preservation and replay (executed)

Local ignored archive directory:
`/Users/weibohan/Workspace/oxidase/target/qualification-evidence/7ar-originals/`.
Do not run `cargo clean` before retaining these archives elsewhere in an authorized
workspace. No third-party storage, permission expansion or production Secret is used.

| Original | Artifact | ZIP SHA-256 | Bytes | Provider expiry |
| --- | --- | --- | ---: | --- |
| Final C | 11306813903 | `24dd32f3aa3ae5c2d5fb78a69820f2127db805ba18f7a0b30d852c1c71251c91` | 1412778 | 2026-11-03T15:12:36Z |
| Historical H2 C | 11305458830 | `773f7a734cb7633013c9c388dc0b1cee265f1a7c35113f9d78e652987f95138f` | 6487823 | 2026-11-03T14:35:26Z |
| Formal H | 11305298669 | `2a66efa8eaa0120ae5e4e5166d7e13386a62dd4c00d4a3b9a68ca422490063e7` | 38012471 | 2026-11-03T14:29:58Z |

All three were re-downloaded; each provider digest equals the downloaded archive
and original local ZIP. Final C verified all 36 original per-file hashes. Its
frozen c0db analyzer SHA-256 is
`9de0d99e9142bbee55f19830068f2acce4e7227ca0bb75b6d72b8f5f890b9b05`.
Independent replay returned 1/FAIL and is byte-identical to the original report
(`9e8050b6d4916a10b1125ff46e5880113da0c737275cf864f243803613703883`).
Source-set, binary and PID/start identities remain in the original receipt and
existing index; current summaries do not replace original bytes or fill missing
Recovery/Quiet data. The historical H2 C was also independently replayed with
its own `3822a49` analyzer: all 47 checksum entries verify, exit1/FAIL, byte-equal
report `de3d7e46edbe3937e2da743cd3d85e54d33785c8f44b0dbb40cbdbf8089445a5`.
Formal H verifies all 35 entries and uses its own `097c6ec` analyzer: exit2 /
INCONCLUSIVE, byte-equal report
`09d5fe97384f7f7bdb82e25a950f277d61ca400166d2f1a21681ac5ad8a4a124`.
These are exact original verdicts, not requalification of changed source.

## Focused original C experiments (executed, not formal)

Both runs use unchanged `c0db6cd`, seed700218, the registered normal-release
recipe, and the original deadlines/request quota. Every offered operation has
a received result. Neither reproduces a normal positive-AAAA/worker 504 or a
missing operation-bound cancellation ACK. This does **not** establish closure
of the historical R-504/R-CANCEL failures.

| Run / artifact | Offered = received | Observed positive AAAA | Other actual failures |
| --- | ---: | --- | --- |
| `37224069013` / `11310944929` | 120801 | full32768-byte IPv6 200, head16.282ms | 11 H2 segmented-upload head failures during TTL-zero; 2 incomplete Upgrade error captures; unexpected responses remain failures |
| `37225226553` / `11311438679` | 113043 | full32768-byte IPv6 200, head7.01ms | 6 H2 segmented-upload head failures during TTL-zero; 3 incomplete Upgrade503 captures; no ACK-missing result |

Archive SHA-256 respectively:
`cb1b3b4be47260f45279507c7428782ee321fdcfd8964be8319db2142df08741` and
`add1a544c03e25886ba809940d9f434554ba0a20cc668e06356fabd2b2937c1b`.
The raw original reports still include two `RL_TRIGGER` findings because that
analyzer omitted its DNS-withdraw/response-header probe branches. Correcting
those branches requires exact raw counter scope, finite fault windows, complete
safe wire responses and independent recovery; it does not excuse normal 504s,
unrelated phases or Upgrade lanes absent from the original window contract.

## Confirmed local counterexamples and candidate repairs

### R-H2: early response with an unread upload

A direct TLS/H2 fixture with locked Hyper/h2 and unchanged reset guards isolates
the library boundary. Exactly1000 empty-body503 requests finish. With the same
segmented1MiB upload used by the resource tool, the old fixture fails before the
1000-request retirement quota (around request600). A test-only decrypted-control-
frame tap records `NO_ERROR` resets, then1024 `STREAM_CLOSED` resets, followed by
server `ENHANCE_YOUR_CALM / too_many_internal_resets`. No DATA/secret is retained.
The h2 reset-stream retention bound explains the late-DATA escalation; this is
not a reason to increase that library guard or hide a reconnect/business retry.

A single-variable control sends the503 head and DATA immediately but defers its
EOS until streaming disposal of the original request reaches EOS. It completes
1000 uploads, receives1048576000 bytes, and emits none of those reset/GOAWAY
frames, on stable and MSRV1.88. The Gateway regression now also passes1000
unchanged segmented uploads on one H2 connection on both toolchains.
Candidate disposition applies only when Service execution never claimed the
request payload. Proxy-owned streams are never reacquired/replayed; HTTP/1 and
Upgrade are unchanged. DATA and response head are not buffered. Disposal has
an independent absolute/byte bound. A real zero-flow-control-window/PING test
shows the cooperative-only old control retaining the actual input beyond its
deadline, whereas the existing tracked H2 stream task now destroys only that
expired input and releases its active guard without another Body poll. A sibling
started before expiry completes its exact body/trailer/EOS on the same connection.
This local cause/fix does not retroactively
prove the direction of every historical null-cause H2 failure, or R-504.

### R-TLS-CLOSE: first EOF omitted the other write-half shutdown

Old tunnel code cancelled the opposite copy at first EOF without shutting down
its writer. Actual TLS then reports `UnexpectedEof` instead of `close_notify`.
The repair shuts down that remaining writer exactly once on clean first EOF,
without replacing non-EOF failures or shutting down the already completed half
twice. Both EOF directions, real two-hop TLS, cleanup cancellation and incomplete
application-message negatives execute successfully. Server Upgrade unit12,
Upgrade wire7 and protocol-bridging6 tests pass on stable and MSRV1.88.
Historical notices remain original facts; only a fresh campaign can qualify
the candidate TLS behavior.

### R-CANCEL: ACK fact and ACK-query cleanup are distinct

A held-body real Gateway fixture proves upstream Drop within the original3s
window and a successful healthy sibling. Deliberately blocked ACK-query driver
cleanup demonstrates the old helper erasing an already received ACK. The new
helper preserves operation identity, actual Drop time, ACK observation time,
original absolute deadline and separate driver join/cleanup outcome. Cleanup
failure still fails; an unjoined driver or late ACK cannot become cancellation
success. Actual pre-first-poll cancellation uses RAII abort rather than silently
detaching the taken JoinHandle. Independent analyzer negatives cover late ACK,
extended deadline, inconsistent Drop/observation, error cleanup and missing join.
The static IPv6 mixed Proxy/gRPC/upload/held-cancel regression succeeds without
hidden replay/reconnect, but does not establish what happened to historical8:172.

### Candidate local gates (executed)

- `cargo fmt --all -- --check`: PASS.
- `cargo test --workspace --locked`: PASS; the server library executes262 passing
  tests plus one pre-existing ignored test; the soak library executes109 passing
  tests. No new regression is ignored. Admin restart/race, DNS lease/pool/deadline,
  protocol and cancellation fixtures run on real loopback sockets.
- Independent analyzer corpus:127/127 PASS.
- Scoped body32/32, H2 executor4/4 and client36/36 pass on both stable and1.88.
  Server and soak all-target/all-feature locked Clippy pass. Full workspace
  Clippy, warnings-denied docs and dependency policy also pass. Full MSRV locked
  all-target/all-feature check and workspace tests pass on the same candidate.
  Release/fuzz compile and new hosted-head checks are separate gates; compiling
  fuzz harnesses does not constitute an executed fuzz campaign.

Logical commits: `5fded2a` TLS shutdown, `92b48da` bounded H2 unread-input
disposition, `ae006ab` actual IPv6/TLS transport lifecycle regressions, and
`0f92a70` preserved cancellation/driver witnesses, complete Upgrade error bodies,
original reset-guard counterexample and independently scoped control probes.
The existing Draft PR23 foundation run37224069727 passes its four required jobs
only for `c405ac7`, not these new commits. Final new-head Hosted CI and candidate
focused/formal Linux results are not yet claimed.

## R-CAPACITY: frozen units and source-derived dispositions

This section investigates production source at protected `41a21ac`; the candidate's
TLS shutdown fix does not repair or redefine any capacity below. The list is the
**actual 21 kinds** from frozen H `097c6ec` / run `37204003262`, not a remembered
list, observed maximum, registry proxy or proposed declaration. Old H retains all
21 `RL_CAPACITY_UNPROVEN` findings. A source formula below is not an executed
saturation test or a new qualification result.

Scope is one CLI-owned `RunningServer`. Multiple embedded server instances need
an explicit multiplier; process census alone does not assert that multiplier.
Configured Cluster/static endpoint counts may be inputs to a formula, but source
has no global cap on all accepted source-program definitions. New source/Bundle
input bounds must apply before construction and cover both lowering paths.

`S` means all actual snapshot instances, including prepared/waiting candidates and
retired request/tunnel pins. `C` and `E` mean bounded accepted Cluster/static
endpoint definition counts, not map sizes at the current scrape. `H` means all
actual current, Scheduled, Waiting and Exiting health owner futures. `B` includes
issued business endpoint permits and temporary status-retry reservations. Until
their global ownership/admission inputs are proven, formulas using these symbols
are dependencies, not numeric capacity proofs.

| Frozen kind | Unit / construction and final owner | Source formula or missing prerequisite | Disposition |
| --- | --- | --- | --- |
| `cluster` | `PreparedCluster` object, Snapshot Resource Arc plus admitted work; `snapshot.rs:438`, `cluster.rs:657–768` | Per input at most `C`; across all generations depends on `C × (S + admitted preparation workers)`. Failed preparation also owns partial resource maps before the Snapshot token exists. | UNRESOLVED composition: prepared candidate and all pinned/retired owner bounds |
| `cluster_runtime` | Actual shared `ClusterRuntimeState` Arc; `cluster.rs:669`, `3403–3422` | Same Cluster ID reuses runtime; a removed/readded ID can allocate another. At most one per live Cluster plus construction-in-progress; do not count one global runtime merely because names match. | UNRESOLVED composition with `cluster` |
| `discovery_lease` | `begin_discovery_query` refresh lease, not a business endpoint permit; `cluster.rs:984–1006` | One query slot per active owner. Manager aborts and **awaits** old owners before replacement (`discovery_manager.rs:196–203`), source/portable discovery owner cap 128. At most 128 in this server path. | PROVEN source formula; saturation/retirement regression still required |
| `discovery_round` | Actual current owner round future; `discovery_manager.rs:323`, `411` | One sequential round per owner; old future Drop is awaited before new owners. At most 128. | PROVEN source formula; lifecycle regression still required |
| `dispatch_retirement_task` | Actual cleanup future captures its original reservation until Drop; `upstream_timing.rs:504–513`, `608–650` | Reservation acquired before scheduling; normal pool-ready work releases it. At most 1024 per Proxy owner, including Scheduled/Exiting. Runtime teardown drops never-polled guards. | PROVEN server-owner formula; not a count of every Hyper task |
| `dns_failure_memo` | Actual negative target-family memo token; `dns_resolver.rs:519–573` | Current resolver targets are pruned before writes; `MAX_DNS_TARGETS=32`, two families. Stored entries ≤ `128 × 64 = 8192`; conservative token bound including old/new replacement RHS ≤ `128 × 65 = 8320`. Candidate resolvers have not queried and therefore have no memos. | PROVEN source formula; replacement/saturation/owner-drop verification required |
| `dns_query` | Actual logical family resolution future, including quota wait; `dns_resolver.rs:283`, `640`, `756` | A/AAAA ≤2 per owner; SRV RRset finishes before target families and `buffer_unordered(4)` limits four **families**, not four pairs. Total Waiting+Running ≤ `128 × 4 = 512`; executing network admission ≤64. | PROVEN outer formula; Hickory private work is a separate boundary |
| `endpoint` | Actual `PreparedEndpoint` object, not endpoint name or current member count; `cluster.rs:699–704`, `2520–2546` | Static count follows `E`; current dynamic set ≤256. Replacement can temporarily own old and new sets. Health round retains a complete old `Arc<[Arc<PreparedEndpoint>]>`, not only its 32 active probes. Business/retry work retains old endpoint objects. | UNRESOLVED composition with candidate, health, request and retirement bounds |
| `endpoint_admission` | Shared physical admission counter, not weak tombstone; `cluster.rs:3463–3471` | Compatible and same-address incarnations can share the counter. Old permits keep it alive; observation holds only a weak scalar. Membership tombstone cap `max_endpoints + max(active, policy max_in_flight, inherited_count)` (`2416–2465`) is not all counter objects across generations. | UNRESOLVED composition; no strong-registry shortcut |
| `health_pool_entry` | Actual registry entry guard; `upstream_pool.rs:190–222` | Registry mutex serializes construction; evict first when full, then construct entry token. ≤1024 per HealthClient registry. Issued Client families/IO are not entries. | PROVEN entry formula; family/IO proof remains separate |
| `health_probe` | Actual waiting/running probe future; `cluster_health.rs:224–237`, `394–404` | Per actual owner ≤32; global executing probes≤64. Therefore total probe futures≤`32 × H`, **not**64. Current replacement aborts without awaiting old owner Drop; no all-generation `H` bound is established. | NEEDS_FIX owner retirement/admission, then independent saturation test |
| `proxy_pool_entry` | Actual registry entry guard | Same locked evict-before-construction rule; ≤1024 per Proxy registry. Private old requests can build an unregistered family. | PROVEN entry formula; not a family bound |
| `snapshot_preparation` | Actual `RuntimeSnapshot::prepare_*` work token; `snapshot.rs:194` | Running server callers hold compile gate1 across their blocking preparation. This bounds active preparation, not snapshots returned from it and waiting to send. Startup is separately serial. | PROVEN active-work formula; retained candidates NEEDS_FIX |
| `upstream_connect_attempt` | Actual pending TCP connect, `upstream_transport.rs:668–690` | Proxy/Health StaticTargetCache each has a 1024 connection gate. Cold fallback and connector reconnect use the same gate without double charge. Conservative total≤2048 in these production paths. | PROVEN pending-connect formula; successful established IO is not covered |
| `upstream_task` | Existing Hyper executor future, token captured before spawn; `upstream_timing.rs:730–755` | Includes driver/dispatch/idle/other library execution, not just one user request. No executor semaphore. Needs the locked Hyper spawn inventory plus real family/IO/admitted-attempt bounds. | LIBRARY_BOUNDARY / UNRESOLVED combination |
| `upstream_tcp_connection` | Actual socket-owning IO guard; `upstream_transport.rs:508–527` | Connection gate is released when dial/handshake future completes. It does not remain in the established socket. Registry cap, idle timeout or current active requests does not cap all established/retired sockets. | NEEDS_FIX lifetime admission or a complete outer proof |
| `upstream_tls_connection` | Authenticated TLS IO on the same real TCP owner | Subset of actual TCP connections; not one new independent allowance per TLS phase. Requires established TCP lifetime bound. | NEEDS_FIX / dependent on TCP proof |
| `upstream_tls_handshake` | Actual handshake future (`upstream_transport.rs:703–738`) | The same Proxy/Health connection gates remain owned through handshake. Conservative total≤2048; this is not authenticated live TLS IO. | PROVEN pending-handshake formula |
| `upstream_upload_task` | Request-bound Hyper body pipe; weak progress binding and actual future token | Requires exact spawn/binding/cancellation contract and retained attempt permits. Early response/EOS does not prove upload future destruction; one request must not cancel a shared H2 driver. | LIBRARY_BOUNDARY / UNRESOLVED until R-CANCEL/R-H2 causal proof |
| `warm_expiry_task` | Scheduled 90-second weak expiry future; `upstream_transport.rs:443–464`, `588–642` | Warm consumption/owner Drop requests abort but does not await actual task destruction. Old scheduled/exiting timers can remain after their slot or family has gone. One active slot does not prove one live timer. | NEEDS_FIX actual future admission or a proved lifecycle combination |
| `warm_socket_slot` | Actual preconnected transport owned in the shared connector slot; `upstream_transport.rs:428–439` | At most one per surviving connector family, but family construction has no all-generation quota and cold gate is returned after pool handoff. A 90-second expiry is not an arrival-count bound. | NEEDS_FIX / dependent on family and established-IO admission |

### Two confirmed construction/retirement entrance defects

**Prepared source candidate.** `ReloadHandle::reload_path_with_operation`
acquires compile gate1 before the blocking worker (`server.rs:1246`) but drops
the permit inside that worker. The completed Snapshot then waits in `send`
(`1347–1362`). Eight channel entries do not bound external producers holding
completed candidates. Admin mutation gate1 serializes only Admin requests; it
does not prove the public/source ReloadHandle path bounded.

The minimal retained-candidate fix is a concrete, independent fail-fast permit
acquired **before compilation/preparation**, carried through queued/pending
manager work and final reject/commit/cancellation, and released on actual final
owner Drop. Waiting callers must not construct first or form another unbounded
queue. The existing compile gate remains a worker gate: the manager currently
reacquires it for Admin compatibility (`server.rs:767–778`), so blindly retaining
that same permit would create self-rejection/deadlock. No admission decision may
consult ResourceCensus or replace PublishedRuntime/If-Match/recovery fences.

**Health generations.** `ClusterHealthManager::activate_snapshot` stops old
owners and immediately schedules replacements (`cluster_health.rs:89–144`);
`reap_finished` is nonblocking. Map1 can coexist with multiple real Scheduled /
Exiting owner guards in a paused current-thread schedule. The minimum owner
repair can await retired future Drop before replacing, as discovery already does,
or reserve finite actual owner capacity before task construction and retain it
through Drop. A candidate must not be accepted with an inert health field because
post-publication admission failed. Legitimate old request streams are not aborted
to make this count look small.

All-generation snapshot/Cluster composition must additionally account for changed
bind listener retirement: `server.rs:1693` detaches retired listener handles,
whose connection states still have their own admission. Current listener limits
do not alone constrain arbitrary concurrently draining listener generations.
Candidate/publication authority and legitimate issued stream completion remain
unchanged during this investigation.

### Executed isolated R-CAPACITY counterexamples (not R1 production fixes)

Ordinary, **non-ignored** desired regressions are saved only in
`/private/tmp/7ar-capacity-counterexamples.patch`, SHA-256
`9de96aa9cc564d84eff2d70abc830b8268f39e20e93e403925467ac9fc9094f1`.
They are not mixed into R1's default suite while the confirmed R2 defects remain
unfixed. `git apply --check` passes on the unchanged old baseline/candidate.
R2 must apply the tests with the actual fix and execute them normally; keeping
them out of R1 is not a claim that an ignored or unexecuted test passes.

Isolation uses an archive of `41a21ac` in `/private/tmp/7ar-capacity-tests.a0zdJu`.
The production crates and both lockfiles have no diff from `c0db6cd`; the only
source overlay is these two cfg-tests. Actual rustc 1.97.1 and 1.88.0 each execute
one matching test per command and each exit **101/FAIL**:

| Regression | Controlled old facts | Cleanup before the desired-bound failure |
| --- | --- | --- |
| `prepared_source_candidates_are_admitted_before_the_commit_queue` | full 8-slot commit queue; exact compiler permit released after each finished blocking preparation; 9 actual Candidate Snapshot objects held outside `send` | all nine entered callers abort and join; only unchanged Current Snapshot remains (live1), invariant failures0 |
| `replaced_health_owners_exit_before_replacement_is_constructed` | current-thread loop never yields while eight different health-policy owners are prepared/activated; current map1, actual created8/destroyed0/live8, no probe first poll | shutdown collects every owner future; actual live0, created=destroyed, invariant failures0 |

Commands from the isolated source copy use the corresponding independent
`target-stable` / `target-msrv` directory, `CARGO_NET_OFFLINE=true`, and:

```sh
cargo test -p oxidase-server --lib --locked prepared_source_candidates_are_admitted_before_the_commit_queue -- --nocapture
cargo test -p oxidase-server --lib --locked replaced_health_owners_exit_before_replacement_is_constructed -- --nocapture
cargo +1.88.0 test -p oxidase-server --lib --locked prepared_source_candidates_are_admitted_before_the_commit_queue -- --nocapture
cargo +1.88.0 test -p oxidase-server --lib --locked replaced_health_owners_exit_before_replacement_is_constructed -- --nocapture
```

Exact local logs and `receipt.json` remain in that isolated directory. Initial
stable reproduction used a shared build target and was subsequently repeated
with an independent target. One incorrectly located MSRV command matched zero
tests and is NOT RUN; it is not included as a pass. These are source admission /
retirement counterexamples, not Linux campaigns, memory leak evidence or new
capacity values inferred from observed peaks. No Admin/publication, DNS/lease,
deadline or production resource policy has been changed for these tests.

## Delivery/qualification

### Registered candidate focused repeats

After freezing the candidate and its tool/analyzer source, run two independent
Linux normal-release C jobs with seeds700218 and700219. Both preserve the original
180-second warmup, eight ordinary workers plus cancel/Upgrade, 32768-byte responses,
1048576-byte uploads, unthrottled operations, 1000-request retirement, original
timeouts/fault sequence and unchanged finite-window allowances. Use diagnostic
180/90/60/30/30-second phases and `formal:false`, not formal minima. Collect every
offered operation even on failure and preserve raw bytes/hash/driver results.
No blind repeated retry-until-green: each run is inspected for the repaired reset
chain, actual TLS close, exact ACK timing/cleanup, normal full IPv6 responses and
any remaining failure. Zero historical reproduction does not prove R-504 closed.
No formal-hour campaign starts before the R1 causal and capacity prerequisites.

No case is closed by this initial ledger or by ordinary CI. Each closure requires
old counterexample, cause, minimal fix, same counterexample and original-load
repeat. Formal H/C must use the same frozen final implementation and tool source.
7A remains unqualified while any important case is FAIL/UNRESOLVED/INCONCLUSIVE.
