# Phase-six acceptance evidence

Scope: 6A–6D only. Actual starting protected main:
`ebfb7549bf9c1ddd91384cf85cff4098982b8acf`.
Gateway/Oxista/Bundle/Admin remain alpha and workspace stays `0.3.0-alpha.1`.
This is an evidence ledger, not a claim that in-progress stages are implemented.

## Baseline

The clean starting main passed all nine requested gates: fmt, workspace Clippy
all-target/all-feature with warnings denied, workspace tests, docs with warnings
denied, cargo-deny, release build, Rust 1.88 all-target/all-feature check, Rust 1.88
workspace tests, and locked fuzz-bin compilation. The raw generated baseline log
is retained as `artifacts/discovery-baseline-ebfb754.log.gz`.
Existing ignored manual benchmarks/soak were not counted as executed.

## Stage status

| Stage | Implementation | Local / Hosted / campaign evidence |
| --- | --- | --- |
| 6A transport identity/deadlines | normally merged through protected PR #16 | final head `39caf68` PR run `37131533884` PASS; merged main `aaece2a` push run `37131852985` PASS |
| 6B A/AAAA discovery | normally merged through protected PR #17 | final head `bd58363` PR run `37137424130` PASS; merged main `890a802` push run `37138029438` PASS |
| 6C SRV discovery | normally merged through protected PR #18 | final head `b27974a` PR run `37143336854` PASS; merged main `a1a06b0` push run `37143737883` PASS |
| 6D integration/qualification | in progress from protected main `a1a06b0` | final-head integration/Hosted/fuzz/Linux acceptance not yet recorded |

## 6D integration contract

Draft [PR #19](https://github.com/weibohan07/oxidase/pull/19) starts from protected
main `a1a06b0d89fa8303233ac31a46be86dce747d397`. Its receipt-only foundation is
not the final implementation gate. The following tests use actual CLI operations,
local DNS replies, physical TCP/TLS peers and bounded child processes; neither
DNS reconciliation nor the qualification controller obtains publication authority.

| ID | Contract | Executable regression | Evidence boundary |
| --- | --- | --- | --- |
| DS-30 | Source → signed Bundle A → B → rollback A → Source retains CAS and origin semantics | CLI `signed_dns_publications_preserve_cas_fence_late_owners_and_resume_only_explicitly` | stable/Rust 1.88 repeated local PASS; final Hosted run recorded separately |
| DS-31 | A received late answer cannot revive a retired/drained owner | the same CLI test gates a real positive DNS response, retires the owner, then observes the successful-send acknowledgement | no fixed-sleep or query-intention substitute for the controlled receive/retirement race |
| DS-32 | Post-publication persistence failure and dropped caller retain the recovery fence while DNS changes operational membership | server `published_runtime_survives_caller_cancellation_and_completion_storage_failure` | actual journal fault injection, A→B and exact PublishedRuntime identity assertions PASS on stable/Rust 1.88 |
| DS-33 | A source-free signed Bundle process restart starts cold, then dials the new DNS address | CLI `actual_signed_bundle_process_restart_starts_cold_and_uses_new_dns_not_old_packed_ips` | actual child kill/restart with removed YAML; generation-zero/unavailable before released DNS, then new IPv6 peer |
| DS-34 | Retry across a new SRV generation never refreshes a logical request's total deadline | wire `retry_across_a_new_srv_generation_keeps_the_original_total_deadline` | three actual H2 peers; original total timeout, bounded attempts and released permits PASS on stable/Rust 1.88 |
| DS-35 | Stateful fuzzing reaches production membership, selection, expiry, replacement and cancellation rather than parser rejection alone | `discovery_runtime` driver and deterministic seed tests | compiled and seed tests PASS; real ASan campaign is a separate receipt |
| DS-36 | Source-free policy fuzzing validates all six deadlines and required capabilities before activation | `portable_discovery` driver and deterministic seed tests | locked compile/MSRV PASS; real ASan campaign is a separate receipt |
| DS-37 | Gateway, DNS, upstream and load controller are distinct processes; resource samples belong to the gateway PID | validation-only `oxidase-discovery-soak` | Linux `/proc/<gateway_pid>` campaign required; missing measurements remain null |
| DS-38 | Normal and cancelled gRPC DATA, terminal trailers and held Upgrade traffic have different, observable lifecycles | process campaign's incremental byte validation, upstream Drop acknowledgement and gateway metric delta | ordinary short smoke is not the protocol campaign or a long-term guarantee |
| DS-39 | Warm-up, steady load, DNS/publication churn and cooldown retain original logs, samples and failures | manual `discovery-qualification` workflow | final-head required checks, manual Linux campaign and merged-main push checks are independent evidence |
| DS-40 | Explain exposes fixed discovery/address policy and all six phased deadlines without predicting live IPs | CLI `actual_explain_describes_both_discovery_policies_and_phased_budget_without_dns` | actual A/AAAA+SRV CLI processes and local UDP/TCP no-query observations; static legacy description stays explicit |

The signed-Admin race and restart pair passed three serial runs on stable and
three on Rust 1.88. The six-test DNS/TLS/H2 wire suite and recovery-fault test also
passed on both toolchains. An initial fixture-token permission warning exposed a
test-envelope assumption; test-only token/signing files now have Unix mode 0600.
The deadline fixture initially exhausted two distinct members before reaching
the total deadline; its corrected three-peer test preserves the original timeout
assertion. These failures were not interpreted as passing production evidence.

The separate-process tool rejects reused output directories, checks actual opaque
gRPC bytes and trailers, and distinguishes completed responses from intentional
cancellation. Ordinary smoke, fuzz campaigns, Linux curves and final Hosted
receipts are reported separately below when executed; a workflow definition does
not qualify them.

### First frozen 6D head: actual gate finding

Head `220bb7384cd528a07995a6805c1b02dd66623f70` passed the final local
35-second process smokes and one additional ASan property run, but **failed**
the complete workspace Clippy gate. Its actual [PR run `37148237544`](https://github.com/weibohan07/oxidase/actions/runs/37148237544)
also failed Stable workspace at `clippy::duplicate_mod`; stable test/release/doc
steps were skipped. The new recovery regression and resolver unit tests loaded
the same DNS fixture twice in one library test crate. This is repaired by one
shared `cfg(test)` module, not a lint allowance or a production-state change.
All-target/all-feature workspace Clippy and the resolver 26/26 plus recovery-fault
test pass after the repair. The repaired head still needs fresh complete gates,
its own Hosted checks and actual Linux qualification. Raw local/Hosted failures
are retained as `artifacts/discovery-6d-220bb73-*-failure.log.gz`.

### Executed 6D ASan property campaigns

Both campaigns actually ran on clean, frozen implementation
`9812a2db26d3f973e74cdae4c6eab7f13a9833b7`, macOS aarch64, with offline Cargo,
cargo-fuzz 0.13.2 and nightly Rust 1.100.0 (2026-08-29). They use dev/debug
assertions plus AddressSanitizer, a ten-second per-input timeout, 2048 MiB RSS
limit and fresh seed/corpus directories. The report includes exact commands,
tool versions, head/dirty/source/lock hashes and original libFuzzer statistics.

| Target | Seed | Actual fuzz seconds | Executions | Corpus files initial/final | New units added | Peak fuzzer RSS MiB | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| discovery_runtime | 600401 | 61 | 1050 | 2 / 289 | 290 | 244 | PASS |
| portable_discovery | 600402 | 61 | 238 | 2 / 59 | 61 | 445 | PASS |

Exit codes are zero; crash, timeout and OOM flags are false; failure artifact
directories are empty. Source-set hash
`d62be291a05d5913479cdea658d35c18f1f677caa18e406f511de31036d350a5`, both
lockfiles and HEAD are identical before/after. Raw receipts and logs are
`artifacts/discovery-6d-asan-{runtime,portable}-9812a2d.{json,log.gz}`.
Corpus minimization means new-units-added is not final-file-count minus initial.
These are local property campaigns, not Hosted fuzz, a wire parser audit,
gateway memory observations or a promise that all possible inputs are safe.

### First actual Linux process campaign and independent review

[Run `37148441986`](https://github.com/weibohan07/oxidase/actions/runs/37148441986)
actually executed both separated-process campaigns on implementation `9812a2d`,
Ubuntu x86_64, kernel 6.17.0-1022-azure, Rust/Cargo 1.99.0. Its qualification job
completed SUCCESS; unrelated external-conformance jobs were skipped rather than
represented as executed suites. Artifact `11283750224`, 2,836,679 bytes, service
digest `sha256:339a2cf4321b6269bd727940dc8b7ba7b61732c53deea810fe931ce5799d2e82`,
is preserved in `artifacts/discovery-6d-linux-37148441986-raw.tar.gz` with summaries.
The recorded dirty state is only the workflow's generated `discovery-results/`
directory, not a tracked-source modification.

Discovery used 600 seconds steady, concurrency 8, seed 600601; protocol used 120
seconds steady, concurrency 6, seed 600602. Each has 30 seconds warm-up, 120 seconds
cooldown, nominal 1-second samples, 3-second control interval and 32768-byte payloads.
Actual total observed durations were 750.325 / 270.313 seconds, with distinct
gateway/generator/DNS/upstream PIDs. Discovery had 335621 requests, 75092 complete
responses, 4786 intentional cancellations, 255743 expected unavailable responses
and 1475 actual retries. Protocol had 36028 requests, 7742 complete gRPC responses,
515 cancellations and 20 Upgrade tunnels. Both reported zero unexpected errors.

Independent recomputation of the original 648 / 253 samples found:

| Gateway-PID curve | Discovery | Protocol |
| --- | --- | --- |
| RSS post-warm / peak / final KiB | 24168 / 25812 / 25132 | 23792 / 24688 / 24416 |
| Steady RSS slope KiB/s | +1.92879 | +4.82625 |
| RSS quarter medians KiB | 24700 / 25122 / 25480 / 25548 | 24196 / 24376 / 24498 / 24532 |
| FD post-warm / peak / final | 28 / 30 / 16 | 23 / 27 / 14 |
| Steady FD slope FD/s | -0.000196954 | +0.000968006 |

All final *measured* active requests/connections/streams/tunnels, discovery
supervisors, cluster/retry permits and retired-admission counters were zero.
Pool count, health-task count and old snapshots stayed null: their reclamation
was not measured by this public process view. RSS retained 964 / 624 KiB above
post-warm baseline despite cooldown reduction; small positive drift is visible,
not a leak-free plateau or long-term reliability conclusion. Actual sample intervals
vary because controller work is not a fixed-frequency sampling clock.

Before/after-DNS runtime objects matched in all 164 / 33 changes; actual H1/H2
ALPN, positive and negative answers, TCP fallback, CNAME, health transitions,
conditional signed activation/rollback, held gRPC trailers, Upgrade bytes and
cancellation Drop acknowledgements were observed. The Linux campaign had no
positive AAAA, timeout or mid-body-error events; those are independent wire-test
evidence, not campaign coverage.

The review also identified a proof-strength limitation: eight expected-B calls
did not explicitly assert status 200, so non-200 replies skipped peer validation.
The artifact proves an actual B response and no mismatched *successful* peer,
not eight independently successful B streams. The assertion is strengthened with
a regression rejecting non-200, partial and cancelled responses, and the ordinary
stable/Rust 1.88 process smoke passes with `successful_new_b_streams: 8`.
A fresh campaign remains mandatory; this original SUCCESS run is retained,
not retroactively given the stronger guarantee.

### Short-smoke failure, retained evidence and planned-stop boundary

The complete local stable workspace test on `ca0ffc9` failed one ordinary
protocol process smoke at a generic final qualification guard. Its four Hosted
required jobs passed independently in run `37150265178`; that green does not
erase the local failure. The old guard omitted individual failing counts and the
temporary test directory was removed, so the original failed term remains
**UNKNOWN**, not retrospectively attributed to a particular production defect.
Raw output is retained as
`artifacts/discovery-6d-ca0ffc9-initial-process-gate-failure.log.gz`.

The tool now records detailed final evidence and separate request-body transport,
content and timeout faults before applying the same zero-fault guard. A failed
ordinary test preserves its evidence directory instead of hiding the failure
behind a missing success summary. Independent fault injection with a real H2
seven-byte segmented POST proves that forced pre-head cancellation after the
first byte causes a body error, not content corruption. Planned load shutdown
instead stops between operations and lets the already-started request finish
within its existing twelve-second bound, with a fifteen-second worker join bound.
It does not disable intentional post-head cancellation or relax any zero-fault,
trailer, new-peer or permit assertion. The new unit suite passes 20/20 and the
ordinary two-process-campaign tests pass 2/2 on both stable and Rust 1.88; fresh
complete gates and Linux qualification are separate receipts, not implied here.
After separating Upgrade accounting, both final-source 35-second full-control
campaigns pass: 16343 / 16311 worker results each exactly equal their worker
outcome sum, protocol has ten separately recorded unavailable Upgrade probes,
both have eight complete new-B streams and zero unexpected/request faults.
Focused toolchain logs and summaries are retained under
`artifacts/discovery-6d-final-tool-*`.

### Strengthened replacement-stream campaign, before planned-stop repair

[Run `37150296893`](https://github.com/weibohan07/oxidase/actions/runs/37150296893)
completed SUCCESS on exact `ca0ffc92825530763f57df308b4668c44f271c25`.
Both actual Linux campaigns now record `successful_new_b_streams: 8` after
checking every full 200 response's physical peer, identity, DATA and trailers.
Discovery observed 330800 requests, 78507 complete responses, 4844 cancellations
and 1611 gateway retries; protocol observed 35256 requests, 7914 complete gRPC
responses, 529 cancellations and 18 Upgrade tunnels. Both report zero unexpected
errors. The gateway PIDs are 6091 / 7394, distinct from all controller/fixture PIDs.
All 160 / 32 DNS-change runtime object pairs are unchanged. Measured final active
and permit/supervisor counters are zero, while pool/health-task/old-snapshot
measurements remain null. RSS post-warm / peak / final is 23712 / 25588 / 25200
and 23560 / 24412 / 24164 KiB; steady slopes remain positive, +2.28997 / +6.41280
KiB/s. This is not a leak-free or long-term qualification claim.

Independent review also found that the protocol summary's `expected_unavailable`
included fifteen control-loop Upgrade probes, while `requests` counted only load
worker results. These old counts are preserved, not silently rewritten or claimed
to partition one denominator. The tool separates unavailable Upgrade probes in
new receipts and adds a successful-campaign worker-accounting assertion.

Artifact `11284476091` has service digest
`sha256:179a3d8a6a37432115d570928daa869a37db0e7d3a62edffde9b969829bc5b1e`;
the raw archive and both summaries are retained as
`artifacts/discovery-6d-linux-37150296893-*`. This run precedes the planned-stop
tool repair above and cannot replace fresh qualification of that source.

## Protected 6A delivery receipt

PR [#16](https://github.com/weibohan07/oxidase/pull/16) was normally merged without
an administrator override. Base: `ebfb7549bf9c1ddd91384cf85cff4098982b8acf`;
final head: `39caf6874be5acef42ec442f44fcc46974ec0d97`;
merge: `aaece2a0c263ce58e3ba7d398a33c11892186316`.
The exact final-head [PR run](https://github.com/weibohan07/oxidase/actions/runs/37131533884)
and independent merged-main [push run](https://github.com/weibohan07/oxidase/actions/runs/37131852985)
both completed successfully with all four required jobs: MSRV 1.88, Stable
workspace, Dependency policy and Fuzz harness compile smoke. Main remained strict,
with force pushes/deletion disabled. Earlier failed/local-only receipts below
remain history, not the final acceptance record.

## Protected 6B delivery receipt

PR [#17](https://github.com/weibohan07/oxidase/pull/17) was normally merged without
an administrator override. Base: `aaece2a0c263ce58e3ba7d398a33c11892186316`;
final head: `bd58363b0f4f16468937b357608062ecf25ca79d`;
merge: `890a802dd74e58de8bf3e316422e771f59172621`.
[Final-head PR run `37137424130`](https://github.com/weibohan07/oxidase/actions/runs/37137424130)
and independent [merged-main push run `37138029438`](https://github.com/weibohan07/oxidase/actions/runs/37138029438)
completed with all four required jobs SUCCESS. Main remained strict/up-to-date,
with force push/deletion forbidden; the older actual Clippy failure remains
recorded below rather than replaced by a local or receipt-only green run.

The repaired source also passed all nine locked local gates on that exact
`bd58363` head. Raw log:
`artifacts/discovery-6b-bd58363-post-hosted-fix-gates.log.gz`. Six actual locked CLI
example commands PASS (basic check/test/explain, secure-resilient check,
secure-admin check/test), retained in
`artifacts/discovery-6b-bd58363-examples.log.gz`. Expected migration and public
test-token permission warnings are not silently removed. The recorded manual
benchmark/fuzz/Linux qualification limitations remain separate from these gates.

## Protected 6C delivery receipt

PR [#18](https://github.com/weibohan07/oxidase/pull/18) was normally merged without
an administrator override. Base: `890a802dd74e58de8bf3e316422e771f59172621`;
final head: `b27974afc8565bae369eb7e4e49a0b20c9ffa42d`;
merge: `a1a06b0d89fa8303233ac31a46be86dce747d397`.
[Final-head PR run `37143336854`](https://github.com/weibohan07/oxidase/actions/runs/37143336854)
and independent [merged-main push run `37143737883`](https://github.com/weibohan07/oxidase/actions/runs/37143737883)
each completed with all four required jobs SUCCESS. Main remained strict/up-to-date,
with force pushes/deletion disabled. This is separate from the ADR-only Draft run.

All nine locked local release commands were rerun on exact final head `b27974a`
and PASS. Raw receipt:
`artifacts/discovery-6c-b27974a-final-gates.log.gz`. The six actual CLI examples
also passed on its unchanged implementation ancestor `3c031c8`; their retained
log is not represented as a new final-head execution. The SRV component-expiry,
partial-positive scheduling and long-SOA suppression findings were fixed with
regressions before merge. ASan and Linux process campaigns still belong to 6D.

## 6C executable contract

Draft [PR #18](https://github.com/weibohan07/oxidase/pull/18) starts at protected
main `890a802dd74e58de8bf3e316422e771f59172621`. Its ADR/receipt-only head
`3999ec6c9f4b08dc79ce113c057dfe957e4d5462` passed run `37140254523`; that is not
an implementation-head acceptance run. The following rows describe executable
local contracts, with final-head and merged-main Hosted receipts recorded separately.

| ID | Contract | Executable regression | Local evidence |
| --- | --- | --- | --- |
| DS-20 | Separate SRV name grammar, no fixed port/null loophole, precise spans | config `tests/srv_discovery.rs` plus portable reconstruction tests | stable/MSRV config suites PASS 96 tests each |
| DS-21 | Required SRV/base-DNS/deadline capabilities; offline source-free signed validation | actual CLI `tests/srv_discovery_offline.rs` | stable/MSRV PASS 2/2 each; real subprocess UDP/TCP query count remains zero |
| DS-22 | Priority before admission/retry exclusion; target weight before address LB | runtime `srv_weight_is_per_logical_target_not_amplified_by_address_count`, `srv_lowest_healthy_priority_is_not_bypassed_by_saturation_or_retry_exclusion`; wire `srv_health_priority_and_admission_cannot_send_saturated_primary_traffic_to_backup` | runtime and actual health/H2 fixtures PASS |
| DS-23 | Complete zero-inclusive u16 weighting, all-zero eligible selection, seeded reproducibility | runtime discovery weighted-selection tests and SRV resolver records | deterministic boundary/distribution tests PASS; no weight-sized array |
| DS-24 | One absolute whole-round deadline, bounded/coalesced target families; completed partial results survive | resolver `srv_whole_round_timeout_preserves_fast_target_and_releases_single_global_slot` | one-slot real DNS fixture PASS, fast A retained despite AAAA/other-target timeout |
| DS-25 | Independent SRV/address/CNAME original lifetimes and separate stale authority | runtime `srv_and_address_expiry_each_require_their_own_stale_authority`, `srv_zero_ttl_and_duplicate_zero_ttl_never_seed_stale`; resolver CNAME test | identified component-authority bug fixed with public-API regressions |
| DS-26 | Negative SOA and failure memo do not slide, exceed configured query ceiling or grow with target churn | resolver `srv_negative_target_refresh_ceiling_recovers_before_long_soa_expiry_without_sliding`, negative/backoff/churn tests; manager `srv_refresh_uses_original_component_expiry_and_target_negative_deadline` | bounded owner-local failure memo and scheduling PASS; no positive-IP memo cache |
| DS-27 | Dot withdrawal/NXDOMAIN fence, conflicting records fail closed, observable aggregate limits | resolver dot/target-NXDOMAIN/record-byte-name quota tests; runtime received-round quota tests | resolver stable/MSRV PASS 25/25; opaque discarded Hickory bytes are not claimed observable |
| DS-28 | Weight-only pool reuse; withdrawn member gets no new stream while issued trailers finish | wire `srv_weight_only_reuses_pool_but_withdrawal_and_new_target_do_not_reuse_it`; runtime remove/readd and policy-replacement admission tests | actual H2 pool reuse/withdrawal PASS; held physical counter survives policy replacement |
| DS-29 | DNS port is actual socket; logical Host/base/raw query/TLS identity remain fixed; no publisher/metric-label authority | wire `srv_actual_socket_preserves_fixed_tls_name_and_rejects_an_untrusted_replacement` and both other SRV wire tests | trusted exact SNI observed, untrusted replacement fails before HTTP dispatch; exact PublishedRuntime Arc unchanged |

The five-test real A/AAAA+SRV DNS/TLS/H2 wire suite passed on stable and Rust
1.88. Stable was repeated 20 times serially, every run PASS 5/5. These are bounded
macOS regression executions, not a Linux qualification campaign. Source and
runtime libraries keep DNS generation out of Bundle/config identity and out of
fifth-stage publication authority. Phase-6D signed Admin races, restart, fuzz and
Linux process-level qualification are not implied by this table.

Frozen intermediate implementation/documentation head `3c031c8` passed all nine
locked local gates, including stable/MSRV workspace tests, denied-warning docs
and Clippy, release build, unchanged cargo-deny policy and fuzz-bin compilation.
The independent audit then identified excessive target-negative suppression under
a long SOA TTL. Its scheduling-ceiling repair requires a fresh complete gate and
its own exact final-head Hosted acceptance; the intermediate green is not used
to qualify that repair.

The ceiling repair's focused resolver suite passes 26/26 on stable and Rust1.88;
all server targets/features also pass Clippy with warnings denied. Raw receipts
are retained in `artifacts/discovery-6c-negative-ceiling-{stable,msrv,clippy}.log.gz`.
It preserves the raw 60-second SOA expiry while actual local DNS target questions
resume after the configured test ceiling. Separate final gates remain mandatory.

## 6A executable contract and intermediate evidence

These local results describe the tested implementation, not final-head Hosted
acceptance. The Draft's design-only head `53a1b14` passed PR run `37122950253`;
that run must not be used to qualify the later implementation. The later
implementation head `b105021` has an actual failed Hosted run, recorded below.

## 6B executable contract (before final-head gates)

Draft [PR #17](https://github.com/weibohan07/oxidase/pull/17) starts from protected
main `aaece2a0c263ce58e3ba7d398a33c11892186316`. Its receipt-only head `e8a323d`
passed run `37132909545`; that run does **not** qualify the A/AAAA implementation
that followed. Final implementation-head and merged-main gates remain separate.

| ID | Contract | Executable regression | Current local evidence |
| --- | --- | --- | --- |
| DS-10 | Strict source/portable contracts, precise spans, no DNS during validation | `oxidase-config/tests/dns_discovery.rs`; actual CLI `actual_check_bundle_build_and_verify_are_offline_and_do_not_query_dns` | focused source/portable/MSRV and real CLI PASS; frozen full gate pending |
| DS-11 | Approved physical target is actual socket; fixed authority/base/raw query | `dns_rotation_moves_new_h2_stream_to_b_while_old_a_stream_finishes_with_trailers` | real TLS/H2 downstream and distinct H2 upstream peers PASS |
| DS-12 | Independent family/CNAME expirations, TTL0 unavailable, no fresh lifetime refund | resolver `raw_queries_observe_independent_families_deduplicate_and_preserve_zero_ttl`; runtime discovery membership tests; wire `cold_failure_recovers_but_nxdomain_and_zero_ttl_revoke_real_pool_use` | focused resolver/runtime/wire PASS |
| DS-13 | UDP/TCP fallback, canonical names, CNAME cycles/depth, packet/record/target quotas | `dns_resolver::tests` (14 real/pure fixture tests) | PASS 14/14; fixed limits and dependency graph/MSRV checked |
| DS-14 | Negative/deletion distinct from transient; finite stale and bounded failure schedule | negative SOA/CNAME resolver tests; runtime stale-deadline tests; `family_negative_cache_backoff_and_name_revocation_are_bounded_and_independent` | targeted tests PASS; no completed-answer cache restarts TTL |
| DS-15 | New H2 stream cannot use removed pool; existing A stream completes; fresh readd incarnation | real A→B wire test; `dns_withdrawal_reclaims_idle_pool_and_readd_cannot_reuse_old_incarnation`; runtime session/queued-lease tests | real wire and final server library gate PASS; latest runtime receipt recorded with full gate |
| DS-16 | Expired bookkeeping is not eligible quota; rejected positive does not hide recovery under its raw TTL | paused runtime merge-quota test; `merged_quota_rejection_uses_failure_backoff_not_rejected_positive_ttl` | regression added and server scheduling PASS; frozen workspace gate pending |
| DS-17 | Commit-only task activation, explicit owner retirement, resume-safe independent health tasks | health `removed_cluster_stops_supervisor_even_when_an_old_snapshot_is_pinned`; `replaced_health_policy_cancels_old_owner_and_same_arc_resume_restarts_once`; runtime query-session fencing tests | health PASS 11/11; no failed candidate long-lived task |
| DS-18 | DNS does not publish configuration or create dynamic metric labels | both real DNS wire tests compare exact PublishedRuntime Arc/ETag/origin/version/readiness; metrics reject `endpoint="discovered-..."` | wire PASS; signed Admin competition and restart campaign belong to 6D |
| DS-19 | Jitter desynchronizes instances and is deterministically testable without extending TTL | `early_jitter_has_deterministic_seed_and_does_not_refund_ttl` | injected-seed and early-bound regression PASS |

The final focused server library run passed 207 tests; one existing ignored manual
benchmark was **not run**. Focused Clippy denied warnings successfully. Intermediate
build errors while collaborators were editing unfrozen APIs were not acceptance
runs; only the subsequent frozen-source receipts qualify those changes. SRV and
the 6D fuzz/Linux campaign remain NOT RUN, not implied by these local results.

### Frozen implementation local gates and actual Hosted failure

Frozen implementation `250b285044a9d1c969d8eaad5d98f14dfa60afe0` passed all nine
local gates listed below, including both entire workspace test runs. Raw output:
`artifacts/discovery-6b-250b285-local-gates.log.gz`. This is macOS evidence, not
the subsequent Hosted outcome.

That exact head ran [PR run `37136494778`](https://github.com/weibohan07/oxidase/actions/runs/37136494778).
MSRV 1.88, Dependency policy and Fuzz harness compile smoke PASS. Stable workspace
FAIL at Clippy; its tests/release/docs were skipped. GitHub used Rust 1.99, which
deprecates `AtomicU64::fetch_update`; local stable was 1.97.1. Raw failing job:
`artifacts/discovery-6b-pr17-37136494778-stable-failure.log.gz`.

The repair uses a checked compare-exchange loop supported by Rust 1.88 and newer
stable, without a warning suppression or MSRV increase. Regression
`endpoint_incarnation_cas_is_unique_under_race_and_fails_closed_at_exhaustion`
proves 2,048 concurrent unique claims and no rollover after `u64::MAX`. Stable
and Rust 1.88 discovery tests pass 18/18 after the repair. The repaired final head
requires its own four checks and an independent merged-main run; neither the
old macOS PASS nor the receipt-only Draft run qualifies it.

## 6A historical gates and Hosted-failure investigation

### Actual PR 16 Hosted failure

Implementation/documentation head `b105021` ran
[GitHub Actions run `37129738230`](https://github.com/weibohan07/oxidase/actions/runs/37129738230).
Both `MSRV 1.88` and `Stable workspace` FAIL at the existing `oxidase-soak`
`tests::protocol_campaign_exercises_grpc_and_upgrade` smoke test,
`crates/oxidase-soak/src/lib.rs:311`: `summary.body_cancellations > 0` was false.
This is the only reported failing test in those two jobs; the new 6A CLI and wire
regressions before it actually passed in both jobs. That run's overall gate is
FAIL, not partially green acceptance. At that point the PR had not been merged;
the repaired final head subsequently passed its own run as recorded above.

Raw failing job output is retained in
`artifacts/discovery-6a-pr16-37129738230-failure.log.gz`. The local nine-gate PASS
on macOS remains valid historical evidence but does not prove Linux Hosted PASS.
No old green run, local result, or design-only check substitutes for the repaired
final head's required checks and the eventual independent main push run.

The fixture diagnosis is a cancellation-versus-completion race: its 10 ms
trailer/EOS path can complete before the client's intended drop on Linux. The
repair is committed as `f0237648d3759f60c84b5ecf6edf8915056c8c2f`
(`fix(soak): synchronize observed streaming cancellations`): hold the cancellation
path open, acknowledge the actual upstream body Drop, and assert the cancellation
metric delta. The existing cancellation assertion remains intact, not weakened,
ignored or skipped. Local repaired-source verification is recorded below;
new-head Hosted results are still PENDING.

### Verified local Hosted-failure repair

The repaired source is frozen at `f0237648d3759f60c84b5ecf6edf8915056c8c2f`.
Its sequential post-fix gate run exited 0: all nine commands in the local-gate
table below were rerun and PASS, including both complete workspace test runs
under stable and Rust 1.88, locked Clippy/docs/release and locked fuzz-bin compile.
Raw output is retained separately from the original run in
`artifacts/discovery-6a-post-hosted-fix-gates.log.gz`.

`protocol::tests::grpc_first_frame_cancellation_drops_live_body_and_records_cancelled`
uses an actual TLS/H2 request, holds the live upstream trailer/EOS path open,
drops the downstream body, waits for the real upstream body Drop acknowledgement,
and asserts exactly one cancellation metric increment. A normal gRPC/trailer
request then succeeds on the same H2 connection without another cancellation.
The combined fixture also acknowledges actual dropped upstream body ownership.

The seven-test `oxidase-soak` library suite was actually repeated 20 times on
stable and 20 times on Rust 1.88: every run passes 7/7, with no failures or ignored
tests. Both the original combined/protocol smoke assertions and the new live-body
regression execute. Raw repeated-run evidence is retained in
`artifacts/discovery-6a-soak-cancellation-stable-20.log.gz` and
`artifacts/discovery-6a-soak-cancellation-msrv-20.log.gz`.
These are bounded local regressions, not a Linux qualification or fuzz campaign.
The repaired final PR-head required checks and eventual merged-main push CI
remain PENDING; the old failed run is preserved rather than reclassified.

| ID | Requirement / implementation | Executable regression | Actual result |
| --- | --- | --- | --- |
| DS-01 | Logical authority/base path stays separate from fixed physical dial | `upstream_transport::tests::fixed_dial_target_never_resolves_the_logical_name_again`; `upstream_transport::tests::tls_uses_fixed_logical_sni_and_proves_h2_alpn_and_actual_peer`; wire `ipv6_authority_base_path_and_raw_query_survive_direct_dial_and_pool_reuse` | post-fix local gates PASS; repaired-head Hosted pending |
| DS-02 | Pool keys isolate address, authority, protocol and TLS security policy | `every_origin_dial_protocol_and_security_boundary_has_a_distinct_pool`; `strong_pool_entries_are_bounded_idle_lru_is_reclaimed_and_active_arc_survives`; `retirement_removes_all_cached_keys_without_pinning_resource_or_existing_client`; wire `custom_ca_and_fixed_server_name_succeed_and_policy_reload_does_not_reuse_pool` | post-fix local gates PASS; repaired-head Hosted pending |
| DS-03 | One absolute pre-head deadline spans queue, replay buffering and all retries | wire `three_response_head_attempts_share_one_absolute_total_budget`; `total_deadline_caps_admission_queue_without_consuming_another_attempt`; `total_deadline_caps_explicit_bounded_replay_buffer_before_dispatch`; unit `repeated_attempts_do_not_renew_the_absolute_budget` | post-fix local gates PASS; repaired-head Hosted pending |
| DS-04 | Demand-relative idle timers do not charge unpolled backpressure | `idle_time_starts_with_first_body_demand_and_terminates_once`; `returning_data_suspends_idle_time_during_send_backpressure`; wire `progress_upload_does_not_start_response_header_timer_until_local_eos`; `response_body_idle_failure_preserves_sent_200_and_releases_permits` | post-fix local gates PASS; repaired-head Hosted pending |
| DS-05 | Response head can arrive before upload EOS | wire `http1_early_200_and_413_do_not_wait_for_upload_eos`; `h2_early_200_and_413_do_not_wait_for_upload_eos`; `h2_flow_blocked_upload_is_cancelled_without_killing_sibling_streams` | post-fix local gates PASS; repaired-head Hosted pending |
| DS-06 | Cancellation releases two-leg admission, preserves sibling H2 streams and bounds retired connecting work | `response_completion_cancels_upload_and_holds_permit_until_upload_drop`; `retry_reservation_precedes_cancellation_and_reuses_one_cluster_permit`; `status_retry_without_reserved_alternative_preserves_original_stream`; `cancelling_cold_h2_connecting_owner_preserves_a_valid_waiter`; `cancelled_connecting_work_is_bounded_and_cannot_renew_its_cap`; `dropping_retirement_owner_stops_outstanding_cleanup_tasks`; `dropping_an_unpolled_dispatch_cannot_start_a_cancelled_request` | post-fix local gates PASS; repaired-head Hosted pending |
| DS-07 | Downstream upload fault is not a passive endpoint failure | wire `downstream_upload_idle_timeout_is_408_without_passive_endpoint_failure` (actual HTTP/1 and TLS/H2); `post_head_local_request_timeout_does_not_eject_endpoint`; `request_idle_telemetry_records_only_the_first_local_fault` | post-fix local gates PASS; repaired-head Hosted pending |
| DS-08 | Legacy YAML/Bundle semantics remain explicit; new policies require capability | `legacy_upstream_contract_and_precise_migration_warnings_are_preserved`; `portable_timeouts_preserve_legacy_shape_and_reconstruct_phased_spans`; `phased_bundle_requires_declared_capability_in_verify_and_activation`; actual CLI `actual_signed_phased_bundle_preserves_all_deadlines_through_admin_activation`; `legacy_timeout_migration_warnings_match_human_json_and_exact_crlf_spans`; `mixed_timeout_policy_reports_exact_primary_secondary_spans_in_both_formats` | post-fix local gates PASS; repaired-head Hosted pending |
| DS-09 | Health probes use the same identity boundary with independent timeout/quota | `health_timeout_is_independent_and_records_failure`; `health_rounds_enforce_global_and_per_cluster_quotas_without_starving_late_endpoints`; `local_health_admission_wait_is_not_an_endpoint_failure_and_shutdown_cancels_it`; wire `required_upstream_client_certificate_is_used_by_proxy_and_active_health` | post-fix local gates PASS; repaired-head Hosted pending |

The wire test names above belong to
`crates/oxidase-server/tests/upstream_deadlines.rs`, except the custom-CA and
required-client-certificate tests in `upstream_tls_policy.rs`. Tests use Rust
fixtures, ephemeral local sockets and test-only certificate material; ordinary Proxy bodies remain
streaming. Three retry attempts are counted on actual upstream fixtures and
share one absolute total budget; this is not an absolute throughput benchmark.

### Focused executions and historical macOS source freeze

- `cargo test -p oxidase-server --test upstream_deadlines --locked`: PASS 11/11.
  `cargo +1.88.0 test -p oxidase-server --test upstream_deadlines --locked`:
  PASS 11/11. H1/H2 upload-idle, progressive upload and early-head cases exercise
  both protocols, rather than merely inspecting timeout structs.
- `cargo test -p oxidase-cli --test diagnostic_output --test admin_ctl_real_server --locked`:
  PASS 14/14. Rust 1.88 repeats the same command and passes 14/14. These execute
  the actual CLI process against the actual authenticated Admin/data listeners.
- `cargo test -p oxidase-server --lib upstream_timing::tests --locked`:
  PASS 14/14, including the cold shared-H2 connecting owner, zero-window upload,
  bounded connecting retirement and cleanup-owner drop regressions named DS-06.
  A later focused `cargo clippy -p oxidase-server --lib --tests --locked -- -D warnings`
  also passes; this is not a replacement for the frozen workspace gate.
- Final `cargo test -p oxidase-server --lib upstream_transport --locked -- --test-threads=1`:
  PASS 10/10; `static_targets`: PASS 5/5; `upstream_pool`: PASS 5/5;
  `cluster_health`: PASS 8/8, with the same command form. Runtime Cluster tests
  pass 29 tests; one existing ignored manual benchmark was not run.
  Replacement-endpoint reservation regressions pass 5/5.

The macOS source freeze reran every workspace test under stable and Rust 1.88,
including the actual CLI and wire suites above. Earlier focused receipts remain
historical evidence; that frozen run was a local release gate, not Hosted CI or
validation of the later Linux fixture repair. The independent repaired-source
gate receipt above supersedes it for local acceptance only.

### Historical frozen local gates (macOS)

The sequential frozen-source run completed with exit status 0. The tested source
is committed as `44489c5` (`feat(proxy): enforce transport identity and absolute
upstream deadlines`). All nine gates below PASS; full output is retained in
`artifacts/discovery-6a-local-gates.log.gz`. The following `b105021` documentation
head failed Hosted run `37129738230`; the later `f023764` repair has its own fresh
nine-gate PASS receipt above. The final 6A PR-head and independent merged-main
receipts are recorded in the protected delivery section at the top of this file.

| Actual command | Local result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | PASS |
| `cargo test --workspace --locked` | PASS; pre-existing ignored manual benchmarks/campaigns NOT RUN |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` | PASS |
| `cargo deny check` | PASS |
| `cargo build --workspace --release --locked` | PASS |
| `cargo +1.88.0 check --workspace --all-targets --all-features --locked` | PASS |
| `cargo +1.88.0 test --workspace --locked` | PASS; pre-existing ignored manual benchmarks/campaigns NOT RUN |
| `cargo check --manifest-path fuzz/Cargo.toml --bins --locked` | PASS compilation only; no phase-six fuzz campaign claimed |

Six actual example invocations also PASS, retained separately in
`artifacts/discovery-6a-examples.log.gz`:

```text
cargo run -p oxidase-cli --locked -- check examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli --locked -- test examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli --locked -- explain examples/basic-gateway/oxidase.yaml --request examples/basic-gateway/requests/home.yaml
cargo run -p oxidase-cli --locked -- check examples/secure-resilient-gateway/oxidase.yaml
cargo run -p oxidase-cli --locked -- check examples/secure-admin-gateway/oxidase.yaml
cargo run -p oxidase-cli --locked -- test examples/secure-admin-gateway/oxidase.yaml
```

Legacy timing warnings in existing Proxy examples are expected migration
diagnostics, not failures. The public test-only Admin token's `0644` permission
warning is expected; the example never represents production Secret material.

### Signed Bundle / Admin compatibility boundary

The real CLI regression builds and signs a Bundle whose six phased limits are
distinct, verifies its trusted signature, stages and validates it without
changing PublishedRuntime, activates it, and checks all six prepared limits plus
the legacy compatibility mirrors. A second, correctly signed artifact with
`upstream-deadlines` removed may be staged as a structurally sound candidate.
Validation rejects it with `bundle.required_feature_missing` before Resource
preparation; activation rejects the non-validated artifact with
`candidate.not_validated`. Neither operation changes the runtime Arc, ETag or
served response. This is not a relaxation of phase-five publication authority.

The same fixture then activates an old-shape signed Bundle: its serialized
Cluster omits `timeouts`, reconstructs Legacy mode and preserves the loader
migration warning. Separate actual CLI checks prove human/JSON warning codes,
help text, deterministic ordering and exact UTF-8/CRLF spans after a block scalar.

### Latest static-host integration

Static host answer caching and cold address fallback belong to 6A's fixed-endpoint
transport compatibility, not 6B dynamic membership or DNS/SRV public policy.
Final actual regression receipts (also present in the frozen workspace run):

- `static_targets::tests::cache_hits_skip_resolution_and_error_stale_deadline_never_slides`:
  warm hits skip resolution and the bounded static failure-stale window cannot slide.
- `coalesced_native_job_keeps_admission_after_its_first_waiter_is_cancelled`:
  cancelling one waiter does not bypass native job admission or strand another waiter.
- `cold_ipv4_failure_falls_back_to_verified_ipv6_once_and_pooled_hits_reuse_it`:
  actual IPv6 fallback is selected once and reused by a warm pool.
- `cold_address_fallback_uses_one_exact_tcp_deadline_not_one_per_address`:
  cold candidate attempts cannot renew the TCP phase budget.
- `retirement_removes_static_answers_and_a_late_pinned_request_cannot_reinsert_them`:
  retirement releases cached ownership and prevents stale callback reinsertion.
- `failed_pool_retirement_uses_exact_arc_and_cannot_remove_a_newer_replacement` and
  `protocol_change_retires_normal_h2_pool_but_preserves_explicit_http1_upgrade_override`:
  failed or incompatible normal pools retire without deleting a newer pool or
  accidentally removing the explicit trusted HTTP/1 Upgrade override.
- `native_resolution_failure_does_not_eject_a_previously_healthy_physical_endpoint`:
  local native-resolution failure is not fabricated as endpoint passive failure.
- `unrepresentable_legacy_queue_deadline_fails_closed_without_touching_current_admission`:
  extreme legacy durations do not panic or release the original active permit.

Static targets, pool, transport and health focused suites respectively pass
5/5, 5/5, 10/10 and 8/8; runtime Cluster passes 29 with one pre-existing ignored
benchmark. Raw output is retained in
`artifacts/discovery-6a-static-targets.log.gz`,
`artifacts/discovery-6a-upstream-pool.log.gz`,
`artifacts/discovery-6a-upstream-transport.log.gz`,
`artifacts/discovery-6a-cluster-health.log.gz`, and
`artifacts/discovery-6a-runtime-cluster.log.gz`.
These are local results, not a dynamic-discovery or Hosted campaign.

The first sandboxed workspace-test attempt could not bind TCP/Unix fixtures and
is retained as `artifacts/discovery-6a-sandbox-bind-restriction.log.gz`. It is NOT
a passing test result. The same suite was actually rerun with local-socket
permission and passed; no network tests were skipped to obtain that result.
The newly added CLI suites first failed at fixture bind with sandbox
`PermissionDenied`; that attempt is NOT PASS and did not reach their assertions.
Their explicit local-socket-authorized reruns passed the 14 tests listed above.
Existing ignored manual benchmarks/campaigns are not counted as executed.
The frozen local gate log is retained separately from the baseline and sandbox
restriction log; exact final head/merge/run receipts must be added after actual
protected delivery. DNS/fuzz/Linux evidence remains NOT RUN in
6A; a compiled harness is not a campaign.

DNS observations must never change PublishedRuntime's
ETag, origin, serving state or publication authority. No stage-seven work, version
bump, tag or Release belongs to this delivery.
