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
| 6A transport identity/deadlines | implementation locally verified; protected delivery pending | nine frozen local gates PASS; final-head PR and merged-main Hosted acceptance pending |
| 6B A/AAAA discovery | not implemented by this branch | NOT RUN |
| 6C SRV discovery | not implemented by this branch | NOT RUN |
| 6D integration/qualification | not implemented by this branch | NOT RUN |

## 6A executable contract

These local results describe the tested implementation, not final-head Hosted
acceptance. The Draft's design-only head `53a1b14` passed PR run `37122950253`;
that run must not be used to qualify the later implementation.

| ID | Requirement / implementation | Executable regression | Actual result |
| --- | --- | --- | --- |
| DS-01 | Logical authority/base path stays separate from fixed physical dial | `upstream_transport::tests::fixed_dial_target_never_resolves_the_logical_name_again`; `upstream_transport::tests::tls_uses_fixed_logical_sni_and_proves_h2_alpn_and_actual_peer`; wire `ipv6_authority_base_path_and_raw_query_survive_direct_dial_and_pool_reuse` | frozen local gates PASS; final-head Hosted pending |
| DS-02 | Pool keys isolate address, authority, protocol and TLS security policy | `every_origin_dial_protocol_and_security_boundary_has_a_distinct_pool`; `strong_pool_entries_are_bounded_idle_lru_is_reclaimed_and_active_arc_survives`; `retirement_removes_all_cached_keys_without_pinning_resource_or_existing_client`; wire `custom_ca_and_fixed_server_name_succeed_and_policy_reload_does_not_reuse_pool` | frozen local gates PASS; final-head Hosted pending |
| DS-03 | One absolute pre-head deadline spans queue, replay buffering and all retries | wire `three_response_head_attempts_share_one_absolute_total_budget`; `total_deadline_caps_admission_queue_without_consuming_another_attempt`; `total_deadline_caps_explicit_bounded_replay_buffer_before_dispatch`; unit `repeated_attempts_do_not_renew_the_absolute_budget` | frozen local gates PASS; final-head Hosted pending |
| DS-04 | Demand-relative idle timers do not charge unpolled backpressure | `idle_time_starts_with_first_body_demand_and_terminates_once`; `returning_data_suspends_idle_time_during_send_backpressure`; wire `progress_upload_does_not_start_response_header_timer_until_local_eos`; `response_body_idle_failure_preserves_sent_200_and_releases_permits` | frozen local gates PASS; final-head Hosted pending |
| DS-05 | Response head can arrive before upload EOS | wire `http1_early_200_and_413_do_not_wait_for_upload_eos`; `h2_early_200_and_413_do_not_wait_for_upload_eos`; `h2_flow_blocked_upload_is_cancelled_without_killing_sibling_streams` | frozen local gates PASS; final-head Hosted pending |
| DS-06 | Cancellation releases two-leg admission, preserves sibling H2 streams and bounds retired connecting work | `response_completion_cancels_upload_and_holds_permit_until_upload_drop`; `retry_reservation_precedes_cancellation_and_reuses_one_cluster_permit`; `status_retry_without_reserved_alternative_preserves_original_stream`; `cancelling_cold_h2_connecting_owner_preserves_a_valid_waiter`; `cancelled_connecting_work_is_bounded_and_cannot_renew_its_cap`; `dropping_retirement_owner_stops_outstanding_cleanup_tasks`; `dropping_an_unpolled_dispatch_cannot_start_a_cancelled_request` | frozen local gates PASS; final-head Hosted pending |
| DS-07 | Downstream upload fault is not a passive endpoint failure | wire `downstream_upload_idle_timeout_is_408_without_passive_endpoint_failure` (actual HTTP/1 and TLS/H2); `post_head_local_request_timeout_does_not_eject_endpoint`; `request_idle_telemetry_records_only_the_first_local_fault` | frozen local gates PASS; final-head Hosted pending |
| DS-08 | Legacy YAML/Bundle semantics remain explicit; new policies require capability | `legacy_upstream_contract_and_precise_migration_warnings_are_preserved`; `portable_timeouts_preserve_legacy_shape_and_reconstruct_phased_spans`; `phased_bundle_requires_declared_capability_in_verify_and_activation`; actual CLI `actual_signed_phased_bundle_preserves_all_deadlines_through_admin_activation`; `legacy_timeout_migration_warnings_match_human_json_and_exact_crlf_spans`; `mixed_timeout_policy_reports_exact_primary_secondary_spans_in_both_formats` | frozen local gates PASS; final-head Hosted pending |
| DS-09 | Health probes use the same identity boundary with independent timeout/quota | `health_timeout_is_independent_and_records_failure`; `health_rounds_enforce_global_and_per_cluster_quotas_without_starving_late_endpoints`; `local_health_admission_wait_is_not_an_endpoint_failure_and_shutdown_cancels_it`; wire `required_upstream_client_certificate_is_used_by_proxy_and_active_health` | frozen local gates PASS; final-head Hosted pending |

The wire test names above belong to
`crates/oxidase-server/tests/upstream_deadlines.rs`, except the custom-CA and
required-client-certificate tests in `upstream_tls_policy.rs`. Tests use Rust
fixtures, ephemeral local sockets and test-only certificate material; ordinary Proxy bodies remain
streaming. Three retry attempts are counted on actual upstream fixtures and
share one absolute total budget; this is not an absolute throughput benchmark.

### Focused executions and final source freeze

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

The final source freeze reruns every workspace test under stable and Rust 1.88,
including the actual CLI and wire suites above. Earlier focused receipts remain
historical evidence; the frozen run is the local release gate, not Hosted CI.

### Frozen local gates

The sequential frozen-source run completed with exit status 0. The tested source
is committed as `44489c5` (`feat(proxy): enforce transport identity and absolute
upstream deadlines`). All nine gates below PASS; full output is retained in
`artifacts/discovery-6a-local-gates.log.gz`. Subsequent changes are
documentation-only. Final PR-head and merged-main Hosted receipts are pending.

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
