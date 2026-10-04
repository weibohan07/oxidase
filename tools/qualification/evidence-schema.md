# Resource qualification evidence v1 (validation-only)

The independent analyzer reads `receipt.json`, `identity.json`, `events.jsonl`,
`buckets.jsonl`, `errors.jsonl`, and `samples.jsonl`, plus the applicable
`prelude-operations.json`, `control-probes.jsonl`, and
`control-operations.jsonl` journals (a `.gz` suffix is also supported). The
declared bounded fault representation additionally requires
`compact-fault-results.jsonl`, including when it is empty.
All timestamps are integer Linux `CLOCK_MONOTONIC` nanoseconds, not
wall clock or an index. Files retain capture order. Unknown optional fields are
allowed; missing required evidence is never filled with zero.

`receipt.json` has `schema_version: oxidase.resource-qualification/v1` and:

- `implementation_commit`, `tool_commit`, `source_set_sha256`, and `source_files`
  (`[{path, sha256}]`). The source-set digest is SHA-256 of the UTF-8 JSON array,
  sorted by path, encoded with separators `,`/`:` and `ensure_ascii=false`.
- `binaries: [{role, sha256}]`; `identity.json` has `clock: CLOCK_MONOTONIC`,
  `boot_id`, and `processes: [{role,pid,start_ticks,binary_sha256,exe_sha256}]`.
  Roles include gateway, controller, dns, upstream, and sampler. Their PIDs must
  differ and binary hashes must match the captured executable hashes.
- `parameters: {campaign,seed,concurrency,payload_bytes,formal,durations_ns,
  sample_interval_ns,max_sample_gap_ns}`. `durations_ns` keys are `warmup`,
  `steady`, `recovery`, `quiet`, `post_drain`. `formal` does not grant a pass:
  the analyzer independently checks H/C minimum durations.
- `bounds: {kind: {live_max,retired_exit_budget_ms,exiting_exit_budget_ms?}}`;
  optional `quiet_live_max` and `post_drain_live_max` apply to those phases.
  Bounds are frozen before a run, not derived from observed peaks.
  An observed kind without a structural capacity/exit budget makes that formal
  criterion `INCONCLUSIVE`; bounds for ten kinds cannot qualify all 31 kinds.
- `required_gauges: [name]`, `coverage_required: [name]`, and `recipes` below.
  Gauge names are exact raw series, not unlabelled aggregate aliases. The fixed
  H/C fixture requires `oxidase_active_requests`, both
  `oxidase_active_connections{listener="qualification",protocol="http1|h2"}`
  series separately, `oxidase_http2_active_streams{listener="qualification"}`,
  and `oxidase_active_tunnels{listener="qualification"}`. The `http1|h2` notation
  here denotes two literal declarations, not a regex selector. Missing series,
  a wrong listener/protocol, duplicate series or a non-finite value cannot be
  replaced with a zero. Formal H/C cannot delete these declarations to bypass
  the fixed fixture requirement. Bootstrap observations do not grant measured
  Running coverage or fabricate a metric before it is registered.
- `final_counts: {offered,connection_attempts,admitted_http_operations,
  received_operations,workers:[{worker_id,offered,connection_attempts,
  admitted_http_operations,received_operations,last_operation_seq}]}`.
- `complete`, `artifact_truncated`, and optional `fatal_errors`. `controller_result`
  is advisory and never used by the analyzer. Optional `artifacts` entries
  `{path,sha256,bytes}` are checked against the original stored bytes.

Each events row has `writer_seq`, `t_ns`, `kind`. Exactly five ordered `phase`
events name the phases above; `end` terminates post-drain. A closed `fault_window`
event adds `id,start_ns,end_ns,recovery_deadline_ns,target,lanes,allowed,trigger`.
`allowed` contains exact `{status}` or `{error_stage,error_code}` choices.
`trigger` has `source,name,before,after`; an actual counter increase is required.
Windows are finite and confined to steady Running. A `control` adds `action`,
`request_id`, `before_runtime`, `after_runtime`; DNS-only actions must preserve
the entire PublishedRuntime JSON. A `coverage` adds `name,evidence` with an
actual counter increase, or a wire operation identity. Boolean toggle/pass
evidence is insufficient. `held_release` records a real flow release. `fatal`
records panic, timeout, evidence write failure, or abandoned work.
Windows may add `failure_peers`, `fault_case_id`, and `recovery_peers` to isolate
the exact fixture/endpoint. Recovery requires a new operation started after
the window, completed before its deadline, on each affected physical peer.
An already-running request or a healthy response from B cannot prove A recovered.
Post-head failure still checks received DATA prefix SHA-256 and metadata; an
injection cannot excuse corrupt DATA. Expected 503/504 responses must contain
the complete fixed safe response (`Service Unavailable` / `Gateway Timeout`).

Each one-second worker bucket contains `writer_seq,bucket_start_ns,bucket_end_ns,
worker_id,first_operation_seq,last_operation_seq,offered,connection_attempts,
admitted_http_operations,received_operations,outcomes`. Ranges are contiguous,
non-overlapping per worker, start at operation 1, and cover offered operations.
Each outcome has `count,lane,protocol,phase,recipe,target,raw`, its aggregated
`first_start_ns,last_start_ns,last_end_ns` (not part of the histogram key), and optional
`window_id`. `classification` is advisory and ignored. `raw` contains:

```text
status, eof, body_bytes, body_sha256, content_type, trailers,
upstream_name, upstream_peer, authority, server_name, path,
connection_attempted, admitted,
error_stage?, error_code?, error?, cancelled?, data_observed?,
fixture_cancel_ack?
```

Non-admitted outcomes must disclose the connection result. Every outcome other
than a fully completed response has a corresponding errors row with
`worker_id,operation_seq,start_ns,head_ns?,end_ns,lane,protocol,phase,recipe,
target,raw,window_id?`. No error is silently omitted when the artifact is full.
Stop halts admission, not collection. Upgrade handshakes use the separate
`admitted_upgrade_operations` counter in buckets/final/worker counts, and
`raw.admitted=true,raw.upgrade=true`; they are not ordinary HTTP response
successes. `parameters.actual_worker_count` includes the separate low-frequency
cancel/Upgrade workers; `concurrency` remains the number of normal workers.

### Bounded contiguous safe-503 representation

New receipts may explicitly declare
`fault_result_storage: contiguous_safe_503_v1`. Old receipts without that marker
retain the individual `errors.jsonl` contract; an undeclared compact file or an
unknown marker is rejected. This is an encoding change, not an expected-fault
verdict. Every Started and Terminal is still consumed by the producer. The
producer and independent analyzer retain their bounded file/row limits; a full
file fails collection instead of dropping evidence.

Only consecutive, identical, fully received safe gateway 503 responses in the
same worker/connection epoch and finite `churn`/`steady` window are compactable.
Healthy or unwindowed failures, transport/post-head errors, cancellation and
Upgrade still require individual rows. Each compact row has:

```text
schema_version: oxidase.resource-compact-fault/v1
writer_seq, worker_id, first_operation_seq, last_operation_seq, count
first_start_ns, last_start_ns, last_end_ns, min_head_ns, max_head_ns
phase, lane, protocol, recipe, target, window_id
connection_attempts, admitted, raw
```

`count` equals the inclusive consecutive sequence range length.
`connection_attempts` is the same per-operation count, not the range total.
`raw` is exactly the corresponding bucket's normalized wire object, without
`operation_id`, `started_ns`, `head_ns`, or `ended_ns`; `connection_epoch` remains
mandatory. Error stage/code are explicit nulls, diagnostics are empty, and
cancelled/upgrade are false. Safe gateway metadata has no claimed upstream
peer/name, authority, SNI or path, no trailers, and the complete independently
checked `Service Unavailable` DATA bytes, SHA-256, Content-Type and EOF.

The actual minimum/maximum response-head clocks must both fall inside the same
declared finite target/lane/status window. First/last starts and last end must
lie inside exactly one worker bucket. A context/epoch/bucket/retirement change,
normal terminal or EOF flushes the pending range. Per-worker ranges retain raw
capture order, cannot overlap individual error IDs or each other, and cannot
cross bucket boundaries. Range counts must exactly match their bucket anomaly
fingerprints and the final `compact_503_rows` / `compact_503_operations` storage
counts. The independent analyzer checks ranges directly without expanding all
represented operation IDs in memory; missing, orphaned, overlapping, corrupted
or out-of-window ranges fail. No archive from a previous failed campaign is
rewritten into this representation.
Isolation modes without traffic explicitly set `traffic_required=false` and
`actual_worker_count=0`. Control and probe lanes retain separate counters.

Recipes declare independently checkable wire expectations:

```json
{
  "download": {
    "status": 200,
    "content_type": null,
    "body": {
      "kind": "fixture_download", "payload_bytes": 65536,
      "fill_byte": 120, "first_bytes": {"a": 97, "b": 98}
    },
    "trailers": {},
    "allowed_peers": ["127.0.0.1:12345"],
    "authority": "gateway.example.test",
    "server_name": "gateway.example.test",
    "path": "/base/payload?b=2&a=1&a=3"
  }
}
```

The new resource fixture uses body kind `repeat` with fill byte 120 for ordinary
responses, without the legacy 6D upstream-name first byte. Other body kinds are
`grpc` (five-byte length prefix followed by fill bytes),
`repeat`, `utf8`, and `empty`. `cancel` uses an ordinary recipe but must prove
DATA was received, validate the received prefix digest, and retain an actual
fixture cancellation acknowledgement. Client classification or a content-valid
boolean is not evidence. Hashing is streaming and does not buffer gateway bodies.

Each sample has `writer_seq,source,planned_ns,start_ns,end_ns,phase,process`
(gateway role, PID, start ticks, boot ID). Source `os` has
`rss_kib,open_fds,os_threads`, and low-frequency `pss_kib,private_dirty_kib`.
Source `admin` has `resources` (unaltered `oxidase.resources/v1` envelope),
`runtime` (PublishedRuntime), original `metrics` text, `clusters`, `history`,
and `scrapes` with actual start/end/ok. Each source has its own interval and
coverage; an Admin read cannot delay OS sampling. Prometheus text is
independently parsed. Explicit `bootstrap` samples before warmup remain raw,
are counted as prelude, and cannot satisfy formal phase coverage.
Absent values stay null with a reason. Scrape failure and gaps are visible.
Only a resource capture with unchanged sequence and zero writers at both ends
permits exact creation/destruction/state conservation checks. This is not a
globally atomic snapshot. Current legal owners are distinguished from retired
or exiting objects; Running does not require all resource gauges to be zero.

For Respond-only isolation, a recipe explicitly sets `upstream_expected:false`;
it is allowed only in campaign I, with absent upstream metadata. H/C retain
strict physical endpoint/SNI/authority/path checks.

`control-probes.jsonl` uses `oxidase.resource-control-probe/v1`. Its Started row
has `writer_seq,operation_id,start_ns,phase,scenario,protocol,recipe,target,
window_id,request:{path,grpc,payload_bytes,upload_bytes}`. Terminal repeats its
identity, adds `end_ns,connection_attempts,admitted,raw,driver_exit`, and must
pair with exactly one Started. Its recipe is independently reconstructed from
the fixed fixture request, not the reply. Coverage references `operation_id`.
These probes are classified separately and cannot inflate worker denominators.

For the fixed SRV campaign, `positive_aaaa` is an end-to-end proof, not a
top-level A/AAAA supervisor metric. Coverage references the complete actual
IPv6 probe and contains an explicit <=30s `observation_window`, original
`before_raw/after_raw` DNS fixture status, `before_metrics/after_metrics` and
`before_clusters/after_clusters`. The same finite window must prove positive
AAAA replies, a successful `family="srv"` supervisor round, unchanged canonical
service name `_https._tcp.api.discovery.test.`, an advanced membership generation
and fresh eligible members. The physical IPv6 response must fall inside that
window and still pass full DATA/EOF/trailer/SNI/authority/path validation.
Internal target AAAA resolution does not increment a top-level
`family="aaaa"` discovery-plan metric, and the verifier never relabels SRV as
AAAA. An unrelated global counter or IPv6 response alone grants no coverage.

`control-operations.jsonl` uses `oxidase.resource-control-operation/v1` and
records only `control_round` Admin reads, fixture IPC and CLI mutations. Started
has `writer_seq,operation_id,start_ns,operation,request`; Terminal adds
`end_ns,classification,raw`. The analyzer recomputes terminal results from
Admin status/complete EOF/driver join, fixture ACK, or CLI mutation receipt.
Cancellation without an actual join receipt is failed/unknown evidence, not a
fabricated zero. An intentional Admin driver abort *after* complete body EOF is
separately accepted only with actual cancellation/join acknowledgement.
Mutation acknowledgement alone cannot prove publication: actual revision,
ETag and origin transitions are independently checked. This scope does not
claim that bootstrap, sampler startup or every legacy internal action is journaled.

`client-retirements.jsonl` uses `oxidase.resource-client-retirement/v1` and a
separate Started/Terminal denominator. It records `retirement_id:worker:epoch`,
`worker_id,protocol,connection_epoch,start_ns,after_operation_seq,
next_operation_seq,request_budget,submitted_requests`; Terminal adds `end_ns`
and the actual `driver_exit` receipt. The validation fixture explicitly uses
the existing listener budget of 1000 requests: the retired client's actual
submitted count must equal that budget, and its driver must complete and join.
This never silently retries an offered request or relaxes healthy-wire failures.
Successful normal/cancel operations retain `raw.connection_epoch`; failed
connection preparation preserves null, and reconnections may skip retirement
epochs but cannot move them backwards. Upgrade uses its separate short-lived
connection and is not this quota counter.

At RetirementStarted the FIFO collector flushes that worker's normal bucket.
The analyzer requires its last sequence N and terminal time to precede retirement,
the next bucket to start with N+1 only after actual driver join, and a new epoch
for that admission. A stop after joining can legitimately leave the last offered
sequence at N; it cannot fabricate an N+1 response. Epoch counts are independently
summed from the raw histogram, not accepted from the retirement counter alone.
Missing/duplicate join results, 999/1001 counters, unjoined/error/timeout drivers,
unflushed boundary buckets or reused retired epochs fail. Retirement control
counts are not added to the normal offered/admitted/terminal denominator.

`prelude-operations.json` has `schema_version: oxidase.resource-prelude/v1`,
advisory `result`, and `evidence:{prelude_counts,prelude_operations}`. Every
allocated `prelude:N` has `role,terminal,cause,raw,acknowledgement`; counts include
offered/classified/abandoned and per-role totals. Retained proof wire facts must
exactly match their operation identities in this full denominator. Raw protocol,
DATA SHA-256, EOF, trailers and peer metadata are independently checked. Cancel
ACK failure or any abandoned operation cannot count as completion.
Initialization 503 is permitted only for `held` within its explicit <=8s window;
withdrawal 503 only for `probe` within its explicit <=10s window. Both require
complete safe response content, not just status. No allowance becomes steady H/C.

The cancellation ACK is the fixture's actual Body Drop receipt:
`{operation_id,body_dropped_after_data,body_bytes,dropped_ns,termination}`.
It must identify the offered operation and contain a legal DATA prefix; a bare
`fixture_cancel_ack:true` cannot qualify a formal cancel lane. The Drop may race
the client's local timestamp but must remain inside the collected ACK deadline.

Multi-peer recovery uses one shared set of fresh, fully verified physical-peer
responses, not separate A-then-B searches that discard a previously seen B.
The original `fault_window.end_ns + 12s` deadline applies to every peer and is
not refreshed per peer or probe. Each probe is recorded Started/Terminal with
its actual connection/driver outcome; its wire timeout is at most nine seconds
and the remaining original window budget. A timeout, bad body, absent peer or
late driver join cannot establish recovery. The bounded 64-probe cap does not
replace the time bound. Ordinary business operations are never replayed by
this validation controller.

Upgrade telemetry distinguishes normal DATA EOF from tunnel shutdown. A planned
close requires all four (steady) or eight (retained) exact echo responses,
actual request-head write, explicit client shutdown and observed peer termination.
`tunnel_close_result:peer_closed_without_close_notify` retains `eof:false` and
an `INCONCLUSIVE` graceful TLS-close criterion. It is not an HTTP body EOF or a
blanket exception for timeout/reset/corrupt echo; those still fail.

Real non-synthetic captures must retain all 31 census kinds. A finite closed
`drain_transition` (<=45s) is the only allowance for state changes while the
sampler hands Quiet over to post-drain; it cannot replace the requested Running
Quiet duration. Zero-scrape isolation retains first/final facts but has an
`INCONCLUSIVE` Running lifecycle criterion; OS sampling remains independently
continuous. Sampling never forward-fills PSS/private-dirty values when smaps is
not due, and verifies all process identities rather than only the gateway.

Reports use `PASS_IMPLEMENTATION`, `PASS_BOUNDED_QUALIFICATION`, `INCONCLUSIVE`,
or `FAIL` per criterion. Formal minimum duration is not inferred from the requested
duration. RSS drift alone neither proves a leak nor proves allocator retention.
Unattributed persistent growth prevents a whole-run memory qualification pass.

New wire facts may include nullable `h2_reason` and `h2_error_kind`. They are
obtained by bounded traversal/downcast of the actual Hyper error chain, not
formatted diagnostics or guesses about the remote endpoint. Kind is only
`reset`, `goaway`, `io` or `other`; reason is a fixed RFC reason name or
`unknown`. Missing legacy fields stay unavailable, not reconstructed from a
coarse transport error. These facts do not change error classification or
permit a transport failure inside a status-only fault window. Non-null error
facts contradicting a complete success/safe-503 terminal fail independent
validation. An actual single-send TLS/H2 REFUSED_STREAM fixture proves the
reason capture; a non-reproducing test does not explain the original campaign.
