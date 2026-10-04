# Resource qualification evidence v1 (validation-only)

The independent analyzer reads `receipt.json`, `identity.json`, `events.jsonl`,
`buckets.jsonl`, `errors.jsonl`, and `samples.jsonl` (a `.gz` suffix is also
supported). All timestamps are integer Linux `CLOCK_MONOTONIC` nanoseconds, not
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
- `required_gauges: [name]`, `coverage_required: [name]`, and `recipes` below.
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

Reports use `PASS_IMPLEMENTATION`, `PASS_BOUNDED_QUALIFICATION`, `INCONCLUSIVE`,
or `FAIL` per criterion. Formal minimum duration is not inferred from the requested
duration. RSS drift alone neither proves a leak nor proves allocator retention.
Unattributed persistent growth prevents a whole-run memory qualification pass.
