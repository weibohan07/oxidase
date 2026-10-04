"""Deterministic, explicitly synthetic analyzer corpus; not campaign evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

NS = 1_000_000_000
PHASES = ("warmup", "steady", "recovery", "quiet", "post_drain")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def corpus():
    """Return a small valid implementation-only run with known wire bytes."""
    origin = 10 * NS
    durations = {"warmup": NS, "steady": 3 * NS, "recovery": 2 * NS,
                 "quiet": 2 * NS, "post_drain": 2 * NS}
    sources = [{"path": "synthetic/test-only.rs", "sha256": digest(b"test-only")}]
    binary_hash = digest(b"synthetic-test-binary")
    identity = {"clock": "CLOCK_MONOTONIC", "boot_id": "test-boot",
                "processes": [{"role": role, "pid": 100 + index,
                               "start_ticks": 1000 + index,
                               "binary_sha256": binary_hash, "exe_sha256": binary_hash}
                              for index, role in enumerate(
                                  ("gateway", "controller", "dns", "upstream", "sampler"))]}
    recipe = {"status": 200, "content_type": None,
              "body": {"kind": "repeat", "payload_bytes": 17, "fill_byte": 120},
              "trailers": {}, "allowed_peers": ["127.0.0.1:12345"],
              "authority": "gateway.example.test", "server_name": "gateway.example.test",
              "path": "/base/payload?b=2&a=1&a=3"}
    grpc = {**recipe, "content_type": "application/grpc",
            "body": {"kind": "grpc", "payload_bytes": 17, "fill_byte": 120},
            "trailers": {"grpc-status": "0", "grpc-message": "ok"},
            "path": "/base/soak.Service/Call?b=2&a=1&a=3"}
    receipt = {"schema_version": "oxidase.resource-qualification/v1", "synthetic": True,
               "implementation_commit": "1" * 40, "tool_commit": "2" * 40,
               "source_set_sha256": digest(canonical(sources).encode()),
               "source_files": sources,
               "binaries": [{"role": process["role"], "sha256": binary_hash}
                            for process in identity["processes"]],
               "parameters": {"campaign": "H", "seed": 7, "concurrency": 2,
                              "payload_bytes": 17, "formal": False,
                              "durations_ns": durations, "sample_interval_ns": NS // 2,
                              "max_sample_gap_ns": NS},
               "bounds": {kind: {"live_max": 1, "retired_exit_budget_ms": 1000,
                                  "quiet_live_max": 1, "post_drain_live_max": 1}
                          for kind in ("snapshot", "health_supervisor", "proxy_pool_family")},
               "required_gauges": ["oxidase_active_requests", "oxidase_active_connections"],
               "coverage_required": ["tls_http1", "tls_h2", "grpc_trailers"],
               "recipes": {"download": recipe, "grpc": grpc},
               "complete": True, "artifact_truncated": False, "controller_result": "pass"}
    starts = {}
    events = []
    cursor = origin
    for phase in PHASES:
        starts[phase] = cursor
        events.append({"writer_seq": len(events) + 1, "t_ns": cursor,
                       "kind": "phase", "name": phase})
        cursor += durations[phase]
    events.append({"writer_seq": len(events) + 1, "t_ns": cursor, "kind": "end"})
    buckets = []
    worker_counts = []
    for worker in range(2):
        for index, phase in enumerate(PHASES[:3]):
            is_grpc = worker == 1
            body = b"\0" + (17).to_bytes(4, "big") + b"x" * 17 if is_grpc else b"x" * 17
            active_recipe = grpc if is_grpc else recipe
            raw = {"status": 200, "eof": True, "body_bytes": len(body),
                   "body_sha256": digest(body), "content_type": active_recipe["content_type"],
                   "trailers": active_recipe["trailers"], "upstream_name": "a",
                   "upstream_peer": "127.0.0.1:12345", "authority": recipe["authority"],
                   "server_name": recipe["server_name"], "path": active_recipe["path"],
                   "connection_attempted": index == 0, "admitted": True}
            t = starts[phase] + NS // 10
            buckets.append({"writer_seq": len(buckets) + 1, "bucket_start_ns": t,
                            "bucket_end_ns": t + NS // 10, "worker_id": worker,
                            "first_operation_seq": index + 1, "last_operation_seq": index + 1,
                            "offered": 1, "connection_attempts": int(index == 0),
                            "admitted_http_operations": 1, "received_operations": 1,
                            "outcomes": [{"count": 1, "lane": "healthy",
                                          "protocol": "h2" if is_grpc else "http1", "phase": phase,
                                          "recipe": "grpc" if is_grpc else "download", "target": "api",
                                          "classification": "success", "raw": raw}]})
        worker_counts.append({"worker_id": worker, "offered": 3, "connection_attempts": 1,
                              "admitted_http_operations": 3, "received_operations": 3,
                              "last_operation_seq": 3})
    # Actual capture order is chronological, independent worker ranges remain ordered.
    buckets.sort(key=lambda row: (row["bucket_start_ns"], row["worker_id"]))
    for sequence, row in enumerate(buckets, 1):
        row["writer_seq"] = sequence
    receipt["final_counts"] = {"offered": 6, "connection_attempts": 2,
                               "admitted_http_operations": 6, "received_operations": 6,
                               "workers": worker_counts}
    samples = []
    process = {key: identity["processes"][0][key]
               for key in ("role", "pid", "start_ticks")}
    process["boot_id"] = identity["boot_id"]
    for phase in PHASES:
        times = range(starts[phase] + NS // 10, starts[phase] + durations[phase], NS // 2)
        for t in times:
            for source in ("os", "admin"):
                row = {"schema_version": "oxidase.resource-sample/v1", "writer_seq": len(samples) + 1,
                       "source": source, "planned_ns": t, "start_ns": t, "end_ns": t + 1000,
                       "phase": phase, "process": process}
                if source == "os":
                    row.update(rss_kib=1024, open_fds=12, os_threads=4,
                               pss_kib=1000, private_dirty_kib=512)
                else:
                    resources = []
                    for kind in receipt["bounds"]:
                        states = [{"state": name, "live": int(name == ("running" if
                                   kind == "health_supervisor" else "current"))}
                                  for name in ("candidate", "current", "live", "scheduled",
                                               "running", "waiting", "exiting", "retired")]
                        resources.append({"kind": kind, "created": 1, "destroyed": 0, "live": 1,
                                          "published": 1, "states": states, "age_supported": True,
                                          "detail_untracked_live": 0, "oldest_retired_age_ms": 0,
                                          "oldest_exiting_age_ms": 0})
                    row.update(resources={"schema_version": "oxidase.resources/v1", "enabled": True,
                                          "capture_start_ms": (t - origin) // 1_000_000,
                                          "capture_end_ms": (t - origin) // 1_000_000,
                                          "sequence_start": 1, "sequence_end": 1,
                                          "mutations_in_flight_start": 0, "mutations_in_flight_end": 0,
                                          "globally_atomic": False, "invariant_failures": 0,
                                          "detailed_records": 3, "detail_capacity": 4096,
                                          "resources": resources},
                               metrics="oxidase_active_requests 0\noxidase_active_connections 0\n",
                               runtime={"serving_state": "Drained" if phase == "post_drain" else "Running",
                                        "ready": phase != "post_drain", "etag": '"test-v1"', "origin": "source"},
                               scrapes={"resources": {"start_ns": t, "end_ns": t + 1000, "ok": True},
                                        "metrics": {"start_ns": t, "end_ns": t + 1000, "ok": True},
                                        "runtime": {"start_ns": t, "end_ns": t + 1000, "ok": True}})
                samples.append(row)
    return {"receipt.json": receipt, "identity.json": identity, "events.jsonl": events,
            "buckets.jsonl": buckets, "errors.jsonl": [], "samples.jsonl": samples}


def write_corpus(directory: Path, data=None):
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in (data or corpus()).items():
        text = "".join(canonical(row) + "\n" for row in value) if name.endswith(".jsonl") else canonical(value) + "\n"
        (directory / name).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    write_corpus(parser.parse_args().output)
