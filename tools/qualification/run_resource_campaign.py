#!/usr/bin/env python3
"""Bounded workflow orchestration; raw verifier remains a separate program.

This never changes production parameters, keys, policy or source to repair a run.
All credentials remain in the Rust controller's private temporary directory.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time


def command(args, *, stdout=None):
    return subprocess.run(args, check=True, text=True, stdout=stdout)


def capture(args):
    return subprocess.check_output(args, text=True).strip()


def parameters():
    params = json.loads(os.environ["RESOURCE_PARAMETERS"])
    allowed = {"duration", "warm_up", "recovery_running", "quiet_running", "post_drain",
               "concurrency", "payload_size", "upload_size", "seed", "scrape_interval_ms",
               "sample_interval_ms", "formal", "profiling", "observation_disabled", "control_interval",
               "operation_interval_ms"}
    if not isinstance(params, dict) or set(params) - allowed:
        raise ValueError("unknown qualification parameter")
    if params.get("profiling", False):
        raise ValueError("this normal-release workflow does not attest a profiler; use a separately documented experiment")
    for key, value in params.items():
        if key in {"formal", "profiling", "observation_disabled"}:
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be boolean")
        elif key in {"duration", "warm_up", "recovery_running", "quiet_running", "post_drain", "control_interval"}:
            if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:ms|s|m)", value):
                raise ValueError(f"invalid bounded duration: {key}")
        elif not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{key} must be a nonnegative integer")
    # The 150 minute job budget includes release compilation, immutable binary
    # hashing, prelude, bounded in-flight collection, and evidence upload. Fail
    # before building rather than let the runner kill a plausible final receipt.
    defaults = {"duration": "60m", "warm_up": "3m", "recovery_running": "15m",
                "quiet_running": "5m", "post_drain": "5m"}
    phases = []
    for key, default in defaults.items():
        text = params.get(key, default)
        match = re.fullmatch(r"([0-9]+)(ms|s|m)", text)
        seconds = int(match[1]) * {"ms": 0.001, "s": 1, "m": 60}[match[2]]
        if not 0 < seconds <= 7200:
            raise ValueError(f"phase outside controller bounds: {key}")
        phases.append(seconds)
    if sum(phases) > 120 * 60:
        raise ValueError("phase total exceeds 120 minutes; reserve 30 minutes for build/startup/collection/upload")
    return params


def preflight(output):
    source = os.environ["RESOURCE_SOURCE_REF"]
    if not re.fullmatch(r"[0-9a-f]{40}", source) or capture(["git", "rev-parse", "HEAD"]) != source:
        raise ValueError("source_ref must be the exact checked-out commit")
    if capture(["git", "status", "--porcelain=v1"]):
        raise ValueError("qualification source must be clean")
    campaign = os.environ["RESOURCE_CAMPAIGN"]
    if campaign not in {"healthy", "churn", "respond", "static-proxy", "dns-only", "publish-only",
                        "health-only", "dns-background-only", "h2-only", "h2-cancel",
                        "grpc-only", "upgrade-only", "scrape-only"}:
        raise ValueError("unknown H/C/I campaign")
    params = parameters()
    if campaign not in {"healthy", "churn"} and params.get("formal", False):
        raise ValueError("isolation experiment cannot claim formal H/C qualification")
    output.mkdir(parents=True, exist_ok=False)
    record = {"schema_version": "oxidase.resource-workflow/v1", "source_commit": source,
              "parameters": params, "campaign": os.environ["RESOURCE_CAMPAIGN"],
              "run_id": os.environ.get("GITHUB_RUN_ID"), "job": os.environ.get("GITHUB_JOB"),
              "os": platform.platform(), "kernel": platform.release(), "machine": platform.machine(),
              "rustc": capture(["rustc", "-Vv"]), "cargo": capture(["cargo", "-V"]),
              "python": sys.version, "build_profile": "release", "allocator": "default Rust/system allocator; no substitution",
              "build_flags": {key: os.environ.get(key) for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")},
              "profiling": False, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    (output / "workflow.json").write_text(json.dumps(record, indent=2) + "\n")


def checksum_artifacts(output):
    entries = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name == "checksums.json":
            continue
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for data in iter(lambda: stream.read(65536), b""):
                digest.update(data)
        entries.append({"path": path.relative_to(output).as_posix(), "bytes": path.stat().st_size,
                        "sha256": digest.hexdigest()})
    (output / "checksums.json").write_text(json.dumps(entries, indent=2) + "\n")


def run(output):
    params = parameters()
    args = [str(Path("target/release/oxidase-discovery-soak").resolve()), "resource-run",
            "--gateway", str(Path("target/release/oxidase").resolve()),
            "--build-record", str((output / "build-record.json").resolve()),
            "--campaign", os.environ["RESOURCE_CAMPAIGN"], "--output", str(output / "campaign")]
    for key, value in params.items():
        if key == "profiling":
            continue
        if isinstance(value, bool):
            if value:
                args.append("--" + key.replace("_", "-"))
        else:
            args.extend(("--" + key.replace("_", "-"), str(value)))
    (output / "command.json").write_text(json.dumps(args, indent=2) + "\n")
    # The Rust controller has bounded operations, stop collection, phases and
    # subprocess cleanup. Workflow cancellation prevents starting a second run.
    with (output / "controller.log").open("w") as log:
        controller = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT)
    analyzer_args = [sys.executable, "tools/qualification/verify_resource_lifecycle.py",
                     str(output / "campaign")]
    with (output / "analysis.json").open("w") as result:
        analyzer = subprocess.run(analyzer_args, stdout=result, stderr=subprocess.STDOUT)
    checksum_artifacts(output)
    if controller.returncode:
        raise RuntimeError(f"controller exit {controller.returncode}; original evidence retained")
    if analyzer.returncode:
        raise RuntimeError(f"independent analyzer exit {analyzer.returncode}; FAIL/INCONCLUSIVE are not campaign PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "run"))
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        (preflight if arguments.mode == "preflight" else run)(arguments.output)
    except (ValueError, KeyError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"schema_version": "oxidase.resource-workflow/v1", "result": "FAIL",
                          "error": str(error)}), file=sys.stderr)
        sys.exit(1)
