#!/usr/bin/env python3
"""Independently verify resource qualification raw evidence (Python stdlib only).

No controller classification, pass flag, or payload-valid flag is an oracle.
Inputs stay in capture order; malformed rows are not sorted away or interpolated.
Short smoke evidence can verify implementation, never formal qualification.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import statistics
import sys

SCHEMA = "oxidase.resource-qualification/v1"
ANALYSIS_SCHEMA = "oxidase.resource-analysis/v1"
PHASES = ("warmup", "steady", "recovery", "quiet", "post_drain")
NS = 1_000_000_000
MAX_FILE_BYTES = 1 << 30
MAX_LINE_BYTES = 2 << 20
MAX_ROWS = 5_000_000
MAX_ERRORS = 100_000
MAX_PROBES = 50_000
MAX_FINDINGS = 200
ROLES = ("gateway", "controller", "dns", "upstream", "sampler")
HEX256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
COUNT_KEYS = ("offered", "connection_attempts", "admitted_http_operations", "received_operations")
OPTIONAL_COUNT_KEYS = ("admitted_upgrade_operations",)
STATES = ("candidate", "current", "live", "scheduled", "running", "waiting", "exiting", "retired")
RESOURCE_KINDS = frozenset((
    "snapshot_preparation", "snapshot", "cluster", "cluster_runtime", "endpoint", "endpoint_admission",
    "discovery_lease", "cluster_permit", "endpoint_permit", "retry_permit", "health_supervisor", "health_probe",
    "discovery_supervisor", "discovery_round", "dns_query", "dns_failure_memo", "proxy_pool_entry", "health_pool_entry",
    "proxy_pool_family", "health_pool_family", "upstream_tcp_connection", "upstream_tls_connection",
    "upstream_connect_attempt", "upstream_tls_handshake", "warm_socket_slot", "warm_expiry_task", "upstream_task",
    "upstream_upload_task", "dispatch_retirement_task", "response_body", "tunnel"))
FIXTURE_GAUGES = (
    "oxidase_active_requests",
    'oxidase_active_connections{listener="qualification",protocol="http1"}',
    'oxidase_active_connections{listener="qualification",protocol="h2"}',
    'oxidase_http2_active_streams{listener="qualification"}',
    'oxidase_active_tunnels{listener="qualification"}',
)
FIXTURE_REQUEST_BUDGET = 1000


class EvidenceError(Exception):
    pass


def integer(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceError(f"{name} must be an integer >= {minimum}")
    return value


def number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise EvidenceError(f"{name} must be finite numeric evidence")
    return value


def required(value, key):
    if not isinstance(value, dict) or key not in value:
        raise EvidenceError(f"missing required field {key}")
    return value[key]


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def parse_json(text):
    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_keys,
                          parse_constant=lambda value: (_ for _ in ()).throw(
                              EvidenceError(f"non-finite JSON constant {value}")))
    except (ValueError, UnicodeError) as error:
        raise EvidenceError(f"invalid JSON: {error}") from error


class Inputs:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()

    def path(self, name):
        path = self.directory / name
        if not path.is_file() and (self.directory / (name + ".gz")).is_file():
            path = self.directory / (name + ".gz")
        if not path.is_file() or path.is_symlink():
            raise EvidenceError(f"required regular evidence file missing: {name}")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise EvidenceError(f"evidence file exceeds size limit: {name}")
        return path

    def rows(self, name):
        path = self.path(name)
        opener = gzip.open if path.suffix == ".gz" else open
        total = 0
        with opener(path, "rb") as stream:
            for index in range(1, MAX_ROWS + 2):
                line = stream.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                total += len(line)
                if len(line) > MAX_LINE_BYTES or total > MAX_FILE_BYTES or index > MAX_ROWS:
                    raise EvidenceError(f"uncompressed evidence limit exceeded: {name}")
                if not line.endswith(b"\n"):
                    raise EvidenceError(f"truncated/non-terminated row: {name}:{index}")
                if not line.strip():
                    raise EvidenceError(f"empty evidence row: {name}:{index}")
                try:
                    row = parse_json(line.decode("utf-8"))
                except EvidenceError as error:
                    raise EvidenceError(f"{name}:{index}: {error}") from error
                if not isinstance(row, dict):
                    raise EvidenceError(f"{name}:{index}: row must be an object")
                yield index, row

    def document(self, name, maximum=MAX_LINE_BYTES):
        path = self.path(name)
        if path.suffix == ".gz":
            with gzip.open(path, "rb") as stream:
                raw = stream.read(maximum + 1)
        else:
            with path.open("rb") as stream:
                raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise EvidenceError(f"document exceeds size limit: {name}")
        result = parse_json(raw.decode("utf-8"))
        if not isinstance(result, dict):
            raise EvidenceError(f"document must be an object: {name}")
        return result


class Analyzer:
    def __init__(self, directory):
        self.inputs = Inputs(directory)
        self.findings = []
        self.finding_count = Counter()
        self.phases = []
        self.windows = {}
        self.drain_windows = []
        self.coverage = Counter()
        self.errors = {}
        self.errors_by_worker = defaultdict(dict)
        self.consumed_errors = set()
        self.counts = Counter()
        self.workers = defaultdict(Counter)
        self.last_operation = defaultdict(int)
        self.last_bucket_time = defaultdict(int)
        self.worker_success = defaultdict(int)
        self.success_points = []
        self.receipt = {}
        self.gateway = {}
        self.processes = {}
        self.phase_points = defaultdict(lambda: defaultdict(list))
        self.sample_times = defaultdict(list)
        self.sample_count = Counter()
        self.resource_previous = {}
        self.last_resource = {}
        self.concurrent_captures = 0
        self.stable_captures = 0
        self.prelude_samples = 0
        self.verified_wire_responses = 0
        self.publications = 0
        self.raw_histogram = Counter()
        self.digest_cache = {}
        self.probe_references = []
        self.probes = {}
        self.retained_proofs = []
        self.unbounded_kinds = set()
        self.required_gauges = []
        self.retirements = []
        self.retirement_journal = False
        self.epoch_submissions = Counter()
        self.epoch_protocols = {}
        self.bucket_boundaries = defaultdict(list)
        self.first_metric = {}
        self.last_metric = {}
        self.actual_ipv6_responses = 0

    def finding(self, code, message, result="FAIL", **context):
        self.finding_count[result] += 1
        if len(self.findings) < MAX_FINDINGS:
            row = {"code": code, "result": result, "message": message}
            if context:
                row["context"] = context
            self.findings.append(row)

    def phase_at(self, t):
        for phase, start, end in self.phases:
            if start <= t < end:
                return phase
        return None

    def check_phase(self, phase, start, end=None, location=""):
        if phase != self.phase_at(start):
            self.finding("RL_PHASE_MISMATCH", "record phase differs from raw phase timeline",
                         location=location, phase=phase, t_ns=start)
        if end is not None and end < start:
            raise EvidenceError(f"backwards operation/capture interval: {location}")

    def identities(self):
        r = self.receipt
        if required(r, "schema_version") != SCHEMA:
            raise EvidenceError("unknown required evidence schema")
        for key in ("implementation_commit", "tool_commit"):
            if not COMMIT.fullmatch(str(required(r, key))):
                raise EvidenceError(f"invalid exact source commit: {key}")
        sources = required(r, "source_files")
        if not isinstance(sources, list) or not sources or len(sources) > 4096:
            raise EvidenceError("source_files must be a bounded nonempty manifest")
        names = []
        for source in sources:
            name = required(source, "path")
            if not isinstance(name, str) or name.startswith("/") or ".." in Path(name).parts:
                raise EvidenceError("unsafe source manifest path")
            if not HEX256.fullmatch(str(required(source, "sha256"))):
                raise EvidenceError("invalid source file digest")
            names.append(name)
        if len(set(names)) != len(names):
            raise EvidenceError("duplicate source file in identity manifest")
        source_digest = hashlib.sha256(canonical(sorted(sources, key=lambda row: row["path"])).encode()).hexdigest()
        if source_digest != required(r, "source_set_sha256"):
            self.finding("RL_SOURCE_HASH", "source-set manifest digest does not match")
        binaries = {}
        for row in required(r, "binaries"):
            role, digest = required(row, "role"), required(row, "sha256")
            if role in binaries or not HEX256.fullmatch(str(digest)):
                raise EvidenceError("duplicate binary role or invalid binary digest")
            binaries[role] = digest
        identity = self.inputs.document("identity.json")
        if required(identity, "clock") != "CLOCK_MONOTONIC" or not required(identity, "boot_id"):
            raise EvidenceError("process identity needs a shared Linux monotonic clock and boot identity")
        seen_roles, seen_pids = set(), set()
        for process in required(identity, "processes"):
            role = required(process, "role")
            pid = integer(required(process, "pid"), "pid", 1)
            integer(required(process, "start_ticks"), "start_ticks", 1)
            if role in seen_roles or pid in seen_pids:
                self.finding("RL_PROCESS_IDENTITY", "roles share PID or a role is duplicated", role=role)
            seen_roles.add(role)
            seen_pids.add(pid)
            reference = {key: process[key] for key in ("role", "pid", "start_ticks")}
            reference["boot_id"] = identity["boot_id"]
            self.processes[role] = reference
            if process.get("binary_sha256") != binaries.get(role) or process.get("exe_sha256") != binaries.get(role):
                self.finding("RL_BINARY_HASH", "captured executable differs from expected binary", role=role)
            if role == "gateway":
                self.gateway = reference
        if set(ROLES) - seen_roles:
            self.finding("RL_PROCESS_IDENTITY", "required independent process roles missing",
                         roles=sorted(set(ROLES) - seen_roles))
        if r.get("complete") is not True or r.get("artifact_truncated") is not False:
            self.finding("RL_INCOMPLETE", "run did not finish with complete untruncated evidence")
        if r.get("fatal_errors"):
            self.finding("RL_FATAL", "receipt contains fatal collection/worker/process errors")
        if r.get("abandoned_operations"):
            self.finding("RL_ABANDONED_RESULT", "receipt discloses begun operations without terminal evidence")
        for artifact in r.get("artifacts", []):
            name = required(artifact, "path")
            if Path(name).is_absolute() or ".." in Path(name).parts:
                raise EvidenceError("unsafe artifact path")
            path = self.inputs.directory / name
            if not path.is_file() or path.is_symlink():
                self.finding("RL_ARTIFACT", "listed artifact missing", path=name)
            elif path.stat().st_size != artifact.get("bytes") or sha256_file(path) != artifact.get("sha256"):
                self.finding("RL_ARTIFACT", "artifact original-byte checksum/size mismatch", path=name)

    def timeline(self):
        transitions = []
        last_seq = 0
        last_time = -1
        final = None
        for _, row in self.inputs.rows("events.jsonl"):
            sequence = integer(required(row, "writer_seq"), "event writer_seq", 1)
            t = integer(required(row, "t_ns"), "event t_ns")
            if sequence != last_seq + 1 or t < last_time:
                raise EvidenceError("event writer sequence or monotonic capture order is invalid")
            last_seq, last_time = sequence, t
            kind = required(row, "kind")
            if final is not None:
                raise EvidenceError("event after end marker")
            if kind == "phase":
                transitions.append((required(row, "name"), t))
            elif kind == "end":
                final = t
            elif kind == "fault_window":
                window = {key: required(row, key) for key in
                          ("id", "start_ns", "end_ns", "recovery_deadline_ns", "target", "lanes", "allowed", "trigger")}
                if "recovery_peer" in row:
                    window["recovery_peers"] = [row["recovery_peer"]]
                elif "recovery_peers" in row:
                    window["recovery_peers"] = row["recovery_peers"]
                for key in ("failure_peers", "fault_case_id"):
                    if key in row:
                        window[key] = row[key]
                if window["id"] in self.windows:
                    raise EvidenceError("duplicate fault window")
                if not (integer(window["start_ns"], "window start") < integer(window["end_ns"], "window end")
                        <= integer(window["recovery_deadline_ns"], "window recovery deadline")):
                    self.finding("RL_FAULT_WINDOW", "fault window is unbounded or backwards", id=window["id"])
                if t < window["end_ns"] or not window["target"] or not window["lanes"] or not window["allowed"]:
                    self.finding("RL_FAULT_WINDOW", "fault window lacks closed target/lane/outcome evidence", id=window["id"])
                if not self.counter_trigger(window["trigger"]):
                    self.finding("RL_TRIGGER", "fault command lacks actual trigger counter evidence", id=window["id"])
                else:
                    trigger = dict(window["trigger"])
                    if "fixture_before" in row and "fixture_after" in row:
                        trigger.setdefault("before_raw", row["fixture_before"])
                        trigger.setdefault("after_raw", row["fixture_after"])
                    delta = self.raw_counter_delta(trigger)
                    if delta is None and not self.receipt.get("synthetic"):
                        self.finding("RL_TRIGGER", "fault trigger lacks original counter observations", "INCONCLUSIVE", id=window["id"])
                    elif delta is not None and delta <= 0:
                        self.finding("RL_TRIGGER", "fault trigger has no independently observed counter increase", id=window["id"])
                self.windows[window["id"]] = window
            elif kind == "coverage":
                name = required(row, "name")
                evidence = required(row, "evidence")
                if evidence.get("source") == "control_probe":
                    self.probe_references.append((name, evidence))
                elif evidence.get("source") == "runtime_publication":
                    before, after = required(evidence, "before_runtime"), required(evidence, "after_runtime")
                    action = required(evidence, "action")
                    expected_digest = evidence.get("digest")
                    correct_digest = expected_digest is None or after.get("bundle_digest") == expected_digest
                    if self.publication_proven(before, after, action) and correct_digest:
                        self.coverage[name] += 1
                    else:
                        self.finding("RL_PUBLICATION_EVIDENCE", "coverage has no real authorized publication change", behavior=name)
                elif evidence.get("source") == "cluster_membership":
                    if name == "srv_weight_change" and self.weight_change_proven(evidence):
                        self.coverage[name] += 1
                    else:
                        self.finding("RL_MEMBERSHIP_EVIDENCE", "coverage has no precise weight-only member transition", behavior=name)
                elif self.counter_trigger(evidence):
                    delta = self.raw_counter_delta(evidence)
                    if delta is None:
                        if self.receipt.get("parameters", {}).get("formal"):
                            self.finding("RL_TRIGGER", "formal counter trigger lacks original before/after observations", "INCONCLUSIVE", behavior=name)
                        else:
                            self.coverage[name] += evidence["after"] - evidence["before"]
                    elif delta > 0:
                        self.coverage[name] += delta
                    else:
                        self.finding("RL_TRIGGER", "raw counter did not actually increase", behavior=name)
                elif name == "old_held_grpc_and_upgrade" and evidence.get("source") == "wire":
                    self.retained_proof(evidence)
                else:
                    self.finding("RL_TRIGGER", "coverage lacks independently checkable trigger evidence", name=name)
            elif kind == "control":
                action = required(row, "action")
                before, after = required(row, "before_runtime"), required(row, "after_runtime")
                if action.startswith("dns") and before != after:
                    self.finding("RL_PUBLICATION_AUTHORITY", "DNS-only change mutated PublishedRuntime")
                if action in ("activate", "rollback", "reload-source", "resume", "publication") and before != after:
                    self.publications += 1
            elif kind == "fatal":
                self.finding("RL_FATAL", "fatal raw event", error=row.get("error"))
            elif kind == "drain_transition":
                start = integer(required(row, "start_ns"), "drain transition start")
                end = integer(required(row, "end_ns"), "drain transition end")
                if not start < end <= t or end - start > 45 * NS:
                    self.finding("RL_DRAIN_WINDOW", "drain transition is not a closed bounded interval")
                self.drain_windows.append((start, end))
            elif kind not in ("held_release", "fixture", "fixture_final", "stop", "drain", "identity"):
                raise EvidenceError(f"unknown required event kind: {kind}")
        if [row[0] for row in transitions] != list(PHASES) or final is None:
            raise EvidenceError("exactly five ordered phases and an end event are required")
        if any(right[1] <= left[1] for left, right in zip(transitions, transitions[1:])) or final <= transitions[-1][1]:
            raise EvidenceError("phase interval is empty or backwards")
        self.phases = [(phase, start, transitions[i + 1][1] if i + 1 < len(transitions) else final)
                       for i, (phase, start) in enumerate(transitions)]
        durations = required(required(self.receipt, "parameters"), "durations_ns")
        for phase, start, end in self.phases:
            expected = integer(required(durations, phase), f"duration {phase}", 1)
            actual = end - start
            if phase == "quiet":
                actual -= sum(max(0, min(end, right) - max(start, left)) for left, right in self.drain_windows)
            if actual < expected:
                self.finding("RL_PHASE_DURATION", "actual phase is shorter than frozen requested duration", phase=phase)
        if len(self.drain_windows) > 1:
            self.finding("RL_DRAIN_WINDOW", "multiple drain allowances could conceal Running time")
        quiet = next((start, end) for phase, start, end in self.phases if phase == "quiet")
        for start, end in self.drain_windows:
            if not quiet[0] <= start < quiet[1] <= end:
                self.finding("RL_DRAIN_WINDOW", "drain transition does not terminate actual Quiet Running")
        steady = next((start, end) for phase, start, end in self.phases if phase == "steady")
        for window in self.windows.values():
            if not (steady[0] <= window["start_ns"] < window["end_ns"] <= steady[1]):
                self.finding("RL_FAULT_WINDOW", "fault injection escaped steady Running", id=window["id"])
        params = self.receipt["parameters"]
        campaign = required(params, "campaign")
        if campaign not in ("H", "C", "I"):
            raise EvidenceError("campaign must be H, C or I")
        if campaign == "H" and self.windows:
            self.finding("RL_HEALTHY_FAULT", "healthy campaign includes injected unavailability")
        gauges = required(self.receipt, "required_gauges")
        if (not isinstance(gauges, list) or any(not isinstance(name, str) or not name for name in gauges) or
                len(set(gauges)) != len(gauges)):
            raise EvidenceError("required gauges must be unique exact series names")
        self.required_gauges = list(gauges)
        if campaign in ("H", "C") and (params.get("formal") or not self.receipt.get("synthetic")):
            missing = set(FIXTURE_GAUGES) - set(gauges)
            if missing:
                self.finding("RL_REQUIRED_GAUGE_CONTRACT", "H/C receipt omitted mandatory fixed-fixture raw series", series=sorted(missing))
            # Even a damaged declaration cannot suppress measured missing-series
            # evidence. Keep labels exact; never aggregate or invent a zero.
            self.required_gauges.extend(name for name in FIXTURE_GAUGES if name not in gauges)
        if campaign in ("H", "C"):
            payload = integer(required(params, "payload_bytes"), "planned payload_bytes", 1)
            for name, recipe in required(self.receipt, "recipes").items():
                if name not in ("download", "grpc", "upload", "cancel"):
                    continue
                body = required(recipe, "body")
                expected_kind = "grpc" if name == "grpc" else "repeat"
                if body.get("kind") != expected_kind or body.get("payload_bytes") != payload or body.get("fill_byte") != 120 or recipe.get("status") != 200:
                    self.finding("RL_RECIPE_IDENTITY", "declared recipe contradicts the independent resource fixture contract", recipe=name)
        if params.get("formal"):
            if campaign == "I":
                self.finding("RL_FORMAL_DURATION", "isolation experiment is not H/C formal qualification", "INCONCLUSIVE")
            minima = {"warmup": 180, "steady": 3600, "recovery": 900 if campaign == "C" else 600,
                      "quiet": 300, "post_drain": 300}
            for phase, start, end in self.phases:
                actual = end - start
                if phase == "quiet":
                    actual -= sum(max(0, min(end, right) - max(start, left)) for left, right in self.drain_windows)
                if actual < minima[phase] * NS:
                    self.finding("RL_FORMAL_DURATION", "formal minimum duration not reached", "INCONCLUSIVE", phase=phase)

    @staticmethod
    def counter_trigger(value):
        return (isinstance(value, dict) and value.get("source") in
                ("fixture_counter", "metrics_counter", "cluster_counter", "wire_counter") and
                isinstance(value.get("before"), int) and not isinstance(value.get("before"), bool) and
                isinstance(value.get("after"), int) and not isinstance(value.get("after"), bool) and
                0 <= value["before"] < value["after"])

    def raw_counter_delta(self, evidence):
        name = evidence.get("name")
        if not isinstance(name, str):
            return None
        if "before_metrics" in evidence and "after_metrics" in evidence:
            before = self.metrics(evidence["before_metrics"]).get(name)
            after = self.metrics(evidence["after_metrics"]).get(name)
        elif "before_raw" in evidence and "after_raw" in evidence:
            def values(tree):
                if isinstance(tree, dict):
                    found = [number(tree[name], f"raw counter {name}")] if name in tree and isinstance(tree[name], (int, float)) else []
                    for key, value in tree.items():
                        if key != name:
                            found.extend(values(value))
                    return found
                if isinstance(tree, list):
                    return [item for value in tree for item in values(value)]
                return []
            left, right = values(evidence["before_raw"]), values(evidence["after_raw"])
            before, after = sum(left) if left else None, sum(right) if right else None
        else:
            return None
        if before is None or after is None:
            self.finding("RL_TRIGGER", "named raw counter is unavailable")
            return 0
        if "before" in evidence and (before != evidence["before"] or after != evidence.get("after")):
            self.finding("RL_TRIGGER", "declared counter delta contradicts original raw observations")
            return 0
        return after - before

    @staticmethod
    def publication_proven(before, after, action):
        if not isinstance(before, dict) or not isinstance(after, dict):
            return False
        if before.get("schema_version") != "oxidase.admin/v1" or after.get("schema_version") != "oxidase.admin/v1":
            return False
        old, new = before.get("runtime_revision"), after.get("runtime_revision")
        if (not isinstance(old, int) or isinstance(old, bool) or not isinstance(new, int) or isinstance(new, bool) or
                old < 0 or new <= old or not isinstance(before.get("etag"), str) or not isinstance(after.get("etag"), str) or
                before["etag"] == after["etag"]):
            return False
        origin = after.get("origin")
        kind = origin.get("kind") if isinstance(origin, dict) else None
        return (action in ("activate", "rollback") and kind == "bundle") or (action == "reload-source" and kind == "source")

    @staticmethod
    def weight_change_proven(evidence):
        def targets(value):
            if not isinstance(value, dict) or not isinstance(value.get("clusters"), list):
                return None
            result = {}
            for cluster in value["clusters"]:
                discovery = cluster.get("discovery")
                if not isinstance(discovery, dict):
                    continue
                for row in discovery.get("srv_targets", []):
                    key = (cluster.get("cluster"), row.get("target"), row.get("port"), row.get("priority"))
                    if key in result or not isinstance(row.get("weight"), int):
                        return None
                    result[key] = row["weight"]
            return result
        before = targets(evidence.get("before_raw", evidence.get("before")))
        after = targets(evidence.get("after_raw", evidence.get("after")))
        return bool(before) and bool(after) and before.keys() == after.keys() and before != after

    def load_errors(self):
        for _, row in self.inputs.rows("errors.jsonl"):
            key = (integer(required(row, "worker_id"), "error worker_id"),
                   integer(required(row, "operation_seq"), "error operation_seq", 1))
            if key in self.errors or len(self.errors) >= MAX_ERRORS:
                raise EvidenceError("duplicate error operation or error evidence capacity exceeded")
            start, end = integer(required(row, "start_ns"), "operation start"), integer(required(row, "end_ns"), "operation end")
            self.check_phase(required(row, "phase"), start, end, f"error {key}")
            head = row.get("head_ns")
            if head is None and isinstance(row.get("raw"), dict):
                head = row["raw"].get("head_ns")
                row["head_ns"] = head
            if head is not None and not start <= integer(head, "head_ns") <= end:
                raise EvidenceError("response head timestamp outside operation interval")
            required(row, "raw")
            self.errors[key] = row
            self.errors_by_worker[key[0]][key[1]] = row

    def optional_file(self, name):
        return (self.inputs.directory / name).is_file() or (self.inputs.directory / (name + ".gz")).is_file()

    def load_controls(self):
        """A separate denominator for control_round Admin/fixture/CLI work."""
        if not self.optional_file("control-operations.jsonl"):
            if not self.receipt.get("synthetic") and self.receipt["parameters"].get("campaign") == "C":
                self.finding("RL_CONTROL_RESULT", "C control rounds lack their independent started/terminal journal")
            return
        pending, completed, sequence = {}, set(), 0
        for _, row in self.inputs.rows("control-operations.jsonl"):
            if row.get("schema_version") != "oxidase.resource-control-operation/v1":
                raise EvidenceError("unknown control operation schema")
            current = integer(required(row, "writer_seq"), "control writer_seq", 1)
            if current != sequence + 1:
                raise EvidenceError("control operation writer sequence missing or duplicated")
            sequence = current
            operation_id = required(row, "operation_id")
            if not isinstance(operation_id, str) or not operation_id or len(operation_id) > 128:
                raise EvidenceError("invalid control operation identity")
            kind = required(row, "kind")
            if kind == "started":
                if operation_id in pending or operation_id in completed or len(pending) + len(completed) >= MAX_PROBES:
                    raise EvidenceError("duplicate or excessive control operation identity")
                integer(required(row, "start_ns"), "control start")
                if row.get("operation") not in ("admin_read", "fixture_ipc", "cli_mutation"):
                    raise EvidenceError("unknown control operation kind")
                required(row, "request")
                pending[operation_id] = row
                self.counts["control_operations.offered"] += 1
                continue
            if kind != "terminal" or operation_id not in pending:
                raise EvidenceError("control terminal is duplicated or lacks Started")
            started = pending.pop(operation_id)
            completed.add(operation_id)
            start = integer(required(row, "start_ns"), "control terminal start")
            end = integer(required(row, "end_ns"), "control terminal end")
            if start != started["start_ns"] or end < start:
                raise EvidenceError("control terminal changed start identity or moved time backwards")
            if self.phase_at(start) != "steady" or self.phase_at(end) not in ("steady", "recovery"):
                self.finding("RL_CONTROL_PHASE", "control round operation escaped its bounded Running phase")
            raw, request = required(row, "raw"), started["request"]
            if not isinstance(raw, dict) or not isinstance(request, dict):
                raise EvidenceError("control request and raw result must be objects")
            self.counts["control_operations.received"] += 1
            proven = False
            operation = started["operation"]
            if operation == "admin_read":
                if request.get("path") not in ("/api/v1/runtime", "/api/v1/clusters", "/metrics"):
                    self.finding("RL_CONTROL_REQUEST", "Admin read is outside the fixed qualification routes")
                driver = raw.get("driver_exit")
                joined = isinstance(driver, dict) and driver.get("join_acknowledged") is True
                cleanup_cancel = joined and driver.get("result") == "cancelled" and driver.get("abort_requested") is True
                completed_driver = joined and driver.get("result") == "completed"
                if not (completed_driver or cleanup_cancel):
                    self.finding("RL_CONTROL_DRIVER", "Admin driver was not actually completed/joined after complete body")
                if joined and driver.get("exit_ns") is not None and not start <= integer(driver["exit_ns"], "control driver exit") <= end:
                    raise EvidenceError("Admin driver completion outside operation interval")
                status = raw.get("status")
                proven = (isinstance(status, int) and not isinstance(status, bool) and 200 <= status < 300 and
                          raw.get("body_complete") is True and raw.get("error") is None and
                          (completed_driver or cleanup_cancel))
                integer(required(raw, "body_bytes"), "control body bytes")
            elif operation == "fixture_ipc":
                if request.get("role") not in ("dns", "upstream") or not isinstance(request.get("command"), dict):
                    self.finding("RL_CONTROL_REQUEST", "fixture IPC target/command has no fixed identity")
                ack = raw.get("fixture_ack")
                proven = isinstance(ack, dict) and ack.get("ok") is True and raw.get("error") is None
            elif operation == "cli_mutation":
                if request.get("action") not in ("activate", "rollback", "reload-source"):
                    self.finding("RL_CONTROL_REQUEST", "unknown control mutation action")
                receipt = raw.get("mutation_receipt")
                proven = isinstance(receipt, dict) and raw.get("error") is None
                # Mutation ACK alone cannot prove publication. The independent
                # before/after runtime observations remain required coverage.
            derived = "completed" if proven else "failed"
            self.counts[f"control_operations.{derived}"] += 1
            if not proven:
                self.finding("RL_CONTROL_FAILURE", "control operation has failed/unknown terminal facts", operation=operation, operation_id=operation_id)
            if row.get("classification") != derived:
                self.finding("RL_CONTROL_CLASSIFICATION", "control classification contradicts independently derived facts", operation_id=operation_id)
        if pending:
            self.finding("RL_CONTROL_RESULT", "begun control operations lack terminal receipts", ids=list(pending))

    def load_retirements(self):
        """Client retirement is control work, never a silently retried request."""
        self.retirement_journal = self.optional_file("client-retirements.jsonl")
        if not self.retirement_journal:
            if self.receipt["parameters"].get("formal"):
                self.finding("RL_RETIREMENT_RESULT", "formal load lacks independently paired client retirements", "INCONCLUSIVE")
            return
        pending, identities, epochs, sequence = {}, set(), defaultdict(int), 0
        for _, row in self.inputs.rows("client-retirements.jsonl"):
            if row.get("schema_version") != "oxidase.resource-client-retirement/v1":
                raise EvidenceError("unknown client retirement schema")
            current = integer(required(row, "writer_seq"), "retirement writer_seq", 1)
            if current != sequence + 1:
                raise EvidenceError("retirement writer sequence missing or duplicated")
            sequence = current
            retirement_id = required(row, "retirement_id")
            worker = integer(required(row, "worker_id"), "retirement worker")
            epoch = integer(required(row, "connection_epoch"), "retirement epoch", 1)
            start = integer(required(row, "start_ns"), "retirement start")
            after = integer(required(row, "after_operation_seq"), "retirement after sequence", 1)
            next_seq = integer(required(row, "next_operation_seq"), "retirement next sequence", 1)
            if retirement_id != f"{worker}:{epoch}" or next_seq != after + 1:
                raise EvidenceError("retirement identity/next operation sequence changed")
            if row.get("protocol") not in ("http1", "h2"):
                raise EvidenceError("unknown budget-retired client protocol")
            if (integer(required(row, "request_budget"), "retirement request budget", 1) != FIXTURE_REQUEST_BUDGET or
                    integer(required(row, "submitted_requests"), "retirement submitted requests") != FIXTURE_REQUEST_BUDGET):
                self.finding("RL_RETIREMENT_BUDGET", "client retirement does not match exact predeclared listener request budget")
            kind = required(row, "kind")
            if kind == "started":
                if retirement_id in identities or worker in pending or len(identities) >= MAX_PROBES or epoch <= epochs[worker]:
                    raise EvidenceError("duplicate/concurrent/backwards client retirement identity")
                identities.add(retirement_id)
                epochs[worker] = epoch
                pending[worker] = row
                self.counts["client_retirements.offered"] += 1
                continue
            if kind != "terminal" or worker not in pending:
                raise EvidenceError("retirement terminal lacks its Started or is duplicated")
            started = pending.pop(worker)
            fields = ("retirement_id", "worker_id", "connection_epoch", "start_ns", "after_operation_seq",
                      "next_operation_seq", "protocol", "request_budget", "submitted_requests")
            if any(row.get(field) != started.get(field) for field in fields):
                raise EvidenceError("retirement terminal changed actual connection/counter identity")
            end = integer(required(row, "end_ns"), "retirement end")
            if end < start or self.phase_at(start) not in ("warmup", "steady", "recovery"):
                self.finding("RL_RETIREMENT_BOUNDARY", "budget retirement did not occur during active load before next admission")
            driver = required(row, "driver_exit")
            if not isinstance(driver, dict) or driver.get("result") != "completed" or driver.get("join_acknowledged") is not True:
                self.finding("RL_RETIREMENT_DRIVER", "budget-retired connection has no actual completed driver join")
            elif not start <= integer(required(driver, "exit_ns"), "retired driver exit") <= end:
                self.finding("RL_RETIREMENT_DRIVER", "actual driver exit lies outside retirement interval")
            self.retirements.append(row)
            self.counts["client_retirements.received"] += 1
        if pending:
            self.finding("RL_RETIREMENT_RESULT", "begun client retirement did not receive a terminal join", workers=list(pending))

    def retirement_boundaries(self):
        for row in self.retirements:
            worker, epoch, after, next_seq = (row[key] for key in
                                            ("worker_id", "connection_epoch", "after_operation_seq", "next_operation_seq"))
            known = self.bucket_boundaries.get(worker, [])
            prior = [bucket for bucket in known if bucket[1] == after]
            following = [bucket for bucket in known if bucket[0] == next_seq]
            if len(prior) != 1 or prior[0][3] > row["start_ns"]:
                self.finding("RL_RETIREMENT_BOUNDARY", "old operation terminal bucket was not flushed before retirement", worker_id=worker, epoch=epoch)
            if self.last_operation[worker] > after:
                if len(following) != 1 or row["end_ns"] > following[0][2]:
                    self.finding("RL_RETIREMENT_BOUNDARY", "new operation was admitted before actual retirement/join", worker_id=worker, epoch=epoch)
            elif self.last_operation[worker] != after:
                self.finding("RL_RETIREMENT_BOUNDARY", "retirement references an operation absent from the conserved worker ledger")
            # An admission stop may follow the join; that does not invent a new
            # request. The last conserved sequence must then be exactly `after`.
            if self.epoch_submissions[(worker, epoch)] != row["submitted_requests"]:
                self.finding("RL_RETIREMENT_BUDGET", "actual submitted operations in retired epoch do not match counter receipt", worker_id=worker, epoch=epoch)
            if self.epoch_protocols.get((worker, epoch)) != row["protocol"]:
                self.finding("RL_RETIREMENT_IDENTITY", "retirement protocol differs from the real retired client epoch")
            if self.last_operation[worker] > after and not any(
                    item[0] == next_seq and item[4] is not None and item[4] > epoch for item in known):
                self.finding("RL_RETIREMENT_IDENTITY", "next operation reused the retired epoch instead of a new successful connection")

    def load_prelude(self):
        """Preserve every connection preparation and old/new flow operation."""
        if not self.optional_file("prelude-operations.json"):
            if self.retained_proofs and not self.receipt.get("synthetic"):
                self.finding("RL_PRELUDE_RESULT", "retained proof has no full prelude operation denominator")
            return
        document = self.inputs.document("prelude-operations.json", 16 << 20)
        if document.get("schema_version") != "oxidase.resource-prelude/v1":
            raise EvidenceError("unknown prelude operation schema")
        evidence = required(document, "evidence")
        rows = required(evidence, "prelude_operations")
        counts = required(evidence, "prelude_counts")
        if not isinstance(rows, list) or not 0 < len(rows) <= 4096 or not isinstance(counts, dict):
            raise EvidenceError("invalid/excessive prelude operation ledger")
        if counts.get("violations"):
            self.finding("RL_PRELUDE_RESULT", "prelude discloses duplicate/identity ledger violations")
        for proof in self.retained_proofs:
            for name in ("prelude_operations", "prelude_counts"):
                if name in proof and proof[name] != evidence[name]:
                    self.finding("RL_PRELUDE_RESULT", "retained proof and independent prelude file disagree", field=name)
            index = {row.get("operation_id"): row.get("raw") for row in rows if isinstance(row, dict)}
            flows = proof.get("new_b_streams_raw", []) + [proof.get("held_grpc_raw", {}), proof.get("upgrade_raw", {})]
            for raw in flows:
                if not isinstance(raw, dict) or index.get(raw.get("operation_id")) != raw:
                    self.finding("RL_PRELUDE_RESULT", "retained flow does not exactly match its independently conserved prelude operation")
        peers = self.receipt.get("fixture_peers", {})
        approved = [peers[key] for key in ("a", "b") if peers.get(key)]
        if not approved:
            self.finding("RL_PRELUDE_IDENTITY", "prelude has no declared physical fixture endpoints")
        payload = integer(required(self.receipt["parameters"], "payload_bytes"), "prelude payload", 1)
        base = {"status": 200, "content_type": "application/grpc", "body": {"kind": "grpc", "payload_bytes": payload, "fill_byte": 120},
                "trailers": {"grpc-status": "0", "grpc-message": "ok"}, "allowed_peers": approved,
                "authority": "gateway.example.test", "server_name": "gateway.example.test"}
        seen, derived_counts, by_role = set(), Counter(), defaultdict(Counter)
        windows = []
        proof_end = max((integer(raw.get("ended_ns"), "retained flow end")
                         for proof in self.retained_proofs for raw in
                         [proof.get("held_grpc_raw", {}), proof.get("upgrade_raw", {})] if raw.get("ended_ns") is not None), default=0)
        for proof in self.retained_proofs:
            for name, limit, expected_role in (("initialization_window", 8 * NS, "held"), ("withdrawal_window", 10 * NS, "probe")):
                window = proof.get(name)
                if not isinstance(window, dict):
                    continue
                left, right, deadline = (integer(required(window, key), f"prelude {key}") for key in ("start_ns", "end_ns", "deadline_ns"))
                if not left <= right <= deadline or deadline - left > limit or window.get("roles") != [expected_role] or window.get("allowed_statuses") != [503]:
                    self.finding("RL_PRELUDE_WINDOW", "prelude rejection allowance is not a finite exact-role window")
                else:
                    windows.append((expected_role, left, right))
        for index, row in enumerate(rows, 1):
            operation_id = required(row, "operation_id")
            if operation_id in seen or operation_id != f"prelude:{index}":
                raise EvidenceError("prelude identity missing, duplicated or out of allocation order")
            seen.add(operation_id)
            role, raw, terminal = required(row, "role"), required(row, "raw"), row.get("terminal")
            if role not in ("control", "probe", "held", "upgrade", "cancel") or not isinstance(raw, dict) or raw.get("operation_id") != operation_id:
                raise EvidenceError("invalid prelude role or changed raw identity")
            start, end = integer(required(raw, "started_ns"), "prelude start"), integer(required(raw, "ended_ns"), "prelude end")
            head = raw.get("head_ns")
            if end < start or head is not None and not start <= integer(head, "prelude head") <= end:
                raise EvidenceError("prelude capture time is backwards")
            derived_counts["offered"] += 1
            by_role[role]["offered"] += 1
            if terminal is not None:
                derived_counts["classified"] += 1
                by_role[role]["classified"] += 1
            if terminal == "abandoned":
                derived_counts["abandoned"] += 1
                by_role[role]["abandoned"] += 1
            if terminal in (None, "failed", "abandoned"):
                self.finding("RL_PRELUDE_RESULT", "begun prelude operation failed or was never received", operation_id=operation_id)
                self.counts["prelude.failed"] += 1
                continue
            if role == "control":
                if terminal != "prepared" or row.get("cause") != "connection_ready" or raw.get("status") is not None or head is not None or raw.get("error_stage") or raw.get("error_code"):
                    self.finding("RL_PRELUDE_CONNECTION", "connection preparation lacks actual handshake terminal facts")
                self.counts["prelude.connection_prepared"] += 1
                continue
            if raw.get("status") == 503:
                if head is None or not any(owner == role and left <= head <= right for owner, left, right in windows):
                    self.finding("RL_PRELUDE_WINDOW", "prelude 503 lies outside its exact finite role/window")
                fixed = b"Service Unavailable"
                if terminal != "response_complete" or raw.get("eof") is not True or raw.get("body_bytes") != len(fixed) or raw.get("body_sha256") != hashlib.sha256(fixed).hexdigest() or raw.get("content_type") != "text/plain; charset=utf-8" or raw.get("error_stage") or raw.get("error_code"):
                    self.finding("RL_PRELUDE_CONTENT", "expected rejection has incomplete/corrupt safe response")
                self.counts["prelude.expected_rejection"] += 1
                continue
            if role == "upgrade":
                recipe = {"status": 101, "content_type": None, "body": {"kind": "utf8", "text": "qualification-tunnel" * 8}, "trailers": {},
                          "allowed_peers": [peers.get("a")], "authority": "gateway.example.test", "server_name": "gateway.example.test", "path": "/base/ws"}
            else:
                path = "/base/hold?b=2&a=1&a=3" if role == "held" else ("/base/cancel?b=2&a=1&a=3" if role == "cancel" else "/base/soak.Service/Call?b=2&a=1&a=3")
                recipe = {**base, "path": path}
            key = "_prelude_operation"
            if key in self.receipt["recipes"]:
                raise EvidenceError("reserved prelude recipe is user-defined")
            self.receipt["recipes"][key] = recipe
            measured = {**raw, "admitted": True, "connection_attempted": False, "upgrade": role == "upgrade"}
            if row.get("acknowledgement") is not None:
                measured["cancel_ack"] = row["acknowledgement"]
            # ACK may follow the client body Drop; the proof terminal encloses
            # that asynchronous acknowledgement without replacing DATA times.
            collected = {"raw": measured, "start_ns": start, "end_ns": max(end, proof_end), "head_ns": head}
            try:
                derived = self.wire({"lane": "upgrade" if role == "upgrade" else ("cancel" if role == "cancel" else "healthy"),
                                     "phase": "warmup", "protocol": raw.get("protocol"), "recipe": key, "raw": measured}, collected)
                expected = {"completed_success": "response_complete", "intentional_cancelled": "cancelled_after_data", "upgrade_completed": "response_complete"}.get(derived)
                planned_close = derived == "upgrade_completed" and terminal == "tunnel_cancelled" and measured.get("tunnel_close_result") == "peer_closed_without_close_notify"
                if terminal != expected and not planned_close:
                    self.finding("RL_PRELUDE_CLASSIFICATION", "prelude terminal label contradicts independently checked wire facts", operation_id=operation_id)
                self.counts[f"prelude.{derived}"] += 1
            finally:
                del self.receipt["recipes"][key]
        for key in ("offered", "classified", "abandoned"):
            if counts.get(key) != derived_counts[key]:
                self.finding("RL_PRELUDE_CONSERVATION", "prelude count contradicts every begun operation", counter=key)
            self.counts[f"prelude.{key}"] = derived_counts[key]
        normalized = {role: {key: value[key] for key in ("offered", "classified", "abandoned")} for role, value in by_role.items()}
        if counts.get("by_role") != normalized:
            self.finding("RL_PRELUDE_CONSERVATION", "prelude per-role denominator does not conserve raw operations")

    def load_probes(self):
        path = self.inputs.directory / "control-probes.jsonl"
        if not path.is_file() and not (self.inputs.directory / "control-probes.jsonl.gz").is_file():
            if self.probe_references:
                self.finding("RL_PROBE_RESULT", "control probe references have no raw operation ledger")
            return
        pending, sequence = {}, 0
        for _, row in self.inputs.rows("control-probes.jsonl"):
            if row.get("schema_version") != "oxidase.resource-control-probe/v1":
                raise EvidenceError("unknown control probe schema")
            current = integer(required(row, "writer_seq"), "probe writer_seq", 1)
            if current != sequence + 1:
                raise EvidenceError("control probe writer sequence missing or duplicated")
            sequence = current
            operation_id = required(row, "operation_id")
            if not isinstance(operation_id, str) or len(operation_id) > 128:
                raise EvidenceError("invalid control probe identity")
            kind = required(row, "kind")
            if kind == "started":
                if operation_id in pending or operation_id in self.probes or len(pending) + len(self.probes) >= MAX_PROBES:
                    raise EvidenceError("duplicate or excessive control probe identity")
                integer(required(row, "start_ns"), "probe start")
                pending[operation_id] = row
            elif kind == "terminal":
                started = pending.pop(operation_id, None)
                if started is None:
                    raise EvidenceError("control terminal has no independent started operation")
                for key in ("start_ns", "scenario", "protocol", "recipe", "target", "phase", "window_id"):
                    if key in row and key in started and row[key] != started[key]:
                        self.finding("RL_PROBE_RESULT", "control terminal changed its start identity/contract", field=key)
                merged = {**started, **row}
                start = integer(required(merged, "start_ns"), "probe start")
                end = integer(required(merged, "end_ns"), "probe end")
                if end < start:
                    raise EvidenceError("control probe time moves backwards")
                merged.setdefault("phase", self.phase_at(start))
                self.check_phase(merged["phase"], start, end, "control probe")
                raw = required(merged, "raw")
                raw = {**raw, "admitted": required(merged, "admitted"),
                       "connection_attempted": integer(required(merged, "connection_attempts"), "probe connections") > 0}
                merged["raw"] = raw
                driver = merged.get("driver_exit")
                if driver is not None:
                    not_created = isinstance(driver, dict) and driver.get("result") == "not_created" and merged.get("admitted") is False
                    if not isinstance(driver, dict) or driver.get("join_acknowledged") is not True or (driver.get("result") not in ("completed", "error") and not not_created):
                        self.finding("RL_PROBE_DRIVER", "control client driver was not actually joined/classified")
                    elif driver.get("result") == "error" and not merged.get("window_id"):
                        self.finding("RL_PROBE_DRIVER", "driver error has no bounded injection window")
                else:
                    self.finding("RL_PROBE_DRIVER", "control client has no actual driver completion receipt", "INCONCLUSIVE")
                self.probes[operation_id] = merged
            else:
                raise EvidenceError("unknown control probe operation event")
        if pending:
            self.finding("RL_PROBE_RESULT", "begun control probes have no terminal operation", ids=list(pending))
        # Reconstruct the fixed path recipe from the request, not from the reply.
        for operation_id, probe in self.probes.items():
            request = required(probe, "request")
            recipe_name = probe.get("recipe", "grpc" if request.get("grpc") else "download")
            declared = required(required(self.receipt, "recipes"), recipe_name)
            path = required(request, "path")
            if not isinstance(path, str) or not path.startswith("/resource/"):
                self.finding("RL_PROBE_REQUEST", "control probe does not use the fixed resource fixture route")
                continue
            key = "_control_probe"
            if key in self.receipt["recipes"]:
                raise EvidenceError("reserved independent control recipe already exists")
            self.receipt["recipes"][key] = {**declared, "path": "/base" + path}
            outcome = {"lane": "churn" if probe.get("window_id") else "healthy", "phase": probe["phase"],
                       "protocol": required(probe, "protocol"), "recipe": key,
                       "target": probe.get("target", "upstream"), "window_id": probe.get("window_id"), "raw": probe["raw"]}
            error = {**probe, "head_ns": probe["raw"].get("head_ns")}
            try:
                classification = self.wire(outcome, error)
                probe["derived_classification"] = classification
                self.counts["control_probes"] += 1
                self.counts[f"control.{classification}"] += 1
                if classification == "completed_success":
                    self.success_points.append((probe["start_ns"], probe["end_ns"], outcome["target"], 1, probe["raw"].get("upstream_peer")))
            finally:
                del self.receipt["recipes"][key]
        for name, reference in self.probe_references:
            probe = self.probes.get(reference.get("operation_id"))
            if probe is None:
                self.finding("RL_PROBE_RESULT", "coverage points to a missing control operation", behavior=name)
                continue
            if "raw" in reference and any(probe["raw"].get(key) != value for key, value in reference["raw"].items()):
                self.finding("RL_PROBE_RESULT", "coverage raw reply differs from its operation ledger", behavior=name)
            classification = probe.get("derived_classification")
            raw = probe["raw"]
            proven = False
            if name == "deadline_timeout":
                # A header delay alone is not the logical total-budget oracle.
                proven = classification == "expected_injected_failure" and raw.get("status") == 504
                if proven:
                    self.coverage["deadline_timeout_probe"] += 1
            elif name == "post_head_error":
                proven = classification == "expected_injected_failure" and raw.get("status") == 200 and raw.get("error_stage") == "response_body"
            elif name == "positive_aaaa":
                expected = self.receipt.get("fixture_peers", {}).get("ipv6")
                proven = classification == "completed_success" and expected is not None and raw.get("upstream_peer") == expected
                if proven:
                    self.coverage["positive_aaaa_probe"] += 1
            elif name in ("dns_readd", "recovery_a", "fault_recovery"):
                expected = reference.get("expected_peer", self.receipt.get("fixture_peers", {}).get("a"))
                proven = classification == "completed_success" and expected is not None and raw.get("upstream_peer") == expected
                if name == "dns_readd" and proven:
                    self.coverage[name] += 1
            if not proven:
                self.finding("RL_TRIGGER", "control probe does not prove its claimed behavior", behavior=name)

    def retained_proof(self, evidence):
        """Verify raw old/new streams, not the legacy controller booleans."""
        proof = required(evidence, "raw")
        self.retained_proofs.append(proof)
        peers = self.receipt.get("fixture_peers")
        if not isinstance(peers, dict) or not peers.get("a") or not peers.get("b"):
            self.finding("RL_RETAINED_PROOF", "held/new stream proof lacks declared physical fixture A/B identities", "INCONCLUSIVE")
            return
        new_streams = proof.get("new_b_streams_raw")
        held, upgrade = proof.get("held_grpc_raw"), proof.get("upgrade_raw")
        publication = proof.get("publication_window")
        if not isinstance(new_streams, list) or len(new_streams) < 8 or len(new_streams) > 32 or not isinstance(held, dict) or not isinstance(upgrade, dict) or not isinstance(publication, dict):
            self.finding("RL_RETAINED_PROOF", "held/new stream proof has no independently checkable wire facts", "INCONCLUSIVE")
            return
        before = integer(required(publication, "before_ns"), "publication before_ns")
        after = integer(required(publication, "after_ns"), "publication after_ns")
        if before > after:
            raise EvidenceError("publication operation bracket moves backwards")
        if proof.get("unchanged_dns_runtime") != proof.get("after_dns") or not isinstance(proof.get("after_dns"), dict):
            self.finding("RL_PUBLICATION_AUTHORITY", "held proof DNS changed complete PublishedRuntime")
        if proof.get("after_activate") == proof.get("after_dns") or not isinstance(proof.get("after_activate"), dict):
            self.finding("RL_RETAINED_PROOF", "held stream proof has no actual publication metadata change")
        payload = integer(required(self.receipt["parameters"], "payload_bytes"), "payload_bytes")
        base = {"status": 200, "content_type": "application/grpc",
                "body": {"kind": "grpc", "payload_bytes": payload, "fill_byte": 120},
                "trailers": {"grpc-status": "0", "grpc-message": "ok"},
                "authority": "gateway.example.test", "server_name": "gateway.example.test"}
        declared_recipes = required(self.receipt, "recipes")
        temporary = {
            "_retained_new_b": {**base, "allowed_peers": [peers["b"]], "path": "/base/soak.Service/Call?b=2&a=1&a=3"},
            "_retained_held_a": {**base, "allowed_peers": [peers["a"]], "path": "/base/hold?b=2&a=1&a=3"},
            "_retained_upgrade": {"status": 101, "content_type": None,
                                  "body": {"kind": "utf8", "text": "qualification-tunnel" * 8},
                                  "trailers": {}, "allowed_peers": [peers["a"]],
                                  "authority": "gateway.example.test", "server_name": "gateway.example.test", "path": "/base/ws"},
        }
        # These are independent fixed fixture contracts, not expectations copied
        # out of the measured responses. Remove them after this bounded proof.
        if any(name in declared_recipes for name in temporary):
            raise EvidenceError("receipt uses a reserved independent proof recipe")
        declared_recipes.update(temporary)
        initial_failures = self.finding_count["FAIL"]
        operation_ids = set()
        try:
            for raw in new_streams:
                operation_id = required(raw, "operation_id")
                if operation_id in operation_ids or raw.get("upstream_name") != "b":
                    self.finding("RL_RETAINED_PROOF", "new stream repeated an identity or selected withdrawn A")
                operation_ids.add(operation_id)
                self.wire({"lane": "healthy", "phase": "warmup", "protocol": "h2",
                           "recipe": "_retained_new_b", "raw": {**raw, "admitted": True, "connection_attempted": False}})
            for raw, recipe, lane, protocol in ((held, "_retained_held_a", "healthy", "h2"),
                                                (upgrade, "_retained_upgrade", "upgrade", "upgrade")):
                start = integer(required(raw, "started_ns"), "held start")
                head = integer(required(raw, "head_ns"), "held head")
                end = integer(required(raw, "ended_ns"), "held end")
                if not start <= head < before <= after < end:
                    self.finding("RL_RETAINED_PROOF", "old flow does not span the entire real publication operation", recipe=recipe)
                if raw.get("upstream_name") != "a":
                    self.finding("RL_RETAINED_PROOF", "old pinned flow did not use physical fixture A")
                self.wire({"lane": lane, "phase": "warmup", "protocol": protocol, "recipe": recipe,
                           "raw": {**raw, "admitted": True, "connection_attempted": False, "upgrade": lane == "upgrade"}})
            if initial_failures == self.finding_count["FAIL"]:
                self.coverage["old_held_grpc_and_upgrade"] += 1
        finally:
            for name in temporary:
                del declared_recipes[name]

    @staticmethod
    def body_digest(body, raw, partial=None):
        kind = required(body, "kind")
        payload = integer(body.get("payload_bytes", 0), "recipe payload_bytes")
        if payload > 16 * 1024 * 1024:
            raise EvidenceError("recipe payload exceeds supported byte limit")
        prefix = b""
        if kind == "empty":
            payload, fill = 0, 0
        elif kind == "utf8":
            prefix = required(body, "text").encode("utf-8")
            payload, fill = 0, 0
        else:
            fill = integer(required(body, "fill_byte"), "fill_byte")
            if fill > 255:
                raise EvidenceError("fill_byte exceeds byte range")
            if kind == "grpc":
                prefix = b"\0" + payload.to_bytes(4, "big")
            elif kind == "fixture_download":
                if payload:
                    first = required(body, "first_bytes").get(raw.get("upstream_name"))
                    if first is None or not isinstance(first, int) or not 0 <= first <= 255:
                        raise EvidenceError("fixture download lacks declared upstream first byte")
                    prefix, payload = bytes((first,)), payload - 1
            elif kind != "repeat":
                raise EvidenceError(f"unknown required body recipe: {kind}")
        total = len(prefix) + payload
        length = total if partial is None else partial
        if not 0 <= length <= total:
            return total, None
        digest = hashlib.sha256()
        digest.update(prefix[:length])
        remaining = max(0, length - len(prefix))
        block = bytes((fill,)) * min(65536, remaining)
        while remaining:
            take = min(len(block), remaining)
            digest.update(block[:take])
            remaining -= take
        return total, digest.hexdigest()

    def wire(self, outcome, error=None):
        raw = required(outcome, "raw")
        if not isinstance(raw, dict):
            raise EvidenceError("raw outcome must be an object")
        lane, phase = required(outcome, "lane"), required(outcome, "phase")
        recipe_name = required(outcome, "recipe")
        recipe = required(required(self.receipt, "recipes"), recipe_name)
        admitted = required(raw, "admitted")
        status = raw.get("status")
        if status is not None and (integer(status, "wire HTTP status", 100) > 599):
            raise EvidenceError("wire HTTP status exceeds valid status range")
        if not isinstance(admitted, bool) or not isinstance(required(raw, "connection_attempted"), bool):
            raise EvidenceError("connection/admission evidence must be boolean")
        if not admitted:
            if raw.get("status") is not None or not raw["connection_attempted"] or raw.get("data_observed"):
                self.finding("RL_CONNECTION_ACCOUNTING", "non-admitted outcome has impossible connection evidence")
            if raw.get("error_stage") not in ("connection", "connect", "tls", "handshake", "http_handshake"):
                self.finding("RL_CONNECTION_ACCOUNTING", "response-phase failure was misreported as connection preparation")
            return self.failure(outcome, error, "connection_error")
        planned_unclean_upgrade = (lane == "upgrade" and raw.get("tunnel_close_result") == "peer_closed_without_close_notify" and
                                   raw.get("tunnel_client_shutdown") is True and raw.get("error_stage") in (None, "tunnel_close") and
                                   raw.get("error_code") in (None, "peer_closed_without_close_notify"))
        if status != recipe.get("status") or ((raw.get("error_stage") or raw.get("error_code")) and not planned_unclean_upgrade):
            return self.failure(outcome, error, "unexpected_http_response" if status is not None else "transport_error")
        mismatches = []
        for key in ("content_type", "authority", "server_name", "path"):
            if key in recipe and raw.get(key) != recipe[key]:
                mismatches.append(key)
        if recipe.get("upstream_expected") is False:
            if self.receipt["parameters"].get("campaign") != "I" or any(raw.get(key) is not None for key in ("upstream_peer", "upstream_name", "authority", "server_name", "path")):
                mismatches.append("local-only metadata boundary")
        elif (lane != "upgrade" or "allowed_peers" in recipe) and raw.get("upstream_peer") not in required(recipe, "allowed_peers"):
            mismatches.append("upstream_peer")
        body_bytes = integer(required(raw, "body_bytes"), "actual body_bytes")
        body = required(recipe, "body")
        cache_key = (canonical(body), raw.get("upstream_name"), body_bytes if raw.get("cancelled") else None)
        if cache_key not in self.digest_cache:
            result = self.body_digest(body, raw, body_bytes if raw.get("cancelled") else None)
            if len(self.digest_cache) < 1024:
                self.digest_cache[cache_key] = result
        else:
            result = self.digest_cache[cache_key]
        full_length, digest = result
        if digest != raw.get("body_sha256"):
            mismatches.append("body_sha256")
        if raw.get("cancelled"):
            if lane != "cancel" or raw.get("eof") is not False or not 0 < body_bytes < full_length:
                mismatches.append("cancel-prefix")
            if raw.get("data_observed") is not True or raw.get("fixture_cancel_ack") is not True:
                mismatches.append("cancel-ack")
            ack = raw.get("cancel_ack")
            if ack is not None:
                operation_id = raw.get("operation_id")
                if error is not None:
                    operation_id = error["raw"].get("operation_id")
                    if operation_id is None and "worker_id" in error:
                        operation_id = f"{error['worker_id']}:{error['operation_seq']}"
                if (not isinstance(ack, dict) or ack.get("operation_id") != operation_id or
                        ack.get("termination") != "cancelled_after_data" or
                        ack.get("body_dropped_after_data") is not True or
                        not isinstance(ack.get("body_bytes"), int) or isinstance(ack["body_bytes"], bool) or ack["body_bytes"] < body_bytes):
                    mismatches.append("cancel-receipt")
                elif error is not None and not error["start_ns"] <= integer(required(ack, "dropped_ns"), "actual cancellation time") <= error["end_ns"]:
                    mismatches.append("cancel-receipt-time")
            elif self.receipt.get("parameters", {}).get("formal"):
                self.finding("RL_CANCEL_PROOF", "formal cancel lane has only a boolean acknowledgement", "INCONCLUSIVE")
            if mismatches:
                self.finding("RL_CONTENT", "cancel lane lacks valid DATA prefix or actual cancellation proof", fields=mismatches)
                return "content_error"
            self.coverage["client_cancellation"] += 1
            return "intentional_cancelled"
        if (raw.get("eof") is not True and not planned_unclean_upgrade) or body_bytes != full_length:
            mismatches.append("body-length/EOF")
        actual_trailers = required(raw, "trailers")
        for name, value in required(recipe, "trailers").items():
            if actual_trailers.get(name) != value:
                self.finding("RL_TRAILERS", "required response trailer missing or incorrect", trailer=name)
                return "trailer_error"
        if mismatches:
            self.finding("RL_CONTENT", "actual response differs from independent recipe", fields=mismatches)
            return "content_error"
        if lane == "cancel":
            self.finding("RL_CANCEL_PROOF", "cancel lane completed without cancellation proof")
            return "content_error"
        protocol = required(outcome, "protocol")
        if lane == "upgrade":
            if raw.get("upgrade") is not True or raw.get("status") != 101 or protocol != "upgrade":
                self.finding("RL_UPGRADE_PROOF", "upgrade lacks a real 101 handshake/tunnel protocol")
                return "content_error"
            close_result = raw.get("tunnel_close_result")
            if close_result is not None:
                if raw.get("request_head_sent") is not True or raw.get("tunnel_client_shutdown") is not True:
                    self.finding("RL_UPGRADE_PROOF", "tunnel close was not preceded by a real request and intentional shutdown")
                    return "content_error"
                if close_result == "clean_eof" and raw.get("eof") is not True:
                    self.finding("RL_UPGRADE_PROOF", "clean TLS EOF contradicts actual EOF evidence")
                    return "content_error"
                if close_result == "peer_closed_without_close_notify":
                    if raw.get("eof") is not False:
                        self.finding("RL_UPGRADE_PROOF", "unclean TLS close was falsely converted to ordinary EOF")
                        return "content_error"
                    self.finding("RL_GRACEFUL_TLS_CLOSE", "full tunnel exchange ended with observed peer closure without TLS close_notify", "INCONCLUSIVE")
                elif close_result != "clean_eof":
                    self.finding("RL_UPGRADE_PROOF", "unknown/error/timeout tunnel close is not a planned termination")
                    return "content_error"
            self.coverage["upgrade"] += 1
            return "upgrade_completed"
        if protocol == "h2":
            self.coverage["tls_h2"] += 1
        elif protocol == "http1":
            self.coverage["tls_http1"] += 1
        else:
            self.finding("RL_PROTOCOL", "unknown actual wire protocol", protocol=protocol)
        if recipe["body"]["kind"] == "grpc":
            self.coverage["grpc_trailers"] += 1
        self.coverage["complete_download"] += 1
        peer = raw.get("upstream_peer")
        if isinstance(peer, str) and peer.startswith("["):
            try:
                if ipaddress.ip_address(peer[1:peer.index("]")]).version == 6:
                    self.actual_ipv6_responses += 1
            except ValueError:
                raise EvidenceError("invalid physical IPv6 peer")
        if "upload" in recipe:
            upload = raw.get("upload")
            if not isinstance(upload, dict) or upload.get("eof") is not True or upload.get("fixture_ack") is not True:
                self.finding("RL_UPLOAD_PROOF", "upload lacks complete fixture acknowledgement")
                return "content_error"
            length, digest = self.body_digest(recipe["upload"].get("body", recipe["upload"]), raw)
            if upload.get("body_bytes", upload.get("bytes")) != length or upload.get("body_sha256", upload.get("sha256")) != digest:
                self.finding("RL_UPLOAD_PROOF", "actual upstream upload differs from independent recipe")
                return "content_error"
            self.coverage["large_upload"] += 1
        return "completed_success"

    def failure(self, outcome, error, classification):
        raw = outcome["raw"]
        window_id = outcome.get("window_id")
        if error is None:
            self.finding("RL_MISSING_RESULT", "non-normal terminal lacks operation-level raw evidence")
            return classification
        if error.get("window_id") != window_id:
            self.finding("RL_FAULT_WINDOW", "bucket and operation fault window differ")
        window = self.windows.get(window_id)
        allowed = False
        if window and outcome.get("target") == window["target"] and outcome["lane"] in window["lanes"]:
            observed = error.get("head_ns") if raw.get("status") is not None and not raw.get("error_stage") else error.get("raw", {}).get("ended_ns", error["end_ns"])
            if observed is None:
                observed = error["end_ns"]
            if not error["start_ns"] <= integer(observed, "actual failure time") <= error["end_ns"]:
                raise EvidenceError("actual failure time lies outside collected operation")
            if window["start_ns"] <= observed <= window["end_ns"]:
                for choice in window["allowed"]:
                    if ("status" in choice and choice["status"] == raw.get("status")) or (
                            "error_stage" in choice and choice["error_stage"] == raw.get("error_stage") and
                            choice.get("error_code") == raw.get("error_code")):
                        allowed = True
        if allowed and outcome["lane"] != "healthy":
            if raw.get("status") in (503, 504) and not raw.get("error_stage"):
                safe = b"Service Unavailable" if raw["status"] == 503 else b"Gateway Timeout"
                if (raw.get("eof") is not True or raw.get("content_type") != "text/plain; charset=utf-8" or
                        raw.get("body_bytes") != len(safe) or raw.get("body_sha256") != hashlib.sha256(safe).hexdigest()):
                    self.finding("RL_CONTENT", "finite injected status does not excuse incomplete/corrupt safe response")
                    return "content_error"
            if raw.get("status") == 200 and raw.get("error_stage") == "response_body":
                recipe = required(required(self.receipt, "recipes"), required(outcome, "recipe"))
                prefix_errors = []
                for key in ("content_type", "authority", "server_name", "path"):
                    if key in recipe and raw.get(key) != recipe[key]:
                        prefix_errors.append(key)
                if raw.get("upstream_peer") not in required(recipe, "allowed_peers"):
                    prefix_errors.append("upstream_peer")
                if "failure_peers" in window and raw.get("upstream_peer") not in window["failure_peers"]:
                    prefix_errors.append("fault target peer")
                received = integer(required(raw, "body_bytes"), "partial response bytes")
                _, digest = self.body_digest(required(recipe, "body"), raw, received)
                if raw.get("data_observed") is not bool(received) or raw.get("eof") is not False:
                    prefix_errors.append("partial DATA/error evidence")
                if digest is None or raw.get("body_sha256") != digest:
                    prefix_errors.append("partial body digest")
                if prefix_errors:
                    self.finding("RL_CONTENT", "injected body error cannot excuse corrupt DATA/metadata", fields=prefix_errors)
                    return "content_error"
                case_id = raw.get("fault_case_id")
                expected_case = window.get("fault_case_id")
                if expected_case is not None and case_id != expected_case:
                    self.finding("RL_FAULT_WINDOW", "actual fixture fault case differs from the declared case")
                    return "transport_error"
                if expected_case is None and case_id is not None and str(window_id).startswith("fault-") and str(case_id) != str(window_id)[6:]:
                    self.finding("RL_FAULT_WINDOW", "actual fixture fault case differs from the claimed window")
                    return "transport_error"
                self.coverage["post_head_error"] += 1
                if received:
                    self.coverage["post_head_error_after_data"] += 1
            return "expected_injected_failure"
        self.finding("RL_UNEXPECTED_RESPONSE", "wire failure is outside exact target/time/phase allowance",
                     status=raw.get("status"), stage=raw.get("error_stage"), window_id=window_id)
        return classification

    @staticmethod
    def fingerprint(outcome):
        fields = {key: outcome.get(key) for key in
                  ("lane", "protocol", "phase", "recipe", "target", "window_id")}
        fields["raw"] = {key: value for key, value in outcome.get("raw", {}).items()
                         if key not in ("operation_id", "started_ns", "head_ns", "ended_ns")}
        # JSON object order is not semantic; this does not reorder raw rows.
        return json.dumps(fields, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    def operations(self):
        sequence = 0
        for _, row in self.inputs.rows("buckets.jsonl"):
            current = integer(required(row, "writer_seq"), "bucket writer_seq", 1)
            if current != sequence + 1:
                raise EvidenceError("bucket writer sequence is missing or duplicated")
            sequence = current
            worker = integer(required(row, "worker_id"), "worker_id")
            first = integer(required(row, "first_operation_seq"), "first_operation_seq", 1)
            last = integer(required(row, "last_operation_seq"), "last_operation_seq", 1)
            start = integer(required(row, "bucket_start_ns"), "bucket start")
            end = integer(required(row, "bucket_end_ns"), "bucket end")
            if first != self.last_operation[worker] + 1 or last < first:
                self.finding("RL_OPERATION_SEQUENCE", "worker operation range overlaps or loses a result", worker_id=worker)
            if end < start or start < self.last_bucket_time[worker]:
                raise EvidenceError("worker bucket time moves backwards")
            self.last_operation[worker] = last
            self.last_bucket_time[worker] = end
            epoch_at_first = None
            offered = last - first + 1
            for key in COUNT_KEYS + OPTIONAL_COUNT_KEYS:
                value = integer(row.get(key, 0) if key in OPTIONAL_COUNT_KEYS else required(row, key), f"bucket {key}")
                self.counts[key] += value
                self.workers[worker][key] += value
            if row["offered"] != offered or row["received_operations"] != offered:
                self.finding("RL_RESULT_CONSERVATION", "offered operation range does not equal received terminals")
            if offered > MAX_ROWS:
                raise EvidenceError("bucket exceeds bounded operation capacity")
            error_rows = [((worker, operation), self.errors_by_worker[worker][operation])
                          for operation in range(first, last + 1) if operation in self.errors_by_worker[worker]]
            anomaly_hist = Counter()
            for key, item in error_rows:
                self.consumed_errors.add(key)
                if not start <= item["start_ns"] <= item["end_ns"] <= end:
                    self.finding("RL_BUCKET_INTERVAL", "operation evidence lies outside its bucket interval", worker_id=worker)
                anomaly_hist[self.fingerprint(item)] += 1
            total = attempts = admitted = upgrades = 0
            for outcome in required(row, "outcomes"):
                count = integer(required(outcome, "count"), "outcome count", 1)
                total += count
                raw = required(outcome, "raw")
                if raw.get("connection_attempted") is True:
                    attempts += count
                if raw.get("admitted") is True:
                    if outcome.get("lane") == "upgrade":
                        upgrades += count
                    else:
                        admitted += count
                        if self.retirement_journal:
                            epoch = integer(required(raw, "connection_epoch"), "actual submitted client epoch", 1)
                            self.epoch_submissions[(worker, epoch)] += count
                            protocol = required(outcome, "protocol")
                            known = self.epoch_protocols.setdefault((worker, epoch), protocol)
                            if known != protocol:
                                self.finding("RL_RETIREMENT_IDENTITY", "one successful connection epoch changed protocol")
                            if self.epoch_submissions[(worker, epoch)] > FIXTURE_REQUEST_BUDGET:
                                self.finding("RL_RETIREMENT_BUDGET", "new request reused an epoch beyond its listener budget")
                            if outcome.get("first_start_ns", start) == start:
                                epoch_at_first = epoch
                outcome_start = outcome.get("first_start_ns", start)
                self.check_phase(required(outcome, "phase"), outcome_start, end, "bucket")
                if "first_start_ns" in outcome:
                    last_start = integer(required(outcome, "last_start_ns"), "last operation start")
                    last_end = integer(required(outcome, "last_end_ns"), "last operation end")
                    if not start <= outcome_start <= last_start <= last_end <= end:
                        raise EvidenceError("histogram operation timing lies outside bucket")
                    self.check_phase(outcome["phase"], last_start, last_end, "histogram end")
                fingerprint = self.fingerprint(outcome)
                matching_errors = [item for _, item in error_rows if self.fingerprint(item) == fingerprint]
                nonnormal = (raw.get("cancelled") or raw.get("error_stage") or raw.get("error_code") or
                             not raw.get("admitted") or raw.get("eof") is not True or
                             raw.get("status") != self.receipt.get("recipes", {}).get(outcome.get("recipe"), {}).get("status"))
                if nonnormal and anomaly_hist[fingerprint] != count:
                    self.finding("RL_MISSING_RESULT", "anomaly histogram does not match all individual terminal receipts")
                if matching_errors:
                    if len(matching_errors) != count:
                        self.finding("RL_RESULT_CONSERVATION", "individual terminal evidence count differs from histogram")
                    for error in matching_errors:
                        derived = self.wire(outcome, error)
                        self.counts[derived] += 1
                else:
                    derived = self.wire(outcome)
                    self.counts[derived] += count
                if derived == "completed_success":
                    self.worker_success[worker] += count
                    self.success_points.append((outcome.get("last_start_ns", outcome_start), outcome.get("last_end_ns", end),
                                                outcome.get("target"), count, raw.get("upstream_peer")))
                    self.raw_histogram[(outcome["phase"], outcome["lane"], outcome["protocol"])] += count
                    self.verified_wire_responses += count
                if outcome["phase"] in ("quiet", "post_drain"):
                    self.finding("RL_QUIET_ADMISSION", "business admission continued after quiet Running began")
            if total != offered or attempts != row["connection_attempts"] or admitted != row["admitted_http_operations"] or upgrades != row.get("admitted_upgrade_operations", 0):
                self.finding("RL_RESULT_CONSERVATION", "raw histogram does not conserve offered/connect/admitted/terminal counts")
            self.bucket_boundaries[worker].append((first, last, start, end, epoch_at_first))
        self.retirement_boundaries()
        if set(self.errors) != self.consumed_errors:
            self.finding("RL_ABANDONED_RESULT", "operation-level errors are not covered by a worker bucket")
        final = required(self.receipt, "final_counts")
        for key in COUNT_KEYS + OPTIONAL_COUNT_KEYS:
            if self.counts[key] != integer(final.get(key, 0) if key in OPTIONAL_COUNT_KEYS else required(final, key), f"final {key}"):
                self.finding("RL_RESULT_CONSERVATION", "final independently started count differs from raw received", counter=key)
        seen = set()
        for expected in required(final, "workers"):
            worker = integer(required(expected, "worker_id"), "final worker_id")
            if worker in seen:
                raise EvidenceError("duplicate final worker identity")
            seen.add(worker)
            for key in COUNT_KEYS + OPTIONAL_COUNT_KEYS:
                if integer(expected.get(key, 0) if key in OPTIONAL_COUNT_KEYS else required(expected, key), f"worker {key}") != self.workers[worker][key]:
                    self.finding("RL_RESULT_CONSERVATION", "worker start/end counter differs from received", worker_id=worker, counter=key)
            if expected.get("last_operation_seq") != self.last_operation[worker]:
                self.finding("RL_OPERATION_SEQUENCE", "worker final sequence differs from raw range", worker_id=worker)
        if seen != set(self.workers):
            self.finding("RL_WORKER_IDENTITY", "worker identity set differs from raw results")
        worker_count = self.receipt["parameters"].get("actual_worker_count", self.receipt["parameters"].get("admitted_worker_count", self.receipt["parameters"].get("concurrency")))
        if len(seen) != integer(worker_count, "admitted worker count"):
            self.finding("RL_WORKER_IDENTITY", "worker count differs from frozen concurrency")
        if self.receipt["parameters"].get("traffic_required", True) and self.counts["completed_success"] == 0:
            self.finding("RL_NO_REAL_SUCCESS", "no response completed with independently verified body/trailers")
        for window in self.windows.values():
            peers = window.get("recovery_peers", [None])
            if not isinstance(peers, list) or not peers or any(peer is not None and not isinstance(peer, str) for peer in peers):
                raise EvidenceError("recovery peer scope must be a nonempty bounded list")
            for required_peer in peers:
                if not any(window["end_ns"] <= start <= end <= window["recovery_deadline_ns"] and target == window["target"] and
                           (required_peer is None or peer == required_peer)
                           for start, end, target, _, peer in self.success_points):
                    self.finding("RL_RECOVERY_DEADLINE", "fault target/peer did not fully recover within its deadline", id=window["id"], peer=required_peer)

    @staticmethod
    def metrics(text):
        if not isinstance(text, str):
            raise EvidenceError("raw metrics must be text")
        output = {}
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            fields = line.rsplit(None, 1)
            if len(fields) != 2:
                raise EvidenceError("malformed Prometheus evidence")
            try:
                value = float(fields[1])
            except ValueError as error:
                raise EvidenceError("invalid Prometheus number") from error
            if not math.isfinite(value):
                raise EvidenceError("non-finite Prometheus evidence")
            if fields[0] in output:
                raise EvidenceError("duplicate raw metric sample")
            output[fields[0]] = value
        return output

    def census(self, sample):
        resources = sample.get("resources")
        if not isinstance(resources, dict) or resources.get("schema_version") != "oxidase.resources/v1":
            self.finding("RL_MISSING_GAUGE", "required raw resource capture unavailable")
            return
        if resources.get("enabled") is not True:
            params = self.receipt.get("parameters", {})
            intentional = params.get("campaign") == "I" and params.get("observation_disabled") is True
            self.finding("RL_MISSING_GAUGE", "resource observation disabled", "INCONCLUSIVE" if intentional else "FAIL")
            return
        if integer(required(resources, "invariant_failures"), "invariant failures"):
            self.finding("RL_CENSUS_INVARIANT", "resource census reports invariant failures")
        if resources.get("globally_atomic") is not False:
            raise EvidenceError("resource capture must not claim global atomicity")
        stable = (required(resources, "sequence_start") == required(resources, "sequence_end") and
                  required(resources, "mutations_in_flight_start") == 0 and
                  required(resources, "mutations_in_flight_end") == 0)
        self.stable_captures += int(stable)
        self.concurrent_captures += int(not stable)
        rows = required(resources, "resources")
        kinds = set()
        for row in rows:
            kind = required(row, "kind")
            if kind in kinds:
                raise EvidenceError("duplicate resource kind in raw census")
            kinds.add(kind)
            values = {key: integer(required(row, key), f"{kind} {key}")
                      for key in ("created", "destroyed", "live", "published", "detail_untracked_live")}
            states = {}
            for state in required(row, "states"):
                name = required(state, "state")
                if name not in STATES or name in states:
                    raise EvidenceError("duplicate/unknown resource state")
                states[name] = integer(required(state, "live"), "state live")
            if set(states) != set(STATES):
                raise EvidenceError("resource capture is missing a state")
            if stable and (values["created"] < values["destroyed"] or
                           values["created"] - values["destroyed"] != values["live"] or
                           sum(states.values()) != values["live"]):
                self.finding("RL_RESOURCE_CONSERVATION", "quiescent capture violates actual object conservation", kind=kind)
            previous = self.resource_previous.get(kind)
            if previous and any(values[key] < previous[key] for key in ("created", "destroyed", "published")):
                self.finding("RL_COUNTER_RESET", "process lifecycle counter went backwards", kind=kind)
            self.resource_previous[kind] = values
            self.last_resource[kind] = {**values, "states": states}
            bounds = self.receipt.get("bounds", {}).get(kind)
            if not bounds and self.receipt["parameters"].get("formal") and kind not in self.unbounded_kinds:
                self.unbounded_kinds.add(kind)
                self.finding("RL_CAPACITY_UNPROVEN", "observed resource kind has no predeclared structural capacity or exit budget; a peak is not a bound", "INCONCLUSIVE", kind=kind)
            if bounds:
                maximum = integer(required(bounds, "live_max"), f"{kind} live_max")
                maximum = bounds.get(f"{sample['phase']}_live_max", maximum)
                if values["live"] > maximum:
                    self.finding("RL_RESOURCE_BOUND", "actual live object count exceeds frozen capacity", kind=kind, live=values["live"], maximum=maximum)
                for state in ("retired", "exiting"):
                    budget = bounds.get(f"{state}_exit_budget_ms", bounds.get("retired_exit_budget_ms"))
                    age = row.get(f"oldest_{state}_age_ms")
                    if states[state]:
                        if row.get("age_supported") is not True or age is None or values["detail_untracked_live"]:
                            self.finding("RL_RETIREMENT_AGE", "retiring object age is unavailable", "INCONCLUSIVE", kind=kind, state=state)
                        elif budget is None:
                            self.finding("RL_RETIREMENT_BUDGET", "retiring owner lacks frozen exit budget", "INCONCLUSIVE", kind=kind)
                        elif number(age, "retirement age") > number(budget, "exit budget"):
                            self.finding("RL_RETIRED_LEAK", "retired/exiting owner exceeded its exit budget", kind=kind, state=state, age_ms=age, budget_ms=budget)
            self.phase_points[sample["phase"]][f"live.{kind}"].append((sample["end_ns"], values["live"]))
            self.phase_points[sample["phase"]][f"retired.{kind}"].append((sample["end_ns"], states["retired"]))
        missing = set(self.receipt.get("bounds", {})) - kinds
        if not self.receipt.get("synthetic"):
            missing |= RESOURCE_KINDS - kinds
        if missing:
            self.finding("RL_MISSING_GAUGE", "bounded resource kinds missing", kinds=sorted(missing))

    def samples(self):
        sequence = 0
        per_source_time = {}
        for _, row in self.inputs.rows("samples.jsonl"):
            current = integer(required(row, "writer_seq"), "sample writer_seq", 1)
            if current != sequence + 1:
                raise EvidenceError("sample writer sequence missing or duplicated")
            sequence = current
            source = row.get("source", "combined")
            if source not in ("os", "admin", "combined"):
                raise EvidenceError("unknown required sample source")
            start, end = integer(required(row, "start_ns"), "sample start"), integer(required(row, "end_ns"), "sample end")
            planned = integer(row.get("planned_ns", row.get("due_ns")), "sample planned_ns")
            if start < planned or start < per_source_time.get(source, -1):
                raise EvidenceError("sample capture/planned monotonic order invalid")
            per_source_time[source] = start
            phase = required(row, "phase")
            prelude = phase == "bootstrap" and start < self.phases[0][1]
            if prelude:
                self.prelude_samples += 1
            else:
                self.check_phase(phase, start, end, "sample")
            process = required(row, "process")
            if not isinstance(process, dict) or {key: process.get(key) for key in self.gateway} != self.gateway:
                self.finding("RL_PROCESS_IDENTITY", "sample is not the exact gateway process instance")
            if end < start:
                raise EvidenceError("sample capture interval is backwards")
            if row.get("error"):
                self.finding("RL_SAMPLE_FAILURE", "sampler reports a capture failure", error=row["error"])
            if row.get("errors"):
                self.finding("RL_SAMPLE_FAILURE", "sampler reports specific failed reads", errors=row["errors"])
            if "identity_valid" in row and row["identity_valid"] is not True:
                self.finding("RL_PROCESS_IDENTITY", "sampler could not verify live process start identity")
            for check in row.get("identity_checks", []):
                captured = check.get("process", {})
                expected = self.processes.get(captured.get("role"))
                if check.get("valid") is not True or expected is None or {key: captured.get(key) for key in expected} != expected:
                    self.finding("RL_PROCESS_IDENTITY", "capture instance check failed or names another process")
            if prelude:
                # Explicit bootstrap captures remain in raw input. They do not
                # replace any warm-up/Running sample or formal duration.
                continue
            self.sample_times[source].append((start, end))
            self.sample_count[(source, row["phase"])] += 1
            if source in ("os", "combined"):
                for key in ("rss_kib", "open_fds", "os_threads"):
                    if row.get(key) is None:
                        self.finding("RL_MISSING_GAUGE", "mandatory OS metric unavailable", metric=key)
                    else:
                        value = number(row[key], key)
                        if value < 0:
                            raise EvidenceError("negative OS metric")
                        self.phase_points[row["phase"]][key].append((end, value))
                for key in ("pss_kib", "private_dirty_kib"):
                    if row.get(key) is not None:
                        self.phase_points[row["phase"]][key].append((end, number(row[key], key)))
            if source in ("admin", "combined"):
                for name, capture in required(row, "scrapes").items():
                    if capture.get("ok") is not True:
                        self.finding("RL_SAMPLE_FAILURE", "Admin scrape failed", scrape=name, error=capture.get("error"))
                    if not start <= integer(required(capture, "start_ns"), "scrape start") <= integer(required(capture, "end_ns"), "scrape end") <= end:
                        raise EvidenceError("scrape timestamps lie outside capture interval")
                metrics = self.metrics(required(row, "metrics"))
                for name, value in metrics.items():
                    self.first_metric.setdefault(name, value)
                    self.last_metric[name] = value
                for name in self.required_gauges:
                    if name not in metrics:
                        self.finding("RL_MISSING_GAUGE", "mandatory raw metric unavailable", metric=name)
                    else:
                        self.phase_points[row["phase"]][name].append((end, metrics[name]))
                runtime = row.get("runtime")
                if not isinstance(runtime, dict):
                    self.finding("RL_RUNTIME_EVIDENCE", "serving state evidence unavailable")
                else:
                    state = runtime.get("serving_state", runtime.get("state"))
                    expected = "drained" if row["phase"] == "post_drain" else "running"
                    runtime_capture = row["scrapes"].get("runtime", {"start_ns": start, "end_ns": end})
                    in_transition = any(left <= runtime_capture["end_ns"] and runtime_capture["start_ns"] <= right
                                        for left, right in self.drain_windows)
                    transition_state = isinstance(state, str) and state.lower() in ("running", "draining", "drained")
                    if (not isinstance(state, str) or state.lower() != expected) and not (in_transition and transition_state):
                        self.finding("RL_RUNNING_WINDOW", "sample serving state contradicts observation phase", phase=row["phase"], state=state)
                if "liveness" in row and (not isinstance(row["liveness"], dict) or row["liveness"].get("status") != 200):
                    self.finding("RL_LIVENESS", "gateway liveness failed while its process should remain available")
                if "readiness" in row:
                    readiness = row["readiness"]
                    ready_capture = row["scrapes"].get("readiness", {"start_ns": start, "end_ns": end})
                    in_transition = any(left <= ready_capture["end_ns"] and ready_capture["start_ns"] <= right
                                        for left, right in self.drain_windows)
                    expected = 503 if row["phase"] == "post_drain" else 200
                    if (not isinstance(readiness, dict) or readiness.get("status") != expected) and not (
                            in_transition and isinstance(readiness, dict) and readiness.get("status") in (200, 503)):
                        self.finding("RL_READINESS", "readiness contradicts Running/drained phase")
                self.census(row)
        params = self.receipt["parameters"]
        max_gap = integer(required(params, "max_sample_gap_ns"), "max sample gap", 1)
        sources = ("os", "admin") if "combined" not in self.sample_times else ("combined",)
        for source in sources:
            points = self.sample_times[source]
            intentional_sparse = source == "admin" and params.get("campaign") == "I" and params.get("scrape_interval_ns") == 0
            source_gap = params.get("max_admin_sample_gap_ns", max(max_gap, params.get("scrape_interval_ns", 0) * 4)) if source == "admin" else max_gap
            if not points:
                self.finding("RL_SAMPLE_COVERAGE", "sample source has no raw captures", "INCONCLUSIVE" if intentional_sparse else "FAIL", source=source)
                continue
            if intentional_sparse:
                self.finding("RL_SAMPLE_COVERAGE", "first/final-only isolation sampling cannot prove Running lifecycle intervals", "INCONCLUSIVE", source=source)
                continue
            for phase, start, end in self.phases:
                selected = [(left, right) for left, right in points if start <= left < end]
                if len(selected) < 2:
                    self.finding("RL_SAMPLE_COVERAGE", "phase lacks repeated independent samples", source=source, phase=phase)
                    continue
                gaps = [selected[0][0] - start] + [right[0] - left[0] for left, right in zip(selected, selected[1:])] + [end - selected[-1][1]]
                if max(gaps) > integer(source_gap, "source maximum sample gap", 1):
                    self.finding("RL_SAMPLE_GAP", "sampling gap exceeds frozen coverage requirement", source=source, phase=phase, gap_ns=max(gaps))
        if not self.stable_captures:
            self.finding("RL_CAPTURE_CONSERVATION", "no quiescent resource capture permits exact conservation proof", "INCONCLUSIVE")

    @staticmethod
    def curve(points):
        if not points:
            return None
        origin = points[0][0]
        xs = [(t - origin) / NS for t, _ in points]
        ys = [value for _, value in points]
        mean_x, mean_y = statistics.fmean(xs), statistics.fmean(ys)
        denominator = sum((x - mean_x) ** 2 for x in xs)
        slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denominator if denominator else None
        windows = []
        current = 0
        values = []
        for x, value in zip(xs, ys):
            window = int(x // 300)
            if window != current and values:
                windows.append({"window": current, "median": statistics.median(values), "samples": len(values)})
                values = []
            current = window
            values.append(value)
        if values:
            windows.append({"window": current, "median": statistics.median(values), "samples": len(values)})
        tail_start = points[-1][0] - 15 * 60 * NS
        tail = [(t, value) for t, value in points if t >= tail_start]
        return {"baseline": ys[0], "peak": max(ys), "final": ys[-1], "delta": ys[-1] - ys[0],
                "samples": len(points), "slope_per_second": slope, "fixed_5min_windows": windows,
                "tail_slope_per_second": Analyzer.slope(tail)}

    @staticmethod
    def slope(points):
        if len(points) < 2:
            return None
        origin = points[0][0]
        xs, ys = [(t - origin) / NS for t, _ in points], [value for _, value in points]
        mx, my = statistics.fmean(xs), statistics.fmean(ys)
        denominator = sum((x - mx) ** 2 for x in xs)
        return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denominator if denominator else None

    def final_checks(self):
        positive_aaaa = sum(max(0, value - self.first_metric.get(name, value))
                            for name, value in self.last_metric.items()
                            if name.startswith("oxidase_discovery_queries_total{") and
                            'family="aaaa"' in name and 'result="positive"' in name)
        if self.actual_ipv6_responses and positive_aaaa:
            self.coverage["positive_aaaa"] = min(self.actual_ipv6_responses, positive_aaaa)
        total_deadline = self.last_metric.get('oxidase_upstream_timeouts_total{phase="total"}', 0) - self.first_metric.get('oxidase_upstream_timeouts_total{phase="total"}', 0)
        if self.coverage["deadline_timeout_probe"] and total_deadline > 0:
            self.coverage["deadline_timeout"] = min(self.coverage["deadline_timeout_probe"], total_deadline)
        required_coverage = list(required(self.receipt, "coverage_required"))
        params = self.receipt["parameters"]
        if params.get("formal") and params.get("campaign") in ("H", "C"):
            minimum = ["tls_http1", "tls_h2", "grpc_trailers", "large_upload", "complete_download",
                       "client_cancellation", "upgrade", "old_held_grpc_and_upgrade"]
            if params["campaign"] == "C":
                minimum += ["positive_aaaa", "deadline_timeout", "post_head_error",
                            "active_health_failure", "active_health_recovery", "dns_readd",
                            "srv_weight_change", "source_reload", "signed_activate", "signed_rollback"]
            for name in minimum:
                if name not in required_coverage:
                    required_coverage.append(name)
        for name in required_coverage:
            if not self.coverage[name]:
                self.finding("RL_TRIGGER_COVERAGE", "required behavior was not actually evidenced", behavior=name)
        for phase in ("steady", "recovery"):
            if self.receipt["parameters"].get("traffic_required", True) and not any(key[0] == phase and count for key, count in self.raw_histogram.items()):
                self.finding("RL_RUNNING_TRAFFIC", "Running phase has no complete successful proxy responses", phase=phase)
        curves = {phase: {name: self.curve(points) for name, points in values.items()}
                  for phase, values in self.phase_points.items()}
        # Drift is not proof of a leak or allocator retention. Never tune a window
        # until a positive result appears: fixed full/tail windows are reported.
        for phase in ("steady", "recovery", "quiet"):
            curve = curves.get(phase, {}).get("rss_kib")
            if curve and curve["slope_per_second"] and curve["slope_per_second"] > 0 and curve["delta"] > 0:
                self.finding("RL_MEMORY_ATTRIBUTION", "positive RSS drift has no retained-allocation attribution in this evidence", "INCONCLUSIVE", phase=phase, delta_kib=curve["delta"])
        return curves

    def report(self, curves=None):
        if self.finding_count["FAIL"]:
            result = "FAIL"
        elif self.finding_count["INCONCLUSIVE"]:
            result = "INCONCLUSIVE"
        elif self.receipt.get("parameters", {}).get("formal"):
            result = "PASS_BOUNDED_QUALIFICATION"
        else:
            result = "PASS_IMPLEMENTATION"
        return {"schema_version": ANALYSIS_SCHEMA, "result": result,
                "formal_requested": self.receipt.get("parameters", {}).get("formal", False),
                "synthetic_evidence": self.receipt.get("synthetic", False),
                "identity": {"implementation_commit": self.receipt.get("implementation_commit"),
                             "tool_commit": self.receipt.get("tool_commit"),
                             "source_set_sha256": self.receipt.get("source_set_sha256")},
                "findings": self.findings, "finding_counts": dict(self.finding_count),
                "findings_truncated": sum(self.finding_count.values()) > len(self.findings),
                "counts": dict(self.counts), "verified_wire_responses": self.verified_wire_responses,
                "coverage": dict(self.coverage), "actual_publications": self.publications,
                "quiescent_resource_captures": self.stable_captures,
                "concurrent_resource_captures": self.concurrent_captures,
                "prelude_samples": self.prelude_samples,
                "phase_durations_ns": {phase: end - start for phase, start, end in self.phases},
                "sampling": {source: {"captures": len(points),
                                       "capture_duration_ns": self.distribution([end - start for start, end in points]),
                                       "start_interval_ns": self.distribution([right[0] - left[0] for left, right in zip(points, points[1:])])}
                             for source, points in self.sample_times.items()},
                "curves": curves or {},
                "notes": ["Closed-loop bounded-concurrency qualification is not a capacity guarantee.",
                          "Process identity hashes are captured build evidence, not a reproducible-build proof.",
                          "No controller pass/classification/content-valid field was used as an oracle."]}

    def run(self):
        try:
            self.receipt = self.inputs.document("receipt.json")
            self.identities()
            self.timeline()
            self.load_prelude()
            self.load_controls()
            self.load_retirements()
            self.load_errors()
            self.load_probes()
            self.operations()
            self.samples()
            curves = self.final_checks()
            return self.report(curves)
        except Exception as error:
            self.finding("RL_INVALID_EVIDENCE", str(error))
            return self.report()

    @staticmethod
    def distribution(values):
        if not values:
            return None
        ordered = sorted(values)
        return {"min": ordered[0], "median": statistics.median(ordered),
                "p95": ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)], "max": ordered[-1]}


def analyze(directory):
    return Analyzer(directory).run()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, help="save deterministic JSON report; otherwise stdout")
    arguments = parser.parse_args(argv)
    report = analyze(arguments.directory)
    encoded = canonical(report) + "\n"
    if arguments.output:
        try:
            arguments.output.write_text(encoded, encoding="utf-8")
        except OSError as error:
            fallback = {"schema_version": ANALYSIS_SCHEMA, "result": "FAIL",
                        "findings": [{"code": "RL_OUTPUT_FAILURE", "result": "FAIL", "message": str(error)}]}
            sys.stdout.write(canonical(fallback) + "\n")
            return 1
    else:
        sys.stdout.write(encoded)
    return 1 if report["result"] == "FAIL" else 2 if report["result"] == "INCONCLUSIVE" else 0


if __name__ == "__main__":
    sys.exit(main())
