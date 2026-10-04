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
MAX_FINDINGS = 200
ROLES = ("gateway", "controller", "dns", "upstream", "sampler")
HEX256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
COUNT_KEYS = ("offered", "connection_attempts", "admitted_http_operations", "received_operations")
OPTIONAL_COUNT_KEYS = ("admitted_upgrade_operations",)
STATES = ("candidate", "current", "live", "scheduled", "running", "waiting", "exiting", "retired")


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

    def document(self, name):
        path = self.path(name)
        if path.suffix == ".gz":
            with gzip.open(path, "rb") as stream:
                raw = stream.read(MAX_LINE_BYTES + 1)
        else:
            raw = path.read_bytes()
        if len(raw) > MAX_LINE_BYTES:
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
                if window["id"] in self.windows:
                    raise EvidenceError("duplicate fault window")
                if not (integer(window["start_ns"], "window start") < integer(window["end_ns"], "window end")
                        <= integer(window["recovery_deadline_ns"], "window recovery deadline")):
                    self.finding("RL_FAULT_WINDOW", "fault window is unbounded or backwards", id=window["id"])
                if t < window["end_ns"] or not window["target"] or not window["lanes"] or not window["allowed"]:
                    self.finding("RL_FAULT_WINDOW", "fault window lacks closed target/lane/outcome evidence", id=window["id"])
                if not self.counter_trigger(window["trigger"]):
                    self.finding("RL_TRIGGER", "fault command lacks actual trigger counter evidence", id=window["id"])
                self.windows[window["id"]] = window
            elif kind == "coverage":
                name = required(row, "name")
                evidence = required(row, "evidence")
                if self.counter_trigger(evidence):
                    self.coverage[name] += evidence["after"] - evidence["before"]
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
                ("fixture_counter", "metrics_counter", "wire_counter") and
                isinstance(value.get("before"), int) and not isinstance(value.get("before"), bool) and
                isinstance(value.get("after"), int) and not isinstance(value.get("after"), bool) and
                0 <= value["before"] < value["after"])

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

    def retained_proof(self, evidence):
        """Verify raw old/new streams, not the legacy controller booleans."""
        proof = required(evidence, "raw")
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
        initial_failures = self.finding_count["FAIL"] + self.finding_count["INCONCLUSIVE"]
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
            if initial_failures == self.finding_count["FAIL"] + self.finding_count["INCONCLUSIVE"]:
                self.coverage["old_held_grpc_and_upgrade"] += 1
        finally:
            for name in temporary:
                del declared_recipes[name]

    @staticmethod
    def body_digest(body, raw, partial=None):
        kind = required(body, "kind")
        payload = integer(body.get("payload_bytes", 0), "recipe payload_bytes")
        if payload > (1 << 32) - 1:
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
        if status != recipe.get("status") or raw.get("error_stage") or raw.get("error_code"):
            return self.failure(outcome, error, "unexpected_http_response" if status is not None else "transport_error")
        mismatches = []
        for key in ("content_type", "authority", "server_name", "path"):
            if key in recipe and raw.get(key) != recipe[key]:
                mismatches.append(key)
        if (lane != "upgrade" or "allowed_peers" in recipe) and raw.get("upstream_peer") not in required(recipe, "allowed_peers"):
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
                    operation_id = error["raw"].get("operation_id", f"{error['worker_id']}:{error['operation_seq']}")
                if (not isinstance(ack, dict) or ack.get("operation_id") != operation_id or
                        ack.get("termination") != "cancelled_after_data" or
                        ack.get("body_dropped_after_data") is not True or
                        not isinstance(ack.get("body_bytes"), int) or ack["body_bytes"] <= 0):
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
        if raw.get("eof") is not True or body_bytes != full_length:
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
            observed = error.get("head_ns") if raw.get("status") is not None and not raw.get("error_stage") else error["end_ns"]
            if observed is None:
                observed = error["end_ns"]
            if window["start_ns"] <= observed <= window["end_ns"]:
                for choice in window["allowed"]:
                    if ("status" in choice and choice["status"] == raw.get("status")) or (
                            "error_stage" in choice and choice["error_stage"] == raw.get("error_stage") and
                            choice.get("error_code") == raw.get("error_code")):
                        allowed = True
        if allowed and outcome["lane"] != "healthy":
            if raw.get("status") == 200 and raw.get("error_stage") == "response_body":
                recipe = required(required(self.receipt, "recipes"), required(outcome, "recipe"))
                prefix_errors = []
                for key in ("content_type", "authority", "server_name", "path"):
                    if key in recipe and raw.get(key) != recipe[key]:
                        prefix_errors.append(key)
                if raw.get("upstream_peer") not in required(recipe, "allowed_peers"):
                    prefix_errors.append("upstream_peer")
                received = integer(required(raw, "body_bytes"), "partial response bytes")
                _, digest = self.body_digest(required(recipe, "body"), raw, received)
                if received == 0 or raw.get("data_observed") is not True or raw.get("eof") is not False:
                    prefix_errors.append("partial DATA/error evidence")
                if digest is None or raw.get("body_sha256") != digest:
                    prefix_errors.append("partial body digest")
                if prefix_errors:
                    self.finding("RL_CONTENT", "injected body error cannot excuse corrupt DATA/metadata", fields=prefix_errors)
                    return "content_error"
                case_id = raw.get("fault_case_id")
                if case_id is not None and str(window_id).startswith("fault-") and str(case_id) != str(window_id)[6:]:
                    self.finding("RL_FAULT_WINDOW", "actual fixture fault case differs from the claimed window")
                    return "transport_error"
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
                    self.success_points.append((outcome_start, outcome.get("last_end_ns", end), outcome.get("target"), count))
                    self.raw_histogram[(outcome["phase"], outcome["lane"], outcome["protocol"])] += count
                    self.verified_wire_responses += count
                if outcome["phase"] in ("quiet", "post_drain"):
                    self.finding("RL_QUIET_ADMISSION", "business admission continued after quiet Running began")
            if total != offered or attempts != row["connection_attempts"] or admitted != row["admitted_http_operations"] or upgrades != row.get("admitted_upgrade_operations", 0):
                self.finding("RL_RESULT_CONSERVATION", "raw histogram does not conserve offered/connect/admitted/terminal counts")
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
            if not any(window["end_ns"] <= end <= window["recovery_deadline_ns"] and target == window["target"]
                       for _, end, target, _ in self.success_points):
                self.finding("RL_RECOVERY_DEADLINE", "fault target did not fully recover within its deadline", id=window["id"])

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
                for name in required(self.receipt, "required_gauges"):
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
            self.load_errors()
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
