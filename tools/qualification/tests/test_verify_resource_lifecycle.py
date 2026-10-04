"""Positive/negative raw-evidence corpus. All runs here are synthetic tests."""

import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from fixtures import NS, corpus, write_corpus

SCRIPT = Path(__file__).resolve().parents[1] / "verify_resource_lifecycle.py"
SPEC = importlib.util.spec_from_file_location("resource_verifier", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def codes(report):
    return {finding["code"] for finding in report["findings"]}


def anomaly(data, bucket_index=2, **changes):
    bucket = data["buckets.jsonl"][bucket_index]
    outcome = bucket["outcomes"][0]
    outcome["raw"].update(changes)
    row = {"worker_id": bucket["worker_id"], "operation_seq": bucket["first_operation_seq"],
           "start_ns": bucket["bucket_start_ns"], "head_ns": bucket["bucket_start_ns"] + 1,
           "end_ns": bucket["bucket_end_ns"], **copy.deepcopy(outcome)}
    row.pop("count")
    data["errors.jsonl"].append(row)
    return bucket, outcome, row


def fault_corpus():
    data = corpus()
    data["receipt.json"]["parameters"]["campaign"] = "C"
    bucket, outcome, row = anomaly(data, status=503, body_bytes=19, content_type="text/plain; charset=utf-8",
                                  body_sha256=hashlib.sha256(b"Service Unavailable").hexdigest())
    for record in (outcome, row):
        record.update(lane="fault", window_id="reset-1")
    window = {"kind": "fault_window", "t_ns": bucket["bucket_end_ns"] + 1,
              "id": "reset-1", "start_ns": bucket["bucket_start_ns"] - 1,
              "end_ns": bucket["bucket_end_ns"] + 1,
              "recovery_deadline_ns": bucket["bucket_end_ns"] + 4 * NS,
              "target": "api", "lanes": ["fault"], "allowed": [{"status": 503}],
              "trigger": {"source": "fixture_counter", "name": "reset_sent", "before": 0, "after": 1}}
    data["events.jsonl"].insert(2, window)
    for index, event in enumerate(data["events.jsonl"], 1):
        event["writer_seq"] = index
    return data


def retained_corpus():
    data = corpus()
    peers = {"a": "127.0.0.1:12345", "b": "127.0.0.2:23456"}
    data["receipt.json"]["fixture_peers"] = peers
    body = b"\0" + (17).to_bytes(4, "big") + b"x" * 17
    raw = {"status": 200, "eof": True, "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
           "content_type": "application/grpc", "trailers": {"grpc-status": "0", "grpc-message": "ok"},
           "authority": "gateway.example.test", "server_name": "gateway.example.test", "protocol": "h2",
           "started_ns": 10 * NS + 10, "head_ns": 10 * NS + 20, "ended_ns": 10 * NS + 600,
           "upstream_peer": peers["b"], "upstream_name": "b", "path": "/base/soak.Service/Call?b=2&a=1&a=3"}
    streams = [{**raw, "operation_id": f"retained:new-b-{index}"} for index in range(8)]
    held = {**raw, "operation_id": "retained:held", "upstream_name": "a", "upstream_peer": peers["a"],
            "path": "/base/hold?b=2&a=1&a=3"}
    upgrade = {**held, "status": 101, "operation_id": "retained:upgrade", "content_type": None,
               "protocol": "upgrade", "path": "/base/ws", "trailers": {},
               "body_bytes": 160, "body_sha256": hashlib.sha256(b"qualification-tunnel" * 8).hexdigest()}
    before, after = {"etag": "old", "origin": "bundle:a"}, {"etag": "new", "origin": "bundle:b"}
    proof = {"new_b_streams_raw": streams, "held_grpc_raw": held, "upgrade_raw": upgrade,
             "publication_window": {"before_ns": 10 * NS + 200, "after_ns": 10 * NS + 300},
             "unchanged_dns_runtime": before, "after_dns": before, "after_activate": after,
             # Intentionally false: none of these controller booleans is used.
             "held_h2_grpc_completed": False, "opaque_grpc_bytes_verified": False}
    event = {"kind": "coverage", "t_ns": 10 * NS + 700, "name": "old_held_grpc_and_upgrade",
             "evidence": {"source": "wire", "raw": proof}}
    data["events.jsonl"].insert(1, event)
    for index, row in enumerate(data["events.jsonl"], 1):
        row["writer_seq"] = index
    return data


class VerifierCorpusTests(unittest.TestCase):
    def test_typed_h2_error_facts_never_turn_a_reset_into_full_success(self):
        for fields in ({"h2_reason": "refused_stream", "h2_error_kind": "reset"},
                       {"h2_reason": "arbitrary diagnostic string", "h2_error_kind": "reset"},
                       {"h2_reason": "cancel", "h2_error_kind": None},
                       {"h2_reason": None, "h2_error_kind": "unverified_remote"}):
            with self.subTest(fields=fields):
                data = corpus()
                anomaly(data, **fields)
                report = self.assert_failure(data, "RL_H2_ERROR_FACTS")
                self.assertLess(report["counts"].get("completed_success", 0), 6)

    def verify(self, data=None):
        with tempfile.TemporaryDirectory(prefix="oxidase-analyzer-test-") as directory:
            write_corpus(Path(directory), data)
            return VERIFIER.analyze(directory)

    def assert_failure(self, data, code):
        report = self.verify(data)
        self.assertEqual(report["result"], "FAIL", report["findings"])
        self.assertIn(code, codes(report), report["findings"])
        return report

    def test_positive_independent_status_body_trailers_and_running_current_owners(self):
        report = self.verify()
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION")
        self.assertTrue(report["synthetic_evidence"])
        self.assertEqual(report["counts"]["completed_success"], 6)
        self.assertEqual(report["quiescent_resource_captures"], 20)
        self.assertEqual(report["curves"]["quiet"]["live.health_supervisor"]["final"], 1)

    def test_controller_verdict_classification_and_payload_valid_do_not_change_oracle(self):
        original = corpus()
        first = self.verify(original)
        changed = copy.deepcopy(original)
        changed["receipt.json"]["controller_result"] = "fail"
        for row in changed["buckets.jsonl"]:
            row["outcomes"][0]["classification"] = "unexpected_failure"
            row["outcomes"][0]["raw"]["payload_valid"] = False
        self.assertEqual(first, self.verify(changed))

    def test_repeated_analysis_is_byte_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            write_corpus(Path(directory))
            first = VERIFIER.canonical(VERIFIER.analyze(directory))
            second = VERIFIER.canonical(VERIFIER.analyze(directory))
            self.assertEqual(first, second)

    def test_missing_bucket_result(self):
        data = corpus()
        data["buckets.jsonl"].pop(2)
        for index, row in enumerate(data["buckets.jsonl"], 1):
            row["writer_seq"] = index
        self.assert_failure(data, "RL_OPERATION_SEQUENCE")

    def test_duplicate_result_range(self):
        data = corpus()
        data["buckets.jsonl"].insert(1, copy.deepcopy(data["buckets.jsonl"][0]))
        for index, row in enumerate(data["buckets.jsonl"], 1):
            row["writer_seq"] = index
        self.assert_failure(data, "RL_OPERATION_SEQUENCE")

    def test_stop_loses_started_result(self):
        data = corpus()
        data["receipt.json"]["final_counts"]["offered"] += 1
        data["receipt.json"]["final_counts"]["workers"][0]["offered"] += 1
        data["receipt.json"]["final_counts"]["workers"][0]["last_operation_seq"] += 1
        self.assert_failure(data, "RL_RESULT_CONSERVATION")

    def test_connection_preparation_cannot_disappear_before_http_denominator(self):
        data = corpus()
        data["receipt.json"]["final_counts"]["connection_attempts"] += 1
        self.assert_failure(data, "RL_RESULT_CONSERVATION")

    def test_connection_error_is_conserved_but_not_success(self):
        data = corpus()
        bucket, _, _ = anomaly(data, 0, status=None, eof=False, admitted=False,
                               error_stage="connection", error_code="connect_failure")
        bucket["admitted_http_operations"] = 0
        data["receipt.json"]["final_counts"]["admitted_http_operations"] -= 1
        data["receipt.json"]["final_counts"]["workers"][0]["admitted_http_operations"] -= 1
        report = self.assert_failure(data, "RL_UNEXPECTED_RESPONSE")
        self.assertEqual(report["counts"]["received_operations"], 6)
        self.assertEqual(report["counts"]["connection_error"], 1)

    def test_all_healthy_503_is_not_hidden_by_controller_success(self):
        data = corpus()
        for index in range(len(data["buckets.jsonl"])):
            anomaly(data, index, status=503)
        report = self.assert_failure(data, "RL_UNEXPECTED_RESPONSE")
        self.assertEqual(report["counts"].get("completed_success", 0), 0)

    def test_missing_individual_error_is_rejected(self):
        data = corpus()
        data["buckets.jsonl"][2]["outcomes"][0]["raw"].update(status=503)
        self.assert_failure(data, "RL_MISSING_RESULT")

    def test_duplicate_individual_error_is_rejected(self):
        data = corpus()
        _, _, row = anomaly(data, status=503)
        data["errors.jsonl"].append(copy.deepcopy(row))
        self.assert_failure(data, "RL_INVALID_EVIDENCE")

    def test_complete_body_digest_length_eof_and_identity_are_independent(self):
        for field, wrong in (("body_sha256", "0" * 64), ("body_bytes", 16), ("eof", False),
                             ("authority", "attacker.example"), ("upstream_peer", "192.0.2.1:1"),
                             ("path", "/base/payload?a=3&a=1&b=2")):
            with self.subTest(field=field):
                data = corpus()
                data["buckets.jsonl"][0]["outcomes"][0]["raw"][field] = wrong
                self.assert_failure(data, "RL_CONTENT")

    def test_grpc_trailers_cannot_be_replaced_by_200_head(self):
        data = corpus()
        data["buckets.jsonl"][1]["outcomes"][0]["raw"]["trailers"] = {}
        self.assert_failure(data, "RL_TRAILERS")

    def test_grpc_content_type_is_validated(self):
        data = corpus()
        data["buckets.jsonl"][1]["outcomes"][0]["raw"]["content_type"] = "text/plain"
        self.assert_failure(data, "RL_CONTENT")

    def test_cancel_needs_partial_data_digest_and_actual_ack(self):
        data = corpus()
        _, outcome, row = anomaly(data, 2, eof=False, cancelled=True, data_observed=True,
                                  body_bytes=5, body_sha256=hashlib.sha256(b"xxxxx").hexdigest(),
                                  fixture_cancel_ack=True)
        for record in (outcome, row):
            record["lane"] = "cancel"
        self.assertEqual(self.verify(data)["counts"]["intentional_cancelled"], 1)
        outcome["raw"]["fixture_cancel_ack"] = False
        row["raw"]["fixture_cancel_ack"] = False
        self.assert_failure(data, "RL_CONTENT")

    def test_positive_closed_target_fault_window_and_recovery(self):
        report = self.verify(fault_corpus())
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        self.assertEqual(report["counts"]["expected_injected_failure"], 1)

    def test_retained_proof_verifies_eight_b_streams_and_old_flows_across_publication(self):
        report = self.verify(retained_corpus())
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        self.assertEqual(report["coverage"]["old_held_grpc_and_upgrade"], 1)

    def test_retained_proof_rejects_body_trailer_withdrawn_peer_and_false_span(self):
        for change, code in (("body", "RL_CONTENT"), ("trailer", "RL_TRAILERS"),
                             ("peer", "RL_CONTENT"), ("span", "RL_RETAINED_PROOF")):
            with self.subTest(change=change):
                data = retained_corpus()
                proof = data["events.jsonl"][1]["evidence"]["raw"]
                if change == "body":
                    proof["new_b_streams_raw"][0]["body_sha256"] = "0" * 64
                elif change == "trailer":
                    proof["held_grpc_raw"]["trailers"] = {}
                elif change == "peer":
                    proof["new_b_streams_raw"][0]["upstream_peer"] = data["receipt.json"]["fixture_peers"]["a"]
                else:
                    proof["held_grpc_raw"]["ended_ns"] = proof["publication_window"]["after_ns"]
                self.assert_failure(data, code)

    def test_legacy_pass_booleans_alone_do_not_qualify_retained_streams(self):
        data = retained_corpus()
        data["events.jsonl"][1]["evidence"]["raw"] = {"held_h2_grpc_completed": True,
                                                       "opaque_grpc_bytes_verified": True,
                                                       "successful_new_b_streams": 8}
        report = self.verify(data)
        self.assertEqual(report["result"], "INCONCLUSIVE")
        self.assertIn("RL_RETAINED_PROOF", codes(report))

    def test_actual_cancel_receipt_identity_and_time_cannot_be_faked_by_bool(self):
        data = corpus()
        bucket, outcome, error = anomaly(data, 2, eof=False, cancelled=True, data_observed=True,
                                        body_bytes=5, body_sha256=hashlib.sha256(b"xxxxx").hexdigest(),
                                        fixture_cancel_ack=True)
        for record in (outcome, error):
            record["lane"] = "cancel"
            record["raw"]["cancel_ack"] = {"operation_id": "0:2", "termination": "cancelled_after_data",
                                           "body_dropped_after_data": True, "body_bytes": 1024,
                                           "dropped_ns": bucket["bucket_start_ns"] + 10}
        self.assertEqual(self.verify(data)["result"], "PASS_IMPLEMENTATION")
        for record in (outcome, error):
            record["raw"]["cancel_ack"]["body_bytes"] = 4
        self.assert_failure(data, "RL_CONTENT")
        for record in (outcome, error):
            record["raw"]["cancel_ack"]["body_bytes"] = 1024
            record["raw"]["cancel_ack"]["operation_id"] = "unrelated:99"
        self.assert_failure(data, "RL_CONTENT")

    def test_fault_window_does_not_allow_healthy_lane(self):
        data = fault_corpus()
        window = data["events.jsonl"][2]
        window["lanes"] = ["healthy"]
        data["buckets.jsonl"][2]["outcomes"][0]["lane"] = "healthy"
        data["errors.jsonl"][0]["lane"] = "healthy"
        self.assert_failure(data, "RL_UNEXPECTED_RESPONSE")

    def test_fault_wrong_target_window_end_and_recovery_deadline(self):
        for change, code in (("target", "RL_UNEXPECTED_RESPONSE"), ("late", "RL_UNEXPECTED_RESPONSE"),
                             ("deadline", "RL_RECOVERY_DEADLINE"), ("unclosed", "RL_FAULT_WINDOW")):
            with self.subTest(change=change):
                data = fault_corpus()
                window = data["events.jsonl"][2]
                if change == "target":
                    window["target"] = "different-cluster"
                elif change == "late":
                    window["end_ns"] = window["start_ns"] + 1
                elif change == "deadline":
                    window["recovery_deadline_ns"] = window["end_ns"]
                else:
                    window["end_ns"] = window["start_ns"]
                self.assert_failure(data, code)

    def test_healthy_other_peer_cannot_hide_faulted_peer_that_never_recovers(self):
        data = fault_corpus()
        data["events.jsonl"][2]["recovery_peer"] = "127.0.0.2:23456"
        self.assert_failure(data, "RL_RECOVERY_DEADLINE")

    def test_post_head_failure_is_classified_at_body_error_not_old_response_head(self):
        data = fault_corpus()
        outcome = data["buckets.jsonl"][2]["outcomes"][0]
        error = data["errors.jsonl"][0]
        for raw in (outcome["raw"], error["raw"]):
            raw.update(status=200, content_type=None, eof=False, error_stage="response_body", error_code="body_error",
                       body_bytes=5, body_sha256=hashlib.sha256(b"xxxxx").hexdigest(), data_observed=True)
        error["head_ns"] = error["start_ns"]
        window = data["events.jsonl"][2]
        window["start_ns"] = error["start_ns"] + 1
        window["allowed"] = [{"error_stage": "response_body", "error_code": "body_error"}]
        report = self.verify(data)
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        self.assertEqual(report["counts"]["expected_injected_failure"], 1)
        for raw in (outcome["raw"], error["raw"]):
            raw["body_sha256"] = hashlib.sha256(b"wrong").hexdigest()
        self.assert_failure(data, "RL_CONTENT")

    def test_legitimate_post_head_reset_without_flushed_data_keeps_empty_prefix_truth(self):
        data = fault_corpus()
        outcome = data["buckets.jsonl"][2]["outcomes"][0]
        error = data["errors.jsonl"][0]
        for raw in (outcome["raw"], error["raw"]):
            raw.update(status=200, content_type=None, eof=False, error_stage="response_body", error_code="body_error",
                       body_bytes=0, body_sha256=hashlib.sha256(b"").hexdigest(), data_observed=False)
        data["events.jsonl"][2]["allowed"] = [{"error_stage": "response_body", "error_code": "body_error"}]
        report = self.verify(data)
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        self.assertEqual(report["coverage"]["post_head_error"], 1)
        self.assertEqual(report["coverage"].get("post_head_error_after_data", 0), 0)

    def test_http_request_already_sent_cannot_be_connection_preparation_failure(self):
        data = corpus()
        bucket, _, _ = anomaly(data, 0, status=None, eof=False, admitted=False,
                               error_stage="response_head", error_code="header_timeout")
        bucket["admitted_http_operations"] = 0
        data["receipt.json"]["final_counts"]["admitted_http_operations"] -= 1
        data["receipt.json"]["final_counts"]["workers"][0]["admitted_http_operations"] -= 1
        self.assert_failure(data, "RL_CONNECTION_ACCOUNTING")

    def test_boolean_toggle_is_not_actual_trigger(self):
        data = fault_corpus()
        data["events.jsonl"][2]["trigger"] = {"source": "fixture_counter", "success": True}
        self.assert_failure(data, "RL_TRIGGER")

    def test_dns_cannot_change_any_published_runtime_field(self):
        data = corpus()
        row = {"kind": "control", "t_ns": data["events.jsonl"][1]["t_ns"] + 1,
               "action": "dns-refresh", "before_runtime": {"etag": "same", "origin": "same", "revision": 1},
               "after_runtime": {"etag": "same", "origin": "same", "revision": 2}}
        data["events.jsonl"].insert(2, row)
        for index, event in enumerate(data["events.jsonl"], 1):
            event["writer_seq"] = index
        self.assert_failure(data, "RL_PUBLICATION_AUTHORITY")

    def test_phase_changed_or_reordered_cannot_be_sorted_away(self):
        data = corpus()
        data["events.jsonl"][2]["name"] = "quiet"
        self.assert_failure(data, "RL_INVALID_EVIDENCE")
        data = corpus()
        data["samples.jsonl"][4]["phase"] = "recovery"
        self.assert_failure(data, "RL_PHASE_MISMATCH")

    def test_missing_gauge_and_null_os_are_not_zero(self):
        data = corpus()
        data["samples.jsonl"][1]["metrics"] = "oxidase_active_requests 0\n"
        self.assert_failure(data, "RL_MISSING_GAUGE")
        data = corpus()
        data["samples.jsonl"][0]["rss_kib"] = None
        self.assert_failure(data, "RL_MISSING_GAUGE")

    def test_sample_gap_is_disclosed_and_rejected(self):
        data = corpus()
        data["samples.jsonl"] = [row for row in data["samples.jsonl"]
                                if not (row["phase"] == "steady" and row["start_ns"] < 13 * NS)]
        for index, row in enumerate(data["samples.jsonl"], 1):
            row["writer_seq"] = index
        self.assert_failure(data, "RL_SAMPLE_GAP")

    def test_intentional_no_scrape_isolation_is_inconclusive_not_fake_pass(self):
        data = corpus()
        data["receipt.json"]["parameters"].update(campaign="I", scrape_interval_ns=0)
        data["samples.jsonl"] = [row for row in data["samples.jsonl"]
                                if row["source"] == "os" or row["phase"] == "post_drain"]
        for index, row in enumerate(data["samples.jsonl"], 1):
            row["writer_seq"] = index
        report = self.verify(data)
        self.assertEqual(report["result"], "INCONCLUSIVE", report["findings"])
        self.assertIn("RL_SAMPLE_COVERAGE", codes(report))

    def test_declared_admin_interval_is_not_os_interval(self):
        data = corpus()
        data["receipt.json"]["parameters"]["max_sample_gap_ns"] = NS // 2
        data["receipt.json"]["parameters"]["scrape_interval_ns"] = NS
        self.assertNotIn("RL_SAMPLE_GAP", codes(self.verify(data)))

    def test_quiet_running_cannot_be_post_drain(self):
        data = corpus()
        for row in data["samples.jsonl"]:
            if row["source"] == "admin" and row["phase"] == "quiet":
                row["runtime"]["serving_state"] = "Drained"
        self.assert_failure(data, "RL_RUNNING_WINDOW")

    def test_retired_snapshot_age_and_actual_bound_are_detected(self):
        for change, code in (("age", "RL_RETIRED_LEAK"), ("live", "RL_RESOURCE_BOUND")):
            with self.subTest(change=change):
                data = corpus()
                resource = data["samples.jsonl"][-1]["resources"]["resources"][0]
                resource["created"] = resource["live"] = 2
                resource["states"][-1]["live"] = 1
                resource["oldest_retired_age_ms"] = 2000
                if change == "age":
                    data["receipt.json"]["bounds"]["snapshot"]["live_max"] = 2
                    data["receipt.json"]["bounds"]["snapshot"]["post_drain_live_max"] = 2
                self.assert_failure(data, code)

    def test_missing_retired_age_is_inconclusive_not_a_zero(self):
        data = corpus()
        row = data["samples.jsonl"][-1]["resources"]["resources"][0]
        row["states"][1]["live"], row["states"][-1]["live"] = 0, 1
        row["oldest_retired_age_ms"] = None
        report = self.verify(data)
        self.assertEqual(report["result"], "INCONCLUSIVE")
        self.assertIn("RL_RETIREMENT_AGE", codes(report))

    def test_concurrent_capture_not_treated_as_globally_atomic(self):
        data = corpus()
        resource = data["samples.jsonl"][1]["resources"]
        resource["sequence_end"] += 1
        resource["resources"][0]["created"] += 1
        report = self.verify(data)
        self.assertNotIn("RL_RESOURCE_CONSERVATION", codes(report))
        self.assertEqual(report["concurrent_resource_captures"], 1)

    def test_quiescent_conservation_and_counter_reset(self):
        data = corpus()
        data["samples.jsonl"][1]["resources"]["resources"][0]["created"] += 1
        self.assert_failure(data, "RL_RESOURCE_CONSERVATION")

    def test_process_pid_start_ticks_and_binary_identity(self):
        for change, code in (("pid", "RL_PROCESS_IDENTITY"), ("start", "RL_PROCESS_IDENTITY"),
                             ("binary", "RL_BINARY_HASH"), ("source", "RL_SOURCE_HASH")):
            with self.subTest(change=change):
                data = corpus()
                if change == "pid":
                    data["identity.json"]["processes"][1]["pid"] = data["identity.json"]["processes"][0]["pid"]
                elif change == "start":
                    data["samples.jsonl"][0]["process"]["start_ticks"] += 1
                elif change == "binary":
                    data["identity.json"]["processes"][0]["exe_sha256"] = "0" * 64
                else:
                    data["receipt.json"]["source_set_sha256"] = "0" * 64
                self.assert_failure(data, code)

    def test_worker_panic_truncation_and_fatal_are_not_qualified(self):
        for key, value, code in (("fatal_errors", ["worker panic"], "RL_FATAL"),
                                 ("artifact_truncated", True, "RL_INCOMPLETE"),
                                 ("complete", False, "RL_INCOMPLETE")):
            with self.subTest(key=key):
                data = corpus()
                data["receipt.json"][key] = value
                self.assert_failure(data, code)

    def test_positive_rss_slope_neither_proves_leak_nor_allocator(self):
        data = corpus()
        for index, row in enumerate(data["samples.jsonl"]):
            if row["source"] == "os" and row["phase"] == "steady":
                row["rss_kib"] += index
        report = self.verify(data)
        self.assertEqual(report["result"], "INCONCLUSIVE")
        self.assertIn("RL_MEMORY_ATTRIBUTION", codes(report))

    def test_formal_duration_not_granted_by_controller_flag(self):
        data = corpus()
        data["receipt.json"]["parameters"]["formal"] = True
        report = self.verify(data)
        self.assertIn("RL_FORMAL_DURATION", codes(report))
        self.assertNotEqual(report["result"], "PASS_BOUNDED_QUALIFICATION")

    def test_formal_producer_cannot_delete_required_feature_coverage(self):
        data = corpus()
        data["receipt.json"]["parameters"]["formal"] = True
        data["receipt.json"]["coverage_required"] = []
        report = self.assert_failure(data, "RL_TRIGGER_COVERAGE")
        missing = {row.get("context", {}).get("behavior") for row in report["findings"]}
        self.assertIn("large_upload", missing)
        self.assertIn("old_held_grpc_and_upgrade", missing)

    def test_recipe_cannot_be_changed_to_fit_wrong_produced_bytes(self):
        data = corpus()
        recipe = data["receipt.json"]["recipes"]["download"]["body"]
        recipe["fill_byte"] = 121
        for bucket in data["buckets.jsonl"]:
            if bucket["outcomes"][0]["recipe"] == "download":
                bucket["outcomes"][0]["raw"]["body_sha256"] = hashlib.sha256(b"y" * 17).hexdigest()
        self.assert_failure(data, "RL_RECIPE_IDENTITY")

    def test_gzip_input_and_missing_file_always_produce_legal_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_corpus(root)
            path = root / "samples.jsonl"
            (root / "samples.jsonl.gz").write_bytes(gzip.compress(path.read_bytes(), mtime=0))
            path.unlink()
            self.assertEqual(VERIFIER.analyze(root)["result"], "PASS_IMPLEMENTATION")
            (root / "identity.json").unlink()
            result = subprocess.run([sys.executable, str(SCRIPT), str(root)], capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["result"], "FAIL")
            self.assertEqual(result.stderr, b"")

    def test_explicit_bootstrap_is_preserved_but_cannot_replace_running_coverage(self):
        data = corpus()
        prelude = copy.deepcopy(data["samples.jsonl"][0])
        prelude.update(phase="bootstrap", planned_ns=9 * NS, start_ns=9 * NS, end_ns=9 * NS + 1000)
        data["samples.jsonl"].insert(0, prelude)
        for index, row in enumerate(data["samples.jsonl"], 1):
            row["writer_seq"] = index
        report = self.verify(data)
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION")
        self.assertEqual(report["prelude_samples"], 1)
        data["samples.jsonl"][-1]["phase"] = "bootstrap"
        self.assert_failure(data, "RL_PHASE_MISMATCH")

    def test_os_capture_checks_all_roles_without_confusing_them_with_gateway(self):
        data = corpus()
        identity = data["identity.json"]
        row = data["samples.jsonl"][0]
        row["identity_valid"] = True
        row["identity_checks"] = [{"stage": "before", "valid": True,
                                   "process": {**{key: process[key] for key in ("role", "pid", "start_ticks")},
                                               "boot_id": identity["boot_id"]}}
                                  for process in identity["processes"]]
        self.assertEqual(self.verify(data)["result"], "PASS_IMPLEMENTATION")
        row["identity_checks"][-1]["valid"] = False
        self.assert_failure(data, "RL_PROCESS_IDENTITY")

    def test_closed_drain_transition_does_not_make_entire_quiet_state_unchecked(self):
        data = corpus()
        # Quiet lasts two requested seconds, then a 100ms actual drain handoff.
        post = data["events.jsonl"][4]
        transition_start = post["t_ns"]
        post["t_ns"] += NS // 10
        data["events.jsonl"][5]["t_ns"] += NS // 10
        transition = {"kind": "drain_transition", "t_ns": post["t_ns"],
                      "start_ns": transition_start, "end_ns": post["t_ns"]}
        data["events.jsonl"].insert(5, transition)
        for index, row in enumerate(data["events.jsonl"], 1):
            row["writer_seq"] = index
        late = copy.deepcopy(next(row for row in data["samples.jsonl"] if row["source"] == "admin" and row["phase"] == "quiet"))
        late.update(start_ns=transition_start + 1, planned_ns=transition_start + 1,
                    end_ns=transition_start + 1001)
        late["runtime"]["serving_state"] = "draining"
        late["readiness"] = {"status": 503}
        for capture in late["scrapes"].values():
            capture.update(start_ns=late["start_ns"], end_ns=late["end_ns"])
        position = next(index for index, row in enumerate(data["samples.jsonl"]) if row["phase"] == "post_drain")
        data["samples.jsonl"].insert(position, late)
        for row in data["samples.jsonl"][position + 1:]:
            row["planned_ns"] += NS // 10
            row["start_ns"] += NS // 10
            row["end_ns"] += NS // 10
            for capture in row.get("scrapes", {}).values():
                capture["start_ns"] += NS // 10
                capture["end_ns"] += NS // 10
        for index, row in enumerate(data["samples.jsonl"], 1):
            row["writer_seq"] = index
        self.assertEqual(self.verify(data)["result"], "PASS_IMPLEMENTATION")
        first_quiet = next(row for row in data["samples.jsonl"] if row["source"] == "admin" and row["phase"] == "quiet")
        first_quiet["runtime"]["serving_state"] = "drained"
        self.assert_failure(data, "RL_RUNNING_WINDOW")

    def test_individual_receipt_timing_is_not_a_histogram_identity_key(self):
        data = corpus()
        _, _, error = anomaly(data, status=503)
        error["raw"].update(operation_id="0:2", started_ns=error["start_ns"],
                            head_ns=error["head_ns"], ended_ns=error["end_ns"])
        report = self.assert_failure(data, "RL_UNEXPECTED_RESPONSE")
        self.assertNotIn("RL_MISSING_RESULT", codes(report))

    def test_large_upload_requires_independent_upstream_bytes_digest_and_eof(self):
        data = corpus()
        data["receipt.json"]["recipes"]["download"]["upload"] = {
            "body": {"kind": "repeat", "payload_bytes": 19, "fill_byte": 117}}
        for bucket in data["buckets.jsonl"]:
            if bucket["outcomes"][0]["recipe"] == "download":
                bucket["outcomes"][0]["raw"]["upload"] = {
                    "body_bytes": 19, "body_sha256": hashlib.sha256(b"u" * 19).hexdigest(),
                    "eof": True, "fixture_ack": True}
        self.assertEqual(self.verify(data)["result"], "PASS_IMPLEMENTATION")
        data["buckets.jsonl"][0]["outcomes"][0]["raw"]["upload"]["body_bytes"] = 18
        self.assert_failure(data, "RL_UPLOAD_PROOF")

    def test_upgrade_is_separate_from_http_response_denominator(self):
        data = corpus()
        data["receipt.json"]["recipes"]["upgrade"] = {
            "status": 101, "body": {"kind": "utf8", "text": "qualification-tunnel" * 4}, "trailers": {}}
        bucket = data["buckets.jsonl"][0]
        outcome = bucket["outcomes"][0]
        outcome.update(lane="upgrade", protocol="upgrade", recipe="upgrade")
        outcome["raw"].update(status=101, upgrade=True,
                              body_bytes=len(b"qualification-tunnel" * 4),
                              body_sha256=hashlib.sha256(b"qualification-tunnel" * 4).hexdigest())
        bucket.update(admitted_http_operations=0, admitted_upgrade_operations=1)
        final = data["receipt.json"]["final_counts"]
        final["admitted_http_operations"] -= 1
        final["admitted_upgrade_operations"] = 1
        final["workers"][0]["admitted_http_operations"] -= 1
        final["workers"][0]["admitted_upgrade_operations"] = 1
        report = self.verify(data)
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        self.assertEqual(report["counts"]["upgrade_completed"], 1)
        self.assertEqual(report["counts"]["completed_success"], 5)
        self.assertEqual(report["counts"]["admitted_http_operations"], 5)

    def test_unclean_tls_tunnel_close_is_narrow_inconclusive_not_fake_body_eof(self):
        data = retained_corpus()
        upgrade = data["events.jsonl"][1]["evidence"]["raw"]["upgrade_raw"]
        upgrade.update(eof=False, request_head_sent=True, tunnel_client_shutdown=True,
                       tunnel_close_result="peer_closed_without_close_notify")
        report = self.verify(data)
        self.assertEqual(report["result"], "INCONCLUSIVE", report["findings"])
        self.assertIn("RL_GRACEFUL_TLS_CLOSE", codes(report))
        for change in ("timeout", "error", "unknown"):
            upgrade["tunnel_close_result"] = change
            self.assert_failure(data, "RL_CONTENT")
        upgrade["tunnel_close_result"] = "peer_closed_without_close_notify"
        upgrade["body_sha256"] = "0" * 64
        self.assert_failure(data, "RL_CONTENT")
        upgrade["body_sha256"] = hashlib.sha256(b"qualification-tunnel" * 8).hexdigest()
        upgrade["eof"] = True
        self.assert_failure(data, "RL_UPGRADE_PROOF")

    def test_histogram_uses_actual_capture_bounds_without_reclassifying_phase(self):
        data = corpus()
        bucket = data["buckets.jsonl"][2]
        row = bucket["outcomes"][0]
        row.update(first_start_ns=bucket["bucket_start_ns"], last_start_ns=bucket["bucket_start_ns"],
                   last_end_ns=bucket["bucket_end_ns"])
        bucket["bucket_start_ns"] -= NS // 5
        self.assertEqual(self.verify(data)["result"], "PASS_IMPLEMENTATION")
        row["last_start_ns"] = data["events.jsonl"][2]["t_ns"]
        self.assert_failure(data, "RL_INVALID_EVIDENCE")

    def test_raw_row_truncation_duplicate_json_and_nonfinite_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for text in ('{"writer_seq":1}', '{"a":1,"a":2}\n', '{"number":NaN}\n'):
                write_corpus(root)
                (root / "events.jsonl").write_text(text, encoding="utf-8")
                report = VERIFIER.analyze(root)
                self.assertEqual(report["result"], "FAIL")
                self.assertIn("RL_INVALID_EVIDENCE", codes(report))


if __name__ == "__main__":
    unittest.main()
