"""Independent control/prelude journals: synthetic positive and hostile facts."""

import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from fixtures import NS, corpus, write_corpus
from test_verify_resource_lifecycle import VERIFIER, codes, retained_corpus, fault_corpus


def insert_event(data, event):
    # The test producer emits in time order, not a repair of imported evidence.
    position = next(index for index, row in enumerate(data["events.jsonl"]) if row["t_ns"] > event["t_ns"])
    data["events.jsonl"].insert(position, event)
    for index, row in enumerate(data["events.jsonl"], 1):
        row["writer_seq"] = index


def control_corpus(operation="admin_read"):
    data = corpus()
    started = {"schema_version": "oxidase.resource-control-operation/v1", "writer_seq": 1,
               "kind": "started", "operation_id": "control-io-1", "start_ns": 11 * NS + 5,
               "operation": operation, "request": {"path": "/api/v1/runtime"}}
    raw = {"status": 200, "body_bytes": 19, "body_complete": True, "error": None,
           "driver_exit": {"result": "cancelled", "abort_requested": True,
                           "join_acknowledged": True, "exit_ns": 11 * NS + 8}}
    if operation == "fixture_ipc":
        started["request"] = {"role": "dns", "command": {"op": "status"}}
        raw = {"fixture_ack": {"ok": True, "a_queries": 17}, "error": None}
    elif operation == "cli_mutation":
        started["request"] = {"action": "activate", "digest": "1" * 64}
        raw = {"mutation_receipt": {"schema_version": "oxidase.admin/v1", "etag": "next"}, "error": None}
    terminal = {"schema_version": started["schema_version"], "writer_seq": 2,
                "kind": "terminal", "operation_id": started["operation_id"],
                "start_ns": started["start_ns"], "end_ns": 11 * NS + 10,
                "classification": "completed", "raw": raw}
    data["control-operations.jsonl"] = [started, terminal]
    return data


def probe_corpus():
    data = corpus()
    started = {"schema_version": "oxidase.resource-control-probe/v1", "writer_seq": 1, "kind": "started",
               "operation_id": "control-0-1", "start_ns": 11 * NS + 30, "phase": "steady", "scenario": "probe",
               "recipe": "download", "protocol": "h2", "target": "upstream", "window_id": None,
               "request": {"path": "/resource/payload?b=2&a=1&a=3", "grpc": False, "payload_bytes": 17, "upload_bytes": 0}}
    raw = copy.deepcopy(data["buckets.jsonl"][0]["outcomes"][0]["raw"])
    raw.update(operation_id=started["operation_id"], started_ns=started["start_ns"], head_ns=11 * NS + 35,
               ended_ns=11 * NS + 40, path="/base/resource/payload?b=2&a=1&a=3")
    terminal = {**started, "kind": "terminal", "writer_seq": 2, "end_ns": 11 * NS + 45,
                "admitted": True, "connection_attempts": 1, "raw": raw,
                "driver_exit": {"result": "completed", "join_acknowledged": True,
                                "exit_ns": 11 * NS + 44, "abort_requested": False}}
    data["control-probes.jsonl"] = [started, terminal]
    return data


def labelled_metrics_corpus():
    data = corpus()
    data["receipt.json"]["required_gauges"] = list(VERIFIER.FIXTURE_GAUGES)
    # Raw renderer shape, including different real protocol values: this is not
    # a normalized sum and neither protocol can cover the other protocol.
    raw = ('oxidase_active_requests 2\n'
           'oxidase_active_connections{listener="qualification",protocol="http1"} 1\n'
           'oxidase_active_connections{listener="qualification",protocol="h2"} 2\n'
           'oxidase_http2_active_streams{listener="qualification"} 3\n'
           'oxidase_active_tunnels{listener="qualification"} 1\n')
    for row in data["samples.jsonl"]:
        if row["source"] == "admin":
            row["metrics"] = raw
    return data


def retirement_corpus():
    data = corpus()
    for bucket in data["buckets.jsonl"]:
        bucket["outcomes"][0]["raw"]["connection_epoch"] = 1 if bucket["worker_id"] != 0 or bucket["first_operation_seq"] == 1 else 2
    first = data["buckets.jsonl"][0]
    second = copy.deepcopy(first["outcomes"][0])
    second["count"] = 999
    second["raw"]["connection_attempted"] = False
    first["outcomes"].append(second)
    first.update(last_operation_seq=1000, offered=1000, received_operations=1000, admitted_http_operations=1000)
    for bucket in data["buckets.jsonl"]:
        if bucket["worker_id"] == 0 and bucket is not first:
            bucket["first_operation_seq"] += 999
            bucket["last_operation_seq"] += 999
    final = data["receipt.json"]["final_counts"]
    for key in ("offered", "received_operations", "admitted_http_operations"):
        final[key] += 999
        final["workers"][0][key] += 999
    final["workers"][0]["last_operation_seq"] += 999
    start = first["bucket_end_ns"] + 10
    started = {"schema_version": "oxidase.resource-client-retirement/v1", "kind": "started", "writer_seq": 1,
               "retirement_id": "0:1", "worker_id": 0, "protocol": "http1", "connection_epoch": 1,
               "start_ns": start, "after_operation_seq": 1000, "next_operation_seq": 1001,
               "request_budget": 1000, "submitted_requests": 1000}
    terminal = {**started, "kind": "terminal", "writer_seq": 2, "end_ns": start + 10,
                "driver_exit": {"result": "completed", "join_acknowledged": True, "abort_requested": False, "exit_ns": start + 5}}
    data["client-retirements.jsonl"] = [started, terminal]
    return data


def prelude_corpus():
    data = retained_corpus()
    proof = data["events.jsonl"][1]["evidence"]["raw"]
    operations = []
    blank = {"operation_id": "prelude:1", "protocol": "h2", "started_ns": 10 * NS + 1,
             "head_ns": None, "ended_ns": 10 * NS + 8, "status": None, "body_bytes": 0}
    operations.append({"operation_id": "prelude:1", "role": "control", "terminal": "prepared",
                       "cause": "connection_ready", "raw": blank, "acknowledgement": None})
    for role, raw in [("probe", row) for row in proof["new_b_streams_raw"]] + [
            ("held", proof["held_grpc_raw"]), ("upgrade", proof["upgrade_raw"])]:
        operation_id = f"prelude:{len(operations) + 1}"
        raw["operation_id"] = operation_id
        operations.append({"operation_id": operation_id, "role": role, "terminal": "response_complete",
                           "cause": "response_eof", "raw": copy.deepcopy(raw), "acknowledgement": None})
    by_role = {role: {"offered": sum(row["role"] == role for row in operations),
                      "classified": sum(row["role"] == role for row in operations), "abandoned": 0}
               for role in ("control", "probe", "held", "upgrade")}
    counts = {"scope": "prelude_data_plane_and_connection_prepare", "offered": len(operations),
              "classified": len(operations), "abandoned": 0, "by_role": by_role, "violations": []}
    data["prelude-operations.json"] = {"schema_version": "oxidase.resource-prelude/v1", "result": "failed",
                                      "evidence": {"prelude_operations": operations, "prelude_counts": counts}}
    # Deliberately controller result=failed despite independently complete facts.
    proof["prelude_operations"], proof["prelude_counts"] = copy.deepcopy(operations), copy.deepcopy(counts)
    return data


class IndependentJournalTests(unittest.TestCase):
    def verify(self, data):
        with tempfile.TemporaryDirectory(prefix="oxidase-independent-journal-") as directory:
            write_corpus(Path(directory), data)
            return VERIFIER.analyze(directory)

    def fail(self, data, code):
        report = self.verify(data)
        self.assertEqual(report["result"], "FAIL", report["findings"])
        self.assertIn(code, codes(report), report["findings"])
        return report

    def test_control_three_kinds_have_separate_conserved_denominator(self):
        for kind in ("admin_read", "fixture_ipc", "cli_mutation"):
            with self.subTest(kind=kind):
                report = self.verify(control_corpus(kind))
                self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
                self.assertEqual(report["counts"]["control_operations.offered"], 1)
                self.assertEqual(report["counts"]["control_operations.completed"], 1)
                self.assertEqual(report["counts"]["offered"], 6)

    def test_control_missing_duplicate_and_changed_terminal_identity(self):
        for change in ("missing", "duplicate", "time"):
            data = control_corpus()
            if change == "missing":
                data["control-operations.jsonl"].pop()
                code = "RL_CONTROL_RESULT"
            elif change == "duplicate":
                row = copy.deepcopy(data["control-operations.jsonl"][1])
                row["writer_seq"] = 3
                data["control-operations.jsonl"].append(row)
                code = "RL_INVALID_EVIDENCE"
            else:
                data["control-operations.jsonl"][1]["start_ns"] += 1
                code = "RL_INVALID_EVIDENCE"
            self.fail(data, code)

    def test_control_label_cannot_hide_failed_driver_or_incomplete_body(self):
        for result in ("error", "panicked", "timeout", "unavailable", "cancelled"):
            data = control_corpus()
            driver = data["control-operations.jsonl"][1]["raw"]["driver_exit"]
            driver.update(result=result, abort_requested=False)
            self.fail(data, "RL_CONTROL_DRIVER")
        data = control_corpus()
        data["control-operations.jsonl"][1]["raw"]["body_complete"] = False
        self.fail(data, "RL_CONTROL_FAILURE")

    def test_control_fixture_false_ack_and_cli_error_do_not_follow_classification(self):
        data = control_corpus("fixture_ipc")
        data["control-operations.jsonl"][1]["raw"]["fixture_ack"]["ok"] = False
        self.fail(data, "RL_CONTROL_CLASSIFICATION")
        data = control_corpus("cli_mutation")
        data["control-operations.jsonl"][1]["raw"]["error"] = "permission denied"
        self.fail(data, "RL_CONTROL_FAILURE")

    def test_probe_fixed_request_recipe_and_denominator(self):
        report = self.verify(probe_corpus())
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        self.assertEqual(report["counts"]["control_probes"], 1)
        self.assertEqual(report["counts"]["offered"], 6)
        data = probe_corpus()
        data["control-probes.jsonl"][1]["raw"]["body_sha256"] = "0" * 64
        self.fail(data, "RL_CONTENT")

    def test_probe_missing_result_connection_failure_and_driver_panic_cannot_disappear(self):
        data = probe_corpus()
        data["control-probes.jsonl"].pop()
        self.fail(data, "RL_PROBE_RESULT")
        data = probe_corpus()
        terminal = data["control-probes.jsonl"][1]
        terminal["admitted"] = False
        terminal["raw"].update(status=None, body_bytes=0, data_observed=False, error_stage="connect", error_code="refused")
        self.fail(data, "RL_UNEXPECTED_RESPONSE")
        data = probe_corpus()
        data["control-probes.jsonl"][1]["driver_exit"]["result"] = "panicked"
        self.fail(data, "RL_PROBE_DRIVER")

    def test_counter_coverage_uses_raw_before_after_not_claimed_increase(self):
        data = corpus()
        event = {"kind": "coverage", "t_ns": 11 * NS + 10, "name": "active_health_failure", "evidence": {
            "source": "cluster_counter", "name": "active_health_failures", "before": 2, "after": 3,
            "before_raw": {"clusters": [{"endpoints": [{"active_health_failures": 2}]}]},
            "after_raw": {"clusters": [{"endpoints": [{"active_health_failures": 3}]}]}}}
        insert_event(data, event)
        report = self.verify(data)
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        self.assertEqual(report["coverage"]["active_health_failure"], 1)
        event["evidence"]["after_raw"]["clusters"][0]["endpoints"][0]["active_health_failures"] = 2
        self.fail(data, "RL_TRIGGER")

    def test_fault_trigger_numeric_claim_cannot_override_original_fixture_counter(self):
        data = fault_corpus()
        window = data["events.jsonl"][2]
        window.update(fixture_before={"reset_sent": 0}, fixture_after={"reset_sent": 0})
        self.fail(data, "RL_TRIGGER")

    def test_expected_status_still_requires_safe_response_body_and_eof(self):
        data = fault_corpus()
        for row in (data["buckets.jsonl"][2]["outcomes"][0], data["errors.jsonl"][0]):
            row["raw"]["body_sha256"] = "0" * 64
        self.fail(data, "RL_CONTENT")

    def test_prelude_label_cannot_reinterpret_the_same_retained_operation(self):
        data = prelude_corpus()
        proof = data["events.jsonl"][1]["evidence"]["raw"]
        proof["new_b_streams_raw"][0]["ended_ns"] += 1
        self.fail(data, "RL_PRELUDE_RESULT")

    def test_publication_ack_alone_cannot_replace_actual_revision_and_origin(self):
        before = {"schema_version": "oxidase.admin/v1", "runtime_revision": 1, "etag": "a", "origin": {"kind": "bundle"}}
        after = {**before, "runtime_revision": 2, "etag": "b"}
        self.assertTrue(VERIFIER.Analyzer.publication_proven(before, after, "activate"))
        self.assertFalse(VERIFIER.Analyzer.publication_proven(before, before, "activate"))
        self.assertFalse(VERIFIER.Analyzer.publication_proven(before, {**after, "origin": {"kind": "source"}}, "activate"))
        self.assertFalse(VERIFIER.Analyzer.publication_proven(before, {**after, "runtime_revision": 1}, "activate"))

    def test_weight_transition_cannot_change_identity_or_priority(self):
        old = {"clusters": [{"cluster": "upstream", "discovery": {"srv_targets": [
            {"target": "a.example", "port": 443, "priority": 0, "weight": 1},
            {"target": "b.example", "port": 443, "priority": 0, "weight": 1}]}}]}
        new = copy.deepcopy(old)
        new["clusters"][0]["discovery"]["srv_targets"][0]["weight"] = 3
        evidence = {"before_raw": old, "after_raw": new}
        self.assertTrue(VERIFIER.Analyzer.weight_change_proven(evidence))
        new["clusters"][0]["discovery"]["srv_targets"][0]["priority"] = 1
        self.assertFalse(VERIFIER.Analyzer.weight_change_proven(evidence))

    def test_prelude_file_and_retained_proof_are_complete_and_consistent(self):
        report = self.verify(prelude_corpus())
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        self.assertEqual(report["counts"]["prelude.offered"], 11)
        self.assertEqual(report["counts"]["prelude.connection_prepared"], 1)
        self.assertEqual(report["counts"]["offered"], 6)

    def test_prelude_lost_duplicate_or_abandoned_operations_are_not_pass(self):
        for change in ("duplicate", "missing", "abandoned"):
            data = prelude_corpus()
            evidence = data["prelude-operations.json"]["evidence"]
            row = evidence["prelude_operations"][-1]
            if change == "duplicate":
                evidence["prelude_operations"].append(copy.deepcopy(row))
                self.fail(data, "RL_INVALID_EVIDENCE")
            elif change == "missing":
                evidence["prelude_operations"].pop()
                self.fail(data, "RL_PRELUDE_CONSERVATION")
            else:
                row["terminal"] = "abandoned"
                self.fail(data, "RL_PRELUDE_RESULT")

    def test_prelude_body_and_trailers_are_independently_validated(self):
        for key, value, code in (("body_sha256", "0" * 64, "RL_CONTENT"), ("trailers", {}, "RL_TRAILERS")):
            data = prelude_corpus()
            data["prelude-operations.json"]["evidence"]["prelude_operations"][1]["raw"][key] = value
            self.fail(data, code)

    def test_prelude_503_has_finite_role_window_and_complete_safe_body(self):
        data = prelude_corpus()
        proof = data["events.jsonl"][1]["evidence"]["raw"]
        proof["withdrawal_window"] = {"start_ns": 10 * NS, "end_ns": 10 * NS + 100,
                                      "deadline_ns": 10 * NS + 1000, "roles": ["probe"], "allowed_statuses": [503]}
        evidence = data["prelude-operations.json"]["evidence"]
        row = copy.deepcopy(evidence["prelude_operations"][1])
        row["operation_id"] = "prelude:12"
        row["raw"]["operation_id"] = "prelude:12"
        evidence["prelude_operations"].append(row)
        evidence["prelude_counts"]["offered"] += 1
        evidence["prelude_counts"]["classified"] += 1
        evidence["prelude_counts"]["by_role"]["probe"]["offered"] += 1
        evidence["prelude_counts"]["by_role"]["probe"]["classified"] += 1
        raw = row["raw"]
        raw.update(status=503, body_bytes=19, body_sha256=hashlib.sha256(b"Service Unavailable").hexdigest(),
                   content_type="text/plain; charset=utf-8", trailers={})
        proof["prelude_operations"] = copy.deepcopy(evidence["prelude_operations"])
        proof["prelude_counts"] = copy.deepcopy(evidence["prelude_counts"])
        self.assertEqual(self.verify(data)["result"], "PASS_IMPLEMENTATION")
        raw["head_ns"] = 10 * NS + 200
        self.fail(data, "RL_PRELUDE_WINDOW")
        raw["head_ns"] = 10 * NS + 20
        raw["body_sha256"] = "0" * 64
        self.fail(data, "RL_PRELUDE_CONTENT")

    def test_local_respond_recipe_does_not_excuse_proxy_identity_in_health_campaign(self):
        data = corpus()
        recipe = data["receipt.json"]["recipes"]["download"]
        recipe["upstream_expected"] = False
        self.fail(data, "RL_CONTENT")
        data["receipt.json"]["parameters"]["campaign"] = "I"
        for bucket in data["buckets.jsonl"]:
            if bucket["outcomes"][0]["recipe"] == "download":
                for key in ("upstream_peer", "upstream_name", "authority", "server_name", "path"):
                    bucket["outcomes"][0]["raw"][key] = None
        for key in ("authority", "server_name", "path"):
            recipe.pop(key)
        self.assertEqual(self.verify(data)["result"], "PASS_IMPLEMENTATION")

    def test_formal_unbounded_resource_kind_remains_inconclusive(self):
        data = corpus()
        data["receipt.json"]["parameters"]["formal"] = True
        for row in data["samples.jsonl"]:
            if row["source"] == "admin":
                extra = copy.deepcopy(row["resources"]["resources"][0])
                extra["kind"] = "upstream_tcp_connection"
                row["resources"]["resources"].append(extra)
        report = self.verify(data)
        self.assertIn("RL_CAPACITY_UNPROVEN", codes(report))
        self.assertNotEqual(report["result"], "PASS_BOUNDED_QUALIFICATION")

    def test_real_renderer_labelled_series_are_not_replaced_by_global_zeros(self):
        report = self.verify(labelled_metrics_corpus())
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        curves = report["curves"]["steady"]
        self.assertEqual(curves[VERIFIER.FIXTURE_GAUGES[1]]["final"], 1)
        self.assertEqual(curves[VERIFIER.FIXTURE_GAUGES[2]]["final"], 2)
        self.assertNotIn("oxidase_active_connections", curves)

    def test_removing_any_exact_gauge_cannot_be_filled_or_covered_by_other_labels(self):
        for series in VERIFIER.FIXTURE_GAUGES:
            with self.subTest(series=series):
                data = labelled_metrics_corpus()
                measured = next(row for row in data["samples.jsonl"] if row["source"] == "admin" and row["phase"] == "steady")
                measured["metrics"] = "".join(line + "\n" for line in measured["metrics"].splitlines() if not line.startswith(series + " "))
                self.fail(data, "RL_MISSING_GAUGE")

    def test_wrong_protocol_or_listener_does_not_satisfy_fixed_gauge(self):
        for old, new in (('protocol="http1"', 'protocol="http2"'),
                         ('listener="qualification"', 'listener="other"')):
            with self.subTest(new=new):
                data = labelled_metrics_corpus()
                measured = next(row for row in data["samples.jsonl"] if row["source"] == "admin" and row["phase"] == "steady")
                measured["metrics"] = measured["metrics"].replace(old, new)
                self.fail(data, "RL_MISSING_GAUGE")

    def test_duplicate_and_nonfinite_labelled_metrics_are_invalid_raw_evidence(self):
        for change in ("duplicate", "NaN"):
            data = labelled_metrics_corpus()
            measured = next(row for row in data["samples.jsonl"] if row["source"] == "admin")
            line = VERIFIER.FIXTURE_GAUGES[2] + " 2\n"
            if change == "duplicate":
                measured["metrics"] += line
            else:
                measured["metrics"] = measured["metrics"].replace(line, VERIFIER.FIXTURE_GAUGES[2] + " NaN\n")
            self.fail(data, "RL_INVALID_EVIDENCE")

    def test_formal_receipt_cannot_delete_fixed_gauge_declaration(self):
        data = labelled_metrics_corpus()
        data["receipt.json"]["parameters"]["formal"] = True
        data["receipt.json"]["required_gauges"] = []
        report = self.fail(data, "RL_REQUIRED_GAUGE_CONTRACT")
        self.assertNotIn("RL_MISSING_GAUGE", codes(report))
        for row in data["samples.jsonl"]:
            if row["source"] == "admin":
                row["metrics"] = ""
        self.fail(data, "RL_MISSING_GAUGE")

    def test_bootstrap_missing_series_is_retained_but_cannot_replace_running_capture(self):
        data = labelled_metrics_corpus()
        early = copy.deepcopy(next(row for row in data["samples.jsonl"] if row["source"] == "admin"))
        early.update(phase="bootstrap", planned_ns=9 * NS, start_ns=9 * NS, end_ns=9 * NS + 1000, metrics="")
        data["samples.jsonl"].insert(0, early)
        for index, row in enumerate(data["samples.jsonl"], 1):
            row["writer_seq"] = index
        report = self.verify(data)
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        self.assertEqual(report["prelude_samples"], 1)
        measured = next(row for row in data["samples.jsonl"] if row["source"] == "admin" and row["phase"] == "warmup")
        measured["metrics"] = ""
        self.fail(data, "RL_MISSING_GAUGE")

    def test_budget_retirement_has_independent_counter_and_actual_before_admission_boundary(self):
        report = self.verify(retirement_corpus())
        self.assertEqual(report["result"], "PASS_IMPLEMENTATION", report["findings"])
        self.assertEqual(report["counts"]["client_retirements.offered"], 1)
        self.assertEqual(report["counts"]["client_retirements.received"], 1)
        self.assertEqual(report["counts"]["offered"], 1005)

    def test_missing_duplicate_and_changed_retirement_terminal_are_not_received(self):
        for change in ("missing", "duplicate", "epoch", "next_sequence"):
            data = retirement_corpus()
            if change == "missing":
                data["client-retirements.jsonl"].pop()
                code = "RL_RETIREMENT_RESULT"
            elif change == "duplicate":
                row = copy.deepcopy(data["client-retirements.jsonl"][1])
                row["writer_seq"] = 3
                data["client-retirements.jsonl"].append(row)
                code = "RL_INVALID_EVIDENCE"
            else:
                row = data["client-retirements.jsonl"][1]
                row["connection_epoch" if change == "epoch" else "next_operation_seq"] += 1
                code = "RL_INVALID_EVIDENCE"
            self.fail(data, code)

    def test_driver_exit_error_timeout_unknown_or_unjoined_cannot_qualify_retirement(self):
        for result in ("error", "cancelled", "panicked", "timeout", "unavailable"):
            data = retirement_corpus()
            data["client-retirements.jsonl"][1]["driver_exit"]["result"] = result
            self.fail(data, "RL_RETIREMENT_DRIVER")
        data = retirement_corpus()
        data["client-retirements.jsonl"][1]["driver_exit"]["join_acknowledged"] = False
        self.fail(data, "RL_RETIREMENT_DRIVER")

    def test_early_or_over_budget_retirement_counter_cannot_replace_actual_count(self):
        for submitted in (999, 1001):
            data = retirement_corpus()
            for row in data["client-retirements.jsonl"]:
                row["submitted_requests"] = submitted
            self.fail(data, "RL_RETIREMENT_BUDGET")
        data = retirement_corpus()
        data["buckets.jsonl"][0]["outcomes"][0]["raw"]["connection_epoch"] = 2
        self.fail(data, "RL_RETIREMENT_BUDGET")

    def test_old_terminal_must_precede_close_and_new_admission_must_follow_join(self):
        for change in ("old_end", "new_start", "reused_epoch", "protocol"):
            data = retirement_corpus()
            if change == "old_end":
                data["buckets.jsonl"][0]["bucket_end_ns"] = data["client-retirements.jsonl"][0]["start_ns"] + 1
                code = "RL_RETIREMENT_BOUNDARY"
            elif change == "new_start":
                terminal = data["client-retirements.jsonl"][1]
                terminal["end_ns"] = data["buckets.jsonl"][2]["bucket_start_ns"] + 1
                code = "RL_RETIREMENT_BOUNDARY"
            elif change == "reused_epoch":
                data["buckets.jsonl"][2]["outcomes"][0]["raw"]["connection_epoch"] = 1
                code = "RL_RETIREMENT_IDENTITY"
            else:
                for row in data["client-retirements.jsonl"]:
                    row["protocol"] = "h2"
                code = "RL_RETIREMENT_IDENTITY"
            self.fail(data, code)

    def test_connection_failure_epochs_can_skip_but_cannot_go_backwards(self):
        data = retirement_corpus()
        for bucket in data["buckets.jsonl"]:
            if bucket["worker_id"] == 0:
                epoch = bucket["outcomes"][0]["raw"]["connection_epoch"]
                for outcome in bucket["outcomes"]:
                    outcome["raw"]["connection_epoch"] = epoch + 2
        for row in data["client-retirements.jsonl"]:
            row["connection_epoch"] = 3
            row["retirement_id"] = "0:3"
        self.assertEqual(self.verify(data)["result"], "PASS_IMPLEMENTATION")
        backwards = copy.deepcopy(data["client-retirements.jsonl"][0])
        backwards.update(writer_seq=3, connection_epoch=2, retirement_id="0:2")
        data["client-retirements.jsonl"].append(backwards)
        self.fail(data, "RL_INVALID_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
