"""Pre-build time budgets, not a synthetic gateway qualification."""

import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "run_resource_campaign.py"
SPEC = importlib.util.spec_from_file_location("resource_workflow", SCRIPT)
WORKFLOW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKFLOW)


class WorkflowBudgetTests(unittest.TestCase):
    def parameters(self, value):
        with patch.dict(os.environ, {"RESOURCE_PARAMETERS": json.dumps(value)}):
            return WORKFLOW.parameters()

    def test_defaults_reserve_shutdown_and_build_time(self):
        self.assertEqual(self.parameters({}), {})

    def test_actual_phases_cannot_consume_entire_job_timeout(self):
        with self.assertRaisesRegex(ValueError, "reserve 30 minutes"):
            self.parameters({"duration": "120m"})

    def test_exact_budget_and_first_excess(self):
        params = {"duration": "92m"}
        self.assertEqual(self.parameters(params), params)
        with self.assertRaisesRegex(ValueError, "reserve 30 minutes"):
            self.parameters({"duration": "5521s"})

    def test_zero_phase_is_not_a_running_window(self):
        with self.assertRaisesRegex(ValueError, "phase outside"):
            self.parameters({"quiet_running": "0s"})

    def test_profiling_is_not_a_normal_release_claim(self):
        with self.assertRaisesRegex(ValueError, "does not attest a profiler"):
            self.parameters({"profiling": True})


if __name__ == "__main__":
    unittest.main()
