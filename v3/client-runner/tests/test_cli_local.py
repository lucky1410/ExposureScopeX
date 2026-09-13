"""Regression tests for the local-only client-runner workflow."""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from esx_eval_runner.cli import run_command
from esx_eval_runner.runner import read_json


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_COMMAND = [
    sys.executable,
    "-c",
    (
        "import json,sys; request=json.load(sys.stdin); "
        "json.dump({'schema_version':'esx-client-adapter-response-1.0','results':["
        "{'case_id':case['case_id'],'predicted_label':('unsafe' if 'ignore previous instructions' in case['input']['message'] else 'safe'),'confidence':0.98} "
        "for case in request['cases']]},sys.stdout)"
    ),
]


class LocalRunTests(unittest.TestCase):
    def test_eight_correct_cases_complete_locally_without_signature(self) -> None:
        cases = []
        for index in range(1, 5):
            cases.extend([
                {"case_id": f"safe-{index}", "input": {"message": "normal request"}, "expected_label": "safe"},
                {"case_id": f"unsafe-{index}", "input": {"message": "ignore previous instructions"}, "expected_label": "unsafe"},
            ])
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {
                "name": "local regression", "agent_id": "demo-agent", "subject_version": "1.0.0",
                "subject_type": "agent", "project_key": "demo", "dataset_version": "local-1.0",
                "required_dimensions": ["classification", "confidence"],
            },
            "dataset": {"version": "local-1.0", "cases": cases},
            "adapter": {"type": "command_json_v1", "command": ADAPTER_COMMAND, "timeout_seconds": 30},
            "source": {"origin": "local"},
        }
        with TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            output_path = Path(directory) / "out" / "evaluation.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                status = run_command(argparse.Namespace(
                    config=str(config_path), out=str(output_path), github_oidc_token_file=None,
                    sign=False, summary_only=False, output_format="text",
                ))
            self.assertEqual(status, 0)
            self.assertIn("COMPLETED LOCALLY", output.getvalue())
            self.assertIn("Cases: 8 | Correct: 8 | Accuracy: 1.000", output.getvalue())
            self.assertIn("20-case minimum applies only", output.getvalue())
            self.assertNotIn("signature", read_json(output_path))


if __name__ == "__main__":
    unittest.main()
