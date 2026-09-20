"""Generate a synthetic application release review without calling any app."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys

def adapter(weak_confidence: bool) -> None:
    request = json.load(sys.stdin)
    results = [{"case_id": case["case_id"],
                "predicted_label": "review" if case["input"]["flagged"] else "allow",
                "confidence": 0.498 if weak_confidence else 0.90 + (index % 5) * 0.02}
               for index, case in enumerate(request["cases"])]
    json.dump({"schema_version": "esx-client-adapter-response-1.0", "results": results}, sys.stdout)


def fixture(out_dir: Path, *, compare: bool = False) -> int:
    from esx_eval_runner.cli import main as cli
    from esx_eval_runner.release import MANIFEST_SCHEMA

    out_dir = out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit("Choose a new or empty fixture output directory")
    out_dir.mkdir(parents=True, exist_ok=True)
    modules = []
    configurations = []
    for name, weak in (("triage", False), ("recommendations", True)):
        folder = out_dir / name
        folder.mkdir()
        command = [sys.executable, str(Path(__file__).resolve()), "--adapter"]
        if weak:
            command.append("--weak-confidence")
        config = {
            "schema_version": "esx-client-runner-config-1.0",
            "evaluation": {"name": f"Synthetic {name} fixture", "agent_id": name,
                           "project_key": "synthetic-release-demo", "subject_version": "fixture-1",
                           "dataset_version": "synthetic-20", "required_dimensions": ["classification", "confidence"],
                           # Simulates a native probability contract, not real model evidence.
                           "confidence_provenance": {"kind": "native_probability", "meaning": "predicted_label_correctness"}},
            "dataset": {"version": "synthetic-20", "cases": [
                {"case_id": f"synthetic-{index:03}", "input": {"flagged": bool(index % 2), "example_index": index},
                 "expected_label": "review" if index % 2 else "allow"} for index in range(20)
            ]},
            "adapter": {"type": "command_json_v1", "command": command, "timeout_seconds": 30},
        }
        (folder / "esx-eval.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        configurations.append((folder / "esx-eval.json", config))
        modules.append({"id": name, "name": name.title() + " (synthetic)", "owner": "Example team",
                        "required_kinds": ["decision"],
                        "depends_on": ["triage"] if name == "recommendations" else [],
                        "suites": [{"id": name + "-decisions", "kind": "decision", "subject_id": name,
                                    "config": name + "/esx-eval.json"}]})
    modules.extend([
        {"id": "search", "name": "Search (uncovered fixture)", "owner": "Example search team", "required_kinds": ["workflow", "decision"], "suites": []},
        {"id": "external-writes", "required": False, "exclusion_reason": "Synthetic exclusion: no isolated integration tenant.", "suites": []},
    ])
    manifest = {"schema_version": MANIFEST_SCHEMA,
                "application": {"id": "synthetic-release-demo", "version": "fixture-1", "inventory_complete": True},
                "modules": modules}
    manifest_path = out_dir / "release.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    options = []
    if compare:
        baseline = deepcopy(manifest)
        baseline["application"]["version"] = "fixture-0"
        for path, config in configurations:
            prior = deepcopy(config)
            prior["evaluation"]["subject_version"] = "fixture-0"
            prior["adapter"]["command"] = [p for p in prior["adapter"]["command"] if p != "--weak-confidence"]
            path.write_text(json.dumps(prior, indent=2) + "\n", encoding="utf-8")
        baseline_manifest = out_dir / "baseline-manifest.json"
        baseline_manifest.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
        baseline_out = out_dir / "baseline-review.json"
        status = cli(["release", "check", "--manifest", str(baseline_manifest), "--run", "--out", str(baseline_out)])
        for path, config in configurations:
            path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        if status != 0:
            return status
        options = ["--baseline", str(baseline_out)]
    return cli(["release", "check", "--manifest", str(manifest_path), "--run", "--out", str(out_dir / "release-review.json"), *options])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--compare", action="store_true", help="Also run a prior synthetic version to demonstrate regression comparison")
    parser.add_argument("--adapter", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--weak-confidence", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.adapter:
        adapter(args.weak_confidence)
    elif args.out_dir:
        raise SystemExit(fixture(args.out_dir, compare=args.compare))
    else:
        parser.error("--out-dir is required")
