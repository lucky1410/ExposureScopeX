#!/usr/bin/env python3
"""Score an ExposureScopeX benchmark fixture and emit a release-gate report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.assessment_benchmark import score_assessment_benchmark  # noqa: E402
from app.services.scan_profiles import get_scan_profile  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, help="JSON fixture containing cases and observations")
    parser.add_argument("--mode", choices=("light", "medium", "aggressive"), required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        payload = json.loads(args.fixture.read_text(encoding="utf-8"))
        profile = get_scan_profile(args.mode, payload.get("target_type", "url"))
        result = score_assessment_benchmark(
            cases=payload["cases"],
            observations=payload.get("observations", []),
            execution_manifest=payload.get("execution_manifest", []),
            quality_gates=profile["quality_gates"],
            scope_violations=int(payload.get("scope_violations", 0)),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Invalid benchmark fixture: {exc}", file=sys.stderr)
        return 2

    output = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0 if result["release_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
