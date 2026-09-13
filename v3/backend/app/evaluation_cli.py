from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evaluation import EvaluationRequest, evaluate


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate one versioned ExposureScopeX AI quality fixture."
    )
    parser.add_argument("fixture", type=Path, help="Path to an evaluation fixture JSON file")
    parser.add_argument("--output", type=Path, help="Optional path for the result JSON")
    args = parser.parse_args()

    payload = EvaluationRequest.model_validate_json(args.fixture.read_text(encoding="utf-8"))
    result = evaluate(payload)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)
    return {"pass": 0, "fail": 1, "inconclusive": 2}[result["release_decision"]]


if __name__ == "__main__":
    raise SystemExit(main())
