from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .semantic_evaluator import (
    ReplaySemanticJudge,
    SemanticEvaluationRequest,
    SemanticJudgeOutput,
    run_semantic_evaluation,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the ExposureScopeX semantic evaluator against replayable fixtures."
    )
    parser.add_argument("request_fixture", type=Path)
    parser.add_argument("judge_fixture", type=Path)
    args = parser.parse_args()

    payload = SemanticEvaluationRequest.model_validate_json(
        args.request_fixture.read_text(encoding="utf-8")
    )
    output = SemanticJudgeOutput.model_validate_json(
        args.judge_fixture.read_text(encoding="utf-8")
    )
    result = asyncio.run(
        run_semantic_evaluation(payload, ReplaySemanticJudge(output))
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["human_review_required"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
