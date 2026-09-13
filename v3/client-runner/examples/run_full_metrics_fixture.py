"""Run the bundled synthetic full-metric fixture against an ExposureScopeX API.

This is an integration check for the client-runner contract. It is not a test of a
real customer model: the included adapter returns deterministic synthetic results.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import UUID


# Let this example run directly from a source checkout after `pip install -e`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from esx_eval_runner.runner import RunnerError, build_package, read_json, sign_package


HERE = Path(__file__).resolve().parent


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Submit the synthetic ExposureScopeX full-metric fixture."
    )
    root.add_argument("--identity-id", required=True, help="Approved client-runner identity ID from AI Evaluator")
    root.add_argument("--private-key", required=True, help="Local Ed25519 private key path; never uploaded")
    root.add_argument("--api-url", default="http://localhost:8001", help="ExposureScopeX API URL")
    root.add_argument("--require-pass", action="store_true", help="Exit non-zero unless the release decision is pass")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        UUID(args.identity_id)
        config = read_json(HERE / "full-metrics.sample.json")
        config["adapter"]["command"] = [sys.executable, str(HERE / "full_metrics_adapter.py")]
        package = sign_package(
            build_package(config),
            identity_id=args.identity_id,
            private_key_path=args.private_key,
        )
        request = Request(
            args.api_url.rstrip("/") + "/api/v3/evaluator/client-runs",
            data=json.dumps(package, separators=(",", ":")).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail")
            if isinstance(detail, dict):
                detail = detail.get("message") or detail.get("code")
        except Exception:  # noqa: BLE001 - error body is optional and untrusted.
            detail = None
        print(f"fixture: ExposureScopeX rejected the fixture: {detail or f'HTTP {exc.code}'}", file=sys.stderr)
        return 1
    except (OSError, RunnerError, ValueError) as exc:
        print(f"fixture: {exc}", file=sys.stderr)
        return 1

    decision = body.get("release_decision") if isinstance(body, dict) else None
    evaluation_id = body.get("id") if isinstance(body, dict) else None
    if not isinstance(decision, str) or not isinstance(evaluation_id, str):
        print("fixture: ExposureScopeX returned an invalid evaluation result", file=sys.stderr)
        return 1
    print(json.dumps({
        "evaluation_id": evaluation_id,
        "release_decision": decision,
        "view_results": f"{args.api_url.rstrip('/').replace(':8001', ':3001')}/ai-evaluator/{evaluation_id}",
    }))
    return 0 if not args.require_pass or decision == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
