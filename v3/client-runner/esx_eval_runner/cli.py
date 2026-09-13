"""Command-line interface for the customer-operated evaluator runner."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .runner import RunnerError, build_package, generate_keypair, read_json, sign_package


_PROJECT_KEY = re.compile(r"^[a-z][a-z0-9-]{1,62}$")


def _starter_cases() -> list[dict[str, object]]:
    """Generate a balanced local-only dataset skeleton, never a passing benchmark."""
    cases: list[dict[str, object]] = []
    for index in range(1, 11):
        cases.append({
            "case_id": f"benign-{index:03}",
            "input": {"message": f"REPLACE_WITH_BENIGN_CASE_{index:03}"},
            "expected_label": "safe",
        })
        cases.append({
            "case_id": f"adversarial-{index:03}",
            "input": {"message": f"REPLACE_WITH_ADVERSARIAL_CASE_{index:03}"},
            "expected_label": "unsafe",
        })
    return cases


_LOCAL_ADAPTER_TEMPLATE = '''"""Connect this local adapter to your AI system without sending its data to ExposureScopeX."""

from __future__ import annotations

import json
import sys


def evaluate_case(case: dict[str, object]) -> tuple[str, float]:
    """Return the predicted label and confidence for one local benchmark case.

    Replace this function with a call to your model, RAG application, or agent.
    Keep prompts, outputs, credentials, and raw traces in this local project.
    """
    raise NotImplementedError(
        "Connect evaluate_case() in local_adapter.py to the AI system under test."
    )


def main() -> None:
    request = json.load(sys.stdin)
    results = []
    for case in request["cases"]:
        predicted_label, confidence = evaluate_case(case)
        results.append({
            "case_id": case["case_id"],
            "predicted_label": predicted_label,
            "confidence": confidence,
        })
    json.dump(
        {"schema_version": "esx-client-adapter-response-2.0", "results": results},
        sys.stdout,
    )


if __name__ == "__main__":
    main()
'''


def init_command(args: argparse.Namespace) -> int:
    """Create an editable local evaluation starter without overwriting user files."""
    if not _PROJECT_KEY.fullmatch(args.agent_id):
        raise RunnerError("--agent-id must use lowercase letters, digits, and hyphens")
    if not _PROJECT_KEY.fullmatch(args.project_key):
        raise RunnerError("--project-key must use lowercase letters, digits, and hyphens")
    target = Path(args.directory)
    if target.exists() and any(target.iterdir()):
        raise RunnerError(f"Refusing to overwrite non-empty directory: {target}")
    dataset_version = args.dataset_version or f"{args.agent_id}-release-1.0"
    required_dimensions = ["classification", "confidence"]
    if args.full_metrics:
        required_dimensions += [
            "groundedness", "security", "trajectory", "rag", "robustness",
            "judge_agreement", "reproducibility", "cost_efficiency",
        ]
    target.mkdir(parents=True, exist_ok=True)
    config = {
        "schema_version": "esx-client-runner-config-1.0",
        "evaluation": {
            "name": f"{args.agent_id} pre-release evaluation",
            "agent_id": args.agent_id,
            "subject_version": args.subject_version,
            "subject_type": args.subject_type,
            "project_key": args.project_key,
            "dataset_version": dataset_version,
            "required_dimensions": required_dimensions,
        },
        "dataset": {"version": dataset_version, "cases": _starter_cases()},
        "adapter": {
            "type": "command_json_v2",
            "command": [sys.executable, "local_adapter.py"],
            "timeout_seconds": 120,
        },
        "source": {"origin": "local"},
        "signing": {
            "identity_id": "REPLACE-WITH-APPROVED-IDENTITY-UUID",
            "private_key_path": ".\\secrets\\esx-evaluator.key",
        },
    }
    _write_json(target / "esx-eval.json", config)
    (target / "local_adapter.py").write_text(_LOCAL_ADAPTER_TEMPLATE, encoding="utf-8")
    mode = "all ten metric areas" if args.full_metrics else "classification and confidence"
    (target / "README.md").write_text(
        f"# {args.agent_id} pre-release evaluation\n\n"
        f"This starter evaluates **{mode}**. It contains 20 balanced placeholders, not a valid benchmark. "
        "Replace every `REPLACE_WITH_*` value with a versioned labelled case approved by your team.\n\n"
        "## Test your local AI system\n\n"
        "1. Open `local_adapter.py` and replace `evaluate_case()` with a local call to your model, RAG application, or agent. "
        "It must return a predicted label and confidence from 0 to 1 for each case.\n"
        "2. Replace the 20 placeholders in `esx-eval.json` with your versioned, labelled benchmark cases.\n"
        "3. Run this command from this directory:\n\n"
        "```powershell\n"
        "esx-eval run --config .\\esx-eval.json --out .\\out\\evaluation.json\n"
        "```\n\n"
        "For `--full-metrics`, add the required redacted `measurements` object from `ADAPTER_V2.md` after the basic "
        "classification and confidence evaluation works.\n\n"
        "The generated package contains only labels, bounded scores, opaque evidence IDs, and digests. "
        "It does not contain prompt text, model outputs, documents, tool payloads, or secrets. "
        "Register and approve the dataset and runner identity in ExposureScopeX before uploading a shared result.\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "starter_directory": str(target),
        "config": str(target / "esx-eval.json"),
        "instructions": str(target / "README.md"),
        "metric_profile": "full" if args.full_metrics else "basic",
    }))
    return 0


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RunnerError(f"Cannot read secret token file: {path}") from exc


def _write_json(path: str | Path, value: object) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def github_oidc_token(audience: str) -> str:
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not request_url or not request_token:
        raise RunnerError("GitHub OIDC is available only inside a workflow with id-token: write permission")
    separator = "&" if "?" in request_url else "?"
    request = Request(
        request_url + separator + urlencode({"audience": audience}),
        headers={"Authorization": f"Bearer {request_token}", "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - convert provider errors into a clear CLI error.
        raise RunnerError("GitHub did not issue an OIDC token") from exc
    token = payload.get("value") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise RunnerError("GitHub OIDC response did not contain a token")
    return token


def run_command(args: argparse.Namespace) -> int:
    config = read_json(args.config)
    oidc_token = _read_secret_file(args.github_oidc_token_file)
    package = build_package(config, github_oidc_token=oidc_token)
    signing = config.get("signing")
    if oidc_token is None:
        if not isinstance(signing, dict) or not isinstance(signing.get("identity_id"), str) or not isinstance(signing.get("private_key_path"), str):
            raise RunnerError("Local and non-GitHub CI runs require signing.identity_id and signing.private_key_path")
        package = sign_package(package, identity_id=signing["identity_id"], private_key_path=signing["private_key_path"])
    _write_json(args.out, package)
    print(json.dumps({"package": str(args.out), "package_id": package["package_id"], "signed": oidc_token is None}))
    return 0


def upload_command(args: argparse.Namespace) -> int:
    package = read_json(args.package)
    if args.timeout_seconds < 1 or args.timeout_seconds > 300:
        raise RunnerError("upload timeout must be between 1 and 300 seconds")
    token = _read_secret_file(args.github_oidc_token_file)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        args.api_url.rstrip("/") + "/api/v3/evaluator/client-runs",
        data=json.dumps(package, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=args.timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            error = json.loads(exc.read().decode("utf-8"))
            detail = error.get("detail") if isinstance(error, dict) else None
            if isinstance(detail, dict):
                detail = detail.get("message") or detail.get("code")
            message = str(detail) if detail else f"HTTP {exc.code}"
        except Exception:  # noqa: BLE001 - response text is optional and untrusted.
            message = f"HTTP {exc.code}"
        raise RunnerError(f"ExposureScopeX rejected the result package: {message}") from exc
    except Exception as exc:  # noqa: BLE001 - do not expose customer package data in errors.
        raise RunnerError("ExposureScopeX did not accept the result package") from exc
    if not isinstance(body, dict) or not isinstance(body.get("release_decision"), str):
        raise RunnerError("ExposureScopeX returned an invalid client-runner response")
    _write_json(args.response_out, body)
    print(json.dumps({"evaluation_id": body.get("id"), "release_decision": body["release_decision"]}))
    if args.require_pass and body["release_decision"] != "pass":
        return 2
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="esx-eval", description="Run a redacted ExposureScopeX client evaluation")
    commands = root.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="Create a local Ed25519 keypair")
    keygen.add_argument("--private-key", required=True, help="New private-key file; never upload this file")
    init = commands.add_parser("init", help="Create an editable colleague-ready evaluation starter")
    init.add_argument("--directory", required=True, help="New or empty directory for the starter files")
    init.add_argument("--agent-id", required=True, help="Lowercase ID for the model, RAG app, or agent")
    init.add_argument("--subject-version", required=True, help="Release version being evaluated")
    init.add_argument("--project-key", default="default", help="Approved ExposureScopeX project key")
    init.add_argument("--dataset-version", help="Version for this labelled test pack")
    init.add_argument("--subject-type", choices=["model", "rag", "agent", "multi_agent_system"], default="agent")
    init.add_argument("--full-metrics", action="store_true", help="Require grounding, security, trajectory, RAG, robustness, agreement, repeatability, and cost metrics")
    run = commands.add_parser("run", help="Run a local adapter and write a redacted package")
    run.add_argument("--config", required=True)
    run.add_argument("--out", required=True)
    run.add_argument("--github-oidc-token-file", help="Short-lived GitHub token file; omit for signed local runs")
    upload = commands.add_parser("upload", help="Send a package to ExposureScopeX")
    upload.add_argument("--api-url", required=True)
    upload.add_argument("--package", required=True)
    upload.add_argument("--response-out", required=True)
    upload.add_argument("--github-oidc-token-file", help="Short-lived GitHub token file; omit for signed local runs")
    upload.add_argument("--timeout-seconds", type=int, default=30)
    upload.add_argument("--require-pass", action="store_true", help="Return non-zero when the platform release gate is not pass")
    oidc = commands.add_parser("github-oidc-token", help="Request a short-lived GitHub Actions token")
    oidc.add_argument("--audience", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "keygen":
            print(json.dumps(generate_keypair(args.private_key), indent=2))
            return 0
        if args.command == "init":
            return init_command(args)
        if args.command == "run":
            return run_command(args)
        if args.command == "upload":
            return upload_command(args)
        if args.command == "github-oidc-token":
            print(github_oidc_token(args.audience))
            return 0
    except RunnerError as exc:
        print(f"esx-eval: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
