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


def _starter_cases(case_count: int) -> list[dict[str, object]]:
    """Generate a local-only dataset skeleton, never a passing benchmark."""
    cases: list[dict[str, object]] = []
    for index in range(1, case_count + 1):
        sequence = (index + 1) // 2
        if index % 2:
            cases.append({
                "case_id": f"benign-{sequence:03}",
                "input": {"message": f"REPLACE_WITH_BENIGN_CASE_{sequence:03}"},
                "expected_label": "safe",
            })
        else:
            cases.append({
                "case_id": f"adversarial-{sequence:03}",
                "input": {"message": f"REPLACE_WITH_ADVERSARIAL_CASE_{sequence:03}"},
                "expected_label": "unsafe",
            })
    return cases


_LOCAL_ADAPTER_TEMPLATE = '''"""Connect this local adapter to your AI system without sending its data to ExposureScopeX."""

from __future__ import annotations

import json
from pathlib import Path
import sys


def evaluate_case(case: dict[str, object]) -> tuple[str, float]:
    """Return the predicted label and confidence for one local benchmark case.

    Replace this function with a call to your model, RAG application, or agent.
    Keep prompts, outputs, credentials, and raw traces in this local project.
    """
    raise NotImplementedError(
        "Connect evaluate_case() in local_adapter.py to the AI system under test."
    )


def collect_requested_measurements(request: dict[str, object]) -> dict[str, object]:
    """Load local full-metric records only when this test requests them.

    Fill full_metric_measurements.json with redacted metadata from the local
    trace store, evidence ledger, RAG pipeline, and provider telemetry. Never
    put prompts, responses, documents, tool payloads, or credentials in it.
    """
    required = set(request["evaluation"]["required_dimensions"])
    if required <= {"classification", "confidence"}:
        return {}
    path = Path("full_metric_measurements.json")
    if not path.exists():
        raise NotImplementedError(
            "Fill full_metric_measurements.json before running a full-metric evaluation."
        )
    measurements = json.loads(path.read_text(encoding="utf-8"))
    if "REPLACE_WITH_" in json.dumps(measurements):
        raise NotImplementedError(
            "Replace every REPLACE_WITH_* value in full_metric_measurements.json with local measured metadata."
        )
    return measurements


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
    response = {"schema_version": "esx-client-adapter-response-2.0", "results": results}
    measurements = collect_requested_measurements(request)
    if measurements:
        response["measurements"] = measurements
    json.dump(response, sys.stdout)


if __name__ == "__main__":
    main()
'''


_FULL_METRIC_MEASUREMENTS_TEMPLATE = '''{
  "claims": [
    {
      "claim_id": "REPLACE_WITH_CLAIM_ID",
      "evidence_ids": ["REPLACE_WITH_EVIDENCE_ID"],
      "entailment_score": 0.0,
      "citations_valid": false,
      "evidence_integrity_valid": false
    }
  ],
  "security": {
    "cases": [
      {
        "case_id": "REPLACE_WITH_SECURITY_CASE_ID",
        "expected_attack_success": false,
        "observed_attack_success": false,
        "expected_detection": true,
        "observed_detection": false,
        "evidence_ids": ["REPLACE_WITH_SECURITY_EVIDENCE_ID"],
        "evidence_integrity_valid": false
      }
    ]
  },
  "trajectory": {
    "required_milestones": ["REPLACE_WITH_REQUIRED_MILESTONE"],
    "observed_milestones": ["REPLACE_WITH_OBSERVED_MILESTONE"],
    "action_count": 0,
    "redundant_actions": 0,
    "policy_violations": [],
    "scope_violations": [],
    "tool_misuse_events": []
  },
  "rag": {
    "relevant_document_ids": ["REPLACE_WITH_RELEVANT_DOCUMENT_ID"],
    "retrieved_document_ids": ["REPLACE_WITH_RETRIEVED_DOCUMENT_ID"],
    "cited_document_ids": ["REPLACE_WITH_CITED_DOCUMENT_ID"],
    "answer_claims": [
      {
        "claim_id": "REPLACE_WITH_RAG_CLAIM_ID",
        "evidence_ids": ["REPLACE_WITH_RAG_EVIDENCE_ID"],
        "entailment_score": 0.0,
        "citations_valid": false,
        "evidence_integrity_valid": false
      }
    ],
    "k": 1
  },
  "robustness": {
    "baseline_correct": false,
    "baseline_confidence": 0.0,
    "baseline_label": "REPLACE_WITH_BASELINE_LABEL",
    "perturbations": [
      {
        "case_id": "REPLACE_WITH_PARAPHRASE_CASE_ID",
        "correct": false,
        "confidence": 0.0,
        "predicted_label": "REPLACE_WITH_PARAPHRASE_LABEL",
        "variation_type": "paraphrase"
      },
      {
        "case_id": "REPLACE_WITH_PERTURBATION_CASE_ID",
        "correct": false,
        "confidence": 0.0,
        "predicted_label": "REPLACE_WITH_PERTURBATION_LABEL",
        "variation_type": "perturbation"
      },
      {
        "case_id": "REPLACE_WITH_REPEAT_CASE_ID",
        "correct": false,
        "confidence": 0.0,
        "predicted_label": "REPLACE_WITH_REPEAT_LABEL",
        "variation_type": "repeat"
      }
    ]
  },
  "judge_agreement": {
    "decisions": [
      {"case_id": "REPLACE_WITH_JUDGE_CASE_ID", "judge_id": "REPLACE_WITH_JUDGE_A", "verdict": "inconclusive", "confidence": 0.0},
      {"case_id": "REPLACE_WITH_JUDGE_CASE_ID", "judge_id": "REPLACE_WITH_JUDGE_B", "verdict": "inconclusive", "confidence": 0.0}
    ]
  },
  "reproducibility": {
    "decisions": [
      {"case_id": "REPLACE_WITH_REPEATABILITY_CASE_ID", "run_id": "REPLACE_WITH_RUN_A", "verdict": "inconclusive"},
      {"case_id": "REPLACE_WITH_REPEATABILITY_CASE_ID", "run_id": "REPLACE_WITH_RUN_B", "verdict": "inconclusive"}
    ]
  },
  "cost_efficiency": {
    "cost_source": "metered",
    "observations": [
      {
        "case_id": "REPLACE_WITH_COST_CASE_ID",
        "input_tokens": 0,
        "output_tokens": 0,
        "request_count": 1,
        "retry_count": 0,
        "tool_call_count": 0,
        "cache_hit": false,
        "fallback_used": false,
        "cost_usd": 0.0,
        "latency_ms": 0,
        "timed_out": false
      }
    ]
  }
}
'''


def init_command(args: argparse.Namespace) -> int:
    """Create an editable local evaluation starter without overwriting user files."""
    if not _PROJECT_KEY.fullmatch(args.agent_id):
        raise RunnerError("--agent-id must use lowercase letters, digits, and hyphens")
    if not _PROJECT_KEY.fullmatch(args.project_key):
        raise RunnerError("--project-key must use lowercase letters, digits, and hyphens")
    if args.case_count < 1 or args.case_count > 10_000:
        raise RunnerError("--case-count must be a number between 1 and 10,000")
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
        "dataset": {"version": dataset_version, "cases": _starter_cases(args.case_count)},
        "adapter": {
            "type": "command_json_v2",
            "command": [sys.executable, "local_adapter.py"],
            "timeout_seconds": 120,
        },
        "source": {"origin": "local"},
    }
    _write_json(target / "esx-eval.json", config)
    (target / "local_adapter.py").write_text(_LOCAL_ADAPTER_TEMPLATE, encoding="utf-8")
    if args.full_metrics:
        (target / "full_metric_measurements.json").write_text(
            _FULL_METRIC_MEASUREMENTS_TEMPLATE, encoding="utf-8"
        )
    mode = "all ten metric areas" if args.full_metrics else "classification and confidence"
    full_metric_instructions = (
        "For `--full-metrics`, fill `full_metric_measurements.json` with local redacted metadata after the basic "
        "classification and confidence evaluation works. The generated file lists every required metric area and rejects "
        "unreplaced placeholders.\n\n"
        if args.full_metrics else ""
    )
    (target / "README.md").write_text(
        f"# {args.agent_id} pre-release evaluation\n\n"
        f"This starter evaluates **{mode}**. It contains {args.case_count} placeholder(s), not a valid benchmark. "
        "Replace every `REPLACE_WITH_*` value with a versioned labelled case approved by your team.\n\n"
        "## Test your local AI system\n\n"
        "1. Open `local_adapter.py` and replace `evaluate_case()` with a local call to your model, RAG application, or agent. "
        "It must return a predicted label and confidence from 0 to 1 for each case.\n"
        f"2. Replace the {args.case_count} placeholders in `esx-eval.json` with your versioned, labelled benchmark cases.\n"
        "3. Run this command from this directory:\n\n"
        "```powershell\n"
        "esx-eval run --config .\\esx-eval.json --out .\\out\\evaluation.json\n"
        "```\n\n"
        "This is a local-only run: no result is uploaded and no identity, private key, or 20-case release gate is required. "
        "The terminal prints every case result and the output file stays in this folder.\n\n"
        f"{full_metric_instructions}"
        "The generated package contains only labels, bounded scores, opaque evidence IDs, and digests. "
        "It does not contain prompt text, model outputs, documents, tool payloads, or secrets. "
        "Only if you later want a governed ExposureScopeX release decision, add signing details and use `esx-eval run --sign` before upload. "
        "That optional platform decision requires at least 20 labelled cases.\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "starter_directory": str(target),
        "config": str(target / "esx-eval.json"),
        "instructions": str(target / "README.md"),
        "metric_profile": "full" if args.full_metrics else "basic",
    }))
    return 0


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _local_metrics(expected: list[str], predicted: list[str], confidences: list[float]) -> dict[str, object]:
    """Calculate local inspection metrics without contacting the ExposureScopeX API."""
    labels = sorted(set(expected) | set(predicted))
    per_label: dict[str, dict[str, float | int]] = {}
    for label in labels:
        true_positive = sum(actual == label and observed == label for actual, observed in zip(expected, predicted))
        false_positive = sum(actual != label and observed == label for actual, observed in zip(expected, predicted))
        false_negative = sum(actual == label and observed != label for actual, observed in zip(expected, predicted))
        precision = _ratio(true_positive, true_positive + false_positive)
        recall = _ratio(true_positive, true_positive + false_negative)
        per_label[label] = {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "precision": precision,
            "recall": recall,
            "f1": _ratio(2 * precision * recall, precision + recall),
        }
    correct = [actual == observed for actual, observed in zip(expected, predicted)]
    macro_precision = _ratio(sum(float(item["precision"]) for item in per_label.values()), len(per_label))
    macro_recall = _ratio(sum(float(item["recall"]) for item in per_label.values()), len(per_label))
    macro_f1 = _ratio(sum(float(item["f1"]) for item in per_label.values()), len(per_label))
    brier_score = _ratio(sum((confidence - int(is_correct)) ** 2 for confidence, is_correct in zip(confidences, correct)), len(correct))
    bins: dict[int, list[tuple[float, bool]]] = {}
    for confidence, is_correct in zip(confidences, correct):
        bins.setdefault(min(9, int(confidence * 10)), []).append((confidence, is_correct))
    calibration_error = sum(
        abs(_ratio(sum(confidence for confidence, _ in values), len(values)) - _ratio(sum(is_correct for _, is_correct in values), len(values)))
        * _ratio(len(values), len(correct))
        for values in bins.values()
    )
    return {
        "case_count": len(expected),
        "correct_count": sum(correct),
        "accuracy": _ratio(sum(correct), len(correct)),
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "correctness_brier_score": brier_score,
        "expected_calibration_error": calibration_error,
        "per_label": per_label,
    }


def _print_local_results(config: dict[str, object], package: dict[str, object], *, summary_only: bool) -> None:
    """Present local results in a human-readable terminal report, never a release verdict."""
    evaluation = package["evaluation"]
    execution = package["execution"]
    assert isinstance(evaluation, dict) and isinstance(execution, dict)
    expected = evaluation["expected_labels"]
    predicted = evaluation["predicted_labels"]
    confidences = evaluation["confidences"]
    assert isinstance(expected, list) and isinstance(predicted, list) and isinstance(confidences, list)
    metrics = _local_metrics(expected, predicted, confidences)
    print("\nESX LOCAL EVALUATION")
    print("Status: COMPLETED LOCALLY (not uploaded; not a platform release decision)")
    print(f"Subject: {evaluation['agent_id']} {evaluation['subject_version']}")
    print(f"Dataset: {evaluation['dataset_version']}")
    print(f"Cases: {metrics['case_count']} | Correct: {metrics['correct_count']} | Accuracy: {metrics['accuracy']:.3f}")
    print(f"Macro precision: {metrics['macro_precision']:.3f} | Macro recall: {metrics['macro_recall']:.3f} | Macro F1: {metrics['macro_f1']:.3f}")
    print(f"Brier score: {metrics['correctness_brier_score']:.3f} | Expected calibration error: {metrics['expected_calibration_error']:.3f}")
    print(f"Duration: {execution['duration_ms']} ms | Required metrics: {', '.join(evaluation['required_dimensions'])}")
    if metrics["case_count"] < 20:
        print(f"Sample-size note: {metrics['case_count']} cases are valid for local testing. The 20-case minimum applies only to an optional governed ExposureScopeX release decision.")
    if not summary_only:
        dataset = config["dataset"]
        assert isinstance(dataset, dict) and isinstance(dataset["cases"], list)
        print("\nCASE RESULTS")
        for item, actual, observed, confidence in zip(dataset["cases"], expected, predicted, confidences):
            assert isinstance(item, dict)
            outcome = "CORRECT" if actual == observed else "INCORRECT"
            print(f"{item['case_id']}: {outcome} | expected={actual} | predicted={observed} | confidence={confidence:.3f}")
    print("\nNo prompts, model outputs, source files, tool data, environment variables, or credentials were sent to ExposureScopeX.")


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
    if args.sign and oidc_token is None:
        if not isinstance(signing, dict) or not isinstance(signing.get("identity_id"), str) or not isinstance(signing.get("private_key_path"), str):
            raise RunnerError("--sign requires signing.identity_id and signing.private_key_path in the config")
        package = sign_package(package, identity_id=signing["identity_id"], private_key_path=signing["private_key_path"])
    _write_json(args.out, package)
    if args.output_format == "json":
        print(json.dumps({"package": str(args.out), "package_id": package["package_id"], "signed": "signature" in package, "uploaded": False}))
    else:
        _print_local_results(config, package, summary_only=args.summary_only)
        print(f"\nLocal result package: {args.out}")
        if "signature" not in package:
            print("To request a governed shared decision later, add signing settings and run again with --sign, then use esx-eval upload.")
    return 0


def upload_command(args: argparse.Namespace) -> int:
    package = read_json(args.package)
    if args.timeout_seconds < 1 or args.timeout_seconds > 300:
        raise RunnerError("upload timeout must be between 1 and 300 seconds")
    token = _read_secret_file(args.github_oidc_token_file)
    if token is None and not isinstance(package.get("signature"), dict):
        raise RunnerError("This is an unsigned local-only package. It was not meant to be uploaded. Add signing settings, rerun with --sign, then upload only if a shared ExposureScopeX release decision is required.")
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
    root = argparse.ArgumentParser(prog="esx-eval", description="Run a local AI pre-release evaluation")
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
    init.add_argument("--case-count", type=int, default=1, help="Number of local starter cases (1-10,000; default: 1)")
    init.add_argument("--full-metrics", action="store_true", help="Require grounding, security, trajectory, RAG, robustness, agreement, repeatability, and cost metrics")
    run = commands.add_parser("run", help="Run locally and print results; it never uploads")
    run.add_argument("--config", required=True)
    run.add_argument("--out", required=True)
    run.add_argument("--github-oidc-token-file", help="Short-lived GitHub token file; omit for signed local runs")
    run.add_argument("--sign", action="store_true", help="Opt in to signing for a later shared platform decision")
    run.add_argument("--summary-only", action="store_true", help="Do not print each case result")
    run.add_argument("--output-format", choices=["text", "json"], default="text", help="Terminal output format (default: text)")
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
