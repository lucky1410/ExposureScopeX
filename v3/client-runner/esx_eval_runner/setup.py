"""Local setup page for the customer-facing HTTP evaluation workflow."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import platform
import re
import secrets
import webbrowser
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request

from .assurance import build_risk_plan, create_scope
from .discovery import discover_repository
from .evidence_requirements import render_evidence_requirements_markdown
from .http_utils import build_no_redirect_opener
from .profiles import PROFILE_NAMES, build_cases, profile
from .runner import CONFIG_SCHEMA_VERSION, _is_loopback_host
from .workflows import build_workflow_pack_catalog


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_OPAQUE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")

_SETUP_FIELD_HELP = {
    "APPLICATION REPOSITORY": "Optional local folder to inspect. The scan only reports supported source and dependency evidence; documentation and backlog mentions are not treated as installed frameworks.",
    "CONNECTION METHOD": "Choose how the runner reaches one approved user workflow. Use an existing JSON API when available. Choose a local browser journey only when the application has no usable API.",
    "LOCAL API URL": "The exact local endpoint that receives one evaluation request per case. Example: http://127.0.0.1:8000/evaluate. This is your application endpoint, not an ExposureScopeX endpoint.",
    "LOCAL WEB APP URL": "The local web application URL used for an approved browser journey. Example: http://127.0.0.1:3000. Browser testing stays on this computer.",
    "APPLICATION ID": "A short lowercase name for the application being tested, such as support-agent. It is used only to label local reports.",
    "VERSION UNDER TEST": "The build, release, or commit version you are evaluating, such as 1.4.0 or 2026.09.14-rc1.",
    "PROJECT KEY": "A short lowercase grouping name for this evaluation, such as payments or staging. It keeps local reports organized.",
    "LABEL RESPONSE PATH": "Where the outcome label is located in your API JSON response. For {\"decision\": {\"label\": \"safe\"}}, enter decision.label. The value must match the expected labels in the generated cases, such as safe or unsafe.",
    "CONFIDENCE RESPONSE PATH": "Where a numeric confidence value from 0 to 1 appears in your API JSON response. For {\"decision\": {\"confidence\": 0.91}}, enter decision.confidence. Leave it empty only when your application does not provide confidence.",
    "INCLUDE GROUNDEDNESS": "Turn this on only when the endpoint can return the generated response text and the exact retrieved source chunks used for that case. PRE-D then compares claims with those sources using an independent local judge; it is not inferred from evidence IDs alone.",
    "LOCAL GROUNDING JUDGE MODEL": "The installed local Ollama model PRE-D should use for claim extraction and evidence comparison. This stays on this computer and becomes part of the generated local judge command.",
    "RESPONSE TEXT FIELD": "Where the generated response text appears in the tested JSON response. PRE-D reads this text locally for groundedness only; it is never copied into the final report.",
    "RETRIEVED SOURCE CHUNKS FIELD": "Where the exact retrieved source chunks appear in the tested JSON response. PRE-D expects an array of objects such as [{\"evidence_id\":\"doc-1\",\"text\":\"chunk\"}]. Empty arrays are valid and mean no evidence was retrieved.",
    "START PATH": "The page route to open after the local web-app URL. Use / for the home page or /chat for a chat screen.",
    "EXPECTED VISIBLE TEXT": "Text that must be visible after the approved browser journey finishes, such as Welcome or Request blocked. This is the browser journey's observable pass condition.",
    "APPROVED LOGIN": "Turn this on only for a dedicated local test account. ExposureScopeX reads credentials from the named environment variables at run time and never stores their values in a plan, report, or log.",
    "LOGIN METHOD": "Choose credentials from local environment variables for a standard sign-in form. Choose interactive SSO when you will complete the approved identity-provider flow yourself in a visible browser; only the local application's session state is saved.",
    "LOGIN PATH": "The same-origin route that renders the application sign-in form, such as /login. The runner will not follow a login link to another host.",
    "USERNAME ENVIRONMENT VARIABLE": "The name of an environment variable already set on this computer, for example ESX_TEST_USERNAME. Enter the name, not the username itself.",
    "PASSWORD ENVIRONMENT VARIABLE": "The name of an environment variable already set on this computer, for example ESX_TEST_PASSWORD. Enter the name, not the password itself.",
    "POST-LOGIN PATH": "A same-origin route that should be available after the approved sign-in succeeds, such as /workspace. This becomes one explicit authenticated starter workflow, not claimed application-wide coverage.",
    "POST-LOGIN EXPECTED TEXT": "A stable, non-sensitive phrase that should be visible in the approved post-login workflow, such as Dashboard or Your projects.",
    "SAVE FAILURE SCREENSHOTS": "Optional. Saves screenshots only beside the local plan when a browser step fails. They can contain test-account UI data, are never included in the result package, and should be handled as local evidence.",
    "This is an approved staging API": "Select only for a designated test tenant that has approved controls. Do not use production credentials, customer data, or unrestricted tools during evaluation.",
    "EVALUATION PROFILE": "A starting test pack. Smoke verifies a connection and basic boundaries; Release adds broader checks; Adversarial exercises authorized safety boundaries; Custom creates one editable starter case.",
    "OPTIONAL EXTRA CASES": "Optional product-specific cases in JSON. Each case supplies an input and expected label. Leave this blank to begin with the selected profile; you can edit generated cases later.",
    "NEW EMPTY FOLDER": "The location for this plan and its local report files. Existing non-empty folders are never overwritten; the runner creates a sibling ending in -2, -3, and so on.",
    "I reviewed the selected scope": "Required confirmation that only approved components and a safe test target are in scope. Missing evidence is shown as NOT MEASURABLE instead of receiving an invented score.",
}

_PROBE_MESSAGE = "ESX local connection check. Return your normal JSON response without performing actions."


def create_http_plan(values: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    """Backward-compatible entry point for an editable HTTP plan."""
    return create_guided_plan({**values, "connection_type": "http", "confirm_plan": True})


def _decision_cases(values: object, task: str) -> list[dict[str, Any]]:
    """Convert the guided nested decision dataset into the runner's safe plan shape."""
    if not isinstance(values, list) or not values:
        raise ValueError("Import at least one labelled decision case")
    if len(values) > 500:
        raise ValueError("Local decision setup accepts at most 500 cases per plan")
    cases: list[dict[str, Any]] = []
    labels: set[str] = set()
    case_ids: set[str] = set()
    for index, item in enumerate(values, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Decision case {index} must be an object")
        case_id = item.get("case_id")
        input_data = item.get("input")
        expected = item.get("expected")
        if not isinstance(case_id, str) or not _OPAQUE_REFERENCE.fullmatch(case_id) or case_id in case_ids:
            raise ValueError(f"Decision case {index} needs a unique opaque case_id")
        if not isinstance(input_data, dict) or not isinstance(expected, dict):
            raise ValueError(f"Decision case {case_id} needs input and expected objects")
        label = expected.get("label")
        if not isinstance(label, str) or not _OPAQUE_REFERENCE.fullmatch(label):
            raise ValueError(f"Decision case {case_id} needs an expected.label reference")
        case = {"case_id": case_id, "task": task, "input": input_data, "expected_label": label}
        if "allowed_evidence_ids" in expected:
            evidence_ids = expected["allowed_evidence_ids"]
            if not isinstance(evidence_ids, list) or not all(
                isinstance(value, str) and _OPAQUE_REFERENCE.fullmatch(value) for value in evidence_ids
            ) or len(set(evidence_ids)) != len(evidence_ids):
                raise ValueError(f"Decision case {case_id} allowed_evidence_ids must be unique opaque references")
            case["expected_evidence_ids"] = evidence_ids
        if "must_abstain" in expected:
            if not isinstance(expected["must_abstain"], bool):
                raise ValueError(f"Decision case {case_id} must_abstain must be true or false")
            case["must_abstain"] = expected["must_abstain"]
        cases.append(case)
        labels.add(label)
        case_ids.add(case_id)
    if len(labels) < 2:
        raise ValueError("Decision evaluation needs at least two expected labels to calculate accuracy, precision, recall, and F1")
    return cases


def _host_python_command(host_os: str) -> str:
    """Use an OS-appropriate Python launcher in generated local commands."""
    return "py" if host_os == "windows" else "python3"


def _default_grounding_judge(host_os: str, model: object) -> dict[str, Any]:
    """Generate a valid local Ollama grounding-judge block for setup-created plans."""
    if not isinstance(model, str) or not _OPAQUE_REFERENCE.fullmatch(model.strip()):
        raise ValueError("Grounding judge model must be an opaque local model name")
    return {
        "type": "command_json_v1",
        "command": [
            _host_python_command(host_os),
            "-m",
            "esx_eval_runner.ollama_grounding_judge",
            "--model",
            model.strip(),
        ],
        "identity": "local-ollama-grounding-judge",
        "version": "1.0.0",
        "independent_from_target": True,
    }


def create_guided_plan(values: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    """Create one self-contained, customer-confirmed local evaluation workflow."""
    for key in ("directory", "agent_id", "subject_version", "project_key", "url"):
        if not isinstance(values.get(key), str) or not values[key].strip():
            raise ValueError(f"{key.replace('_', ' ')} is required")
    if not _IDENTIFIER.fullmatch(values["agent_id"]) or not _IDENTIFIER.fullmatch(values["project_key"]):
        raise ValueError("Application ID and project key must use lowercase letters, digits, and hyphens")
    profile_name = values.get("profile", "smoke")
    if profile_name not in PROFILE_NAMES:
        raise ValueError("Choose a valid evaluation profile")
    additions = values.get("custom_cases", [])
    if not isinstance(additions, list):
        raise ValueError("Additional cases must be a JSON array")
    connection_type = values.get("connection_type", "http")
    if connection_type not in {"http", "decision", "browser"}:
        raise ValueError("Choose a local decision API, generic HTTP API, or browser journey connection")
    if connection_type == "decision":
        # Decision datasets are authored around a product capability, not an
        # unrelated generic HTTP profile.
        profile_name = "custom"
    host_os = _host_os(values.get("host_os"))
    target = _available_plan_directory(Path(values["directory"]).expanduser().resolve())
    decision_task = values.get("decision_task") if connection_type == "decision" else None
    dataset_version = f"{values['agent_id']}-{decision_task or profile_name}-1.0"
    host = urlparse(values["url"]).hostname or ""
    if connection_type == "browser" and not _is_loopback_host(host):
        raise ValueError("Browser journeys can use a loopback URL only")
    target_environment = "local" if _is_loopback_host(host) else "staging"
    discovery = values.get("discovery")
    if discovery is not None and not isinstance(discovery, dict):
        raise ValueError("Discovery data is invalid; scan the repository again")
    selected_ids = values.get("selected_component_ids", [])
    if not isinstance(selected_ids, list) or not all(isinstance(item, str) for item in selected_ids):
        raise ValueError("Selected components are invalid")
    if discovery and discovery.get("components"):
        if not selected_ids:
            raise ValueError("Select at least one discovered component that is approved for evaluation")
        scope = create_scope(discovery, selected_ids)
    else:
        workflow_id = f"workflow-{values['agent_id']}"
        discovery = {
            "status": "not_scanned",
            "repository": None,
            "components": [{"id": workflow_id, "name": f"Declared workflow: {values['agent_id']}", "kind": "workflow_entry_point", "confidence": "customer_declared"}],
            "limitations": "No repository scan was requested. Scope contains only the customer-declared workflow.",
        }
        scope = create_scope(discovery, [workflow_id])
    plan = build_risk_plan(scope, profile_name)
    # Scope discovery can recommend broader assurance work, but a connection
    # must not silently make unsupported evidence dimensions part of this run.
    # The active scorecard starts with the evidence this connection can collect.
    evaluation_dimensions = ["classification", "confidence"]
    include_groundedness = bool(values.get("include_groundedness"))
    if include_groundedness and connection_type == "browser":
        raise ValueError("Groundedness requires a local API or decision endpoint, not a browser-only workflow")
    if connection_type == "browser":
        # A declared UI journey proves reachability and its approved signal. It
        # does not expose a model label or confidence, so use its own baseline.
        plan["required_dimensions"] = [
            "workflow_coverage",
            *(
                dimension for dimension in plan["required_dimensions"]
                if dimension not in {"classification", "confidence"}
            ),
        ]
        plan["notice"] += " Browser journeys use workflow coverage as their baseline; model classification and confidence require a connected API or adapter."
        evaluation_dimensions = ["workflow_coverage"]
    workflow_catalog = build_workflow_pack_catalog(discovery, scope)
    if values.get("confirm_plan") is not True:
        raise ValueError("Confirm the reviewed scope and plan before creating the local evaluation")
    plan["status"] = "customer_confirmed"
    plan["confirmation"] = "confirmed_in_local_setup"
    if connection_type == "browser":
        path = values.get("browser_path", "/")
        expected_text = values.get("browser_expected_text", "")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("Browser start path must start with /")
        if not isinstance(expected_text, str) or not expected_text.strip():
            raise ValueError("Browser expected text is required")
        cases = [{
            "case_id": "browser-pre-auth-001",
            "input": {"journey": [{"type": "goto", "path": path}, {"type": "expect_text", "value": expected_text.strip()}]},
            "expected_label": "pass",
            "requires_auth": False,
        }]
        adapter: dict[str, Any] = {
            "type": "browser_journey", "base_url": values["url"], "pass_label": "pass", "fail_label": "fail",
            "timeout_seconds": 60, "action_timeout_ms": 15_000,
            "capture_failure_screenshots": bool(values.get("browser_capture_failure_screenshots")),
            "evidence_dir": ".esx/browser-evidence",
        }
        if values.get("browser_auth_enabled"):
            auth_mode = values.get("browser_auth_mode", "password")
            if auth_mode not in {"password", "interactive_sso"}:
                raise ValueError("Choose a valid approved login method")
            required_auth = ("browser_login_path", "browser_post_login_path", "browser_post_login_expected_text")
            if auth_mode == "password":
                required_auth += (
                    "browser_username_env", "browser_password_env", "browser_username_selector",
                    "browser_password_selector", "browser_submit_selector",
                )
            if any(not isinstance(values.get(key), str) or not values[key].strip() for key in required_auth):
                raise ValueError("Approved login requires the login path, post-login path, and expected text; form login also requires credential environment-variable names and selectors")
            post_login_path = values["browser_post_login_path"].strip()
            if not post_login_path.startswith("/"):
                raise ValueError("Post-login path must start with /")
            adapter["session_state_path"] = ".esx/auth-session.json"
            success = {"type": "wait_for_text", "value": values["browser_post_login_expected_text"].strip()}
            if auth_mode == "password":
                adapter["auth"] = {
                    "login_path": values["browser_login_path"].strip(),
                    "username_env": values["browser_username_env"].strip(),
                    "password_env": values["browser_password_env"].strip(),
                    "username_selector": values["browser_username_selector"].strip(),
                    "password_selector": values["browser_password_selector"].strip(),
                    "submit_selector": values["browser_submit_selector"].strip(),
                    "success": success,
                }
            else:
                adapter["session_bootstrap"] = {"login_path": values["browser_login_path"].strip(), "success": success}
            cases.append({
                "case_id": "browser-authenticated-001",
                "input": {"journey": [
                    {"type": "goto", "path": post_login_path},
                    {"type": "wait_for_stable", "settle_ms": 250},
                    {"type": "wait_for_text", "value": values["browser_post_login_expected_text"].strip()},
                    {"type": "assert_path", "path": post_login_path},
                ]},
                "expected_label": "pass",
                "requires_auth": True,
            })
    elif connection_type == "decision":
        task = values.get("decision_task")
        if not isinstance(task, str) or not _OPAQUE_REFERENCE.fullmatch(task):
            raise ValueError("Decision task must be an opaque reference such as investigation-triage")
        cases = _decision_cases(values.get("decision_cases"), task)
        adapter = {
            "type": "http_json_target", "url": values["url"], "request_mode": "decision",
            "response_label_path": values.get("response_label_path", "label"),
            "response_confidence_path": values.get("response_confidence_path", "confidence"),
            "timeout_seconds": 60, "allow_remote": bool(values.get("allow_remote")),
            "target_environment": target_environment, "max_cases": 500, "minimum_delay_ms": 100,
        }
        for field in ("response_evidence_ids_path", "response_abstained_path"):
            value = values.get(field)
            if isinstance(value, str) and value.strip():
                adapter[field] = value.strip()
        has_decision_evidence = any(
            "expected_evidence_ids" in case or "must_abstain" in case
            for case in cases
        )
        has_decision_response_mapping = bool(
            values.get("response_evidence_ids_path") or values.get("response_abstained_path")
        )
        if has_decision_evidence and has_decision_response_mapping:
            evaluation_dimensions.append("decision_evidence")
        plan["notice"] += " This local decision plan sends case_id and input to the configured endpoint and measures labelled decision outcomes."
    else:
        cases = build_cases(profile_name, additions)
        adapter = {"type": "http_json_target", "url": values["url"], "request_mode": values.get("request_mode", "message"), "response_label_path": values.get("response_label_path", "decision.label"), "response_confidence_path": values.get("response_confidence_path", "decision.confidence"), "timeout_seconds": 60, "allow_remote": bool(values.get("allow_remote")), "target_environment": target_environment, "max_cases": 500, "minimum_delay_ms": 100}
    if include_groundedness:
        response_text_path = values.get("response_text_path")
        response_grounding_evidence_path = values.get("response_grounding_evidence_path")
        dotted = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")
        if not isinstance(response_text_path, str) or not re.fullmatch(dotted, response_text_path):
            raise ValueError("Choose the response text field from the tested local API response")
        if not isinstance(response_grounding_evidence_path, str) or not re.fullmatch(dotted, response_grounding_evidence_path):
            raise ValueError("Choose the retrieved source chunks field from the tested local API response")
        adapter["response_text_path"] = response_text_path
        adapter["response_grounding_evidence_path"] = response_grounding_evidence_path
        evaluation_dimensions.append("groundedness")
        plan["notice"] += " This plan also requests groundedness from endpoint-returned response text and retrieved source chunks, scored locally with an independent grounding judge."
    config = {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "evaluation": {
            "name": (
                f"{values['agent_id']} {decision_task} decision evaluation"
                if connection_type == "decision"
                else f"{values['agent_id']} {profile(profile_name)['name'].lower()}"
            ),
            "agent_id": values["agent_id"], "subject_version": values["subject_version"],
            "subject_type": values.get("subject_type", "agent"), "project_key": values["project_key"],
            "dataset_version": dataset_version, "required_dimensions": evaluation_dimensions,
            "scorecard_type": "decision_evaluation" if connection_type == "decision" else "model_evaluation",
            "decision_task": decision_task,
        },
        "dataset": {"version": dataset_version, "cases": cases},
        "adapter": adapter,
        "source": {"origin": "local"},
        "telemetry": {
            "enabled": True,
            "trajectory": {"required_milestones": []},
            "tool_use": {"expected_tools_by_case": {}},
            "rag": {"relevant_document_ids": []},
            "robustness": {"baseline_case_id": None, "baseline_label": None},
        },
        "plan": {
            "profile": profile_name,
            "profile_description": (
                f"Browser workflow starter: {len(cases)} explicit case(s), including "
                f"{sum(bool(case.get('requires_auth')) for case in cases)} authenticated case(s). "
                "Browser mode does not generate the HTTP profile's generic labelled cases."
                if connection_type == "browser" else
                f"Decision evaluation starter: {len(cases)} imported labelled case(s) for task {values['decision_task']}."
                if connection_type == "decision" else profile(profile_name)["description"]
            ),
            "review_required": False,
            "generated_case_count": len(cases),
        },
        "assurance": {"discovery_file": "discovery.json", "scope_file": "assurance-scope.json", "plan_file": "risk-plan.json", "workflow_packs_file": "workflow-packs.json", "telemetry_file": "out/telemetry.jsonl", "planned_dimensions": plan["required_dimensions"]},
        "environment": {"host_os": host_os},
    }
    if include_groundedness:
        config["assurance"]["grounding_judge"] = _default_grounding_judge(
            host_os, values.get("grounding_judge_model", "your-local-ollama-model"),
        )
    target.mkdir(parents=True, exist_ok=True)
    path = target / "esx-eval.json"
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (target / "discovery.json").write_text(json.dumps(discovery, indent=2) + "\n", encoding="utf-8")
    (target / "assurance-scope.json").write_text(json.dumps(scope, indent=2) + "\n", encoding="utf-8")
    (target / "risk-plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    (target / "workflow-packs.json").write_text(json.dumps(workflow_catalog, indent=2) + "\n", encoding="utf-8")
    (target / "PRE-D_EVIDENCE_REQUIREMENTS.md").write_text(
        render_evidence_requirements_markdown(config), encoding="utf-8"
    )
    (target / "README.md").write_text(_plan_readme(config, plan), encoding="utf-8")
    return path, config


def _available_plan_directory(requested: Path) -> Path:
    """Keep existing local work intact by choosing a predictable sibling folder."""
    if not requested.exists() or not any(requested.iterdir()):
        return requested
    for number in range(2, 10_001):
        candidate = requested.with_name(f"{requested.name}-{number}")
        if not candidate.exists():
            return candidate
    raise ValueError(f"Could not find an available plan folder beside: {requested}")


def _host_os(value: object = None) -> str:
    """Normalize host names for generated cross-platform instructions."""
    name = str(value or platform.system()).lower()
    if name.startswith("win"):
        return "windows"
    if name in {"darwin", "macos", "mac os"}:
        return "macos"
    return "linux"


def _plan_readme(config: dict[str, Any], plan: dict[str, Any] | None = None) -> str:
    adapter = config["adapter"]
    host_os = _host_os((config.get("environment") or {}).get("host_os"))
    python_command = "py" if host_os == "windows" else "python3"
    is_decision_plan = config.get("evaluation", {}).get("scorecard_type") == "decision_evaluation"
    connection = (
        "browser journey" if adapter["type"] == "browser_journey" else
        "local decision API" if is_decision_plan else "JSON API"
    )
    staging_note = ""
    if adapter.get("target_environment") == "staging":
        staging_note = '''

## Required staging security configuration

This plan cannot run against a remote target until the `adapter` configuration
also includes mTLS `client_certificate_path` and `client_private_key_path`, plus
a signed `target_attestation`. The attestation endpoint must be on the same
HTTPS host and prove that this is a synthetic-data test tenant with production
actions disabled. See the runner's `README.md` Security boundary section before
adding those values. Do not downgrade this target to plain HTTP.
'''
    browser_note = ""
    if adapter["type"] == "browser_journey":
        authenticated_cases = sum(bool(case.get("requires_auth")) for case in config["dataset"]["cases"])
        browser_note = f'''

## Browser coverage and approved authentication

This generated plan contains exactly {len(config["dataset"]["cases"])} browser case(s):
{len(config["dataset"]["cases"]) - authenticated_cases} pre-auth and {authenticated_cases} authenticated.
The selected profile does not generate its generic HTTP cases for a browser
target. Add and review a case for each user workflow you need to cover.

{("The runner signs in with the approved test account from environment variables, then saves local browser session state at `" + str(adapter.get("session_state_path")) + "` for reuse. That file can contain session cookies; keep it local and delete it when the test account changes. No credential values or cookies enter the report." if adapter.get("auth") else "Run `esx-eval browser-auth --config ./esx-eval.json`, complete the approved SSO flow in its visible browser, return to the local app, and press Enter to save only local-application session state at `" + str(adapter.get("session_state_path")) + "`. That file can contain session cookies; keep it local and delete it when the test account, role, or environment changes." if adapter.get("session_bootstrap") else "This plan has no authenticated cases. Add approved login configuration only when the protected workflow is in scope.")}

Browser actions include `goto`, `fill`, `click`, `press`, `wait_for_url`,
`wait_for_text`, `wait_for_selector`, `wait_for_navigation`, `wait_for_stable`,
`assert_path`, and `assert_title`. On failure, the local report names the case,
step, and failure category. Failure screenshots are opt-in and remain in the
local evidence directory.

`workflow-packs.json` lists source-derived workflow candidates from the
approved scope. They are not executed automatically. To list candidates, run
`esx-eval workflow-pack list --config ./esx-eval.json`; to add one, supply its
pack ID, a stable expected text, and an approved persona. See
`BROWSER_WORKFLOWS.md` in the runner installation for the full commands.

## Broaden module coverage now

Use this workflow to expand beyond the starter case without guessing:

1. Review `workflow-packs.json` and add one candidate per product area you want
   to cover first, such as case management, threat hunt, audit, or settings.
2. Add or bootstrap the approved persona for that area with
   `esx-eval persona add` and `esx-eval browser-auth` when the default session
   is not enough.
3. Prefer one stable workflow signal per reviewed case, then rerun and inspect
   the local coverage matrix in the HTML report.
4. Once a case is stable, save it as a reusable pack with
   `esx-eval workflow-pack save` so the next run extends coverage instead of
   starting over.
'''
    decision_note = ""
    if is_decision_plan:
        decision_note = f'''

## Decision evaluation contract

This plan calls `{adapter['url']}` once per labelled case with:

```json
{{"case_id": "case-001", "input": {{"...": "local test input"}}}}
```

The endpoint must return the configured decision label at
`{adapter['response_label_path']}` and a numeric 0-to-1 confidence at
`{adapter['response_confidence_path']}`. That produces local accuracy,
precision, recall, F1, and confidence-calibration metrics. When configured,
opaque evidence IDs and an `abstained` boolean produce evidence-reference and
abstention checks. They do not, by themselves, prove groundedness.

For the full response contract and a reusable dataset example, see
`DECISION_EVALUATION.md` in the runner installation. No ExposureScopeX account
or platform connection is required.
'''
    groundedness_note = ""
    if "groundedness" in config["evaluation"]["required_dimensions"] and adapter["type"] == "http_json_target":
        groundedness_note = f'''

## Groundedness in this plan

This plan requests local groundedness. The endpoint must return the generated
response text at `{adapter["response_text_path"]}` and the retrieved source
chunks at `{adapter["response_grounding_evidence_path"]}` for every case.
Evidence IDs alone do not count as groundedness.

PRE-D uses the independent local judge configured in
`assurance.grounding_judge` to extract atomic claims, review extraction
completeness, and compare those claims with the supplied sources. Before the
first run, confirm the configured local model name in `esx-eval.json`, then run:

```text
esx-eval evidence-check --config ./esx-eval.json
```

If your endpoint cannot return the response text and sources directly, keep this
metric out of the plan and use a local `grounding-material.json` file later
instead.
'''
    return f'''# Local pre-release evaluation

This folder was generated locally by `esx-eval setup` on {host_os}. It evaluates a customer-owned {connection} without uploading prompts, responses, source code, credentials, or results.

## Run this plan

1. Start the application locally, or use an approved staging URL.
2. Read `PRE-D_EVIDENCE_REQUIREMENTS.md`. It states, for every metric in this plan, what your team must define and what the application must emit locally before PRE-D can calculate a real score.
3. Open `esx-eval.json` and review every labelled test case. Replace, remove, or add cases to match the product's real requirements.
4. The runner uses the approved {connection} at `{adapter.get('url', adapter.get('base_url'))}`.{" It reads the decision label from `" + adapter['response_label_path'] + "` and a numeric confidence from `" + adapter['response_confidence_path'] + "`." if adapter['type'] == 'http_json_target' else " It measures declared workflow coverage from the configured browser assertion; it does not infer model labels or confidence from a UI pass/fail result."}
5. Run:

```text
esx-eval run --config ./esx-eval.json --out ./out/evaluation.json
esx-eval view --report ./out/evaluation.local-report.html
```

The terminal and HTML report are private and local. A successful smoke plan proves only this connection and the selected labelled cases, not universal safety or reliability.
{browser_note}{decision_note}{groundedness_note}

## Scope, plan, and evidence

This folder already contains `discovery.json`, `assurance-scope.json`, and
`risk-plan.json`. The run command automatically uses them to make the local
Assurance Graph. Its recommended later dimensions are: {", ".join((plan or {}).get("required_dimensions", ["classification", "confidence"]))}. The active scorecard for this plan calculates only: {", ".join(config["evaluation"]["required_dimensions"])}. Recommended dimensions do not appear as missing scores unless you explicitly add their matching evidence connection.

Grounding, RAG, trajectory, tool-use, security detection, robustness, repeatability, judge agreement, and provider cost are separate local evidence packs. They are not part of this run unless you explicitly add their matching evidence connection. When selected later, the generated plan can derive complete records from supported redacted OpenTelemetry or connector metadata without a second adapter.

For a model-quality scorecard, use the JSON API or local adapter connection and
include at least two expected outcome classes plus observed model confidence
values. Constant confidence is flagged as limited because it cannot show
behavior across confidence levels. Browser workflow coverage and model quality
are displayed in separate scorecards so a successful UI assertion cannot appear
as a perfect AI quality score.

For trajectory measurement, add only the product's approved opaque milestone IDs to `telemetry.trajectory.required_milestones` in `esx-eval.json`. For tool-use quality, add approved opaque tool IDs by case to `telemetry.tool_use.expected_tools_by_case`. For robustness, mark one labelled case as `telemetry.robustness.baseline_case_id`, then emit controlled paraphrase, perturbation, or repeat observations. For RAG recall, add only the expected opaque document IDs to `telemetry.rag.relevant_document_ids`. The local report names these fields only when they are needed. Do not add prompt text, answers, or document content.

To capture supported OpenTelemetry JSON metadata locally, run this in a second
terminal before the evaluation, then configure the test application with the
printed loopback URL and token:

```text
esx-eval telemetry --out ./out/telemetry.jsonl
```

For a browser journey, install the optional local dependency once:

```text
{python_command} -m pip install "exposurescopex-eval-runner[browser]"
playwright install chromium
```
{staging_note}'''


def _probe_local_http_target(url: object, request_mode: object = "message") -> dict[str, Any]:
    """Send one fixed, local-only probe and return a value-redacted response shape."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Enter a local API URL before testing the connection")
    parsed = urlparse(url.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Enter an http or https API URL without credentials, query parameters, or a fragment")
    if not _is_loopback_host(parsed.hostname):
        raise ValueError("Zero-adapter connection testing is limited to a loopback URL. Approved staging targets require the managed mTLS and signed-attestation configuration.")
    if request_mode not in {"message", "input", "decision"}:
        raise ValueError("Connection testing needs message, input, or decision request mode")
    probe_input = {"message": _PROBE_MESSAGE}
    body = (
        {"message": _PROBE_MESSAGE} if request_mode == "message" else
        {"case_id": "esx-connection-check", "input": probe_input} if request_mode == "decision" else
        {"input": probe_input}
    )
    request = Request(
        url.strip(),
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "ExposureScopeX-Eval-Runner/setup",
            "X-ESX-Evaluation-Mode": "local-connection-check",
        },
        method="POST",
    )
    try:
        with build_no_redirect_opener().open(request, timeout=10) as response:
            response_bytes = response.read(1_048_577)
    except HTTPError as exc:
        schema = (
            '{"case_id":"esx-connection-check","input":{...}}'
            if request_mode == "decision" else
            '{"input":{...}}' if request_mode == "input" else
            '{"message":"..."}'
        )
        raise ValueError(f"The local API returned HTTP {exc.code}. It must accept a JSON POST body shaped like {schema}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ValueError("The local API could not be reached. Start the application and check the URL.") from exc
    if len(response_bytes) > 1_048_576:
        raise ValueError("The local API response exceeded 1 MB")
    try:
        response = json.loads(response_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("The local API did not return a JSON object") from exc
    if not isinstance(response, dict):
        raise ValueError("The local API must return a JSON object")
    fields = _response_fields(response)
    label_candidates = _rank_response_candidates(fields, kind="label")
    confidence_candidates = _rank_response_candidates(fields, kind="confidence")
    return {
        "url": url.strip(),
        "request_mode": request_mode,
        "request": {"body": "<fixed local connection check>"},
        "response_shape": _redacted_response_shape(response),
        "fields": [{"path": item["path"], "type": item["type"]} for item in fields],
        "label_candidates": label_candidates,
        "confidence_candidates": confidence_candidates,
        "evidence_id_candidates": _rank_response_candidates(fields, kind="evidence_ids"),
        "abstained_candidates": _rank_response_candidates(fields, kind="abstained"),
        "response_text_candidates": _rank_response_candidates(fields, kind="response_text"),
        "grounding_evidence_candidates": _rank_response_candidates(fields, kind="grounding_evidence"),
    }


def _response_fields(value: object, prefix: str = "") -> list[dict[str, Any]]:
    """List dotted object paths without retaining response values."""
    if isinstance(value, dict):
        fields: list[dict[str, Any]] = []
        for key, child in value.items():
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                continue
            child_prefix = f"{prefix}.{key}" if prefix else key
            fields.extend(_response_fields(child, child_prefix))
        return fields
    if not prefix:
        return []
    value_type = "boolean" if isinstance(value, bool) else "number" if isinstance(value, (int, float)) else "string" if isinstance(value, str) else "array" if isinstance(value, list) else "null"
    return [{"path": prefix, "type": value_type, "value": value}]


def _redacted_response_shape(value: object) -> object:
    """Keep JSON keys and types for mapping while withholding all response content."""
    if isinstance(value, dict):
        return {key: _redacted_response_shape(child) for key, child in value.items() if isinstance(key, str)}
    if isinstance(value, list):
        return ["<array items redacted>"]
    if isinstance(value, bool):
        return "<boolean>"
    if isinstance(value, (int, float)):
        return "<number>"
    if value is None:
        return "<null>"
    return "<string>"


def _rank_response_candidates(fields: list[dict[str, Any]], *, kind: str) -> list[dict[str, str]]:
    """Suggest likely mappings while requiring the customer to confirm them."""
    ranked: list[tuple[int, str, str]] = []
    for field in fields:
        path = field["path"]
        value = field["value"]
        name = path.rsplit(".", 1)[-1].lower()
        if kind == "label":
            if field["type"] != "string":
                continue
            score = 0
            if name in {"label", "decision", "outcome", "verdict", "result", "status"}:
                score += 10
            if str(value).lower() in {"safe", "unsafe", "allow", "allowed", "block", "blocked", "pass", "fail"}:
                score += 20
        elif kind == "confidence":
            if field["type"] != "number" or not 0 <= float(value) <= 1:
                continue
            score = 10 if any(word in name for word in ("confidence", "probability", "score")) else 1
        elif kind == "response_text":
            if field["type"] != "string":
                continue
            score = 0
            if name in {"response", "answer", "output", "summary", "content", "text", "message", "completion"}:
                score += 12
            if any(word in name for word in ("response", "answer", "output", "summary", "content", "completion")):
                score += 8
        elif kind == "evidence_ids":
            if field["type"] != "array" or not any(word in name for word in ("evidence", "citation", "source")):
                continue
            score = 10
        elif kind == "grounding_evidence":
            if field["type"] != "array" or not any(word in name for word in ("evidence", "source", "chunk", "retriev", "context", "document", "support")):
                continue
            score = 5
            if isinstance(value, list) and value:
                first = value[0]
                if isinstance(first, dict):
                    keys = {str(key).lower() for key in first}
                    if any(key in keys for key in {"evidence_id", "source_id", "document_id", "chunk_id", "id"}):
                        score += 10
                    if any(key in keys for key in {"text", "content", "chunk", "snippet", "passage"}):
                        score += 10
        elif kind == "abstained":
            if field["type"] != "boolean" or not any(word in name for word in ("abstain", "refus", "declin")):
                continue
            score = 10
        else:
            continue
        if score:
            ranked.append((score, path, field["type"]))
    return [{"path": path, "type": value_type} for _score, path, value_type in sorted(ranked, key=lambda item: (-item[0], item[1]))]


def serve_setup(default_directory: str | None = None) -> None:
    """Serve one local page on loopback until the user presses Ctrl+C."""
    token = secrets.token_urlsafe(24)
    verified_connections: dict[str, dict[str, Any]] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/browser":
                body = _guided_setup_html_with_evidence(token, default_directory).encode("utf-8")
            elif self.path == "/":
                body = _pred_local_setup_html(token, default_directory).encode("utf-8")
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if self.headers.get("X-ESX-Setup-Token") != token:
                self._json(403, {"error": "Local setup authorization failed"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 1_048_576:
                    raise ValueError("Request must contain at most 1 MB of JSON")
                values = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(values, dict):
                    raise ValueError("Request must be a JSON object")
                values["host_os"] = _host_os()
                if self.path == "/api/discover":
                    self._json(200, discover_repository(values.get("repository", "")))
                    return
                if self.path == "/api/test-connection":
                    request_mode = values.get("request_mode", "message")
                    probe = _probe_local_http_target(values.get("url"), request_mode)
                    verified_connections[f"{request_mode}:{probe['url']}"] = probe
                    self._json(200, probe)
                    return
                if self.path == "/api/create-plan":
                    connection_type = values.get("connection_type", "http")
                    if connection_type in {"http", "decision"}:
                        request_mode = "decision" if connection_type == "decision" else "message"
                        probe = verified_connections.get(f"{request_mode}:{values.get('url', '')}")
                        if probe is None:
                            raise ValueError("Test this local API connection and confirm its response mappings before creating a plan")
                        label_path = values.get("response_label_path")
                        confidence_path = values.get("response_confidence_path")
                        labels = {item["path"] for item in probe["label_candidates"]}
                        confidences = {item["path"] for item in probe["confidence_candidates"]}
                        if label_path not in labels or confidence_path not in confidences:
                            raise ValueError("Choose the label and confidence fields from the tested local API response")
                        optional_fields = (
                            ("response_evidence_ids_path", "evidence_id_candidates"),
                            ("response_abstained_path", "abstained_candidates"),
                        )
                        for field, candidate_key in optional_fields:
                            value = values.get(field)
                            if value and value not in {item["path"] for item in probe[candidate_key]}:
                                raise ValueError(f"Choose {field.replace('_', ' ')} from the tested local API response")
                        if values.get("include_groundedness"):
                            for field, candidate_key in (
                                ("response_text_path", "response_text_candidates"),
                                ("response_grounding_evidence_path", "grounding_evidence_candidates"),
                            ):
                                value = values.get(field)
                                if value not in {item["path"] for item in probe[candidate_key]}:
                                    raise ValueError(f"Choose {field.replace('_', ' ')} from the tested local API response")
                    path, config = create_guided_plan(values)
                    self._json(201, {"config": str(path), "cases": len(config["dataset"]["cases"]), "profile": config["plan"]["profile"], "files": ["esx-eval.json", "discovery.json", "assurance-scope.json", "risk-plan.json", "workflow-packs.json", "PRE-D_EVIDENCE_REQUIREMENTS.md", "README.md"], "planned_dimensions": config["assurance"]["planned_dimensions"], "connection_type": connection_type})
                    return
                self._json(404, {"error": "Unknown local setup endpoint"})
            except (ValueError, json.JSONDecodeError) as exc:
                self._json(400, {"error": str(exc)})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"Open the local setup page: {url}")
    print("The page is local-only. Press Ctrl+C here when you are finished.")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nLocal setup page stopped.")
    finally:
        server.server_close()


def _pred_local_setup_html(token: str, default_directory: str | None) -> str:
    """Render local-first setup with an explicit decision-evaluation path."""
    page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRE-D Local Setup</title>
<style>
:root{--ink:#102022;--paper:#f7f5ee;--muted:#5e716b;--line:#b5c5bc;--coral:#ef7151;--lime:#c8ef72;--green:#216c4a}
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(125deg,#e5eee5,#f8f2e7);color:var(--ink);font:16px Georgia,serif}
main{max-width:1050px;margin:32px auto;padding:36px;background:var(--paper);border:1px solid var(--ink);box-shadow:8px 8px 0 var(--ink)}
h1{margin:0;font-size:48px;letter-spacing:-.05em;line-height:.95}
h1 em{color:var(--coral)}
h2{margin:0 0 8px;font-size:26px;font-weight:400}
.lead{max-width:760px;color:var(--muted);font-size:18px;line-height:1.5}
.step{padding:26px 0;border-top:1px solid var(--line)}
.choice,.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0}
.grid{grid-template-columns:1fr 1fr}
.choice button{min-height:110px;margin:0;padding:15px;border:1px solid #738a7d;background:#fffdf7;color:var(--ink);box-shadow:none;text-align:left;font:16px Georgia,serif}
.choice button.active{border:2px solid var(--ink);background:#e1f0df;box-shadow:4px 4px 0 var(--ink)}
.choice strong,.choice small{display:block}
.choice small{margin-top:6px;color:var(--muted);font-size:13px;line-height:1.35}
.note,.warning,.success{margin:14px 0;padding:14px;border-left:4px solid var(--green);background:#e9f1e7;line-height:1.45}
.warning{border-color:#b67522;background:#fff1dc}
.success{background:#ddf2df}
.small{font-size:14px;color:var(--muted);line-height:1.45}
label{display:block;margin:14px 0 5px;font:700 11px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.09em}
input,select,textarea{width:100%;padding:11px;border:1px solid #71877b;background:#fffdf7;color:var(--ink);font:14px ui-monospace,SFMono-Regular,Consolas,monospace}
textarea{min-height:180px}
.hidden{display:none!important}
.scope,#connection_probe_result{padding:14px;border:1px solid var(--line);background:#edf3ed;line-height:1.45}
.scope label{font:14px Georgia,serif;letter-spacing:0}
.scope input,.check input{width:auto;margin-right:8px}
button{margin-top:16px;padding:12px 16px;border:2px solid var(--ink);background:var(--coral);color:#fff;font:700 13px ui-monospace,SFMono-Regular,Consolas,monospace;box-shadow:3px 3px 0 var(--ink);cursor:pointer}
button.secondary{background:#dfe9df;color:var(--ink)}
pre{overflow:auto;white-space:pre-wrap;word-break:break-word;padding:14px;background:#112224;color:#e2eee7;font:13px ui-monospace,SFMono-Regular,Consolas,monospace}
details{margin-top:14px;border:1px solid var(--line);padding:12px;background:#fffdf7}
summary{cursor:pointer;font-weight:bold}
@media(max-width:720px){main{margin:0;padding:22px;box-shadow:none;border:0}.grid,.choice{grid-template-columns:1fr}h1{font-size:38px}}
</style>
</head>
<body>
<main>
<p style="font:700 11px ui-monospace,monospace;letter-spacing:.15em;color:var(--coral)">PRE-D LOCAL / NO ACCOUNT / NO UPLOAD</p>
<h1>Evaluate decisions <em>with evidence.</em></h1>
<p class="lead">PRE-D runs on this computer. Choose browser workflows for the app experience, a decision endpoint for AI quality, and optional local groundedness when the endpoint can return the generated response plus the exact retrieved source chunks for each case.</p>

<section class="step">
<h2>1. Optional: discover and confirm scope</h2>
<p>Repository discovery identifies implemented candidates only. It never executes discovered code and does not turn routes or framework names into coverage.</p>
<label>APPLICATION REPOSITORY</label>
<input id="repository" placeholder="C:\\work\\my-ai-app">
<button class="secondary" type="button" onclick="discover()">DISCOVER LOCALLY</button>
<div id="scope" class="scope">No repository scanned. This plan will contain one customer-declared entry point.</div>
</section>

<section class="step">
<h2>2. Choose the evaluation method</h2>
<p class="note" id="method_note"><strong>Decision evaluation is selected.</strong> PRE-D will call a local endpoint with labelled cases and calculate decision metrics locally.</p>
<div class="choice">
<button id="mode_decision" class="active" type="button" onclick="selectMode('decision')"><strong>Decision evaluation</strong><small>Accuracy, precision, recall, F1, and confidence from labelled local cases.</small></button>
<button id="mode_browser" type="button" onclick="selectMode('browser')"><strong>Browser workflow</strong><small>Login, navigation, and user-visible signals. Does not measure decision quality.</small></button>
<button id="mode_http" type="button" onclick="selectMode('http')"><strong>Generic JSON API</strong><small>Use existing baseline profiles for a simple local API.</small></button>
</div>
<input id="connection_type" type="hidden" value="decision">

<div class="grid">
<div><label id="url_label">LOCAL DECISION API URL</label><input id="url" value="http://127.0.0.1:8000/eval"></div>
<div><label>APPLICATION ID</label><input id="agent_id" value="my-ai-application"></div>
<div><label>VERSION UNDER TEST</label><input id="subject_version" value="0.1.0"></div>
<div><label>PROJECT KEY</label><input id="project_key" value="default"></div>
</div>

<div id="decision_fields">
<label>DECISION TASK</label>
<input id="decision_task" value="investigation-triage" placeholder="For example: investigation-triage">
<p class="note">Your endpoint receives <code>{"case_id":"case-001","input":{...}}</code> and returns a label and 0-to-1 confidence. Evidence IDs and an abstained flag are optional. Groundedness is available only when the endpoint also returns the generated response text and the exact retrieved source chunks for that case.</p>
<label>LABELLED CASES</label>
<input id="decision_file" type="file" accept="application/json">
<textarea id="decision_cases" spellcheck="false">[{"case_id":"triage-001","input":{"title":"replace with a synthetic local test case"},"expected":{"label":"escalate","allowed_evidence_ids":["sig-001"],"must_abstain":false}},{"case_id":"triage-002","input":{"title":"replace with a second synthetic local test case"},"expected":{"label":"do-not-escalate","must_abstain":false}}]</textarea>
<p class="note">Import a JSON array or paste it here. Use at least two expected labels. These test cases remain on your computer and are not copied into the final result package.</p>
</div>

<div id="browser_fields" class="hidden">
<p class="warning">This is browser workflow testing. It will prove only the visible signals you explicitly define. It will not produce accuracy, F1, hallucination, groundedness, or model confidence metrics.</p>
<div class="grid">
<div><label>START PATH</label><input id="browser_path" value="/"></div>
<div><label>EXPECTED VISIBLE TEXT</label><input id="browser_expected_text" placeholder="For example: Dashboard"></div>
</div>
</div>

<div id="api_fields" class="hidden">
<p class="note">Generic API mode uses a baseline profile. Use Decision evaluation for labelled business or AI decisions.</p>
<label>EVALUATION PROFILE</label>
<select id="profile">
<option value="smoke">Smoke: 4 API baseline cases</option>
<option value="release">Release: 12 API baseline cases</option>
<option value="red_team">Adversarial: 12 authorized boundary cases</option>
<option value="custom">Custom: one editable starter case</option>
</select>
</div>

<div id="groundedness_panel" class="note">
<label class="check"><input id="include_groundedness" type="checkbox" onchange="groundednessChanged()"> INCLUDE GROUNDEDNESS IN THIS PLAN</label>
<p class="small">Use this only for a local API or decision endpoint that can return both the generated response text and the exact retrieved source chunks used for that response. PRE-D then performs claim extraction, evidence comparison, and local groundedness scoring with an independent judge.</p>
<div id="groundedness_fields" class="hidden">
<div class="grid">
<div><label>LOCAL GROUNDING JUDGE MODEL</label><input id="grounding_judge_model" value="llama3.1:8b-instruct"></div>
</div>
<p class="small" id="groundedness_mapping_note">Test the local endpoint to choose the response text and retrieved source chunk fields.</p>
</div>
<input id="response_text_path" type="hidden">
<input id="response_grounding_evidence_path" type="hidden">
</div>

<div id="mapping_fields">
<button class="secondary" type="button" onclick="testConnection()">TEST LOCAL CONNECTION</button>
<div id="connection_probe_result">Test the local endpoint before creating this plan. PRE-D retains only field names and types during the connection check.</div>
<input id="label_path" type="hidden" value="label">
<input id="confidence_path" type="hidden" value="confidence">
<input id="evidence_ids_path" type="hidden">
<input id="abstained_path" type="hidden">
</div>
</section>

<section class="step">
<h2>3. Create the local plan</h2>
<p>The plan records only the approved scope, labelled cases, and response mappings required for this local run. Existing non-empty folders are never overwritten.</p>
<label>NEW EMPTY FOLDER FOR THIS PLAN</label>
<input id="directory" value="__DIRECTORY__">
<label class="check"><input id="confirm_plan" type="checkbox"> I reviewed the local test scope and understand that a missing metric means missing evidence, not a pass or failure.</label>
<button type="button" onclick="createPlan()">CREATE LOCAL PLAN</button>
<pre id="result">First choose an evaluation method and test the local endpoint when using decision or API mode.</pre>
</section>

<section class="step">
<h2>4. Run locally</h2>
<pre>cd &lt;your-plan-folder&gt;
esx-eval evidence-check --config ./esx-eval.json
esx-eval run --config ./esx-eval.json --out ./out/evaluation.json
esx-eval view --report ./out/evaluation.local-report.html</pre>
<details>
<summary>When do I need telemetry?</summary>
<p>Classification, F1, and confidence come from labelled local decision cases plus endpoint results. Groundedness comes from the generated response text, the exact retrieved source chunks, and a local judge configured in the plan. Telemetry is still for separate layers such as RAG traces, tool use, trajectory, security behavior, cost, and latency.</p>
</details>
</section>
</main>
<script>
const token=__TOKEN__;
let latestDiscovery=null;
let latestProbe=null;
const byId=id=>document.getElementById(id);

async function post(path,data){
  const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-ESX-Setup-Token':token},body:JSON.stringify(data)});
  const payload=await response.json();
  if(!response.ok) throw Error(payload.error||'Request failed');
  return payload;
}

function groundednessAllowed(){
  return byId('connection_type').value!=='browser';
}

function renderMapping(target,title,field,candidates,optional,emptyText){
  const label=document.createElement('label');
  const select=document.createElement('select');
  label.textContent=title;
  target.append(label);
  if(optional){
    const blank=document.createElement('option');
    blank.value='';
    blank.textContent='Do not map this field';
    select.append(blank);
  }
  for(const candidate of candidates||[]){
    const option=document.createElement('option');
    option.value=candidate.path;
    option.textContent=candidate.path+' ('+candidate.type+')';
    select.append(option);
  }
  const current=byId(field).value;
  if(current && [...select.options].some(option=>option.value===current)) select.value=current;
  byId(field).value=select.value;
  select.addEventListener('change',()=>byId(field).value=select.value);
  target.append(select);
  if(!(candidates||[]).length){
    const note=document.createElement('p');
    note.className='small';
    note.textContent=emptyText;
    target.append(note);
  }
}

function renderProbe(){
  const mode=byId('connection_type').value;
  const target=byId('connection_probe_result');
  if(mode==='browser'){
    target.textContent='Browser mode has no endpoint connection probe on this page.';
    return;
  }
  if(!latestProbe){
    target.textContent='Test this local endpoint before creating this plan. PRE-D retains only field names and types during the connection check.';
    return;
  }
  target.replaceChildren();
  const success=document.createElement('strong');
  success.textContent='Connection confirmed. Select response mappings.';
  target.append(success);
  renderMapping(target,'DECISION LABEL','label_path',latestProbe.label_candidates,false,'No compatible label field was found.');
  renderMapping(target,'DECISION CONFIDENCE','confidence_path',latestProbe.confidence_candidates,false,'No numeric 0-to-1 confidence field was found.');
  if(mode==='decision'){
    renderMapping(target,'EVIDENCE IDS (OPTIONAL)','evidence_ids_path',latestProbe.evidence_id_candidates,true,'Evidence IDs are optional for this plan.');
    renderMapping(target,'ABSTAINED FLAG (OPTIONAL)','abstained_path',latestProbe.abstained_candidates,true,'An abstained flag is optional for this plan.');
  } else {
    byId('evidence_ids_path').value='';
    byId('abstained_path').value='';
  }
  if(byId('include_groundedness').checked && groundednessAllowed()){
    const groundednessNote=document.createElement('p');
    groundednessNote.className='small';
    groundednessNote.textContent='Groundedness needs the generated response text and the exact retrieved source chunks from this same response.';
    target.append(groundednessNote);
    renderMapping(target,'RESPONSE TEXT FIELD','response_text_path',latestProbe.response_text_candidates,false,'No likely response text field was found.');
    renderMapping(target,'RETRIEVED SOURCE CHUNKS FIELD','response_grounding_evidence_path',latestProbe.grounding_evidence_candidates,false,'No likely retrieved source chunk array was found.');
  } else {
    byId('response_text_path').value='';
    byId('response_grounding_evidence_path').value='';
  }
  const shape=document.createElement('pre');
  shape.textContent='Value-redacted response structure: '+JSON.stringify(latestProbe.response_shape,null,2);
  target.append(shape);
}

function selectMode(mode){
  byId('connection_type').value=mode;
  for(const item of ['decision','browser','http']) byId('mode_'+item).classList.toggle('active',item===mode);
  byId('decision_fields').classList.toggle('hidden',mode!=='decision');
  byId('browser_fields').classList.toggle('hidden',mode!=='browser');
  byId('api_fields').classList.toggle('hidden',mode!=='http');
  byId('mapping_fields').classList.toggle('hidden',mode==='browser');
  byId('groundedness_panel').classList.toggle('hidden',mode==='browser');
  byId('url_label').textContent=mode==='browser'?'LOCAL WEB APP URL':mode==='decision'?'LOCAL DECISION API URL':'LOCAL API URL';
  byId('method_note').innerHTML=
    mode==='decision'
      ? '<strong>Decision evaluation is selected.</strong> PRE-D sends labelled cases to a local endpoint and calculates accuracy, precision, recall, F1, and confidence locally.'
      : mode==='browser'
        ? '<strong>Browser workflow is selected.</strong> PRE-D checks the visible journey you define. Decision metrics are intentionally not produced by this mode.'
        : '<strong>Generic JSON API is selected.</strong> PRE-D runs the selected local API profile. Use Decision evaluation for labelled business or AI decisions.';
  if(mode==='browser'){
    byId('include_groundedness').checked=false;
  }
  groundednessChanged();
  renderProbe();
}

function groundednessChanged(){
  const enabled=byId('include_groundedness').checked && groundednessAllowed();
  byId('groundedness_fields').classList.toggle('hidden',!enabled);
  if(!enabled){
    byId('response_text_path').value='';
    byId('response_grounding_evidence_path').value='';
  }
  renderProbe();
}

function showScope(data){
  const holder=byId('scope');
  holder.replaceChildren();
  const components=data.components||[];
  if(!components.length){
    holder.textContent='No implemented integration hints found. The plan will contain one customer-declared entry point.';
    return;
  }
  const heading=document.createElement('strong');
  heading.textContent='Approve only components safe to evaluate:';
  holder.append(heading);
  components.forEach((item,index)=>{
    const label=document.createElement('label');
    const box=document.createElement('input');
    box.type='checkbox';
    box.checked=index===0;
    box.dataset.component=item.id;
    label.append(box,document.createTextNode(' '+item.name+' ('+item.kind+'; '+(item.verification_status||'customer declared')+')'));
    holder.append(label);
  });
}

async function discover(){
  const holder=byId('scope');
  holder.textContent='Discovering locally...';
  try{
    latestDiscovery=await post('/api/discover',{repository:byId('repository').value});
    showScope(latestDiscovery);
  }catch(error){
    latestDiscovery=null;
    holder.textContent='Could not scan: '+error.message;
  }
}

async function testConnection(){
  const mode=byId('connection_type').value;
  if(mode==='browser') return;
  const target=byId('connection_probe_result');
  target.textContent='Testing the local endpoint with one harmless fixed request...';
  try{
    latestProbe=await post('/api/test-connection',{url:byId('url').value,request_mode:mode==='decision'?'decision':'message'});
    renderProbe();
  }catch(error){
    latestProbe=null;
    target.textContent='Could not confirm connection: '+error.message;
  }
}

function selectedComponents(){
  return [...document.querySelectorAll('[data-component]:checked')].map(item=>item.dataset.component);
}

byId('decision_file').addEventListener('change',event=>{
  const file=event.target.files[0];
  if(!file) return;
  const reader=new FileReader();
  reader.onload=()=>{
    try{
      const value=JSON.parse(String(reader.result));
      if(!Array.isArray(value)) throw Error('Expected a JSON array');
      byId('decision_cases').value=JSON.stringify(value,null,2);
    }catch(error){
      byId('result').textContent='Could not import labelled cases: '+error.message;
    }
  };
  reader.readAsText(file);
});

async function createPlan(){
  const out=byId('result');
  const mode=byId('connection_type').value;
  out.className='';
  out.textContent='Creating the local plan...';
  try{
    let decisionCases=[];
    if(mode==='decision'){
      decisionCases=JSON.parse(byId('decision_cases').value);
      if(!Array.isArray(decisionCases)) throw Error('Labelled cases must be a JSON array');
    }
    const payload={
      directory:byId('directory').value,
      agent_id:byId('agent_id').value,
      subject_version:byId('subject_version').value,
      project_key:byId('project_key').value,
      url:byId('url').value,
      connection_type:mode,
      profile:byId('profile').value,
      decision_task:byId('decision_task').value,
      decision_cases:decisionCases,
      confirm_plan:byId('confirm_plan').checked,
      include_groundedness:byId('include_groundedness').checked && groundednessAllowed(),
      grounding_judge_model:byId('grounding_judge_model').value,
      response_label_path:byId('label_path').value,
      response_confidence_path:byId('confidence_path').value,
      response_evidence_ids_path:byId('evidence_ids_path').value,
      response_abstained_path:byId('abstained_path').value,
      response_text_path:byId('response_text_path').value,
      response_grounding_evidence_path:byId('response_grounding_evidence_path').value,
      browser_path:byId('browser_path').value,
      browser_expected_text:byId('browser_expected_text').value
    };
    if(latestDiscovery){
      payload.discovery=latestDiscovery;
      payload.selected_component_ids=selectedComponents();
    }
    const created=await post('/api/create-plan',payload);
    out.className='success';
    out.textContent='Created '+created.connection_type+' plan with '+created.cases+' case(s). Open README.md in the plan folder, run evidence-check, then run the local evaluation command in step 4.';
  }catch(error){
    out.textContent='Could not create plan: '+error.message;
  }
}
</script>
</body>
</html>"""
    redirect = "<script>document.getElementById('mode_browser').addEventListener('click',()=>{window.location.href='/browser'});</script>"
    return page.replace("__TOKEN__", json.dumps(token)).replace("__DIRECTORY__", json.dumps(default_directory or str(Path.cwd() / "pred-local-evaluation"))).replace("</body>", redirect + "</body>")


def _legacy_guided_setup_html(token: str, default_directory: str | None) -> str:
    """Render one local workflow without asking customers to write an adapter."""
    return """<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ESX Local Evaluation Setup</title><style>*{box-sizing:border-box}body{margin:0;background:#e9ece2;color:#182726;font:16px Georgia,serif}main{max-width:960px;margin:28px auto;padding:30px;background:#fffdf7;border:1px solid #19312e;box-shadow:7px 7px #19312e}h1{margin:0;font-size:40px}.lead{font-size:18px;color:#536a63}.step{border-top:1px solid #b8c7bf;padding:21px 0}h2{margin:0 0 8px}label{display:block;margin:13px 0 5px;font:13px ui-monospace,monospace}input,select,textarea{width:100%;padding:10px;border:1px solid #526963;background:#fffdf7;font:14px ui-monospace,monospace}textarea{min-height:95px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.scope{background:#f0f5ed;padding:12px;max-height:250px;overflow:auto}.scope label,.check{font:14px Georgia,serif}.scope input,.check input{width:auto;margin-right:8px}.note,.success{padding:12px;background:#f0f5ed;border-left:4px solid #507765}.success{background:#e6f3e7;border-color:#145c38}.hidden{display:none}button{margin-top:15px;background:#ef633d;color:white;border:2px solid #182726;padding:11px 16px;font-weight:bold;box-shadow:3px 3px #182726;cursor:pointer}button.secondary{background:#dfe9e2;color:#182726}pre{white-space:pre-wrap;word-break:break-word;background:#182726;color:#e7f1eb;padding:14px}@media(max-width:650px){main{margin:0;padding:20px;box-shadow:none;border:0}.grid{grid-template-columns:1fr}h1{font-size:32px}}</style></head><body><main><p style=\"font-family:monospace;color:#507765\">LOCAL-ONLY | NO ACCOUNT | NO UPLOAD</p><h1>Set up a real application evaluation</h1><p class=\"lead\">Choose one customer-facing workflow. You do not need to find or call every internal agent, and the runner never silently executes discovered code.</p><section class=\"step\"><h2>1. Discover and approve scope</h2><p>Optional: scan a local repository for routes, agents, RAG, tools, and observability. Source text stays on this computer.</p><label>APPLICATION REPOSITORY</label><input id=\"repository\" placeholder=\"C:\\\\work\\\\my-ai-app\"><button class=\"secondary\" onclick=\"discover()\">SCAN LOCALLY</button><div id=\"scope\" class=\"scope\">No repository scanned. The plan will contain one customer-declared workflow.</div></section><section class=\"step\"><h2>2. Connect the approved workflow</h2><p class=\"note\">Use an existing local JSON API whenever possible. Use a browser journey only for a local UI without an API. An adapter is not required for either path.</p><label>CONNECTION METHOD</label><select id=\"connection_type\" onchange=\"connectionChanged()\"><option value=\"http\">Existing local JSON API</option><option value=\"browser\">Local browser journey</option></select><div class=\"grid\"><div><label id=\"url_label\">LOCAL API URL</label><input id=\"url\" value=\"http://127.0.0.1:8000/evaluate\"></div><div><label>APPLICATION ID</label><input id=\"agent_id\" value=\"my-ai-application\"></div><div><label>VERSION UNDER TEST</label><input id=\"subject_version\" value=\"0.1.0\"></div><div><label>PROJECT KEY</label><input id=\"project_key\" value=\"default\"></div></div><div id=\"http_fields\" class=\"grid\"><div><label>LABEL RESPONSE PATH</label><input id=\"label_path\" value=\"decision.label\"></div><div><label>CONFIDENCE RESPONSE PATH</label><input id=\"confidence_path\" value=\"decision.confidence\"></div></div><div id=\"browser_fields\" class=\"grid hidden\"><div><label>START PATH</label><input id=\"browser_path\" value=\"/\"></div><div><label>EXPECTED VISIBLE TEXT</label><input id=\"browser_expected_text\" placeholder=\"For example: Welcome\"></div></div><label id=\"remote_check\" class=\"check\"><input id=\"allow_remote\" type=\"checkbox\"> This is an approved staging API with mTLS and signed test-tenant attestation</label></section><section class=\"step\"><h2>3. Choose coverage and create the plan</h2><p>Profiles add safe baseline cases. Add product-specific cases if needed; all cases remain editable in the generated configuration.</p><label>EVALUATION PROFILE</label><select id=\"profile\"><option value=\"smoke\">Smoke check: 4 connection and boundary cases</option><option value=\"release\">Release readiness: 12 broader baseline cases</option><option value=\"red_team\">Adversarial safety review: 12 authorized boundary cases</option><option value=\"custom\">Custom: one editable starter case</option></select><label>OPTIONAL EXTRA CASES (JSON ARRAY, HTTP ONLY)</label><textarea id=\"custom_cases\" placeholder='[{\"case_id\":\"billing-001\",\"input\":{\"message\":\"Where is my invoice?\"},\"expected_label\":\"safe\"}]'></textarea><label>NEW EMPTY FOLDER FOR THIS PLAN</label><input id=\"directory\" value=\"__DIRECTORY__\"><label class=\"check\"><input id=\"confirm_plan\" type=\"checkbox\"> I reviewed the selected scope and understand missing evidence is reported as NOT MEASURABLE.</label><button onclick=\"createPlan()\">CREATE LOCAL EVALUATION</button><pre id=\"result\">This generates esx-eval.json, discovery.json, assurance-scope.json, risk-plan.json, and README.md.</pre></section><section class=\"step\"><h2>4. Run and inspect results</h2><pre>cd &lt;your-plan-folder&gt;\nesx-eval run --config .\\esx-eval.json --out .\\out\\evaluation.json\nesx-eval view --report .\\out\\evaluation.local-report.html</pre><p>One command includes the generated scope and risk plan in the Assurance Graph. Prompts, outputs, source code, and results remain local.</p></section></main><script>const token=__TOKEN__;let latestDiscovery=null;const byId=id=>document.getElementById(id);async function post(path,data){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-ESX-Setup-Token':token},body:JSON.stringify(data)});const p=await r.json();if(!r.ok)throw Error(p.error||'Request failed');return p}function showScope(data){const holder=byId('scope');holder.replaceChildren();const components=data.components||[];if(!components.length){holder.textContent='No integration hints found. The plan will contain one customer-declared workflow.';return}const heading=document.createElement('strong');heading.textContent='Confirm only the components safe to test:';holder.append(heading);components.forEach((item,index)=>{const label=document.createElement('label'),box=document.createElement('input');box.type='checkbox';box.checked=index===0;box.dataset.component=item.id;label.append(box,document.createTextNode(' '+item.name+' ('+item.kind+')'));holder.append(label)})}async function discover(){const holder=byId('scope');holder.textContent='Scanning locally...';try{latestDiscovery=await post('/api/discover',{repository:byId('repository').value});showScope(latestDiscovery)}catch(error){latestDiscovery=null;holder.textContent='Could not scan: '+error.message}}function connectionChanged(){const browser=byId('connection_type').value==='browser';byId('http_fields').classList.toggle('hidden',browser);byId('browser_fields').classList.toggle('hidden',!browser);byId('remote_check').classList.toggle('hidden',browser);byId('url_label').textContent=browser?'LOCAL WEB APP URL':'LOCAL API URL'}function selectedComponents(){return [...document.querySelectorAll('[data-component]:checked')].map(item=>item.dataset.component)}async function createPlan(){const out=byId('result');out.className='';out.textContent='Creating the reviewed local evaluation...';try{let extra=[];if(byId('custom_cases').value.trim()){extra=JSON.parse(byId('custom_cases').value);if(!Array.isArray(extra))throw Error('Extra cases must be a JSON array')}const payload={directory:byId('directory').value,agent_id:byId('agent_id').value,subject_version:byId('subject_version').value,project_key:byId('project_key').value,url:byId('url').value,connection_type:byId('connection_type').value,profile:byId('profile').value,custom_cases:extra,confirm_plan:byId('confirm_plan').checked,allow_remote:byId('allow_remote').checked,response_label_path:byId('label_path').value,response_confidence_path:byId('confidence_path').value,browser_path:byId('browser_path').value,browser_expected_text:byId('browser_expected_text').value};if(latestDiscovery){payload.discovery=latestDiscovery;payload.selected_component_ids=selectedComponents()}const created=await post('/api/create-plan',payload);out.className='success';out.textContent='Created '+created.config+'\\n\\nFiles: '+created.files.join(', ')+'\\nPlanned coverage: '+created.planned_dimensions.join(', ')+'\\n\\nNext: read README.md, review esx-eval.json, then run step 4.'}catch(error){out.textContent='Could not create plan: '+error.message}}</script></body></html>""".replace("__TOKEN__", json.dumps(token)).replace("__DIRECTORY__", json.dumps(default_directory or str(Path.cwd() / "esx-evaluation")))


def _legacy_browser_guided_setup_html(token: str, default_directory: str | None) -> str:
    """Previous setup markup retained temporarily for backward-compatible source history."""
    return """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ESX Local Evaluation Setup</title><style>*{box-sizing:border-box}body{margin:0;background:#e9ece2;color:#182726;font:16px Georgia,serif}main{max-width:980px;margin:28px auto;padding:32px;background:#fffdf7;border:1px solid #19312e;box-shadow:7px 7px #19312e}h1{margin:0;font-size:40px}.lead{font-size:18px;color:#536a63}.step{border-top:1px solid #b8c7bf;padding:22px 0}h2{margin:0 0 8px}label{display:block;margin:13px 0 5px;font:13px ui-monospace,monospace}input,select,textarea{width:100%;padding:10px;border:1px solid #526963;background:#fffdf7;font:14px ui-monospace,monospace}textarea{min-height:95px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.scope{background:#f0f5ed;padding:12px;max-height:250px;overflow:auto}.scope label,.check{font:14px Georgia,serif}.scope input,.check input{width:auto;margin-right:8px}.note,.success,.warning{padding:12px;background:#f0f5ed;border-left:4px solid #507765}.success{background:#e6f3e7;border-color:#145c38}.warning{background:#fff1df;border-color:#bd7219}.hidden{display:none}button{margin-top:15px;background:#ef633d;color:white;border:2px solid #182726;padding:11px 16px;font-weight:bold;box-shadow:3px 3px #182726;cursor:pointer}button.secondary{background:#dfe9e2;color:#182726}pre{white-space:pre-wrap;word-break:break-word;background:#182726;color:#e7f1eb;padding:14px}.small{font-size:14px;color:#536a63}@media(max-width:650px){main{margin:0;padding:20px;box-shadow:none;border:0}.grid{grid-template-columns:1fr}h1{font-size:32px}}</style></head><body><main><p style="font-family:monospace;color:#507765">LOCAL-ONLY | NO ACCOUNT | NO UPLOAD</p><h1>Set up an application evaluation</h1><p class="lead">Connect a user-facing workflow, not every internal agent. Discovery suggests candidates; you approve exactly what the runner may test.</p><section class="step"><h2>1. Discover and approve scope</h2><p>Optional: inspect a local repository for implemented routes, frameworks, retrieval stores, and observability. Source text never leaves this computer.</p><label>APPLICATION REPOSITORY</label><input id="repository" placeholder="C:\\work\\my-ai-app"><button class="secondary" onclick="discover()">SCAN LOCALLY</button><div id="scope" class="scope">No repository scanned. The plan will contain one customer-declared workflow.</div></section><section class="step"><h2>2. Connect one approved workflow</h2><p class="note">Use a local JSON API if one exists. Choose browser workflow for a local web app with no usable API. Neither path requires you to edit the target application&apos;s production code.</p><label>CONNECTION METHOD</label><select id="connection_type" onchange="connectionChanged()"><option value="http">Existing local JSON API</option><option value="browser">Local browser workflow</option></select><div class="grid"><div><label id="url_label">LOCAL API URL</label><input id="url" value="http://127.0.0.1:8000/evaluate"></div><div><label>APPLICATION ID</label><input id="agent_id" value="my-ai-application"></div><div><label>VERSION UNDER TEST</label><input id="subject_version" value="0.1.0"></div><div><label>PROJECT KEY</label><input id="project_key" value="default"></div></div><div id="http_fields" class="grid"><div><label>LABEL RESPONSE PATH</label><input id="label_path" value="decision.label"></div><div><label>CONFIDENCE RESPONSE PATH</label><input id="confidence_path" value="decision.confidence"></div></div><div id="browser_fields" class="hidden"><p class="warning">Browser mode creates one explicit pre-auth starter case. Selecting Smoke, Release, or Adversarial does not secretly create 4 or 12 browser cases. Add a reviewed case for each workflow you need to cover.</p><div class="grid"><div><label>START PATH</label><input id="browser_path" value="/"></div><div><label>EXPECTED VISIBLE TEXT</label><input id="browser_expected_text" placeholder="For example: Sign in"></div></div><label class="check"><input id="browser_auth_enabled" type="checkbox" onchange="authChanged()"> APPROVED LOGIN: add one authenticated post-login workflow</label><div id="browser_auth_fields" class="hidden"><p class="note">Use a dedicated test account. Enter environment-variable names only. Credentials, cookies, and saved sessions remain local and are never written to the plan or report.</p><div class="grid"><div><label>LOGIN PATH</label><input id="browser_login_path" value="/login"></div><div><label>POST-LOGIN PATH</label><input id="browser_post_login_path" placeholder="For example: /dashboard"></div><div><label>USERNAME ENVIRONMENT VARIABLE</label><input id="browser_username_env" value="ESX_TEST_USERNAME"></div><div><label>PASSWORD ENVIRONMENT VARIABLE</label><input id="browser_password_env" value="ESX_TEST_PASSWORD"></div><div><label>USERNAME SELECTOR</label><input id="browser_username_selector" placeholder="For example: input[name='email']"></div><div><label>PASSWORD SELECTOR</label><input id="browser_password_selector" placeholder="For example: input[name='password']"></div><div><label>SUBMIT SELECTOR</label><input id="browser_submit_selector" value="button[type='submit']"></div><div><label>POST-LOGIN EXPECTED TEXT</label><input id="browser_post_login_expected_text" placeholder="For example: Dashboard"></div></div><label class="check"><input id="browser_capture_failure_screenshots" type="checkbox"> SAVE FAILURE SCREENSHOTS LOCALLY</label></div></div><label id="remote_check" class="check"><input id="allow_remote" type="checkbox"> This is an approved staging API with mTLS and a signed test-tenant attestation</label></section><section class="step"><h2>3. Create a truthful, editable plan</h2><p>Profiles generate HTTP API test cases only. Browser mode reports precisely which starter journeys it created; it never treats discovered routes as executed coverage.</p><label>EVALUATION PROFILE</label><select id="profile"><option value="smoke">Smoke API profile: 4 connection and boundary cases</option><option value="release">Release API profile: 12 broader baseline cases</option><option value="red_team">Adversarial API profile: 12 authorized boundary cases</option><option value="custom">Custom API profile: one editable starter case</option></select><label id="extra_cases_label">OPTIONAL EXTRA CASES (JSON ARRAY, API ONLY)</label><textarea id="custom_cases" placeholder='[{"case_id":"billing-001","input":{"message":"Where is my invoice?"},"expected_label":"safe"}]'></textarea><label>NEW EMPTY FOLDER FOR THIS PLAN</label><input id="directory" value="__DIRECTORY__"><label class="check"><input id="confirm_plan" type="checkbox"> I reviewed the selected scope and understand missing evidence is reported as NOT MEASURABLE.</label><button onclick="createPlan()">CREATE LOCAL EVALUATION</button><pre id="result">This creates esx-eval.json, discovery.json, assurance-scope.json, risk-plan.json, and README.md.</pre></section><section class="step"><h2>4. Run and inspect results</h2><pre>cd &lt;your-plan-folder&gt;\\nesx-eval run --config .\\esx-eval.json --out .\\out\\evaluation.json\\nesx-eval view --report .\\out\\evaluation.local-report.html</pre><p class="small">The report separates discovered components, approved scope, executed workflows, and measured dimensions. Browser failures name the failed step and category; screenshots are optional local evidence.</p></section></main><script>const token=__TOKEN__;let latestDiscovery=null;const byId=id=>document.getElementById(id);async function post(path,data){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-ESX-Setup-Token':token},body:JSON.stringify(data)});const p=await r.json();if(!r.ok)throw Error(p.error||'Request failed');return p}function showScope(data){const holder=byId('scope');holder.replaceChildren();const components=data.components||[];if(!components.length){holder.textContent='No implemented integration hints found. The plan will contain one customer-declared workflow.';return}const heading=document.createElement('strong');heading.textContent='Approve only the components safe to evaluate:';holder.append(heading);components.forEach((item,index)=>{const label=document.createElement('label'),box=document.createElement('input');box.type='checkbox';box.checked=index===0;box.dataset.component=item.id;label.append(box,document.createTextNode(' '+item.name+' ('+item.kind+'; '+(item.verification_status||'customer declared')+')'));holder.append(label)});if((data.workflow_suggestions||[]).length){const hint=document.createElement('p');hint.className='small';hint.textContent='Suggested workflows require review; a discovered route is not a browser journey or executed coverage.';holder.append(hint)}}async function discover(){const holder=byId('scope');holder.textContent='Scanning locally...';try{latestDiscovery=await post('/api/discover',{repository:byId('repository').value});showScope(latestDiscovery)}catch(error){latestDiscovery=null;holder.textContent='Could not scan: '+error.message}}function connectionChanged(){const browser=byId('connection_type').value==='browser';byId('http_fields').classList.toggle('hidden',browser);byId('browser_fields').classList.toggle('hidden',!browser);byId('remote_check').classList.toggle('hidden',browser);byId('extra_cases_label').classList.toggle('hidden',browser);byId('custom_cases').classList.toggle('hidden',browser);byId('url_label').textContent=browser?'LOCAL WEB APP URL':'LOCAL API URL'}function authChanged(){byId('browser_auth_fields').classList.toggle('hidden',!byId('browser_auth_enabled').checked)}function selectedComponents(){return [...document.querySelectorAll('[data-component]:checked')].map(item=>item.dataset.component)}async function createPlan(){const out=byId('result');out.className='';out.textContent='Creating the reviewed local evaluation...';try{let extra=[];if(byId('connection_type').value==='http'&&byId('custom_cases').value.trim()){extra=JSON.parse(byId('custom_cases').value);if(!Array.isArray(extra))throw Error('Extra cases must be a JSON array')}const payload={directory:byId('directory').value,agent_id:byId('agent_id').value,subject_version:byId('subject_version').value,project_key:byId('project_key').value,url:byId('url').value,connection_type:byId('connection_type').value,profile:byId('profile').value,custom_cases:extra,confirm_plan:byId('confirm_plan').checked,allow_remote:byId('allow_remote').checked,response_label_path:byId('label_path').value,response_confidence_path:byId('confidence_path').value,browser_path:byId('browser_path').value,browser_expected_text:byId('browser_expected_text').value,browser_auth_enabled:byId('browser_auth_enabled').checked,browser_login_path:byId('browser_login_path').value,browser_post_login_path:byId('browser_post_login_path').value,browser_username_env:byId('browser_username_env').value,browser_password_env:byId('browser_password_env').value,browser_username_selector:byId('browser_username_selector').value,browser_password_selector:byId('browser_password_selector').value,browser_submit_selector:byId('browser_submit_selector').value,browser_post_login_expected_text:byId('browser_post_login_expected_text').value,browser_capture_failure_screenshots:byId('browser_capture_failure_screenshots').checked};if(latestDiscovery){payload.discovery=latestDiscovery;payload.selected_component_ids=selectedComponents()}const created=await post('/api/create-plan',payload);out.className='success';out.textContent='Created '+created.config+'\\n\\nGenerated cases: '+created.cases+'\\nFiles: '+created.files.join(', ')+'\\nPlanned dimensions: '+created.planned_dimensions.join(', ')+'\\n\\nNext: read README.md, review esx-eval.json, then run the command in step 4.'}catch(error){out.textContent='Could not create plan: '+error.message}}</script></body></html>""".replace("__TOKEN__", json.dumps(token)).replace("__DIRECTORY__", json.dumps(default_directory or str(Path.cwd() / "esx-evaluation")))


def _guided_setup_html_with_evidence(token: str, default_directory: str | None) -> str:
    """Label discovery evidence and explain each setup field in context."""
    page = _guided_setup_html(token, default_directory)
    host_label = {"windows": "WINDOWS", "macos": "MACOS", "linux": "LINUX"}[_host_os()]
    tooltip_style = """<style>.esx-help{display:inline-grid;place-items:center;width:16px;height:16px;margin-left:5px;border:1px solid #507765;border-radius:50%;background:#f0f5ed;color:#19312e;font:700 11px/1 ui-monospace,monospace;cursor:help;position:relative;vertical-align:middle}.esx-help:hover::after,.esx-help:focus::after{content:attr(data-tooltip);display:block;position:absolute;z-index:10;left:0;top:22px;width:300px;padding:10px;border:1px solid #19312e;background:#fffdf7;color:#182726;font:13px/1.35 Georgia,serif;box-shadow:3px 3px #19312e;text-transform:none}.esx-help:focus{outline:2px solid #ef633d;outline-offset:2px}.zero-adapter{margin:14px 0}.zero-adapter h3{margin:0 0 6px;font-size:16px}.zero-adapter select{margin:4px 0 12px}.zero-adapter pre{margin:12px 0;background:#f7faf5;color:#182726;border:1px solid #b8c7bf}.zero-status{font:14px/1.4 Georgia,serif}</style>"""
    tooltip_script = f"""<script>(() => {{
const help={json.dumps(_SETUP_FIELD_HELP)};
for(const label of document.querySelectorAll('label')){{const original=label.textContent.trim();const key=Object.keys(help).find(candidate=>original.startsWith(candidate));if(!key)continue;label.title=help[key];const badge=document.createElement('span');badge.className='esx-help';badge.tabIndex=0;badge.textContent='?';badge.dataset.tooltip=help[key];badge.setAttribute('aria-label',help[key]);label.append(' ',badge);}}
const httpFields=document.getElementById('http_fields'), remoteCheck=document.getElementById('remote_check'), urlInput=document.getElementById('url');
const mapping=document.createElement('div');mapping.className='note zero-adapter';mapping.id='zero_adapter_mapping';
const heading=document.createElement('h3');heading.textContent='Test your connection - no adapter required';
const copy=document.createElement('p');copy.textContent='Enter a loopback API URL, then test it. We send one fixed harmless request, keep no response content, and show only the response structure so you can confirm the suggested fields.';
const testButton=document.createElement('button');testButton.type='button';testButton.className='secondary';testButton.textContent='TEST LOCAL CONNECTION';
const status=document.createElement('div');status.className='zero-status';status.id='connection_probe_result';status.textContent='Test the local API before creating a plan.';
mapping.append(heading,copy,testButton,status);httpFields.before(mapping);httpFields.classList.add('hidden');remoteCheck.classList.add('hidden');remoteCheck.querySelector('input').checked=false;
function renderChoice(title,inputId,candidates,emptyText){{const input=document.getElementById(inputId);const label=document.createElement('label');label.textContent=title;status.append(label);if(!candidates.length){{input.value='';const note=document.createElement('p');note.textContent=emptyText;status.append(note);return;}}const select=document.createElement('select');for(const candidate of candidates){{const option=document.createElement('option');option.value=candidate.path;option.textContent=candidate.path+' ('+candidate.type+')';select.append(option);}}input.value=select.value;select.addEventListener('change',()=>input.value=select.value);status.append(select);}}
async function testConnection(){{status.textContent='Testing the local API with one fixed request...';try{{const probe=await post('/api/test-connection',{{url:urlInput.value}});status.replaceChildren();const success=document.createElement('strong');success.textContent='Connection confirmed. Choose the suggested fields below.';status.append(success);renderChoice('OUTCOME FIELD', 'label_path', probe.label_candidates, 'No likely text outcome field was found. This endpoint needs a response that includes a label such as safe, unsafe, allow, block, pass, or fail.');renderChoice('CONFIDENCE FIELD', 'confidence_path', probe.confidence_candidates, 'No numeric 0-1 confidence field was found. This endpoint needs one for the current confidence metrics.');const shapeLabel=document.createElement('p');shapeLabel.textContent='Value-redacted response structure:';const shape=document.createElement('pre');shape.textContent=JSON.stringify(probe.response_shape,null,2);status.append(shapeLabel,shape);}}catch(error){{status.textContent='Could not confirm connection: '+error.message;}}}}
testButton.addEventListener('click',testConnection);urlInput.addEventListener('input',()=>{{status.textContent='URL changed. Test this local API again before creating a plan.';}});
document.getElementById('connection_type').addEventListener('change',()=>{{const browser=document.getElementById('connection_type').value==='browser';mapping.classList.toggle('hidden',browser);if(!browser){{httpFields.classList.add('hidden');remoteCheck.classList.add('hidden');}}}});
}})();</script>"""
    return (
        page.replace("LOCAL-ONLY | NO ACCOUNT | NO UPLOAD", f"LOCAL-ONLY | HOST: {host_label} | NO ACCOUNT | NO UPLOAD")
        .replace("item.name+' ('+item.kind+')'", "item.name+' ('+item.kind+'; '+(item.verification_status||'customer declared')+')'")
        .replace("</head>", tooltip_style + "</head>")
        .replace("</body>", tooltip_script + "</body>")
    )


def _guided_setup_html(token: str, default_directory: str | None) -> str:
    """Render the current zero-adapter setup with form or interactive SSO login."""
    return """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ESX Local Evaluation Setup</title>
<style>*{box-sizing:border-box}body{margin:0;background:#e9ece2;color:#182726;font:16px Georgia,serif}main{max-width:980px;margin:28px auto;padding:32px;background:#fffdf7;border:1px solid #19312e;box-shadow:7px 7px #19312e}h1{margin:0;font-size:40px}.lead{font-size:18px;color:#536a63}.step{border-top:1px solid #b8c7bf;padding:22px 0}h2{margin:0 0 8px}label{display:block;margin:13px 0 5px;font:13px ui-monospace,monospace}input,select,textarea{width:100%;padding:10px;border:1px solid #526963;background:#fffdf7;font:14px ui-monospace,monospace}textarea{min-height:95px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.scope{background:#f0f5ed;padding:12px;max-height:250px;overflow:auto}.scope label,.check{font:14px Georgia,serif}.scope input,.check input{width:auto;margin-right:8px}.note,.success,.warning{padding:12px;background:#f0f5ed;border-left:4px solid #507765}.success{background:#e6f3e7;border-color:#145c38}.warning{background:#fff1df;border-color:#bd7219}.hidden{display:none}button{margin-top:15px;background:#ef633d;color:white;border:2px solid #182726;padding:11px 16px;font-weight:bold;box-shadow:3px 3px #182726;cursor:pointer}button.secondary{background:#dfe9e2;color:#182726}pre{white-space:pre-wrap;word-break:break-word;background:#182726;color:#e7f1eb;padding:14px}.small{font-size:14px;color:#536a63}@media(max-width:650px){main{margin:0;padding:20px;box-shadow:none;border:0}.grid{grid-template-columns:1fr}h1{font-size:32px}}</style></head>
<body><main><p style="font-family:monospace;color:#507765">LOCAL-ONLY | NO ACCOUNT | NO UPLOAD</p><h1>Set up an application evaluation</h1><p class="lead">Connect a user-facing workflow, not every internal agent. Discovery suggests candidates; you approve exactly what the runner may test.</p>
<section class="step"><h2>1. Discover and approve scope</h2><p>Optional: inspect a local repository for implemented routes, frameworks, retrieval stores, and observability. Source text never leaves this computer.</p><label>APPLICATION REPOSITORY</label><input id="repository" placeholder="C:\\work\\my-ai-app"><button class="secondary" onclick="discover()">SCAN LOCALLY</button><div id="scope" class="scope">No repository scanned. The plan will contain one customer-declared workflow.</div></section>
<section class="step"><h2>2. Connect one approved workflow</h2><p class="note">Use a local JSON API if one exists. Choose browser workflow for a local web app with no usable API. Neither path requires you to edit the target application&apos;s production code.</p><label>CONNECTION METHOD</label><select id="connection_type" onchange="connectionChanged()"><option value="http">Existing local JSON API</option><option value="browser">Local browser workflow</option></select><div class="grid"><div><label id="url_label">LOCAL API URL</label><input id="url" value="http://127.0.0.1:8000/evaluate"></div><div><label>APPLICATION ID</label><input id="agent_id" value="my-ai-application"></div><div><label>VERSION UNDER TEST</label><input id="subject_version" value="0.1.0"></div><div><label>PROJECT KEY</label><input id="project_key" value="default"></div></div><div id="http_fields" class="grid"><div><label>LABEL RESPONSE PATH</label><input id="label_path" value="decision.label"></div><div><label>CONFIDENCE RESPONSE PATH</label><input id="confidence_path" value="decision.confidence"></div></div>
<div id="browser_fields" class="hidden"><p class="warning">Browser mode creates one explicit pre-auth starter case. Selecting Smoke, Release, or Adversarial does not secretly create 4 or 12 browser cases. Add a reviewed case for each workflow you need to cover.</p><div class="grid"><div><label>START PATH</label><input id="browser_path" value="/"></div><div><label>EXPECTED VISIBLE TEXT</label><input id="browser_expected_text" placeholder="For example: Sign in"></div></div><label class="check"><input id="browser_auth_enabled" type="checkbox" onchange="authChanged()"> APPROVED LOGIN: add one authenticated post-login workflow</label><div id="browser_auth_fields" class="hidden"><p class="note">Use a dedicated test account. Credentials, cookies, and saved sessions stay local and are never written to the plan or report.</p><label>LOGIN METHOD</label><select id="browser_auth_mode" onchange="authMethodChanged()"><option value="password">Sign-in form using local environment variables</option><option value="interactive_sso">Interactive SSO or existing approved browser session</option></select><div class="grid"><div><label>LOGIN PATH</label><input id="browser_login_path" value="/login"></div><div><label>POST-LOGIN PATH</label><input id="browser_post_login_path" placeholder="For example: /dashboard"></div><div class="form-auth-only"><label>USERNAME ENVIRONMENT VARIABLE</label><input id="browser_username_env" value="ESX_TEST_USERNAME"></div><div class="form-auth-only"><label>PASSWORD ENVIRONMENT VARIABLE</label><input id="browser_password_env" value="ESX_TEST_PASSWORD"></div><div class="form-auth-only"><label>USERNAME SELECTOR</label><input id="browser_username_selector" placeholder="For example: input[name='email']"></div><div class="form-auth-only"><label>PASSWORD SELECTOR</label><input id="browser_password_selector" placeholder="For example: input[name='password']"></div><div class="form-auth-only"><label>SUBMIT SELECTOR</label><input id="browser_submit_selector" value="button[type='submit']"></div><div><label>POST-LOGIN EXPECTED TEXT</label><input id="browser_post_login_expected_text" placeholder="For example: Dashboard"></div></div><p id="interactive_sso_note" class="note hidden">After plan creation, run <code>esx-eval browser-auth --config ./esx-eval.json</code>. Complete approved SSO in its visible browser, return to this local app, then press Enter. Only local-app session state is kept.</p><label class="check"><input id="browser_capture_failure_screenshots" type="checkbox"> SAVE FAILURE SCREENSHOTS LOCALLY</label></div></div><label id="remote_check" class="check"><input id="allow_remote" type="checkbox"> This is an approved staging API with mTLS and a signed test-tenant attestation</label></section>
<section class="step"><h2>3. Create a truthful, editable plan</h2><p>Profiles generate HTTP API test cases only. Browser mode reports precisely which starter journeys it created; it never treats discovered routes as executed coverage.</p><label>EVALUATION PROFILE</label><select id="profile"><option value="smoke">Smoke API profile: 4 connection and boundary cases</option><option value="release">Release API profile: 12 broader baseline cases</option><option value="red_team">Adversarial API profile: 12 authorized boundary cases</option><option value="custom">Custom API profile: one editable starter case</option></select><label id="extra_cases_label">OPTIONAL EXTRA CASES (JSON ARRAY, API ONLY)</label><textarea id="custom_cases" placeholder='[{"case_id":"billing-001","input":{"message":"Where is my invoice?"},"expected_label":"safe"}]'></textarea><label>NEW EMPTY FOLDER FOR THIS PLAN</label><input id="directory" value="__DIRECTORY__"><label class="check"><input id="confirm_plan" type="checkbox"> I reviewed the selected scope and understand missing evidence is reported as NOT MEASURABLE.</label><button onclick="createPlan()">CREATE LOCAL EVALUATION</button><pre id="result">This creates esx-eval.json, discovery.json, assurance-scope.json, risk-plan.json, and README.md.</pre></section>
<section class="step"><h2>4. Run and inspect results</h2><pre>cd &lt;your-plan-folder&gt;<br>esx-eval run --config ./esx-eval.json --out ./out/evaluation.json<br>esx-eval view --report ./out/evaluation.local-report.html</pre><p class="small">The report separates discovered components, approved scope, executed workflows, and measured dimensions. Browser failures name the failed step and category; screenshots are optional local evidence.</p></section></main>
<script>const token=__TOKEN__;let latestDiscovery=null;const byId=id=>document.getElementById(id);async function post(path,data){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-ESX-Setup-Token':token},body:JSON.stringify(data)});const p=await r.json();if(!r.ok)throw Error(p.error||'Request failed');return p}function showScope(data){const holder=byId('scope');holder.replaceChildren();const components=data.components||[];if(!components.length){holder.textContent='No implemented integration hints found. The plan will contain one customer-declared workflow.';return}const heading=document.createElement('strong');heading.textContent='Approve only the components safe to evaluate:';holder.append(heading);components.forEach((item,index)=>{const label=document.createElement('label'),box=document.createElement('input');box.type='checkbox';box.checked=index===0;box.dataset.component=item.id;label.append(box,document.createTextNode(' '+item.name+' ('+item.kind+'; '+(item.verification_status||'customer declared')+')'));holder.append(label)});if((data.workflow_suggestions||[]).length){const hint=document.createElement('p');hint.className='small';hint.textContent='Suggested workflows require review; a discovered route is not a browser journey or executed coverage.';holder.append(hint)}}async function discover(){const holder=byId('scope');holder.textContent='Scanning locally...';try{latestDiscovery=await post('/api/discover',{repository:byId('repository').value});showScope(latestDiscovery)}catch(error){latestDiscovery=null;holder.textContent='Could not scan: '+error.message}}function connectionChanged(){const browser=byId('connection_type').value==='browser';byId('http_fields').classList.toggle('hidden',browser);byId('browser_fields').classList.toggle('hidden',!browser);byId('remote_check').classList.toggle('hidden',browser);byId('extra_cases_label').classList.toggle('hidden',browser);byId('custom_cases').classList.toggle('hidden',browser);byId('url_label').textContent=browser?'LOCAL WEB APP URL':'LOCAL API URL'}function authChanged(){byId('browser_auth_fields').classList.toggle('hidden',!byId('browser_auth_enabled').checked);authMethodChanged()}function authMethodChanged(){const manual=byId('browser_auth_mode').value==='interactive_sso';document.querySelectorAll('.form-auth-only').forEach(item=>item.classList.toggle('hidden',manual));byId('interactive_sso_note').classList.toggle('hidden',!manual)}function selectedComponents(){return [...document.querySelectorAll('[data-component]:checked')].map(item=>item.dataset.component)}async function createPlan(){const out=byId('result');out.className='';out.textContent='Creating the reviewed local evaluation...';try{let extra=[];if(byId('connection_type').value==='http'&&byId('custom_cases').value.trim()){extra=JSON.parse(byId('custom_cases').value);if(!Array.isArray(extra))throw Error('Extra cases must be a JSON array')}const payload={directory:byId('directory').value,agent_id:byId('agent_id').value,subject_version:byId('subject_version').value,project_key:byId('project_key').value,url:byId('url').value,connection_type:byId('connection_type').value,profile:byId('profile').value,custom_cases:extra,confirm_plan:byId('confirm_plan').checked,allow_remote:byId('allow_remote').checked,response_label_path:byId('label_path').value,response_confidence_path:byId('confidence_path').value,browser_path:byId('browser_path').value,browser_expected_text:byId('browser_expected_text').value,browser_auth_enabled:byId('browser_auth_enabled').checked,browser_auth_mode:byId('browser_auth_mode').value,browser_login_path:byId('browser_login_path').value,browser_post_login_path:byId('browser_post_login_path').value,browser_username_env:byId('browser_username_env').value,browser_password_env:byId('browser_password_env').value,browser_username_selector:byId('browser_username_selector').value,browser_password_selector:byId('browser_password_selector').value,browser_submit_selector:byId('browser_submit_selector').value,browser_post_login_expected_text:byId('browser_post_login_expected_text').value,browser_capture_failure_screenshots:byId('browser_capture_failure_screenshots').checked};if(latestDiscovery){payload.discovery=latestDiscovery;payload.selected_component_ids=selectedComponents()}const created=await post('/api/create-plan',payload);out.className='success';out.textContent='Created '+created.config+'\n\nGenerated cases: '+created.cases+'\nFiles: '+created.files.join(', ')+'\nPlanned dimensions: '+created.planned_dimensions.join(', ')+'\n\nNext: read README.md, review esx-eval.json, then run the command in step 4.'}catch(error){out.textContent='Could not create plan: '+error.message}}</script></body></html>""".replace("__TOKEN__", json.dumps(token)).replace("__DIRECTORY__", json.dumps(default_directory or str(Path.cwd() / "esx-evaluation")))


def _setup_html(token: str, default_directory: str | None) -> str:
    directory = json.dumps(default_directory or str(Path.cwd() / "esx-evaluation"))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ESX Local Evaluation Setup</title><style>*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(120deg,#e9ece2,#d4e6dc);color:#182726;font:16px Georgia,serif}}main{{max-width:1050px;margin:35px auto;padding:34px;background:#fffdf7;border:1px solid #19312e;box-shadow:8px 8px 0 #19312e}}h1{{font-size:42px;margin:0}}.lead{{color:#536a63;font-size:18px;max-width:760px}}.step{{border-top:1px solid #b8c7bf;padding:20px 0}}h2{{font-size:23px;margin:0 0 8px}}label{{display:block;font:13px ui-monospace,monospace;margin:14px 0 5px}}input,select{{width:100%;padding:10px;border:1px solid #526963;background:#fffdf7;font:15px ui-monospace,monospace}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:15px}}button{{margin-top:18px;background:#ef633d;color:white;border:2px solid #182726;padding:12px 18px;font:bold 16px ui-monospace,monospace;box-shadow:3px 3px 0 #182726;cursor:pointer}}button.secondary{{background:#dfe9e2;color:#182726}}pre{{background:#182726;color:#e7f1eb;padding:16px;white-space:pre-wrap;word-break:break-word}}.note{{background:#f0f5ed;border-left:4px solid #507765;padding:12px}}@media(max-width:650px){{main{{margin:0;padding:20px;box-shadow:none;border:0}}h1{{font-size:32px}}.grid{{grid-template-columns:1fr}}}}</style></head><body><main><p style="font-family:ui-monospace,monospace;color:#507765">LOCAL-ONLY | NO ACCOUNT | NO UPLOAD</p><h1>Set up a pre-release evaluation</h1><p class="lead">Connect the workflow your users actually use. For a normal web application, point us at its local JSON API. You do not need to locate or call each internal agent.</p><section class="step"><h2>1. Discover integration hints (optional)</h2><p>Scan a local repository for frameworks, routes, and observability signals. Source content stays on this computer.</p><label>APPLICATION REPOSITORY</label><input id="repository" placeholder="C:\\work\\my-ai-app"><button class="secondary" onclick="discover()">SCAN LOCALLY</button><pre id="discovery">No repository scanned yet.</pre></section><section class="step"><h2>2. Connect one user-facing workflow</h2><p class="note">Available now: JSON-over-HTTP endpoint. The runner sends one POST per case. Browser journeys and opaque custom protocols need their own connector; they are not silently guessed.</p><div class="grid"><div><label>LOCAL OR APPROVED STAGING URL</label><input id="url" value="http://127.0.0.1:8000/evaluate"></div><div><label>APPLICATION ID</label><input id="agent_id" value="my-ai-application"></div><div><label>VERSION UNDER TEST</label><input id="subject_version" value="0.1.0"></div><div><label>PROJECT KEY</label><input id="project_key" value="default"></div><div><label>LABEL RESPONSE PATH</label><input id="label_path" value="decision.label"></div><div><label>CONFIDENCE RESPONSE PATH</label><input id="confidence_path" value="decision.confidence"></div></div><label><input id="allow_remote" type="checkbox" style="width:auto"> This is an approved non-local staging target</label></section><section class="step"><h2>3. Choose and review a plan</h2><p>Every plan is editable after creation. “Safe” means the request should be allowed; “unsafe” means the application should block or refuse it.</p><label>EVALUATION PROFILE</label><select id="profile"><option value="smoke">Smoke check: 4 connection and basic boundary cases</option><option value="release">Release readiness: 12 broader baseline cases</option><option value="red_team">Adversarial safety review: 12 authorized boundary cases</option><option value="custom">Custom: start empty and write cases yourself</option></select><label>NEW EMPTY FOLDER FOR THIS PLAN</label><input id="directory" value={directory}><button onclick="createPlan()">CREATE LOCAL PLAN</button><pre id="result">Review the generated esx-eval.json before running it.</pre></section><section class="step"><h2>4. Run and view your local results</h2><pre>cd &lt;your-plan-folder&gt;\nesx-eval run --config .\\esx-eval.json --out .\\out\\evaluation.json\nesx-eval view --report .\\out\\evaluation.local-report.html</pre><p>Scores, raw responses, test prompts, and reports remain local unless your team separately opts into the signed upload flow.</p></section></main><script>const token={json.dumps(token)};async function post(path,data){{const r=await fetch(path,{{method:'POST',headers:{{'Content-Type':'application/json','X-ESX-Setup-Token':token}},body:JSON.stringify(data)}});const p=await r.json();if(!r.ok)throw Error(p.error||'Request failed');return p;}}async function discover(){{const out=document.querySelector('#discovery');out.textContent='Scanning locally...';try{{out.textContent=JSON.stringify(await post('/api/discover',{{repository:repository.value}}),null,2)}}catch(e){{out.textContent='Could not scan: '+e.message}}}}async function createPlan(){{const out=document.querySelector('#result');out.textContent='Creating local plan...';try{{let p={{profile:profile.value,response_label_path:label_path.value,response_confidence_path:confidence_path.value,request_mode:'message',allow_remote:allow_remote.checked}};['directory','agent_id','subject_version','project_key','url'].forEach(k=>p[k]=document.querySelector('#'+k).value);out.textContent=JSON.stringify(await post('/api/create-plan',p),null,2)+'\\n\\nNext: open esx-eval.json, review the labelled cases, then run the command below.'}}catch(e){{out.textContent='Could not create plan: '+e.message}}}}</script></body></html>'''
