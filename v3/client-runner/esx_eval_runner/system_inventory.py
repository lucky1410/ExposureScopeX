"""Bounded, non-executing system discovery and reviewable test-plan generation."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import random
from typing import Any

from .runner import RunnerError, read_json, sha256


SCHEMA = "pre-d-system-plan-1.0"
LAYERS = ("functional", "workflow", "ai", "integration", "code", "authorization", "security", "reliability")
IGNORED = {".git", "node_modules", ".venv", "venv", "build", "dist", ".next", "__pycache__", ".pytest_cache"}


def document(path: str | Path) -> dict:
    path = Path(path)
    try:
        if path.stat().st_size > 8_000_000:
            raise RunnerError("System input exceeds the 8 MB limit")
    except OSError as exc:
        raise RunnerError(f"Cannot read local system input: {path}") from exc
    value = read_json(path)
    if not isinstance(value, dict):
        raise RunnerError("System input must be a JSON object")
    return value


def identifier(*parts: Any) -> str:
    return "component-" + sha256(list(parts))[:16]


def _python_routes(text: str) -> list[tuple[str, str]]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError):
        return []
    prefixes = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            prefix = next((k.value.value for k in node.value.keywords if k.arg == "prefix"
                           and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str)), "")
            for target in node.targets:
                if isinstance(target, ast.Name):
                    prefixes[target.id] = prefix
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call) or not isinstance(deco.func, ast.Attribute):
                continue
            if deco.func.attr not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            if deco.args and isinstance(deco.args[0], ast.Constant) and isinstance(deco.args[0].value, str):
                owner = deco.func.value.id if isinstance(deco.func.value, ast.Name) else ""
                found.append((deco.func.attr.upper(), prefixes.get(owner, "") + deco.args[0].value))
    return found


def discover_system(*, project_id: str, version: str, repository: str | None = None,
                    openapi: str | None = None, base_url: str = "", max_files: int = 2000) -> dict:
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", project_id) or not version:
        raise RunnerError("Supply a lowercase project ID and application version")
    if not repository and not openapi:
        raise RunnerError("Provide a repository or a local OpenAPI JSON file")
    if not 1 <= max_files <= 10000:
        raise RunnerError("max_files must be between 1 and 10000")
    components: dict[str, dict] = {}
    checks = []
    warnings = []
    counts = {"files_scanned": 0, "files_skipped": 0, "truncated": False}

    def add(kind: str, route: str, source: str, method: str = "", module: str | None = None, **extra: Any) -> dict:
        key = identifier(kind, method, route)
        row = components.setdefault(key, {
            "id": key, "name": (method + " " + route).strip(), "module": module or next(
                (p for p in route.split("/") if p and not p.startswith("{")), "root"),
            "kind": kind, "path": route, "method": method,
            "state": "discovered", "enabled": "unknown", "evidence": [],
            "required_layers": ["functional"] if kind == "api" else ["workflow"] if kind == "page" else ["code"],
            "suggested_layers": list(LAYERS), "depends_on": [],
        })
        row["evidence"].append({"source": source, "basis": extra.pop("basis", "source_declaration")})
        row.update(extra)
        return row

    if repository:
        from .system_safety import linked
        root = Path(repository).resolve()
        if not root.is_dir():
            raise RunnerError("Repository must be a local directory")
        stop = False
        for folder, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in IGNORED and not linked(Path(folder, d)))
            for name in sorted(files):
                path = Path(folder, name)
                if linked(path) or path.suffix.lower() not in {".py", ".tsx", ".jsx", ".js", ".ts"}:
                    continue
                if counts["files_scanned"] >= max_files:
                    counts["truncated"] = True
                    stop = True
                    break
                counts["files_scanned"] += 1
                rel = path.relative_to(root).as_posix()
                if path.stat().st_size > 256_000:
                    counts["files_skipped"] += 1
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    counts["files_skipped"] += 1
                    continue
                if path.suffix == ".py":
                    routes = _python_routes(text)
                else:
                    routes = [(m.upper(), p) for m, p in re.findall(
                        r"\b(?:app|router)\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]", text)]
                for method, route in routes:
                    if route.startswith("/") and len(route) <= 512:
                        add("api", route, rel, method, basis="source_route_candidate")
                if path.name in {"page.tsx", "page.jsx", "page.js"} and "app" in path.relative_to(root).parts:
                    parts = path.relative_to(root).parts
                    route = "/" + "/".join(p for p in parts[parts.index("app") + 1:-1] if not p.startswith("("))
                    add("page", route, rel, basis="filesystem_route_candidate")
                for route in re.findall(r"<Route\b[^>]*\bpath\s*=\s*['\"]([^'\"]+)['\"]", text):
                    add("page", route, rel, basis="source_route_candidate")
                if path.name.startswith("test_") or re.search(r"\.(test|spec)\.[jt]sx?$", name):
                    add("test_suite", rel, rel, module="code-tests", basis="test_file_present")
                elif any(p.lower() in {"services", "workers", "jobs"} for p in path.relative_to(root).parts[:-1]):
                    add("service", rel, rel, module="services", basis="source_location_candidate",
                        required_layers=["integration"])
                # These are review hints, not proof that a model/retriever executes at runtime.
                if not path.name.startswith("test_") and re.search(r"\b(?:ChatOpenAI|ChatAnthropic|Ollama|Anthropic|OpenAI|VectorStore|as_retriever)\b", text):
                    add("ai_candidate", rel, rel, module="ai", basis="framework_symbol_candidate",
                        required_layers=["ai"], suggested_dimensions=["classification", "decision_evidence", "groundedness", "hallucination", "rag"])
            if stop:
                break
        warnings.append("Source routes are candidates: mounted prefixes, dynamic routes and feature flags require review; no source was imported or executed.")
    if openapi:
        spec = document(openapi)
        if not str(spec.get("openapi", "")).startswith("3.") or not isinstance(spec.get("paths"), dict):
            raise RunnerError("Use a local OpenAPI 3.x JSON document; remote references are not fetched")
        schema_digest = sha256(spec.get("components", {}))
        for route, path_item in sorted(spec["paths"].items()):
            if not isinstance(route, str) or not route.startswith("/") or not isinstance(path_item, dict):
                continue
            for method in ("get", "head", "post", "put", "patch", "delete", "options"):
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue
                tags = operation.get("tags", [])
                if not isinstance(tags, list):
                    raise RunnerError("OpenAPI tags must be an array")
                row = add("api", route, Path(openapi).name + "#/paths/" + route + "/" + method,
                          method.upper(), module=str(tags[0]) if tags else None, basis="openapi_contract")
                row["contract_sha256"] = sha256({"operation": operation, "parameters": path_item.get("parameters", []),
                                                "security": spec.get("security", []), "schemas_sha256": schema_digest})
                row["auth_declared"] = bool(operation.get("security", spec.get("security", [])))
                if row["auth_declared"] and "authorization" not in row["required_layers"]:
                    row["required_layers"].append("authorization")
                responses = operation.get("responses", {})
                if not isinstance(responses, dict):
                    raise RunnerError("OpenAPI responses must be an object")
                statuses = [int(s) for s in responses if isinstance(s, str) and re.fullmatch(r"2\d\d", s)]
                if not isinstance(path_item.get("parameters", []), list) or not isinstance(operation.get("parameters", []), list):
                    raise RunnerError("OpenAPI parameters must be arrays")
                parameters = path_item.get("parameters", []) + operation.get("parameters", [])
                needs_inputs = "{" in route or any(isinstance(p, dict) and p.get("required") for p in parameters)
                checks.append({
                    "id": "contract-" + row["id"], "type": "http", "layer": "functional",
                    "component_ids": [row["id"]], "enabled": False, "reviewed": False,
                    "role": "anonymous", "method": method.upper(), "path": route,
                    "expected_status": statuses, "json_assertions": [], "headers_from_env": {},
                    "expectation_basis": "declared_openapi_contract",
                    "authoring_note": "Supply approved inputs and independent content assertions before enabling." if needs_inputs
                    else "Review status and add meaningful content assertions; status alone is contract reachability.",
                })
    if len(components) > 10000:
        raise RunnerError("Discovery exceeds 10000 components; narrow the repository or specification")
    drafted = {key for check in checks for key in check["component_ids"]}
    for row in components.values():
        if row["kind"] == "api" and row["id"] not in drafted:
            checks.append(check_template("http", row, "source-" + row["id"]))
    return {
        "schema_version": SCHEMA, "project_id": project_id, "application_version": version,
        "inventory_confirmed": False, "base_url": base_url, "roles": ["anonymous"],
        "environment": "local", "isolation_note": "", "components": list(components.values()),
        "checks": checks, "discovery": {**counts, "warnings": warnings},
        "notice": "Module grouping and expectations are suggestions. Review scope, roles, flags and dependencies; discovery never counts as execution.",
    }


def add_role_matrix(plan: dict, roles: list[str]) -> None:
    """Generate explicit empty policy slots rather than guessing a role hierarchy."""
    if not roles or len(roles) > 32 or any(not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", r) for r in roles):
        raise RunnerError("Provide up to 32 valid role IDs")
    plan["roles"] = sorted(set(plan.get("roles", []) + roles))
    ids = {c["id"] for c in plan["checks"]}
    for component in plan["components"]:
        if component["kind"] != "api":
            continue
        for role in roles:
            key = "auth-" + component["id"] + "-" + role
            if key not in ids:
                plan["checks"].append({"id": key, "type": "http", "layer": "authorization",
                    "component_ids": [component["id"]], "role": role, "enabled": False, "reviewed": False,
                    "method": component["method"], "path": component["path"], "expected_status": [],
                    "json_assertions": [], "headers_from_env": {},
                    "authoring_note": "Specify independently approved allow/deny statuses and identity environment references; roles grant no permissions."})
        if "authorization" not in component["required_layers"]:
            component["required_layers"].append("authorization")
    plan.pop("approval", None)


def check_template(kind: str, component: dict, check_id: str) -> dict:
    """Draft only; policies and cleanup commands must be supplied by the operator."""
    if kind not in {"http", "tenant", "load", "recovery", "command"}:
        raise RunnerError("Unsupported check template")
    row = {"id": check_id, "type": "http" if kind == "tenant" else kind,
           "layer": "authorization" if kind == "tenant" else "reliability" if kind in {"load", "recovery"} else "code" if kind == "command" else "functional",
           "component_ids": [component["id"]], "enabled": False, "reviewed": False, "timeout_seconds": 30,
           "authoring_note": "Review expected outcomes independently. This disabled draft is not executed coverage."}
    if kind == "command":
        row.update(command=[], cwd=".", result_file="test-results.xml", format="junit")
    else:
        row.update(method=component.get("method") or "GET", path=component.get("path", "/"),
                   role="anonymous", expected_status=[], headers_from_env={}, json_assertions=[])
    if kind == "tenant":
        row.update(authoring_note="Use tenant B's identity to request a known tenant A fixture. Set the approved deny status, or assert returned tenant ownership. Also add a positive control with the owning identity; status alone cannot establish complete isolation.", role="tenant-b")
    if kind == "load":
        row.update(method="GET", requests=10, concurrency=2, max_p95_ms=1000)
    if kind == "recovery":
        row.update(method="GET", inject_command=[], recover_command=[], disruption_expected_status=[], recovery_timeout_seconds=30)
    return row


def sample_population(dataset: dict, per_class: int, seed: int) -> dict:
    """Deterministic stratification of user-labelled data; never generates gold labels."""
    if type(per_class) is not int or not 1 <= per_class <= 500 or type(seed) is not int:
        raise RunnerError("Use an integer seed and 1..500 cases per class")
    cases = dataset.get("cases")
    if not isinstance(cases, list) or not cases or not isinstance(dataset.get("version"), str):
        raise RunnerError("Dataset needs version and a nonempty cases array")
    groups, ids = {}, set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("case_id"), str) or case["case_id"] in ids or not isinstance(case.get("expected_label"), str) or not case["expected_label"] or not isinstance(case.get("input"), dict):
            raise RunnerError("Sampling requires unique case_id, expected_label and input for every labelled record")
        ids.add(case["case_id"])
        groups.setdefault(case["expected_label"], []).append(case)
    generator = random.Random(seed)
    selected = [case for label in sorted(groups) for case in generator.sample(sorted(groups[label], key=lambda c: c["case_id"]), min(per_class, len(groups[label])))]
    if len(selected) > 500:
        raise RunnerError("Selected pack exceeds 500 cases; reduce per-class size or split into reviewed packs")
    return {"version": dataset["version"], "cases": selected,
            "population": {"available_case_count": len(cases), "class_counts": {k: len(v) for k, v in groups.items()},
                           "source": "provided-labelled-dataset/" + sha256(dataset),
                           "sampling_notes": f"Stratified without replacement; seed={seed}; at most {per_class} cases per class. Counts describe this supplied file, not the entire production population."}}
