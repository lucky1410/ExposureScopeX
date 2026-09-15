"""Evidence-tiered local repository discovery that never exports source content."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from .workflows import suggested_workflow


_IGNORED = {".git", ".next", "node_modules", ".venv", "venv", "dist", "build", "coverage", "__pycache__"}
_SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx"}
_MANIFEST_NAMES = {"package.json", "pyproject.toml", "requirements.txt", "requirements-dev.txt"}
_SIGNALS = {
    "langchain": ("agent framework", "LangChain", "agent_framework"),
    "langgraph": ("agent framework", "LangGraph", "agent_framework"),
    "crewai": ("agent framework", "CrewAI", "agent_framework"),
    "llama_index": ("RAG framework", "LlamaIndex", "rag_framework"),
    "openai": ("model provider", "OpenAI-compatible client", "model_provider"),
    "anthropic": ("model provider", "Anthropic client", "model_provider"),
    "ollama": ("model provider", "Ollama", "model_provider"),
    "opentelemetry": ("observability", "OpenTelemetry", "observability"),
    "chromadb": ("retrieval store", "Chroma", "retrieval_store"),
    "qdrant": ("retrieval store", "Qdrant", "retrieval_store"),
    "pinecone": ("retrieval store", "Pinecone", "retrieval_store"),
    "weaviate": ("retrieval store", "Weaviate", "retrieval_store"),
    "redis": ("retrieval store", "Redis", "retrieval_store"),
    "pgvector": ("retrieval store", "pgvector", "retrieval_store"),
}
_APP_FRAMEWORKS = {"fastapi": "FastAPI", "flask": "Flask", "express": "Express", "next": "Next.js"}
_EVIDENCE_RANK = {"source_import": 1, "declared_dependency": 2, "installed_package": 3}


def discover_repository(path: str | Path, *, max_files: int = 2_000) -> dict[str, Any]:
    """Report code/dependency evidence, never unverified documentation mentions."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Repository folder does not exist: {root}")
    files_scanned = 0
    frameworks: set[str] = set()
    entry_points: set[str] = set()
    components: dict[str, dict[str, str]] = {}
    workflow_suggestions: dict[str, dict[str, str]] = {}
    for candidate in root.rglob("*"):
        if files_scanned >= max_files:
            break
        if not candidate.is_file() or any(part in _IGNORED for part in candidate.parts):
            continue
        relative = candidate.relative_to(root).as_posix()
        name = candidate.name.lower()
        if name in {"openapi.json", "openapi.yaml", "openapi.yml"}:
            entry_points.add(f"OpenAPI description: {relative}")
        if name not in _MANIFEST_NAMES and candidate.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        files_scanned += 1
        try:
            content = candidate.read_text(encoding="utf-8", errors="ignore")[:131_072]
        except OSError:
            continue
        dependencies = _manifest_dependencies(name, content)
        for package, display in _APP_FRAMEWORKS.items():
            if package in dependencies or _source_import(content, package):
                frameworks.add(display)
        if name in {"pyproject.toml", "requirements.txt", "requirements-dev.txt"}:
            frameworks.add("Python project")
        if name == "package.json":
            frameworks.add("Node.js project")
        if candidate.suffix.lower() in _SOURCE_SUFFIXES and _has_http_route(content):
            entry_points.add(f"HTTP route definitions: {relative}")
        if candidate.suffix.lower() in _SOURCE_SUFFIXES:
            for method, route in _extract_http_routes(content):
                component_id = f"workflow-{method.lower()}-{_slug(route)}"
                label = f"{method} {route}"
                suggestion = suggested_workflow(route, method, component_id, relative)
                _record_component(components, component_id, f"HTTP route: {label}", "workflow_entry_point", suggestion["capability_area"], "source_route", relative)
                workflow_suggestions[component_id] = suggestion
        for package, (category, display, kind) in _SIGNALS.items():
            evidence = _evidence_for(root, name, content, package, dependencies)
            if evidence is not None:
                _record_component(components, f"{kind}-{_slug(display)}", display, kind, category, evidence, relative)
    for entry_point in entry_points:
        _record_component(components, f"workflow-{_slug(entry_point)}", entry_point, "workflow_entry_point", "workflow entry point", "source_route" if "route definitions" in entry_point else "api_description", entry_point.split(": ", 1)[-1])
    component_list = sorted(components.values(), key=lambda item: item["id"])
    capabilities = [f"{item['category']}: {item['name']} ({item['verification_status']})" for item in component_list if item["kind"] != "workflow_entry_point"]
    return {
        "status": "completed", "repository": str(root), "files_scanned": files_scanned,
        "frameworks": sorted(frameworks), "capabilities": capabilities,
        "entry_points": sorted(entry_points), "components": component_list,
        "workflow_suggestions": sorted(workflow_suggestions.values(), key=lambda item: (item["route"], item["component_id"])),
        "limitations": "Documentation, backlog, comments, and plain text mentions are excluded. Installed packages, declared dependencies, and source imports are different evidence levels. Source routes are reviewable workflow suggestions, not proof of browser reachability, authentication state, execution, or runtime behavior. Customers must confirm scope.",
    }


def _manifest_dependencies(name: str, content: str) -> set[str]:
    """Read declared package names from common manifests without resolving installs."""
    if name == "package.json":
        try:
            package = json.loads(content)
        except json.JSONDecodeError:
            return set()
        result: set[str] = set()
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            values = package.get(key, {}) if isinstance(package, dict) else {}
            if isinstance(values, dict):
                result.update(str(item).lower().replace("-", "_") for item in values)
        return result
    if name.startswith("requirements"):
        return {match.group(1).lower().replace("-", "_") for line in content.splitlines() if not line.lstrip().startswith("#") for match in [re.match(r"\s*([A-Za-z0-9_.-]+)", line)] if match}
    if name == "pyproject.toml":
        return {match.group(1).lower().replace("-", "_") for match in re.finditer(r"(?m)^\s*[\"']?([A-Za-z0-9_.-]+)[\"']?\s*(?:[<>=!~]|$)", content)}
    return set()


def _source_import(content: str, package: str) -> bool:
    escaped = re.escape(package)
    python_pattern = rf"(?m)^\s*(?:from|import)\s+{escaped}(?:[.\s]|$)"
    javascript_pattern = rf"(?m)(?:from\s+[\"']{escaped}(?:[/\"'])|require\(\s*[\"']{escaped}(?:[/\"']))"
    return bool(re.search(python_pattern, content, flags=re.IGNORECASE) or re.search(javascript_pattern, content, flags=re.IGNORECASE))


def _has_http_route(content: str) -> bool:
    return bool(re.search(r"(?m)^\s*@(?:app|router)\.(?:get|post|put|delete|patch)\(", content) or re.search(r"(?m)\b(?:app|router)\.(?:get|post|put|delete|patch)\(", content))


def _extract_http_routes(content: str) -> list[tuple[str, str]]:
    """Read literal source routes only; prose and dynamic route construction are excluded."""
    pattern = re.compile(
        r"(?m)(?:@|\b)(?:app|router)\.(get|post|put|delete|patch)\(\s*[\"']([^\"']+)[\"']",
        flags=re.IGNORECASE,
    )
    routes: set[tuple[str, str]] = set()
    for match in pattern.finditer(content):
        method, route = match.group(1).upper(), match.group(2)
        if route.startswith("/") and "\n" not in route and "\r" not in route and len(route) <= 512:
            routes.add((method, route))
    return sorted(routes)


def _evidence_for(root: Path, name: str, content: str, package: str, dependencies: set[str]) -> str | None:
    if _installed_package(root, package):
        return "installed_package"
    if package in dependencies:
        return "declared_dependency"
    if name not in _MANIFEST_NAMES and _source_import(content, package):
        return "source_import"
    return None


def _installed_package(root: Path, package: str) -> bool:
    """Check common local package locations without importing or executing anything."""
    package_path = package.replace("_", "-")
    if (root / "node_modules" / package_path / "package.json").is_file():
        return True
    return any((environment / part / "site-packages" / package).exists() for environment in (root / ".venv", root / "venv") for part in ("Lib", "lib"))


def _record_component(components: dict[str, dict[str, str]], component_id: str, name: str, kind: str, category: str, evidence: str, evidence_path: str) -> None:
    existing = components.get(component_id)
    if existing and _EVIDENCE_RANK.get(existing["verification_status"], 0) >= _EVIDENCE_RANK.get(evidence, 0):
        return
    components[component_id] = {"id": component_id, "name": name, "kind": kind, "category": category, "verification_status": evidence, "evidence_path": evidence_path}


def _slug(value: str) -> str:
    return "-".join(re.findall(r"[a-z0-9]+", value.lower()))[:72]
