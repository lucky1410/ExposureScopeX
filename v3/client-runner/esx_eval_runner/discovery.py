"""Bounded local repository discovery that never exports source content."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any


_IGNORED = {".git", ".next", "node_modules", ".venv", "venv", "dist", "build", "coverage", "__pycache__"}
_TEXT_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".yaml", ".yml", ".toml", ".md"}
_SIGNALS = {
    "langchain": ("agent framework", "LangChain"),
    "langgraph": ("agent framework", "LangGraph"),
    "crewai": ("agent framework", "CrewAI"),
    "llama_index": ("RAG framework", "LlamaIndex"),
    "openai": ("model provider", "OpenAI-compatible client"),
    "anthropic": ("model provider", "Anthropic client"),
    "ollama": ("model provider", "Ollama"),
    "opentelemetry": ("observability", "OpenTelemetry"),
    "chromadb": ("retrieval store", "Chroma"),
    "qdrant": ("retrieval store", "Qdrant"),
    "pinecone": ("retrieval store", "Pinecone"),
    "weaviate": ("retrieval store", "Weaviate"),
    "redis": ("retrieval store", "Redis"),
    "pgvector": ("retrieval store", "pgvector"),
    "tool_calls": ("tool", "LLM tool calls"),
    "function_call": ("tool", "Function calling"),
}

_KIND_BY_CATEGORY = {
    "agent framework": "agent_framework",
    "RAG framework": "rag_framework",
    "model provider": "model_provider",
    "observability": "observability",
    "retrieval store": "retrieval_store",
    "tool": "tool",
}


def discover_repository(path: str | Path, *, max_files: int = 2_000) -> dict[str, Any]:
    """Identify integration hints locally without returning any source text."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Repository folder does not exist: {root}")
    files_scanned = 0
    frameworks: set[str] = set()
    capabilities: set[str] = set()
    components: dict[str, dict[str, str]] = {}
    entry_points: set[str] = set()
    for candidate in root.rglob("*"):
        if files_scanned >= max_files:
            break
        if not candidate.is_file() or any(part in _IGNORED for part in candidate.parts):
            continue
        relative = candidate.relative_to(root).as_posix()
        name = candidate.name.lower()
        if name in {"openapi.json", "openapi.yaml", "openapi.yml"}:
            entry_points.add(f"OpenAPI description: {relative}")
        if name == "package.json":
            frameworks.add("Node.js application")
        if name in {"next.config.js", "next.config.mjs", "next.config.ts"} or relative.startswith("app/api/"):
            frameworks.add("Next.js")
        if name in {"pyproject.toml", "requirements.txt", "requirements-dev.txt"}:
            frameworks.add("Python application")
        if candidate.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        files_scanned += 1
        try:
            content = candidate.read_text(encoding="utf-8", errors="ignore")[:131_072].lower()
        except OSError:
            continue
        if "fastapi" in content:
            frameworks.add("FastAPI")
        if "flask" in content:
            frameworks.add("Flask")
        if "express" in content:
            frameworks.add("Express")
        if re.search(r"@(app|router)\.(get|post|put|delete|patch)\(", content) or re.search(r"\b(app|router)\.(get|post|put|delete|patch)\(", content):
            entry_points.add(f"HTTP route definitions: {relative}")
        for token, (category, display) in _SIGNALS.items():
            if token in content:
                capabilities.add(f"{category}: {display}")
                component_id = f"{_KIND_BY_CATEGORY[category]}-{_slug(display)}"
                components[component_id] = {
                    "id": component_id,
                    "name": display,
                    "kind": _KIND_BY_CATEGORY[category],
                    "confidence": "technology_signal",
                }
    for entry_point in entry_points:
        component_id = f"workflow-{_slug(entry_point)}"
        components[component_id] = {
            "id": component_id,
            "name": entry_point,
            "kind": "workflow_entry_point",
            "confidence": "repository_signal",
        }
    return {
        "status": "completed",
        "repository": str(root),
        "files_scanned": files_scanned,
        "frameworks": sorted(frameworks),
        "capabilities": sorted(capabilities),
        "entry_points": sorted(entry_points),
        "components": sorted(components.values(), key=lambda item: item["id"]),
        "limitations": "Discovery reports technology hints only. It does not identify every agent, execute code, inspect secrets, or send source content anywhere. Customers must confirm which components are in scope.",
    }


def _slug(value: str) -> str:
    return "-".join(re.findall(r"[a-z0-9]+", value.lower()))[:72]
