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
}


def discover_repository(path: str | Path, *, max_files: int = 2_000) -> dict[str, Any]:
    """Identify integration hints locally without returning any source text."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Repository folder does not exist: {root}")
    files_scanned = 0
    frameworks: set[str] = set()
    capabilities: set[str] = set()
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
    return {
        "status": "completed",
        "repository": str(root),
        "files_scanned": files_scanned,
        "frameworks": sorted(frameworks),
        "capabilities": sorted(capabilities),
        "entry_points": sorted(entry_points),
        "limitations": "Discovery reports technology hints only. It does not identify every agent, execute code, inspect secrets, or send source content anywhere.",
    }
