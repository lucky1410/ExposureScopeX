"""Read-only discovery boundaries and observable source integrity for system profiles."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from .runner import RunnerError, sha256
from .system_inventory import IGNORED, document


POLICY = "pre-d-source-protection-1.0"
TRUSTED_COMMANDS = "pre-d-trusted-local-commands-1.0"
SNAPSHOT = "pre-d-source-snapshot-1.0"
MAX_FILES = 10000
MAX_BYTES = 128_000_000
EXCLUDED = IGNORED | {
    ".git", ".hg", ".svn",
    ".mypy_cache", ".ruff_cache", ".cache", ".tox", ".pytest_cache",
    ".next", ".nuxt", ".turbo", ".parcel-cache", ".vite",
    "node_modules", "dist", "build", "target", "coverage", ".venv", "venv",
    "__pycache__",
}
EXCLUDED_EXTENSIONS = {
    ".7z", ".a", ".avi", ".bmp", ".br", ".bz2", ".class", ".db", ".dll",
    ".dmg", ".doc", ".docx", ".eot", ".exe", ".gif", ".gz", ".ico", ".jar",
    ".jpeg", ".jpg", ".lockb", ".mov", ".mp3", ".mp4", ".msi", ".otf",
    ".pdf", ".png", ".ppt", ".pptx", ".pyc", ".pyd", ".rar", ".so", ".sqlite",
    ".sqlite3", ".tar", ".ttf", ".wasm", ".wav", ".webm", ".woff", ".woff2",
    ".xls", ".xlsx", ".zip", ".zst",
}


def linked(path: Path) -> bool:
    info = path.lstat()
    return path.is_symlink() or bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024))


def protected_roots(plan: dict) -> list[Path]:
    policy = plan.get("source_protection")
    if policy is None:
        return []
    if not isinstance(policy, dict) or policy.get("schema_version") != POLICY or policy.get("mode") != "read_only":
        raise RunnerError("Source protection must use the read_only policy")
    roots = policy.get("roots")
    if not isinstance(roots, list) or len(roots) > 16 or any(not isinstance(p, str) or not Path(p).is_absolute() for p in roots):
        raise RunnerError("Source protection requires up to 16 absolute repository paths")
    resolved = [Path(p).resolve() for p in roots]
    if len(set(resolved)) != len(resolved) or any(not p.is_dir() for p in resolved):
        raise RunnerError("Protected repositories must exist and be distinct directories")
    return resolved


def source_limits(plan: dict) -> tuple[int, int, set[str], set[str]]:
    policy = plan.get("source_protection", {}) if isinstance(plan, dict) else {}
    limits = policy.get("scan_limits", {}) if isinstance(policy, dict) else {}
    if not isinstance(limits, dict):
        raise RunnerError("source_protection.scan_limits must be an object")
    max_files = limits.get("max_files", MAX_FILES)
    max_bytes = limits.get("max_bytes", MAX_BYTES)
    if type(max_files) is not int or not 1 <= max_files <= 1_000_000:
        raise RunnerError("source_protection.scan_limits.max_files must be 1..1000000")
    if type(max_bytes) is not int or not 1 <= max_bytes <= 50_000_000_000:
        raise RunnerError("source_protection.scan_limits.max_bytes must be 1..50000000000")
    extra_dirs = limits.get("excluded_directories", [])
    extra_exts = limits.get("excluded_extensions", [])
    if not isinstance(extra_dirs, list) or len(extra_dirs) > 200 or any(not isinstance(v, str) or not v or "/" in v or "\\" in v for v in extra_dirs):
        raise RunnerError("source_protection.scan_limits.excluded_directories must be directory names")
    if not isinstance(extra_exts, list) or len(extra_exts) > 200 or any(not isinstance(v, str) or not v.startswith(".") or "/" in v or "\\" in v for v in extra_exts):
        raise RunnerError("source_protection.scan_limits.excluded_extensions must be file extensions")
    return max_files, max_bytes, EXCLUDED | set(extra_dirs), EXCLUDED_EXTENSIONS | {v.lower() for v in extra_exts}


def guard_output(plan: dict, target: Path) -> None:
    target = target.resolve()
    if any(target == root or root in target.parents for root in protected_roots(plan)):
        raise RunnerError("PRE-D artifacts must be outside the protected application repository")


def snapshot_sources(roots: list[Path], *, max_files: int | None = None, max_bytes: int | None = None,
                     excluded_directories: set[str] | None = None,
                     excluded_extensions: set[str] | None = None) -> dict:
    """Hash bounded regular files without importing code or retaining file contents."""
    files, issues = {}, []
    total = 0
    max_files = MAX_FILES if max_files is None else max_files
    max_bytes = MAX_BYTES if max_bytes is None else max_bytes
    excluded_directories = excluded_directories or EXCLUDED
    excluded_extensions = excluded_extensions or EXCLUDED_EXTENSIONS
    for index, root in enumerate(roots):
        root = root.resolve()
        def onerror(_error):
            issues.append({"root": index, "reason": "unreadable_directory"})
        for folder, dirs, names in os.walk(root, followlinks=False, onerror=onerror):
            kept = []
            for name in sorted(dirs):
                if name in excluded_directories:
                    continue
                path = Path(folder, name)
                try:
                    if linked(path):
                        issues.append({"root": index, "path": path.relative_to(root).as_posix(), "reason": "linked_directory_not_followed"})
                    else:
                        kept.append(name)
                except OSError:
                    issues.append({"root": index, "reason": "unreadable_directory"})
            dirs[:] = kept
            for name in sorted(names):
                path = Path(folder, name)
                key = str(index) + "/" + path.relative_to(root).as_posix()
                if path.suffix.lower() in excluded_extensions:
                    continue
                if len(files) >= max_files:
                    issues.append({"reason": "file_limit", "max_files": max_files})
                    return _snapshot(roots, files, issues, total, max_files, max_bytes, excluded_directories, excluded_extensions)
                try:
                    before = path.lstat()
                    if linked(path) or not stat.S_ISREG(before.st_mode):
                        issues.append({"path": key, "reason": "nonregular_file_not_read"})
                        continue
                    if total + before.st_size > max_bytes:
                        issues.append({"reason": "byte_limit", "max_bytes": max_bytes})
                        return _snapshot(roots, files, issues, total, max_files, max_bytes, excluded_directories, excluded_extensions)
                    digest = hashlib.sha256()
                    with path.open("rb") as handle:
                        opened = os.fstat(handle.fileno())
                        if (opened.st_ino, opened.st_dev) != (before.st_ino, before.st_dev):
                            raise OSError("Source changed while opening")
                        while chunk := handle.read(65536):
                            total += len(chunk)
                            if total > max_bytes:
                                issues.append({"reason": "byte_limit", "max_bytes": max_bytes})
                                return _snapshot(roots, files, issues, total, max_files, max_bytes, excluded_directories, excluded_extensions)
                            digest.update(chunk)
                    after = path.stat()
                    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                        issues.append({"path": key, "reason": "file_changed_while_reading"})
                    files[key] = digest.hexdigest()
                except OSError:
                    issues.append({"path": key, "reason": "unreadable_file"})
    return _snapshot(roots, files, issues, total, max_files, max_bytes, excluded_directories, excluded_extensions)


def _snapshot(roots: list[Path], files: dict, issues: list, total: int, max_files: int = MAX_FILES,
              max_bytes: int = MAX_BYTES, excluded_directories: set[str] | None = None,
              excluded_extensions: set[str] | None = None) -> dict:
    result = {"schema_version": SNAPSHOT, "roots": [str(r.resolve()) for r in roots],
              "files": files, "issues": issues, "bytes_hashed": total,
              "file_count": len(files), "max_files": max_files, "max_bytes": max_bytes,
              "status": "incomplete" if issues else "complete" if roots else "not_configured",
              "excluded_directories": sorted(excluded_directories or EXCLUDED),
              "excluded_extensions": sorted(excluded_extensions or EXCLUDED_EXTENSIONS)}
    result["snapshot_sha256"] = sha256(result)
    return result


def source_diff(before: dict, after: dict) -> dict:
    a, b = before.get("files", {}), after.get("files", {})
    rows = [{"path": p, "change": "added" if p not in a else "removed" if p not in b else "modified",
             "before_sha256": a.get(p), "after_sha256": b.get(p)}
            for p in sorted(set(a) | set(b)) if a.get(p) != b.get(p)]
    return {"status": "incomplete" if "incomplete" in {before.get("status"), after.get("status")} else
            "changed" if rows or before.get("roots") != after.get("roots") else
            "not_configured" if after.get("status") == "not_configured" else "unchanged",
            "before_sha256": before.get("snapshot_sha256"), "after_sha256": after.get("snapshot_sha256"),
            "files": rows, "changed_file_count": len(rows),
            "before_status": before.get("status"), "after_status": after.get("status"),
            "before_issues": before.get("issues", []), "after_issues": after.get("issues", [])}


def command_sha256(argv: list[str]) -> str:
    return sha256(argv)


def _command_paths(value: object, prefix: str = "") -> list[tuple[str, list[str]]]:
    rows = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            if key in {"command", "inject_command", "recover_command"} and isinstance(item, list):
                rows.append((path, item))
            else:
                rows.extend(_command_paths(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            rows.extend(_command_paths(item, f"{prefix}.{index}" if prefix else str(index)))
    return rows


def _trusted_command_index(plan: dict) -> set[tuple[str, str, str]]:
    policy = plan.get("trusted_command_policy")
    if policy is None:
        return set()
    if not isinstance(policy, dict) or policy.get("schema_version") != TRUSTED_COMMANDS or policy.get("reviewed") is not True:
        raise RunnerError("trusted_command_policy must be reviewed and use the supported schema")
    entries = policy.get("entries")
    if not isinstance(entries, list) or len(entries) > 500:
        raise RunnerError("trusted_command_policy entries must be a bounded list")
    index = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise RunnerError("trusted_command_policy entries must be objects")
        check_id, field, digest = entry.get("check_id"), entry.get("field"), entry.get("argv_sha256")
        if not all(isinstance(v, str) and v for v in (check_id, field, digest)) or not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise RunnerError("trusted_command_policy entries require check_id, field, argv_sha256 and reason")
        index.add((check_id, field, digest))
    return index


def _trusted_command(plan: dict, check_id: str, field: str, argv: list[str], index: set[tuple[str, str, str]]) -> bool:
    return (check_id, field, command_sha256(argv)) in index


def protection_blockers(plan: dict, root: Path) -> list[str]:
    if "source_protection" not in plan:
        return []
    roots = protected_roots(plan)
    guard_output(plan, root)
    blockers = []
    trusted = _trusted_command_index(plan)
    for check in plan.get("checks", []):
        if not check.get("enabled"):
            continue
        if check.get("type") in {"command", "recovery"}:
            if isinstance(check.get("result_file"), str):
                guard_output(plan, root / check["result_file"])
            missing = [field for field, argv in _command_paths(check) if not _trusted_command(plan, check["id"], field, argv, trusted)]
            if missing:
                blockers.append(check["id"] + ": protected profiles require reviewed trusted_command_policy entries for " + ", ".join(missing))
                continue
        if check.get("type") == "evaluation":
            config_path = (root / check["config"]).resolve()
            config = document(config_path)
            guard_output(plan, config_path.parent)
            commands = _command_paths(config)
            missing = [field for field, argv in commands if not _trusted_command(plan, check["id"], field, argv, trusted)]
            if missing:
                blockers.append(check["id"] + ": protected profiles require reviewed trusted_command_policy entries for " + ", ".join(missing))
            if config.get("adapter", {}).get("type") not in {"http_json_target", "browser_journey"} and (not commands or missing):
                blockers.append(check["id"] + ": use a built-in HTTP or browser connector in the protected profile")
            # Browser session and diagnostic paths are relative to the evaluation file.
            def check_paths(value):
                if isinstance(value, dict):
                    for key, item in value.items():
                        if key in {"session_state_path", "evidence_dir", "screenshot_dir", "artifact_dir", "artifacts_dir"} and isinstance(item, str):
                            guard_output(plan, config_path.parent / item)
                        check_paths(item)
                elif isinstance(value, list):
                    for item in value:
                        check_paths(item)
            check_paths(config.get("adapter", {}))
            guard_output(plan, config_path.parent / ".esx")
    expected = plan["source_protection"].get("snapshot")
    if roots:
        max_files, max_bytes, excluded_dirs, excluded_exts = source_limits(plan)
        current = snapshot_sources(roots, max_files=max_files, max_bytes=max_bytes,
                                   excluded_directories=excluded_dirs, excluded_extensions=excluded_exts)
        if current["status"] != "complete":
            reasons = ", ".join(sorted({str(issue.get("reason", "unknown")) for issue in current.get("issues", [])}))
            blockers.append("Source fingerprint is incomplete (" + (reasons or "unknown") + "); review scan limits, excluded paths, unreadable files or links")
        delta = source_diff(expected if isinstance(expected, dict) else {}, current)
        if delta["status"] == "changed":
            blockers.append("Application source changed since setup; refresh the profile and review before execution")
        elif delta["status"] == "incomplete" and current["status"] == "complete":
            blockers.append("Saved source fingerprint was incomplete; refresh the profile after scan-limit review")
    return blockers
