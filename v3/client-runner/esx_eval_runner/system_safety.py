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
EXCLUDED = IGNORED | {".mypy_cache", ".ruff_cache", ".cache", ".tox"}


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


def guard_output(plan: dict, target: Path) -> None:
    target = target.resolve()
    if any(target == root or root in target.parents for root in protected_roots(plan)):
        raise RunnerError("PRE-D artifacts must be outside the protected application repository")


def snapshot_sources(roots: list[Path]) -> dict:
    """Hash bounded regular files without importing code or retaining file contents."""
    files, issues = {}, []
    total = 0
    for index, root in enumerate(roots):
        root = root.resolve()
        def onerror(_error):
            issues.append({"root": index, "reason": "unreadable_directory"})
        for folder, dirs, names in os.walk(root, followlinks=False, onerror=onerror):
            kept = []
            for name in sorted(dirs):
                if name in EXCLUDED:
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
                if len(files) >= MAX_FILES:
                    issues.append({"reason": "file_limit"})
                    return _snapshot(roots, files, issues, total)
                try:
                    before = path.lstat()
                    if linked(path) or not stat.S_ISREG(before.st_mode):
                        issues.append({"path": key, "reason": "nonregular_file_not_read"})
                        continue
                    if total + before.st_size > MAX_BYTES:
                        issues.append({"reason": "byte_limit"})
                        return _snapshot(roots, files, issues, total)
                    digest = hashlib.sha256()
                    with path.open("rb") as handle:
                        opened = os.fstat(handle.fileno())
                        if (opened.st_ino, opened.st_dev) != (before.st_ino, before.st_dev):
                            raise OSError("Source changed while opening")
                        while chunk := handle.read(65536):
                            total += len(chunk)
                            if total > MAX_BYTES:
                                issues.append({"reason": "byte_limit"})
                                return _snapshot(roots, files, issues, total)
                            digest.update(chunk)
                    after = path.stat()
                    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                        issues.append({"path": key, "reason": "file_changed_while_reading"})
                    files[key] = digest.hexdigest()
                except OSError:
                    issues.append({"path": key, "reason": "unreadable_file"})
    return _snapshot(roots, files, issues, total)


def _snapshot(roots: list[Path], files: dict, issues: list, total: int) -> dict:
    result = {"schema_version": SNAPSHOT, "roots": [str(r.resolve()) for r in roots],
              "files": files, "issues": issues, "bytes_hashed": total,
              "status": "incomplete" if issues else "complete" if roots else "not_configured",
              "excluded_directories": sorted(EXCLUDED)}
    result["snapshot_sha256"] = sha256(result)
    return result


def source_diff(before: dict, after: dict) -> dict:
    a, b = before.get("files", {}), after.get("files", {})
    rows = [{"path": p, "change": "added" if p not in a else "removed" if p not in b else "modified",
             "before_sha256": a.get(p), "after_sha256": b.get(p)}
            for p in sorted(set(a) | set(b)) if a.get(p) != b.get(p)]
    return {"status": "changed" if rows or before.get("roots") != after.get("roots") else
            "incomplete" if "incomplete" in {before.get("status"), after.get("status")} else
            "not_configured" if after.get("status") == "not_configured" else "unchanged",
            "before_sha256": before.get("snapshot_sha256"), "after_sha256": after.get("snapshot_sha256"),
            "files": rows, "changed_file_count": len(rows)}


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
        current = snapshot_sources(roots)
        if current["status"] != "complete":
            blockers.append("Source fingerprint is incomplete; review unreadable files, links or scan limits")
        if not isinstance(expected, dict) or source_diff(expected, current)["status"] != "unchanged":
            blockers.append("Application source changed since setup; refresh the profile and review before execution")
    return blockers
