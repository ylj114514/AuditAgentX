"""Semgrep 扫描器封装（通用代码安全规则）。"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.config import settings
from backend.scanners.base import BaseScanner, RawFinding, normalize_severity, redact_secret_text

logger = logging.getLogger(__name__)


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    cli = "semgrep"

    # 项目自定义 taint mode 规则目录
    custom_rules_dir = Path(__file__).resolve().parent.parent.parent / "rules" / "semgrep"

    def __init__(self) -> None:
        self.degraded_reason: str | None = None
        self.batch_status: list[dict[str, Any]] = []

    def run(self, target: Path) -> list[RawFinding]:
        if not self.available():
            return []
        original_target = Path(target).resolve()
        if not original_target.exists():
            raise FileNotFoundError(f"Semgrep target not found: {original_target}")
        if not (original_target.is_file() or original_target.is_dir()):
            raise ValueError(f"Unsupported Semgrep target type: {original_target}")
        max_files = _safe_max_files(getattr(self, "max_files", 20000))
        include_test_findings = bool(getattr(self, "include_test_findings", False))
        # Semgrep/OCaml core on Windows is brittle when cwd/config/target paths
        # contain non-ASCII characters. Run it from a pure-ASCII temp workspace so
        # Semgrep actually executes instead of hanging/crashing on this repo path.
        work_root, scan_root, rules_root, workspace_status = _prepare_ascii_semgrep_workspace(
            Path(target), self.custom_rules_dir, max_files=max_files,
            include_test_findings=include_test_findings,
        )
        self.workspace_status = workspace_status
        try:
            # 不再使用 `--config auto`：auto 在真实项目上会加载过宽规则集。
            # 官方语言包逐个执行，避免一个语言包超时导致 Semgrep 整体 0 结果。
            batches = _plan_semgrep_batches(
                scan_root, rules_root, max_files=max_files,
                include_test_findings=include_test_findings,
            )
            self.batch_status = []
            if not batches:
                copied_files = int(workspace_status.get("copied_files") or 0)
                coverage_status = "not_scanned" if copied_files else "not_applicable"
                reason = "no applicable rule batches"
                workspace_status["coverage_status"] = coverage_status
                workspace_status["reason"] = _append_batch_error(
                    workspace_status.get("reason"), reason,
                )
                self.degraded_reason = f"semgrep {workspace_status['reason']}"
                self.batch_status.append({
                    "name": "planning",
                    "config": None,
                    "command_count": 0,
                    "target_file_count": copied_files,
                    "success": False,
                    "partial_results": False,
                    "error": reason,
                    "finding_count": 0,
                })
                return []
            # 关键：强制 UTF-8。中文 Windows 默认 GBK，semgrep 读含 UTF-8 规则文件会崩（exit 2）
            env = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
            findings: list[RawFinding] = []
            batch_errors: list[str] = []
            if workspace_status["truncated"]:
                batch_errors.append(f"workspace: {workspace_status['reason']}")
            completed_batches = 0
            seen: set[tuple[str, str, int, str]] = set()

            for batch in batches:
                commands = _build_semgrep_commands(batch, scan_root)
                batch_completed = False
                batch_finding_count = 0
                batch_error: str | None = None
                batch_recovery: str | None = None
                batch_coverage_gaps: list[dict[str, str]] = []
                for command_name, cmd in commands:
                    try:
                        proc = self._exec(
                            cmd, cwd=work_root,
                            timeout=int(getattr(settings, "semgrep_batch_timeout", 300)),
                            env=env)
                        batch_findings, degraded = _parse_semgrep_process(
                            scan_root, proc, original_target=original_target,
                        )
                        batch_completed = True
                        batch_finding_count += len(batch_findings)
                        if degraded and _is_parser_degradation(degraded):
                            scoped_gaps = _scoped_parser_coverage_gaps(proc, scan_root)
                            if scoped_gaps:
                                batch_coverage_gaps.extend(scoped_gaps)
                                batch_error = _append_batch_error(
                                    batch_error, f"{command_name}: {degraded}",
                                )
                                batch_recovery = (
                                    "not required: parser failures already scoped to "
                                    f"{len(scoped_gaps)} file(s)"
                                )
                                recovered, recovery_errors = None, []
                            else:
                                recovered, recovery_errors = self._retry_failed_file_command(
                                    batch, cmd, work_root, scan_root, original_target, env,
                                )
                            if recovered is not None:
                                recovered_findings, recovered_count = recovered
                                batch_finding_count += len(recovered_findings)
                                for finding in recovered_findings:
                                    key = (finding.rule_id, finding.file, finding.line, finding.message)
                                    if key in seen:
                                        continue
                                    seen.add(key)
                                    findings.append(finding)
                                if recovery_errors:
                                    batch_recovery = (
                                        f"recovered {recovered_count} file(s); "
                                        f"isolated {len(_parser_coverage_gaps(recovery_errors))} parser-unsupported file(s)"
                                    )
                                    batch_coverage_gaps.extend(
                                        _parser_coverage_gaps(recovery_errors)
                                    )
                                    batch_error = _append_batch_error(
                                        batch_error, "; ".join(recovery_errors),
                                    )
                                else:
                                    batch_recovery = (
                                        f"recovered {recovered_count} file(s) after {degraded}"
                                    )
                            else:
                                batch_error = _append_batch_error(
                                    batch_error, f"{command_name}: {degraded}",
                                )
                        elif degraded:
                            batch_error = _append_batch_error(
                                batch_error, f"{command_name}: {degraded}",
                            )
                            batch_recovery = _recovery_not_attempted_reason(degraded)
                        for finding in batch_findings:
                            key = (finding.rule_id, finding.file, finding.line, finding.message)
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append(finding)
                    except Exception as exc:  # noqa: BLE001  Retry file lists before marking a whole batch failed.
                        command_error = _sanitize_semgrep_detail(_short_error(exc), work_root)
                        recovered, recovery_errors = (None, [])
                        if _is_parser_degradation(command_error):
                            recovered, recovery_errors = self._retry_failed_file_command(
                                batch, cmd, work_root, scan_root, original_target, env,
                            )
                        if recovered is not None:
                            recovered_findings, recovered_count = recovered
                            batch_completed = batch_completed or recovered_count > 0
                            batch_finding_count += len(recovered_findings)
                            for finding in recovered_findings:
                                key = (finding.rule_id, finding.file, finding.line, finding.message)
                                if key in seen:
                                    continue
                                seen.add(key)
                                findings.append(finding)
                            if recovery_errors:
                                batch_recovery = (
                                    f"recovered {recovered_count} file(s); "
                                    f"isolated {len(_parser_coverage_gaps(recovery_errors))} parser-unsupported file(s)"
                                )
                                batch_coverage_gaps.extend(
                                    _parser_coverage_gaps(recovery_errors)
                                )
                                batch_error = _append_batch_error(
                                    batch_error, "; ".join(recovery_errors),
                                )
                            else:
                                batch_recovery = f"recovered {recovered_count} file(s) after {command_error}"
                            continue
                        batch_error = _append_batch_error(batch_error, f"{command_name}: {command_error}")
                        batch_recovery = _recovery_not_attempted_reason(command_error)
                        logger.warning("semgrep batch command failed: %s: %s", command_name, exc)
                if batch_completed:
                    completed_batches += 1
                if batch_error:
                    batch_errors.append(f"{batch['name']}: {batch_error}")
                self.batch_status.append({
                    "name": batch["name"],
                    "config": _batch_config_label(batch),
                    "command_count": len(commands),
                    "target_file_count": len(batch.get("target_files") or []),
                    "success": batch_completed and not batch_error,
                    "partial_results": batch_completed and bool(batch_error),
                    "error": batch_error,
                    "recovery": batch_recovery,
                    "coverage_missing_files": _unique_coverage_gaps(batch_coverage_gaps),
                    "finding_count": batch_finding_count,
                })

            if batch_errors:
                prefix = "partial rule batch failures" if findings or completed_batches else "all rule batches failed"
                self.degraded_reason = f"semgrep {prefix}: {'; '.join(batch_errors)[:260]}"
            return findings
        finally:
            shutil.rmtree(work_root, ignore_errors=True)

    def _retry_failed_file_command(self, batch: dict[str, Any], command: list[str],
                                   work_root: Path, scan_root: Path, original_target: Path,
                                   env: dict[str, str],
                                   ) -> tuple[tuple[list[RawFinding], int] | None, list[str]]:
        """Bisect a failed explicit file chunk until bad source files are isolated.

        Standard language profiles scan a root directory and are deliberately not
        retried file-by-file. Local C/C++ rules use explicit, bounded chunks, so
        binary isolation preserves healthy source files without restarting Semgrep
        once for every file in a parser-degraded chunk.
        """
        target_files = _command_target_files(batch, command)
        directory_mode_recovery = not bool(target_files)
        if not target_files:
            # Directory-mode language profiles are fast in the healthy path, but
            # Semgrep does not identify an exact bad source file until it parses
            # the directory. On degradation, recover with bounded explicit files.
            suffixes = {str(item).lower() for item in (batch.get("suffixes") or [])}
            target_files = _select_source_files(
                scan_root, suffixes, max_files=_safe_max_files(getattr(self, "max_files", 20000)),
                include_test_findings=bool(batch.get("include_test_findings", False)),
            ) if suffixes else []
        if len(target_files) < 2:
            return None, []

        def scan_group(files: list[str]) -> tuple[list[RawFinding], int, list[str]]:
            try:
                proc = self._exec(
                    _build_semgrep_base_command(batch) + files, cwd=work_root,
                    timeout=int(getattr(settings, "semgrep_batch_timeout", 300)), env=env,
                )
                group_findings, degraded = _parse_semgrep_process(
                    scan_root, proc, original_target=original_target,
                )
            except Exception as exc:  # noqa: BLE001  Preserve the exact failed file in scanner status.
                if len(files) == 1:
                    return [], 0, [f"{_coverage_file_label(files[0], scan_root)}: {_short_error(exc)}"]
                group_findings = []
                degraded = _short_error(exc)

            if not degraded:
                return group_findings, len(files), []
            if len(files) == 1:
                return group_findings, 1, [f"{_coverage_file_label(files[0], scan_root)}: {degraded}"]

            midpoint = len(files) // 2
            left_findings, left_completed, left_errors = scan_group(files[:midpoint])
            right_findings, right_completed, right_errors = scan_group(files[midpoint:])
            return (
                left_findings + right_findings,
                left_completed + right_completed,
                left_errors + right_errors,
            )

        if not directory_mode_recovery:
            # Existing explicit-file batches have already failed once as a group;
            # immediately bisect instead of paying for an identical second run.
            midpoint = len(target_files) // 2
            left_findings, left_completed, left_errors = scan_group(target_files[:midpoint])
            right_findings, right_completed, right_errors = scan_group(target_files[midpoint:])
            return (
                (left_findings + right_findings, left_completed + right_completed),
                left_errors + right_errors,
            )

        # Directory-mode recovery starts with bounded explicit chunks, keeping
        # Windows command lines safe before recursively isolating bad files.
        chunk_size = max(1, min(int(batch.get("recovery_file_chunk_size") or 80), 80))
        recovered_findings: list[RawFinding] = []
        recovered_count = 0
        recovery_errors: list[str] = []
        for index in range(0, len(target_files), chunk_size):
            group_findings, group_completed, group_errors = scan_group(target_files[index:index + chunk_size])
            recovered_findings.extend(group_findings)
            recovered_count += group_completed
            recovery_errors.extend(group_errors)
        return (
            (recovered_findings, recovered_count), recovery_errors,
        )


_EXCLUDED_SCAN_PARTS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "reports",
    ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    "thirdparty", "third_party", "third-party", "tests", "test", "__tests__", "sample", "samples",
    "example", "examples", "demo", "docs", "doc",
    "box2d", "imgui", "glfw", "tinyxml",
}
_TEST_SCAN_PARTS = {
    "tests", "test", "__tests__", "sample", "samples", "example", "examples", "demo", "docs", "doc",
}
_LOCKFILE_NAMES = {
    "pnpm-lock.yaml", "yarn.lock", "package-lock.json", "npm-shrinkwrap.json",
    "composer.lock", "poetry.lock", "pdm.lock", "cargo.lock", "gemfile.lock", "go.sum",
}
_TEST_FILE_NAME = re.compile(r"(?:^test_.+|.+\.(?:test|spec)\.[^.]+)$", re.IGNORECASE)
_LARGE_DIRECTORY_BATCH_FILE_CHUNK_SIZE = 200

_LANGUAGE_PROFILES: tuple[dict[str, Any], ...] = (
    {"name": "python", "suffixes": {".py"}, "configs": ["p/python"], "includes": ["**/*.py"]},
    {"name": "javascript", "suffixes": {".js", ".jsx"}, "configs": ["p/javascript"], "includes": ["**/*.js", "**/*.jsx"]},
    {"name": "typescript", "suffixes": {".ts", ".tsx"}, "configs": ["p/typescript"], "includes": ["**/*.ts", "**/*.tsx"]},
    # The Java community ruleset can exceed the process timeout when pointed at
    # thousands of benchmark classes in one invocation.  Large Java sets are
    # therefore passed as bounded explicit source-file chunks below.
    {"name": "java", "suffixes": {".java"}, "configs": ["p/java"], "includes": ["**/*.java"],
     # 200 absolute Windows paths stays safely below the CreateProcess command
     # line limit while remaining much smaller than the former whole-project run.
     "target_file_chunk_size": 200},
    {"name": "php", "suffixes": {".php"}, "configs": ["p/php"], "includes": ["**/*.php"]},
    {"name": "go", "suffixes": {".go"}, "configs": ["p/golang"], "includes": ["**/*.go"]},
    {"name": "ruby", "suffixes": {".rb"}, "configs": ["p/ruby"], "includes": ["**/*.rb"]},
    {"name": "csharp", "suffixes": {".cs"}, "configs": ["p/csharp"], "includes": ["**/*.cs"]},
    # GitHub Actions workflows are executable project code too. Without a YAML
    # profile, YAML-only repositories planned zero Semgrep batches and silently
    # returned no findings even when the workflow contained shell injection.
    {"name": "github-actions", "suffixes": {".yml", ".yaml"}, "configs": ["p/github-actions"],
     "includes": ["**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"]},
    {"name": "c", "suffixes": {".c", ".h"}, "configs": ["p/c"], "includes": ["**/*.c", "**/*.h"]},
    {"name": "cpp", "suffixes": {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}, "configs": [], "includes": ["**/*.cpp", "**/*.cc", "**/*.cxx", "**/*.hpp", "**/*.hh", "**/*.hxx"]},
)


def _prepare_ascii_semgrep_workspace(target: Path, custom_rules_dir: Path, *,
                                     max_files: int = 20000,
                                     include_test_findings: bool = False,
                                     max_total_bytes: int = 512 * 1024 * 1024,
                                     max_file_bytes: int = 500_000,
                                     ) -> tuple[Path, Path, Path, dict[str, Any]]:
    """Copy target and local Semgrep rules to an ASCII temp path for Windows Semgrep."""
    work_root = Path(tempfile.mkdtemp(
        prefix="auditagentx_semgrep_", dir=str(_ascii_temp_base()),
    ))
    scan_root = work_root / "src"
    rules_root = work_root / "rules"
    target = Path(target).resolve()

    workspace_status: dict[str, Any]
    if target.is_file():
        scan_root.mkdir(parents=True, exist_ok=True)
        size = target.stat().st_size
        if size <= max_file_bytes:
            shutil.copy2(target, scan_root / target.name)
            workspace_status = {
                "copied_files": 1, "copied_bytes": size, "skipped_large_files": 0,
                "truncated": False, "reason": None, "coverage_status": "complete",
                "coverage_missing_files": [],
            }
        else:
            workspace_status = {
                "copied_files": 0, "copied_bytes": 0, "skipped_large_files": 1,
                "truncated": True, "reason": f"target exceeds {max_file_bytes} byte file limit",
                "coverage_status": "partial",
                "coverage_missing_files": [{"file": target.name, "reason": "file_size_limit"}],
            }
    else:
        workspace_status = _copy_semgrep_sources(
            target, scan_root, max_files=max_files,
            include_test_findings=include_test_findings,
            max_total_bytes=max_total_bytes,
            max_file_bytes=max_file_bytes,
        )

    if custom_rules_dir.exists():
        shutil.copytree(custom_rules_dir, rules_root, ignore=_ignore_for_semgrep_copy)
    return work_root, scan_root, rules_root, workspace_status


def _ascii_temp_base() -> Path:
    candidates = [Path(tempfile.gettempdir())]
    if os.name == "nt":
        candidates.append(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp")
    else:
        candidates.append(Path("/tmp"))
    for candidate in candidates:
        try:
            if str(candidate).isascii() and candidate.is_dir() and os.access(candidate, os.W_OK):
                return candidate
        except OSError:
            continue
    raise RuntimeError("Semgrep requires a writable ASCII-only temporary directory")


def _copy_semgrep_sources(target: Path, destination: Path, *, max_files: int,
                          include_test_findings: bool = False,
                          max_total_bytes: int = 512 * 1024 * 1024,
                          max_file_bytes: int = 500_000) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True)
    copied = 0
    copied_bytes = 0
    skipped_large = 0
    coverage_missing_files: list[dict[str, str]] = []
    truncated = False
    reason: str | None = None
    for directory, dirnames, filenames in os.walk(target, followlinks=False):
        rel_dir = Path(directory).relative_to(target)
        dirnames[:] = sorted(
            name for name in dirnames
            if not _path_has_excluded_part(
                (*rel_dir.parts, name), include_test_findings=include_test_findings,
            )
        )
        for filename in sorted(filenames):
            path = Path(directory) / filename
            if (path.is_symlink()
                    or _path_has_excluded_part(
                        (*rel_dir.parts, filename), include_test_findings=include_test_findings,
                    )
                    or not _is_semgrep_candidate(path)):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > max_file_bytes:
                skipped_large += 1
                if len(coverage_missing_files) < 100:
                    coverage_missing_files.append({
                        "file": path.relative_to(target).as_posix(),
                        "reason": "file_size_limit",
                    })
                continue
            if copied >= max_files:
                truncated = True
                reason = f"source file limit reached ({max_files})"
                break
            if copied_bytes + size > max_total_bytes:
                truncated = True
                reason = f"workspace byte limit reached ({max_total_bytes})"
                break
            rel = path.relative_to(target)
            output = destination / rel
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, output)
            copied += 1
            copied_bytes += size
        if truncated:
            break
    if skipped_large:
        large_file_reason = f"source file size limit skipped {skipped_large} file(s)"
        reason = _append_batch_error(reason, large_file_reason)
        truncated = True
    return {
        "copied_files": copied,
        "copied_bytes": copied_bytes,
        "skipped_large_files": skipped_large,
        "truncated": truncated,
        "reason": reason,
        "coverage_status": "partial" if truncated else "complete",
        "coverage_missing_files": coverage_missing_files,
    }


def _is_semgrep_candidate(path: Path) -> bool:
    if path.name.lower() in _LOCKFILE_NAMES:
        return False
    supported_suffixes = {
        suffix for profile in _LANGUAGE_PROFILES for suffix in profile["suffixes"]
    }
    supported_suffixes.update({".html", ".htm", ".vue", ".json", ".xml", ".sh", ".bash"})
    manifests = {
        "dockerfile", "requirements.txt", "pyproject.toml", "pipfile",
        "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
        "composer.json", "go.mod", "gemfile",
    }
    return path.suffix.lower() in supported_suffixes or path.name.lower() in manifests


def _safe_max_files(value: Any) -> int:
    try:
        return max(1, min(int(value), 200000))
    except (TypeError, ValueError):
        return 20000


def _ignore_for_semgrep_copy(directory: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        lowered = str(name).lower()
        if lowered in _EXCLUDED_SCAN_PARTS:
            ignored.add(name)
        elif lowered.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z")):
            ignored.add(name)
    return ignored


def _plan_semgrep_batches(target: Path, custom_rules_dir: Path, *,
                          max_files: int = 20000,
                          include_test_findings: bool = False) -> list[dict[str, Any]]:
    """Plan isolated Semgrep batches; one slow language pack must not poison all results."""
    suffixes = _detect_source_suffixes(
        target, max_files=max_files, include_test_findings=include_test_findings,
    )
    batches: list[dict[str, Any]] = []
    includes_by_language: dict[str, list[str]] = {}
    for profile in _LANGUAGE_PROFILES:
        if suffixes & set(profile["suffixes"]):
            includes = list(profile["includes"])
            includes_by_language[profile["name"]] = includes
            for config in profile["configs"]:
                batch = {
                    "name": f"{profile['name']}:{config}",
                    "config": config,
                    "includes": includes,
                    "suffixes": set(profile["suffixes"]),
                    "include_test_findings": include_test_findings,
                }
                _assign_bounded_source_targets(batch, target, max_files=max_files)
                batches.append(batch)
    local_batches = _plan_local_rule_batches(
        custom_rules_dir, target, includes_by_language, max_files=max_files,
        include_test_findings=include_test_findings,
    )
    if local_batches:
        # Keep local rules first and split by language so a heavyweight Python taint
        # rule does not slow down C/C++ scans, and vice versa.
        batches = local_batches + batches
    return batches


def _plan_local_rule_batches(custom_rules_dir: Path, target: Path,
                             includes_by_language: dict[str, list[str]], *,
                             max_files: int = 20000,
                             include_test_findings: bool = False) -> list[dict[str, Any]]:
    batches: list[dict[str, Any]] = []
    python_rule = custom_rules_dir / "taint_injection.yaml"
    if python_rule.exists() and includes_by_language.get("python"):
        batch = {
            "name": "local-python-taint",
            "config": str(python_rule),
            "includes": includes_by_language["python"],
            "suffixes": {".py"},
            "include_test_findings": include_test_findings,
        }
        _assign_bounded_source_targets(batch, target, max_files=max_files)
        batches.append(batch)
    c_cpp_rule = custom_rules_dir / "c_cpp_security.yaml"
    c_cpp_includes = []
    c_cpp_includes.extend(includes_by_language.get("c") or [])
    c_cpp_includes.extend(includes_by_language.get("cpp") or [])
    if c_cpp_rule.exists() and c_cpp_includes:
        batch = {
            "name": "local-c-cpp-security",
            "config": str(c_cpp_rule),
            "includes": list(dict.fromkeys(c_cpp_includes)),
            "suffixes": {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"},
            "include_test_findings": include_test_findings,
        }
        # C/C++ custom rules already use explicit files for compatibility with
        # their mixed-language include set.  Keep that established behavior.
        batch["target_files"] = _select_source_files(
            target, set(batch["suffixes"]), max_files=max_files,
            include_test_findings=include_test_findings, includes=batch["includes"],
        )
        if len(batch["target_files"]) > _LARGE_DIRECTORY_BATCH_FILE_CHUNK_SIZE:
            batch["target_file_chunk_size"] = _LARGE_DIRECTORY_BATCH_FILE_CHUNK_SIZE
        batches.append(batch)
    return batches


def _assign_bounded_source_targets(batch: dict[str, Any], target: Path, *, max_files: int) -> None:
    """Use explicit bounded targets only when a directory batch is genuinely large.

    A single directory invocation is efficient for ordinary repositories but can
    exceed the process budget on benchmark-scale source sets.  Explicit chunks
    retain the same config, excludes and eligible files without introducing a
    project-specific timeout or rule exception.
    """
    chunk_size = int(batch.get("target_file_chunk_size") or _LARGE_DIRECTORY_BATCH_FILE_CHUNK_SIZE)
    target_files = _select_source_files(
        target, set(batch.get("suffixes") or set()), max_files=max_files,
        include_test_findings=bool(batch.get("include_test_findings", False)),
        includes=batch.get("includes") or [],
    )
    if len(target_files) > chunk_size:
        batch["target_files"] = target_files
        batch["target_file_chunk_size"] = chunk_size


def _select_source_files(root: Path | None, suffixes: set[str], *, max_files: int = 20000,
                         include_test_findings: bool = False,
                         includes: list[str] | None = None) -> list[str]:
    if root is None or not root.exists():
        return []
    selected: list[str] = []
    # Filesystem enumeration order differs across OS/filesystems. Keep command
    # chunks deterministic so parser-recovery bisection and its evidence remain
    # reproducible in CI and local scans.
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root)).casefold()):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if _path_has_excluded_part(path.parts, include_test_findings=include_test_findings):
            continue
        relative = path.relative_to(root).as_posix()
        if includes and not _matches_semgrep_include(relative, includes):
            continue
        selected.append(str(path))
        if len(selected) >= max_files:
            break
    return selected


def _matches_semgrep_include(relative_path: str, includes: list[str]) -> bool:
    """Match a workspace-relative path against Semgrep include globs.

    ``**/`` may match zero directories in Semgrep, while Python's fnmatch
    requires at least the literal prefix.  Check both forms to keep explicit
    file batches equivalent to the previous directory batch scope.
    """
    path = str(relative_path).replace("\\", "/")
    for include in includes:
        pattern = str(include).replace("\\", "/")
        if fnmatchcase(path, pattern):
            return True
        if pattern.startswith("**/") and fnmatchcase(path, pattern[3:]):
            return True
    return False


def _append_batch_error(current: str | None, new_error: str) -> str:
    if not current:
        return new_error[:260]
    return f"{current}; {new_error}"[:260]


def _coverage_file_label(path: str, scan_root: Path) -> str:
    """Return a project-relative source label without leaking temp workspace paths."""
    try:
        return Path(path).resolve().relative_to(scan_root.resolve()).as_posix()
    except (OSError, ValueError):
        return Path(path).name


def _parser_coverage_gaps(errors: list[str]) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    for error in errors:
        file, separator, _detail = str(error).partition(": ")
        if not separator or not file:
            continue
        gaps.append({"file": file.replace("\\", "/"), "reason": "parser_unsupported"})
    return gaps


def _scoped_parser_coverage_gaps(proc: subprocess.CompletedProcess,
                                 scan_root: Path) -> list[dict[str, str]]:
    """Extract parser-error file paths already named by Semgrep's JSON response.

    A directory scan with a named parser failure has still examined the other
    source files. Re-running the entire language set only to rediscover the
    same named files wastes the scan budget and does not improve coverage.
    """
    try:
        payload = json.loads(proc.stdout or "{}")
    except (TypeError, json.JSONDecodeError):
        return []
    gaps: list[dict[str, str]] = []
    for error in payload.get("errors") or []:
        if not isinstance(error, dict):
            continue
        detail = " ".join(str(error.get(key) or "") for key in (
            "message", "long_msg", "type", "path",
        ))
        if not _is_parser_degradation(detail):
            continue
        relative = _relative_parser_error_path(detail, scan_root)
        if relative:
            gaps.append({"file": relative, "reason": "parser_unsupported"})
    return _unique_coverage_gaps(gaps)


def _relative_parser_error_path(detail: str, scan_root: Path) -> str | None:
    """Return a project-relative file path from a Semgrep parser diagnostic."""
    text = str(detail or "")
    root = str(Path(scan_root).resolve())
    for prefix in (root, root.replace("\\", "/"), root.replace("/", "\\")):
        index = text.lower().find(prefix.lower())
        if index < 0:
            continue
        remainder = text[index + len(prefix):].lstrip("\\/")
        if not remainder:
            continue
        # Semgrep emits ``path/to/file.tsx:line: message``. Split only the
        # diagnostic line suffix after the workspace root has been removed.
        match = re.match(r"(.+?\.[A-Za-z0-9]+)(?::\d+(?::|$))", remainder)
        if not match:
            continue
        candidate = match.group(1).replace("\\", "/")
        if candidate and not candidate.startswith("../"):
            return candidate
    return None


def _unique_coverage_gaps(gaps: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for gap in gaps:
        file = str(gap.get("file") or "")
        reason = str(gap.get("reason") or "")
        key = (file, reason)
        if not file or key in seen:
            continue
        seen.add(key)
        unique.append({"file": file, "reason": reason})
    return unique


def _batch_config_label(batch: dict[str, Any]) -> str:
    config = str(batch.get("config") or "")
    if str(batch.get("name") or "").startswith("local-"):
        return f"local/{Path(config).name}"
    return config


def _command_target_files(batch: dict[str, Any], command: list[str]) -> list[str]:
    command_values = {str(value) for value in command}
    return [
        str(target_file) for target_file in batch.get("target_files") or []
        if str(target_file) in command_values
    ]


def _build_semgrep_command(batch: dict[str, Any], target: Path) -> list[str]:
    cmd = ["semgrep", "scan", "--config", str(batch["config"])]
    # 尊重 .gitignore 并显式排除生成物/依赖，避免把 vendored code 和报告当成本项目漏洞。
    cmd += _semgrep_common_args(bool(batch.get("include_test_findings", False)))
    for include in batch.get("includes") or []:
        cmd += ["--include", str(include)]
    cmd.append(str(target))
    return cmd


def _build_semgrep_commands(batch: dict[str, Any], target: Path) -> list[tuple[str, list[str]]]:
    target_files = list(batch.get("target_files") or [])
    if not target_files:
        return [(str(batch["name"]), _build_semgrep_command(batch, target))]
    commands: list[tuple[str, list[str]]] = []
    chunk_size = max(1, int(batch.get("target_file_chunk_size") or 40))
    for index in range(0, len(target_files), chunk_size):
        chunk = target_files[index:index + chunk_size]
        cmd = _build_semgrep_base_command(batch)
        cmd.extend(chunk)
        suffix = f"{index // chunk_size + 1}/{(len(target_files) + chunk_size - 1) // chunk_size}"
        commands.append((f"{batch['name']}[{suffix}]", cmd))
    return commands


def _build_semgrep_base_command(batch: dict[str, Any]) -> list[str]:
    cmd = ["semgrep", "scan", "--config", str(batch["config"])]
    cmd += _semgrep_common_args(bool(batch.get("include_test_findings", False)))
    return cmd


def _semgrep_common_args(include_test_findings: bool = False) -> list[str]:
    args = [
        # Semgrep on Windows can be slow even without `auto`; keep rule/file work bounded.
        "--disable-version-check", "--jobs", "4", "--json", "--quiet",
        "--timeout", "3", "--timeout-threshold", "1",
        "--max-target-bytes", "500000",
        "--exclude", "node_modules", "--exclude", "vendor", "--exclude", "dist",
        "--exclude", "build", "--exclude", "reports",
        # 生成后的压缩包和明确的第三方前端组件不属于项目源代码。继续扫描它们
        # 会把 jQuery/UEditor/DPlayer 内部实现当成项目漏洞，且无法给出可修复位置。
        "--exclude", "**/*.min.js", "--exclude", "**/*.map",
        "--exclude", "**/third-party/**", "--exclude", "**/third_party/**",
        "--exclude", "**/thirdparty/**", "--exclude", "**/ThirdParty/**",
        "--exclude", "**/Box2D/**", "--exclude", "**/imgui/**",
        "--exclude", "**/glfw/**", "--exclude", "**/Tinyxml/**",
        "--exclude", "**/ueditor/**", "--exclude", "**/dplayer/**", "--exclude", "**/layui/**",
    ]
    if not include_test_findings:
        args += [
            "--exclude", "**/tests/**", "--exclude", "**/test/**",
            "--exclude", "**/__tests__/**", "--exclude", "**/*.test.*", "--exclude", "**/*.spec.*",
            "--exclude", "**/sample/**", "--exclude", "**/samples/**",
            "--exclude", "**/example/**", "--exclude", "**/examples/**",
            "--exclude", "**/demo/**", "--exclude", "**/docs/**", "--exclude", "**/doc/**",
        ]
    return args


def _parse_semgrep_process(target: Path, proc: subprocess.CompletedProcess, *,
                           original_target: Path | None = None) -> tuple[list[RawFinding], str | None]:
    if not (proc.stdout or "").strip():
        raise RuntimeError(
            f"no JSON output (exit={proc.returncode}): {_clean_stderr(proc.stderr)[:180]}"
        )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        logger.warning("semgrep 执行失败(exit=%s)，未产出有效 JSON。stderr: %s",
                       proc.returncode, (proc.stderr or "")[:500])
        raise RuntimeError(f"invalid JSON output: {_clean_stderr(proc.stderr)[:180]}") from exc
    if not isinstance(data.get("results"), list):
        raise RuntimeError("JSON response missing results array")
    if proc.returncode != 0 and not data.get("results"):
        raise RuntimeError(f"exit={proc.returncode}: {_clean_stderr(proc.stderr)[:180]}")

    degraded: str | None = None
    semgrep_errors = data.get("errors") or []
    if semgrep_errors or proc.returncode != 0:
        # Keep valid findings, but parsing/skipped-target warnings mean coverage
        # was incomplete and must be surfaced as partial rather than full success.
        first = semgrep_errors[0] if semgrep_errors else {"message": proc.stderr}
        detail = first.get("message") or first.get("long_msg") or first.get("type") or str(first)
        degraded = _sanitize_semgrep_detail(str(detail), target)[:180]

    findings: list[RawFinding] = []
    for r in data.get("results", []):
        finding = _raw_finding_from_semgrep_result(
            target, r, original_target=original_target,
        )
        if finding is not None:
            findings.append(finding)
    return findings, degraded


def _raw_finding_from_semgrep_result(target: Path, r: dict[str, Any], *,
                                     original_target: Path | None = None) -> RawFinding | None:
    extra = r.get("extra", {})
    check_id = r.get("check_id", "")
    result_path = r.get("path", "")
    evidence_root = _evidence_root_for_result(target, original_target, result_path)
    if _framework_rule_mismatch(evidence_root, result_path, check_id):
        return None
    start_line = r.get("start", {}).get("line", 0)
    end_line = r.get("end", {}).get("line") or start_line
    rel_path = normalize_result_path(evidence_root, result_path)
    tool_lines = extra.get("lines", "") or ""
    source_snippet = read_source_snippet(evidence_root, result_path, start_line, end_line)
    finding_type = _finding_type(check_id or "semgrep-finding", extra.get("metadata") or {})
    code_snippet = _choose_source_snippet(tool_lines, source_snippet)
    message = extra.get("message", "")
    if finding_type == "Hardcoded Secret":
        code_snippet = redact_secret_text(code_snippet)
        message = redact_secret_text(message)
        tool_lines = redact_secret_text(tool_lines)
        source_snippet = redact_secret_text(source_snippet)
    return RawFinding(
        type=finding_type,
        file=rel_path,
        line=start_line,
        severity=normalize_severity(extra.get("severity", "warning")),
        source=SemgrepScanner.name,
        code_snippet=code_snippet,
        message=message,
        rule_id=check_id,
        extra=_semgrep_extra(extra, tool_lines, source_snippet, r),
    )


def _evidence_root_for_result(scan_root: Path, original_target: Path | None,
                              result_path: str) -> Path:
    """Choose the root that actually owns a Semgrep result path.

    Normal runs report paths inside the ASCII scan copy. Some Semgrep versions,
    wrappers, and test doubles preserve the original absolute path instead. Both
    forms must resolve to the same project-relative evidence contract.
    """
    if original_target is not None:
        try:
            candidate = Path(str(result_path or "")).resolve()
            candidate.relative_to(Path(original_target).resolve())
            return Path(original_target).resolve()
        except (OSError, ValueError):
            pass
    return Path(scan_root).resolve()


def _short_error(exc: Exception) -> str:
    if isinstance(exc, subprocess.TimeoutExpired):
        return f"timed out after {int(exc.timeout or 0)}s"
    text = str(exc) or exc.__class__.__name__
    return " ".join(text.split())[:180]


def _is_parser_degradation(detail: str | None) -> bool:
    """Whether Semgrep identified a source parsing problem worth isolating.

    A batch timeout, engine failure, invalid JSON, or network failure says nothing
    about a particular input file.  Retrying those failures over every source file
    destroys the scan budget and creates misleading ``parser_unsupported`` gaps.
    """
    text = str(detail or "").lower()
    if any(token in text for token in ("timed out", "timeout", "deadline exceeded")):
        return False
    return any(token in text for token in (
        "parser", "parse error", "parse failure", "parse warning", "parsing error",
        "syntax error", "lexical error",
    ))


def _recovery_not_attempted_reason(detail: str | None) -> str | None:
    """Return an auditable reason when file isolation is intentionally skipped."""
    text = str(detail or "").lower()
    if any(token in text for token in ("timed out", "timeout", "deadline exceeded")):
        return "not attempted: execution_timeout"
    return "not attempted: non_parser_batch_failure"


def _sanitize_semgrep_detail(detail: str, temp_root: Path) -> str:
    text = str(detail or "")
    root = str(Path(temp_root).resolve())
    variants = {root, root.replace("\\", "/"), root.replace("/", "\\")}
    for value in sorted(variants, key=len, reverse=True):
        text = text.replace(value, "<scan-root>")
    return text


def _clean_stderr(stderr: str | bytes | None) -> str:
    if stderr is None:
        return ""
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    return " ".join(str(stderr).split())


def _plan_semgrep_profile(target: Path) -> dict[str, list[str]]:
    """Choose Semgrep configs/includes from project languages; never use auto."""
    suffixes = _detect_source_suffixes(target)
    configs: list[str] = []
    includes: list[str] = []
    for profile in _LANGUAGE_PROFILES:
        if suffixes & set(profile["suffixes"]):
            configs.extend(profile["configs"])
            includes.extend(profile["includes"])
    return {
        "configs": list(dict.fromkeys(configs)),
        "includes": list(dict.fromkeys(includes)),
    }


def _detect_source_suffixes(target: Path, *, max_files: int = 50000,
                            include_test_findings: bool = False) -> set[str]:
    suffixes: set[str] = set()
    root = Path(target)
    if root.is_file():
        return {root.suffix.lower()} if root.suffix else set()
    seen = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _path_has_excluded_part(path.parts, include_test_findings=include_test_findings):
            continue
        seen += 1
        if seen > max_files:
            break
        if path.suffix:
            suffixes.add(path.suffix.lower())
    return suffixes


def _path_has_excluded_part(parts: Any, *, include_test_findings: bool) -> bool:
    normalized_parts = tuple(parts)
    for index, part in enumerate(normalized_parts):
        lowered = str(part).lower()
        if (not include_test_findings
                and index == len(normalized_parts) - 1
                and _TEST_FILE_NAME.fullmatch(str(part))):
            return True
        if lowered not in _EXCLUDED_SCAN_PARTS:
            continue
        if include_test_findings and lowered in _TEST_SCAN_PARTS:
            continue
        return True
    return False


def _project_has_suffix(target: Path, suffix: str) -> bool:
    """项目里是否存在指定后缀的源文件（供按语言追加 Semgrep 规则集等决策使用）。"""
    return str(suffix or "").lower() in _detect_source_suffixes(target)


def normalize_result_path(target: Path, result_path: str) -> str:
    """Normalize Semgrep path to a project-relative POSIX path when possible."""
    raw = str(result_path or "")
    if not raw:
        return ""
    target = Path(target).resolve()
    candidate = Path(raw)
    if not candidate.is_absolute():
        try:
            # Prefer an existing path relative to the scanner process cwd. Without
            # this ordering, target/candidate is syntactically inside target even
            # when it duplicates data/projects/<id> and does not exist.
            resolved = (Path.cwd() / candidate).resolve()
            if resolved.is_file():
                return resolved.relative_to(target).as_posix()
        except (OSError, ValueError):
            pass
    try:
        resolved = candidate.resolve() if candidate.is_absolute() else (target / candidate).resolve()
        return resolved.relative_to(target).as_posix()
    except (OSError, ValueError):
        pass
    if not candidate.is_absolute():
        try:
            # Some tools include the scanned directory name in relative paths.
            parts = Path(raw.replace("\\", "/")).parts
            if parts and parts[0].lower() == target.name.lower():
                return Path(*parts[1:]).as_posix()
        except (OSError, ValueError):
            pass
    raw_posix = raw.replace("\\", "/")
    target_posix = target.as_posix().lower().rstrip("/") + "/"
    lowered = raw_posix.lower()
    if lowered.startswith(target_posix):
        return raw_posix[len(target_posix):]
    while raw_posix.startswith("./"):
        raw_posix = raw_posix[2:]
    return raw_posix


def read_source_snippet(target: Path, result_path: str, start_line: int | None,
                        end_line: int | None = None, *, context: int = 0) -> str:
    """Read the matched source lines from disk instead of trusting tool-provided text."""
    line = _to_int(start_line)
    if line is None or line <= 0:
        return ""
    end = _to_int(end_line) or line
    root = Path(target).resolve()
    raw = Path(str(result_path or ""))
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.append(Path.cwd() / raw)
    candidates.append(root / raw)
    rel = normalize_result_path(root, str(result_path or ""))
    if rel:
        candidates.append(root / rel)
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if not resolved.is_file():
            continue
        try:
            lines = resolved.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return ""
        start = max(1, line - context)
        finish = min(len(lines), max(line, end) + context)
        return "\n".join(
            f"{idx} {lines[idx - 1]}" for idx in range(start, finish + 1)
        )
    return ""


def _choose_source_snippet(tool_lines: str, source_snippet: str) -> str:
    if not source_snippet:
        return "" if _bad_tool_lines(tool_lines) else tool_lines
    if _bad_tool_lines(tool_lines):
        return source_snippet
    tool_norm = _normalize_text(tool_lines)
    source_norm = _normalize_text(source_snippet)
    if tool_norm and tool_norm not in source_norm and source_norm not in tool_norm:
        return source_snippet
    return source_snippet or tool_lines


def _bad_tool_lines(value: str) -> bool:
    text = str(value or "").strip().lower()
    return not text or text == "requires login"


def _normalize_text(value: str) -> str:
    return " ".join(str(value or "").split()).lower()


def _semgrep_extra(extra: dict[str, Any], tool_lines: str, source_snippet: str, result: dict[str, Any]) -> dict:
    metadata = extra.get("metadata") or {}
    return {
        "raw_tool_lines": tool_lines,
        "source_snippet": source_snippet,
        "semgrep_metadata": metadata,
        "confidence": _confidence(metadata, extra),
        "technology": metadata.get("technology") or metadata.get("technologies") or [],
        "cwe": metadata.get("cwe") or [],
        "owasp": metadata.get("owasp") or [],
        "fingerprint": extra.get("fingerprint"),
        "semgrep_path": result.get("path"),
    }


def _confidence(metadata: dict[str, Any], extra: dict[str, Any]) -> float:
    raw = metadata.get("confidence") or extra.get("confidence")
    if isinstance(raw, (int, float)):
        return max(0.0, min(float(raw), 1.0))
    mapping = {"high": 0.85, "medium": 0.65, "low": 0.45}
    return mapping.get(str(raw or "").lower(), 0.6)


def _finding_type(check_id: str, metadata: dict[str, Any]) -> str:
    """从规则 ID 恢复稳定漏洞类型，避免自定义规则全部退化成无意义的 `taint`。"""
    text = str(check_id or "").lower().replace("_", "-")
    mapping = [
        (("unsafe-string-copy",), "Buffer Overflow Risk"),
        (("unsafe-format-buffer",), "Buffer Overflow Risk"),
        (("unsafe-scanf",), "Buffer Overflow Risk"),
        (("format-string",), "Format String"),
        (("unsafe-temp-file",), "Insecure Temporary File"),
        (("weak-hash",), "Weak Hash"),
        # Semgrep's React rule identifiers are not user-facing vulnerability
        # families.  Normalize them before strategy routing so they enter the
        # DOM PoC Sandbox path rather than falling through as unsupported text.
        (("dangerously", "innerhtml"), "DOM XSS"),
        (("command-execution",), "Command Execution Risk"),
        (("sql", "inject"), "SQL Injection"), (("command", "inject"), "Command Injection"),
        (("raw-query",), "SQL Injection"), (("os-system",), "Command Injection"),
        (("dangerous-system-call",), "Command Injection"),
        (("path", "travers"), "Path Traversal"), (("cross-site", "script"), "XSS"),
        (("xss",), "XSS"), (("server-side-request",), "SSRF"), (("ssrf",), "SSRF"),
        (("template", "inject"), "Server-Side Template Injection"),
        (("deserial",), "Insecure Deserialization"), (("open-redirect",), "Open Redirect"),
        (("hardcoded", "secret"), "Hardcoded Secret"), (("ldap", "inject"), "LDAP Injection"),
        (("xpath", "inject"), "XPath Injection"),
    ]
    for terms, label in mapping:
        if all(term in text for term in terms):
            return label
    return str(check_id.rsplit(".", 1)[-1] or "semgrep-finding")


def _framework_rule_mismatch(target: Path, result_path: str, check_id: str) -> bool:
    """只在文件明确使用互斥框架时抑制错投规则（如 Flask 文件命中 Django 规则）。"""
    lowered = str(check_id or "").lower()
    rule_framework = next((name for name in (
        "django", "flask", "spring", "symfony", "laravel", "thinkphp",
    )
                           if f".{name}." in lowered), None)
    if not rule_framework:
        return False
    frameworks = _detect_project_frameworks(str(Path(target).resolve()))
    # 项目已经明确采用另一套后端框架时，连 HTML/YAML 等无 import 的文件也必须过滤。
    exclusive = {"django", "flask", "spring", "symfony", "laravel", "thinkphp"}
    if frameworks & exclusive and rule_framework not in frameworks:
        return True
    header = read_source_snippet(target, result_path, 1, 100).lower()
    uses_flask = bool(re.search(r"\bfrom\s+flask\b|\bimport\s+flask\b", header))
    uses_django = bool(re.search(r"\bfrom\s+django\b|\bimport\s+django\b", header))
    return (".django." in lowered and uses_flask and not uses_django) or (
        ".flask." in lowered and uses_django and not uses_flask
    )


@lru_cache(maxsize=64)
def _detect_project_frameworks(target: str) -> frozenset[str]:
    """从依赖清单确定强框架信号，供 Semgrep 规则投放校验。"""
    root = Path(target)
    frameworks: set[str] = set()
    manifests = {
        "requirements.txt", "pyproject.toml", "pipfile", "pom.xml",
        "build.gradle", "build.gradle.kts", "composer.json",
    }
    checked = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.name.lower() not in manifests:
            continue
        if any(part.lower() in {".git", "node_modules", "vendor", "build", "target"}
               for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:500_000].lower()
        except OSError:
            continue
        checked += 1
        if "django" in text:
            frameworks.add("django")
        if re.search(r"(^|[^a-z])flask([^a-z]|$)", text):
            frameworks.add("flask")
        if "spring-boot" in text or "org.springframework" in text:
            frameworks.add("spring")
        if "thinkphp" in text or "topthink/" in text:
            frameworks.add("thinkphp")
        # 只把完整框架包当强信号，避免 symfony/polyfill 等组件误判成 Symfony 应用。
        if "symfony/framework-bundle" in text:
            frameworks.add("symfony")
        if "laravel/framework" in text:
            frameworks.add("laravel")
        if checked >= 30:
            break
    # 一些旧版 ThinkPHP 项目直接内置框架源码，composer 根清单未声明框架依赖。
    if (root / "thinkphp").is_dir() and (root / "application").is_dir():
        frameworks.add("thinkphp")
    return frozenset(frameworks)


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
