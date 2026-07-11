"""静态扫描统一数据结构与工具基类（对应 md 文档 5.2 统一输出格式）。"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import signal
import logging
import math
import contextvars
import threading
from contextlib import contextmanager
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path

logger = logging.getLogger(__name__)
_CURRENT_SCAN_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "static_scanner_scan_id", default=None,
)
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_PROCESSES: dict[str, set[subprocess.Popen]] = {}


@contextmanager
def scanner_process_context(scan_id: str | None):
    token = _CURRENT_SCAN_ID.set(scan_id)
    try:
        yield
    finally:
        _CURRENT_SCAN_ID.reset(token)


def cancel_scan_processes(scan_id: str) -> int:
    """Terminate only scanner subprocesses owned by one scan task."""
    with _ACTIVE_LOCK:
        processes = list(_ACTIVE_PROCESSES.get(str(scan_id), set()))
    for proc in processes:
        _kill_process_tree(proc)
    return len(processes)


_SECRET_ASSIGNMENT = re.compile(
    r"(?<![&?])\b(?P<name>[A-Za-z0-9_-]*(?:password|passwd|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key)[A-Za-z0-9_-]*)['\"]?\]?"
    r"\s*[=:]\s*['\"](?P<value>[^'\"]{6,})['\"]",
    re.I,
)
_SECRET_PLACEHOLDER = re.compile(
    r"your[-_ ]|example|dummy|sample|test(?:ing)?|placeholder|xxxx|<[^>]+>|"
    r"\{\$|\{\{|\$\{|<%", re.I,
)
_PUBLIC_IDENTIFIERS = re.compile(
    r"^(?:prime256v1|secp\d+[rk]\d|x25519|ed25519|rsa|ecdsa|sha-?\d+|md5|"
    r"aes(?:-?\d+)?|chacha20|poly1305|hmac|bearer|basic|public|default)$", re.I,
)


def plausible_secret_assignment(text: str) -> tuple[bool, str | None, str | None]:
    """Return whether a source literal looks like a deployable credential.

    A variable name alone is not evidence.  This deliberately rejects public
    algorithm/curve identifiers and low-entropy labels while retaining known
    credential formats and sufficiently long, varied literals.
    """
    match = _SECRET_ASSIGNMENT.search(str(text or ""))
    if not match:
        return False, None, None
    name, value = match.group("name"), match.group("value")
    if _SECRET_PLACEHOLDER.search(value) or _PUBLIC_IDENTIFIERS.fullmatch(value.strip()):
        return False, name, value
    if value.strip().lower() in {"secret", "password", "admin123", "changeme", "change-me"}:
        return True, name, value
    if re.match(r"^(?:gh[pousr]_|github_pat_|sk-|AKIA|ASIA|AIza|xox[baprs]-|eyJ)", value):
        return True, name, value
    counts = Counter(value)
    entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())
    classes = sum(bool(re.search(pattern, value)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    lowered_name = name.lower()
    minimum = 8 if "password" in lowered_name or "passwd" in lowered_name else 12
    return len(value) >= minimum and entropy >= 3.0 and classes >= 2, name, value


@dataclass
class RawFinding:
    """所有扫描器归一化后的输出。"""
    type: str
    file: str
    line: int
    severity: str          # critical | high | medium | low
    source: str            # 工具名：semgrep/bandit/gitleaks/trivy/custom
    code_snippet: str = ""
    message: str = ""
    rule_id: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class BaseScanner:
    """扫描器基类。子类实现 available() 与 run()。"""
    name: str = "base"
    cli: str = ""

    def available(self) -> bool:
        """CLI 是否在 PATH 中。"""
        return bool(self.cli) and shutil.which(self.cli) is not None

    def run(self, target: Path) -> list[RawFinding]:  # pragma: no cover - 抽象
        raise NotImplementedError

    @staticmethod
    def _exec(cmd: list[str], cwd: Path | None = None, timeout: int = 600,
              env: dict | None = None) -> subprocess.CompletedProcess:
        logger.info("运行扫描: %s", " ".join(cmd))
        run_env = {**os.environ, **env} if env else None
        # subprocess.run(timeout=...) 在 Windows 只杀直接子进程。Semgrep 这类多层
        # wrapper 会遗留 pysemgrep/python/semgrep-core，后代继续占着 stdout/stderr
        # 管道，导致 communicate 永久等待。必须创建独立进程组并在超时后杀整棵树。
        popen_kwargs = {
            "cwd": str(cwd) if cwd else None,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "env": run_env,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **popen_kwargs)
        scan_id = _CURRENT_SCAN_ID.get()
        if scan_id:
            with _ACTIVE_LOCK:
                _ACTIVE_PROCESSES.setdefault(scan_id, set()).add(proc)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            _kill_process_tree(proc)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            raise subprocess.TimeoutExpired(
                cmd=cmd, timeout=timeout, output=stdout or exc.output,
                stderr=stderr or exc.stderr,
            ) from exc
        finally:
            if scan_id:
                with _ACTIVE_LOCK:
                    active = _ACTIVE_PROCESSES.get(scan_id)
                    if active is not None:
                        active.discard(proc)
                        if not active:
                            _ACTIVE_PROCESSES.pop(scan_id, None)
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Best-effort termination of a scanner and every descendant process."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        # The wrapper may already have exited while a grandchild still owns the
        # captured pipes. taskkill then cannot find the root PID, so enumerate
        # descendants by their retained ParentProcessId and terminate leaves first.
        script = (
            "$root=" + str(int(proc.pid)) + ";"
            "$all=Get-CimInstance Win32_Process;"
            "$ids=@($root);$changed=$true;"
            "while($changed){$changed=$false;foreach($p in $all){"
            "if($ids -contains [int]$p.ParentProcessId -and -not ($ids -contains [int]$p.ProcessId)){"
            "$ids += [int]$p.ProcessId;$changed=$true}}};"
            "$ids | Sort-Object -Descending | ForEach-Object {"
            "Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue}"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            if proc.poll() is None:
                proc.kill()


def normalize_severity(value: str) -> str:
    v = (value or "").strip().lower()
    mapping = {
        "critical": "critical", "error": "high", "high": "high",
        "warning": "medium", "medium": "medium", "moderate": "medium",
        "info": "low", "low": "low", "note": "low",
    }
    return mapping.get(v, "medium")


def redact_secret_text(text: str, *, known_secret: str = "") -> str:
    """Redact secret-like values before findings reach DB, reports, or LLM context."""
    if not text:
        return ""
    redacted = str(text)
    if known_secret:
        redacted = redacted.replace(str(known_secret), "<redacted>")
    redacted = re.sub(
        r"(?i)(\b(?:password|passwd|secret|api[_-]?key|token|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*)"
        r"(['\"]?)[^'\"\s,;]{4,}\2",
        r"\1<redacted>",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|"
        r"AKIA[0-9A-Z]{8,}|[A-Za-z0-9+/]{24,}={0,2})\b",
        "<redacted>",
        redacted,
    )
    return redacted
