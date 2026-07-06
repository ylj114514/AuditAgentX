"""静态扫描统一数据结构与工具基类（对应 md 文档 5.2 统一输出格式）。"""
from __future__ import annotations

import shutil
import subprocess
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path

logger = logging.getLogger(__name__)


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
    def _exec(cmd: list[str], cwd: Path | None = None, timeout: int = 600) -> subprocess.CompletedProcess:
        logger.info("运行扫描: %s", " ".join(cmd))
        return subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, capture_output=True,
            text=True, timeout=timeout, check=False,
        )


def normalize_severity(value: str) -> str:
    v = (value or "").strip().lower()
    mapping = {
        "critical": "critical", "error": "high", "high": "high",
        "warning": "medium", "medium": "medium", "moderate": "medium",
        "info": "low", "low": "low", "note": "low",
    }
    return mapping.get(v, "medium")
