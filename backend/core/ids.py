"""统一 ID 生成，保持 md 文档里 proj_001 / scan_001 的可读风格。"""
from __future__ import annotations

import uuid


def _short() -> str:
    return uuid.uuid4().hex[:8]


def project_id() -> str:
    return f"proj_{_short()}"


def scan_id() -> str:
    return f"scan_{_short()}"


def finding_id() -> str:
    return f"find_{_short()}"


def evidence_id() -> str:
    return f"evi_{_short()}"


def report_id() -> str:
    return f"report_{_short()}"
