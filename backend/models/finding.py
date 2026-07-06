"""findings 表 —— 单条安全缺陷。"""
from __future__ import annotations

from typing import Optional, List

from sqlalchemy import String, Integer, Float, Boolean, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)

    type: Mapped[Optional[str]] = mapped_column(String, nullable=True)          # SQL Injection 等
    severity: Mapped[str] = mapped_column(String, default="low")             # critical|high|medium|low
    file_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    start_line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    end_line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    source: Mapped[Optional[str]] = mapped_column(String, nullable=True)        # 发现来源：semgrep/audit_agent 等
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String, default="candidate")         # candidate|confirmed|false_positive
    fix_suggestion: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # 智能体产生的富信息（data_flow/reason 等，JSON 字符串）
    detail_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    evidences: Mapped[List["Evidence"]] = relationship(
        "Evidence", back_populates="finding", cascade="all, delete-orphan"
    )
