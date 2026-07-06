"""scans 表 —— 一次扫描任务。"""
from __future__ import annotations

from datetime import datetime
from typing import Optional, List

from sqlalchemy import String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    scan_type: Mapped[str] = mapped_column(String, default="full")  # full | static | quick
    status: Mapped[str] = mapped_column(String, default="queued")   # queued|running|done|failed
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_stage: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # 本次任务配置快照（便于复现）
    config_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    project: Mapped["Project"] = relationship("Project", back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[List["Report"]] = relationship(
        "Report", back_populates="scan", cascade="all, delete-orphan"
    )
