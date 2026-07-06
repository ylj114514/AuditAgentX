"""evidence 表 —— 证据链（source→sink→PoC→runtime）。"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import String, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False)

    source: Mapped[Optional[str]] = mapped_column(Text, nullable=True)       # JSON: {file,line,code}
    sink: Mapped[Optional[str]] = mapped_column(Text, nullable=True)         # JSON
    data_flow: Mapped[Optional[str]] = mapped_column(Text, nullable=True)    # JSON list
    poc_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)   # JSON
    logs: Mapped[Optional[str]] = mapped_column(Text, nullable=True)         # JSON list

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    finding: Mapped["Finding"] = relationship("Finding", back_populates="evidences")
