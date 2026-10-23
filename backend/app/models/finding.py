"""
SQLAlchemy model for Finding.
"""

from typing import Optional
from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    run_id: Mapped[str] = mapped_column(String(36), ForeignKey("evaluation_runs.id", ondelete="CASCADE"), index=True)
    test_case_id: Mapped[str] = mapped_column(String(36), ForeignKey("test_cases.id"), index=True)
    
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True) # critical, high, medium, low
    
    attack_input_redacted: Mapped[str] = mapped_column(Text)
    target_output_redacted: Mapped[str] = mapped_column(Text)
    
    tool_violation_observed: Mapped[bool] = mapped_column(Boolean, default=False)
    canary_leaked: Mapped[bool] = mapped_column(Boolean, default=False)
    tenant_isolation_breached: Mapped[bool] = mapped_column(Boolean, default=False)
    remediation_guidance: Mapped[str] = mapped_column(Text)

    run = relationship("EvaluationRun", back_populates="findings")
