"""
SQLAlchemy model for TestExecution.
"""

from typing import List, Optional
from sqlalchemy import Boolean, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin


class TestExecution(Base, TimestampMixin):
    __tablename__ = "test_executions"

    run_id: Mapped[str] = mapped_column(String(36), ForeignKey("evaluation_runs.id", ondelete="CASCADE"), index=True)
    test_case_id: Mapped[str] = mapped_column(String(36), ForeignKey("test_cases.id"), index=True)
    
    status: Mapped[str] = mapped_column(String(32), index=True) # passed, failed, error, skipped
    defense_outcome: Mapped[str] = mapped_column(String(32))    # secure, vulnerable, overblocking
    attack_objective_achieved: Mapped[bool] = mapped_column(Boolean, default=False)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_output_sanitized: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tool_calls_attempted: Mapped[list] = mapped_column(JSON, default=list)
    canary_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    tenant_boundary_violated: Mapped[bool] = mapped_column(Boolean, default=False)
    evaluation_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    run = relationship("EvaluationRun", back_populates="executions")
    test_case = relationship("TestCase", back_populates="executions")
