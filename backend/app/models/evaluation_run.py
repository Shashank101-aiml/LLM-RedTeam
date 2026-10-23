"""
SQLAlchemy model for EvaluationRun.
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin


class EvaluationRun(Base, TimestampMixin):
    __tablename__ = "evaluation_runs"

    target_config_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("target_configurations.id"), nullable=True)
    target_name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    dataset_version: Mapped[str] = mapped_column(String(32), default="v1.0.0")
    random_seed: Mapped[Optional[int]] = mapped_column(Integer, default=42)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Progress and counters
    total_tests: Mapped[int] = mapped_column(Integer, default=0)
    completed_tests: Mapped[int] = mapped_column(Integer, default=0)
    passed_tests: Mapped[int] = mapped_column(Integer, default=0)
    failed_tests: Mapped[int] = mapped_column(Integer, default=0)
    errors_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    target_configuration = relationship("TargetConfiguration", back_populates="runs")
    executions = relationship("TestExecution", back_populates="run", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="run", cascade="all, delete-orphan")
    metric_snapshot = relationship("MetricSnapshot", back_populates="run", uselist=False, cascade="all, delete-orphan")
