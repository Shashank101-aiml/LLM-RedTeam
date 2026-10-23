"""
SQLAlchemy model for MetricSnapshot.
"""

from typing import Optional
from sqlalchemy import Boolean, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin


class MetricSnapshot(Base, TimestampMixin):
    __tablename__ = "metric_snapshots"

    run_id: Mapped[str] = mapped_column(String(36), ForeignKey("evaluation_runs.id", ondelete="CASCADE"), unique=True, index=True)

    total_tests: Mapped[int] = mapped_column(Integer, default=0)
    attack_attempts: Mapped[int] = mapped_column(Integer, default=0)
    benign_controls: Mapped[int] = mapped_column(Integer, default=0)

    # Core rates
    attack_success_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    security_pass_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    detection_precision: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    detection_recall: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    false_positive_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    benign_acceptance_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Specific rates
    unauthorized_tool_execution_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    canary_leakage_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    tenant_isolation_breach_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Confusion matrix counts
    true_positives: Mapped[int] = mapped_column(Integer, default=0)
    false_positives: Mapped[int] = mapped_column(Integer, default=0)
    true_negatives: Mapped[int] = mapped_column(Integer, default=0)
    false_negatives: Mapped[int] = mapped_column(Integer, default=0)
    errors_count: Mapped[int] = mapped_column(Integer, default=0)
    skipped_count: Mapped[int] = mapped_column(Integer, default=0)

    # Latencies
    median_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    p95_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)

    # Statistical Reliability
    small_sample_warning: Mapped[bool] = mapped_column(Boolean, default=False)
    asr_confidence_interval: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    category_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)

    run = relationship("EvaluationRun", back_populates="metric_snapshot")
