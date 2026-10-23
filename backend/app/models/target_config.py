"""
SQLAlchemy model for TargetConfiguration.
"""

from sqlalchemy import Boolean, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin


class TargetConfiguration(Base, TimestampMixin):
    __tablename__ = "target_configurations"

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    target_type: Mapped[str] = mapped_column(String(64), default="mock_target")
    endpoint_url: Mapped[str] = mapped_column(String(512), nullable=True)
    model_name: Mapped[str] = mapped_column(String(128), default="mock-sentinel-v1")
    is_safe_mode_allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    adapter_options: Mapped[dict] = mapped_column(JSON, default=dict)

    runs = relationship("EvaluationRun", back_populates="target_configuration")
