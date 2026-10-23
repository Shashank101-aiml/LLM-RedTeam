"""
SQLAlchemy models for TestCase and TestSuite.
"""

from typing import List, Optional
from sqlalchemy import Boolean, Column, ForeignKey, Integer, JSON, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin

# Association table between TestSuite and TestCase
suite_test_case_association = Table(
    "suite_test_case_association",
    Base.metadata,
    Column("suite_id", String(36), ForeignKey("test_suites.id", ondelete="CASCADE"), primary_key=True),
    Column("test_case_id", String(36), ForeignKey("test_cases.id", ondelete="CASCADE"), primary_key=True),
)


class TestCase(Base, TimestampMixin):
    __tablename__ = "test_cases"

    test_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    is_benign_control: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    requires_human_review: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list)

    # Inputs and context
    input_prompt: Mapped[str] = mapped_column(Text)
    system_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retrieved_context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mock_tool_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    synthetic_canary: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_role: Mapped[Optional[str]] = mapped_column(String(64), default="standard_user")
    target_tool_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Expected outcome rules stored as structured JSON
    expected_outcome: Mapped[dict] = mapped_column(JSON, default=dict)

    # Relationships
    suites = relationship("TestSuite", secondary=suite_test_case_association, back_populates="test_cases")
    executions = relationship("TestExecution", back_populates="test_case")


class TestSuite(Base, TimestampMixin):
    __tablename__ = "test_suites"

    suite_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(150))
    description: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    categories: Mapped[List[str]] = mapped_column(JSON, default=list)

    test_cases = relationship("TestCase", secondary=suite_test_case_association, back_populates="suites")
