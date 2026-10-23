"""
Pydantic schemas for individual TestExecution records.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.enums import ExecutionStatus, DefenseOutcome


class TestExecutionBase(BaseModel):
    __test__ = False
    test_case_id: str
    status: ExecutionStatus
    defense_outcome: DefenseOutcome
    attack_objective_achieved: bool = False
    duration_ms: float
    error_message: Optional[str] = None
    target_output_sanitized: Optional[str] = None
    tool_calls_attempted: List[Dict[str, Any]] = Field(default_factory=list)
    canary_detected: bool = False
    tenant_boundary_violated: bool = False
    evaluation_notes: Optional[str] = None


class TestExecutionCreate(TestExecutionBase):
    __test__ = False
    run_id: str


class TestExecutionRead(TestExecutionBase):
    __test__ = False
    model_config = ConfigDict(from_attributes=True)
    id: str
    run_id: str
    created_at: str
