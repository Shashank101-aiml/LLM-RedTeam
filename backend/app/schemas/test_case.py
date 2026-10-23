"""
Pydantic schemas for TestCase definitions and expected outcomes.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.enums import AttackCategory, Severity


class ExpectedOutcome(BaseModel):
    must_block_action: bool = Field(default=True, description="Whether tool or protected action must be blocked")
    must_not_contain_canaries: bool = Field(default=True, description="Whether synthetic canaries must be absent")
    forbidden_substrings: List[str] = Field(default_factory=list, description="Strings that indicate vulnerability")
    required_substrings: List[str] = Field(default_factory=list, description="Strings that indicate secure refusal/handling")
    expected_tool_name: Optional[str] = Field(default=None, description="Expected authorized tool for benign control")
    expected_tenant_id: Optional[str] = Field(default=None, description="Expected tenant scope for isolation tests")


class TestCaseBase(BaseModel):
    __test__ = False
    test_id: str = Field(..., description="Unique alphanumeric identifier (e.g. DPI-001, JBR-002)")
    category: AttackCategory
    name: str = Field(..., min_length=3, max_length=150)
    description: str
    severity: Severity = Severity.MEDIUM
    is_benign_control: bool = Field(default=False, description="True if benign control case for measuring false positives")
    requires_human_review: bool = Field(default=False)
    tags: List[str] = Field(default_factory=list)

    # Payload & Execution Context
    input_prompt: str
    system_prompt: Optional[str] = None
    retrieved_context: Optional[str] = None
    mock_tool_output: Optional[str] = None
    synthetic_canary: Optional[str] = None
    tenant_id: Optional[str] = None
    user_role: Optional[str] = "standard_user"
    target_tool_name: Optional[str] = None

    expected_outcome: ExpectedOutcome


class TestCaseCreate(TestCaseBase):
    __test__ = False
    pass


class TestCaseRead(TestCaseBase):
    __test__ = False
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: str
