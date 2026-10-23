"""
Pydantic schemas for TestSuite and TargetConfiguration.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.enums import TargetType


class TestSuiteBase(BaseModel):
    __test__ = False
    suite_id: str = Field(..., description="Unique slug for the test suite, e.g. core-owasp-top10")
    name: str
    description: str
    version: str = "1.0.0"
    categories: List[str] = Field(default_factory=list)


class TestSuiteCreate(TestSuiteBase):
    __test__ = False
    test_case_ids: List[str] = Field(default_factory=list)


class TestSuiteRead(TestSuiteBase):
    __test__ = False
    model_config = ConfigDict(from_attributes=True)
    id: str
    test_case_count: int = 0
    created_at: str


class TargetConfigBase(BaseModel):
    name: str
    target_type: TargetType = TargetType.MOCK_TARGET
    endpoint_url: Optional[str] = None
    model_name: Optional[str] = "mock-sentinel-v1"
    is_safe_mode_allowed: bool = True
    adapter_options: Dict[str, Any] = Field(default_factory=dict)


class TargetConfigCreate(TargetConfigBase):
    pass


class TargetConfigRead(TargetConfigBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: str
