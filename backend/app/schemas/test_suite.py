"""
Pydantic schemas for TestSuite definitions.
"""

from typing import List
from pydantic import BaseModel, ConfigDict, Field


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
