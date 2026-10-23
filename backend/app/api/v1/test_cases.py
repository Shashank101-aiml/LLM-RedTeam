"""
Test Suites and Test Cases discovery endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from app.core.security import verify_api_key
from app.evaluation.corpus import corpus_registry
from app.schemas.enums import AttackCategory, Severity
from app.schemas.test_case import TestCaseBase
from app.schemas.test_suite import TestSuiteBase

router = APIRouter()


@router.get("/test-suites", response_model=List[TestSuiteBase], dependencies=[Depends(verify_api_key)])
def list_test_suites():
    """Lists standard and bundled benchmark test suites."""
    return corpus_registry.get_available_suites()


@router.get("/test-cases", response_model=List[TestCaseBase], dependencies=[Depends(verify_api_key)])
def list_test_cases(
    category: Optional[AttackCategory] = Query(None, description="Filter by attack category"),
    severity: Optional[Severity] = Query(None, description="Filter by severity"),
    is_benign_control: Optional[bool] = Query(None, description="Filter benign controls"),
):
    """Lists test cases with filtering by category, severity, and benign status."""
    cases = corpus_registry.get_all()
    if category:
        cases = [c for c in cases if c.category == category]
    if severity:
        cases = [c for c in cases if c.severity == severity]
    if is_benign_control is not None:
        cases = [c for c in cases if c.is_benign_control == is_benign_control]
    return cases
