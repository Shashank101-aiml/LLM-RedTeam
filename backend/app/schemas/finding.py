"""
Pydantic schemas for Findings.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.enums import AttackCategory, Severity


class FindingBase(BaseModel):
    title: str
    description: str
    category: AttackCategory
    severity: Severity
    test_case_id: str
    attack_input_redacted: str
    target_output_redacted: str
    tool_violation_observed: bool = False
    canary_leaked: bool = False
    tenant_isolation_breached: bool = False
    remediation_guidance: str


class FindingCreate(FindingBase):
    run_id: str


class FindingRead(FindingBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    run_id: str
    created_at: str
