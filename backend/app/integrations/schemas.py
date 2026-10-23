"""
Pydantic Schemas for External Scanner Integrations and Finding Normalization.
Preserves test provenance and normalizes external scanner outputs (Promptfoo, Garak)
into LLM Sentinel's unified threat model.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.enums import AttackCategory, ExecutionStatus, Severity


class NormalizedFinding(BaseModel):
    __test__ = False
    model_config = ConfigDict(from_attributes=True)

    finding_id: str = Field(..., description="Unique finding ID")
    category: AttackCategory = Field(..., description="Mapped Sentinel attack category")
    severity: Severity = Field(..., description="Mapped severity level")
    title: str = Field(..., description="Descriptive title of the vulnerability")
    description: str = Field(..., description="Detailed explanation of the flaw")
    evidence: str = Field(..., description="Sanitized payload or failure output evidence")
    remediation: str = Field(..., description="Guidance to patch or mitigate the finding")
    source_framework: str = Field(..., description="Source scanner ('promptfoo' | 'garak')")
    source_test_id: str = Field(..., description="Original probe or assertion identifier")
    raw_metadata: Dict[str, Any] = Field(default_factory=dict, description="Original uncompressed metadata for provenance")


class NormalizedExecution(BaseModel):
    __test__ = False
    model_config = ConfigDict(from_attributes=True)

    test_id: str = Field(..., description="Identifier for the execution")
    category: AttackCategory = Field(..., description="Mapped Sentinel attack category")
    status: ExecutionStatus = Field(..., description="Execution outcome ('passed' | 'failed' | 'error')")
    input_prompt: str = Field(..., description="Input prompt or probe text")
    output_text: str = Field("", description="Target output or assertion response")
    duration_ms: float = Field(0.0, description="Duration of the probe execution")
    findings: List[NormalizedFinding] = Field(default_factory=list, description="Findings generated if status is failed")
    source_framework: str = Field(..., description="Origin scanner framework")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="Provenance metadata (detector, model, timestamp)")


class NormalizedBenchmarkReport(BaseModel):
    __test__ = False
    model_config = ConfigDict(from_attributes=True)

    framework: str = Field(..., description="Scanner name ('promptfoo' | 'garak')")
    framework_version: Optional[str] = Field(None, description="Scanner framework version")
    import_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target_model: str = Field("unknown", description="Model or endpoint under evaluation")
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    errors_count: int = 0
    findings_count: int = 0
    attack_success_rate: float = 0.0
    security_pass_rate: float = 1.0
    executions: List[NormalizedExecution] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict, description="Scan run context, timestamps, CLI args")
