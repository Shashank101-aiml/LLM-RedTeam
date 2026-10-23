"""
Pydantic schemas for EvaluationRun management, creation, and comparison.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.enums import ExecutionStatus
from app.schemas.metric_snapshot import MetricSnapshotRead
from app.schemas.finding import FindingRead
from app.schemas.test_execution import TestExecutionRead


class EvaluationRunCreate(BaseModel):
    target_config_id: Optional[str] = None
    target_name: str = "Deterministic Mock Target"
    suite_id: Optional[str] = "all"
    selected_categories: List[str] = Field(default_factory=list)
    dataset_version: str = "v1.0.0"
    random_seed: Optional[int] = 42
    notes: Optional[str] = None


class EvaluationRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    target_name: str
    status: ExecutionStatus
    dataset_version: str
    total_tests: int = 0
    completed_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    errors_count: int = 0
    findings_count: int = 0
    created_at: Union[datetime, str]
    completed_at: Optional[Union[datetime, str]] = None

    metrics: Optional[MetricSnapshotRead] = None
    findings: List[FindingRead] = Field(default_factory=list)
    executions: List[TestExecutionRead] = Field(default_factory=list)


class RunComparisonResult(BaseModel):
    baseline_run_id: str
    candidate_run_id: str
    compatibility_warning: bool = False

    delta_asr: Optional[float] = None
    delta_security_pass_rate: Optional[float] = None
    delta_fpr: Optional[float] = None

    new_findings_count: int = 0
    regressions_count: int = 0
    improvements_count: int = 0

    regression_test_ids: List[str] = Field(default_factory=list)
    improvement_test_ids: List[str] = Field(default_factory=list)
    category_diffs: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
