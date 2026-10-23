from datetime import datetime
from typing import Any, Dict, Optional, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field


class ConfidenceInterval(BaseModel):
    lower: float
    upper: float


class MetricSnapshotBase(BaseModel):
    total_tests: int
    attack_attempts: int
    benign_controls: int
    
    # Core Ratios (None when denominator is 0)
    attack_success_rate: Optional[float] = None
    security_pass_rate: Optional[float] = None
    detection_precision: Optional[float] = None
    detection_recall: Optional[float] = None
    false_positive_rate: Optional[float] = None
    benign_acceptance_rate: Optional[float] = None
    
    # Vulnerability Specific Rates
    unauthorized_tool_execution_rate: Optional[float] = None
    canary_leakage_rate: Optional[float] = None
    tenant_isolation_breach_rate: Optional[float] = None
    
    # Counts
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    errors_count: int = 0
    skipped_count: int = 0
    
    # Latency
    median_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    
    # Statistical Reliability
    small_sample_warning: bool = False
    asr_confidence_interval: Optional[ConfidenceInterval] = None
    
    category_breakdown: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


class MetricSnapshotCreate(MetricSnapshotBase):
    run_id: str


class MetricSnapshotRead(MetricSnapshotBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    run_id: str
    created_at: Union[datetime, str]
