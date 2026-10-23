"""
Execution Context passed to target adapters.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from app.schemas.test_case import TestCaseBase


@dataclass
class ExecutionContext:
    test_case: TestCaseBase
    correlation_id: str
    timeout_seconds: float = 15.0
    model_name: Optional[str] = "mock-sentinel-v1"
    target_options: Dict[str, Any] = field(default_factory=dict)
