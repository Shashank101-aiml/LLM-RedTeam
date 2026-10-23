"""
Base Target Adapter Interface and Response Schema.

Enforces Safe Mode restrictions on all target requests.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from app.core.config import settings
from app.evaluation.context import ExecutionContext


@dataclass
class TargetResponse:
    output_text: str = ""
    tool_calls_attempted: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: float = 0.0
    status_code: Optional[int] = None
    error: Optional[str] = None
    raw_response: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.error is not None or (self.status_code is not None and self.status_code >= 400)


class TargetAdapter(ABC):
    """Abstract Base Class for all LLM and agent target adapters."""

    def __init__(self, name: str, endpoint_url: Optional[str] = None, safe_mode: bool = True):
        self.name = name
        self.endpoint_url = endpoint_url
        self.safe_mode = safe_mode

    def validate_target_safety(self, url: Optional[str] = None) -> None:
        """
        Validates target URL against Safe Mode restrictions.
        Raises PermissionError if target is external while Safe Mode is enabled.
        """
        target = url or self.endpoint_url
        if not target or not self.safe_mode:
            return

        parsed = urlparse(target)
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            return

        # Check against allowed hostnames
        if hostname not in [h.lower() for h in settings.ALLOWED_TARGET_HOSTS]:
            raise PermissionError(
                f"Safe Mode Violation: Target host '{hostname}' is not in the allowed local hosts list "
                f"({settings.ALLOWED_TARGET_HOSTS}). External targets require SAFE_MODE=false."
            )

    @abstractmethod
    async def execute(self, context: ExecutionContext) -> TargetResponse:
        """Executes the adversarial or benign prompt against the target system."""
        pass
