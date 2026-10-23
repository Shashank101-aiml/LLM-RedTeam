"""
Health and Readiness check schemas.
"""

from typing import Dict
from pydantic import BaseModel


class HealthStatus(BaseModel):
    status: str = "ok"
    version: str
    environment: str
    safe_mode: bool
    components: Dict[str, str]
