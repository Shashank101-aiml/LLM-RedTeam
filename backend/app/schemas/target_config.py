"""
Pydantic schemas for TargetConfiguration.
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict
from app.schemas.enums import TargetType


class TargetConfigBase(BaseModel):
    name: str
    target_type: TargetType = TargetType.MOCK_TARGET
    endpoint_url: Optional[str] = None
    model_name: Optional[str] = "mock-sentinel-v1"
    is_safe_mode_allowed: bool = True
    adapter_options: Dict[str, Any] = {}


class TargetConfigCreate(TargetConfigBase):
    pass


class TargetConfigRead(TargetConfigBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: str
