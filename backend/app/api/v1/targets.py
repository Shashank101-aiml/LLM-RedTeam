"""
Target configurations and safe-mode status endpoints.
"""

from typing import Any, Dict
from fastapi import APIRouter, Depends
from app.core.config import settings
from app.core.security import verify_api_key

router = APIRouter()


@router.get("/targets", dependencies=[Depends(verify_api_key)])
def list_target_configurations() -> Dict[str, Any]:
    """Lists configured targets, safe mode status, and allowed hosts."""
    return {
        "safe_mode": settings.SAFE_MODE,
        "allowed_target_hosts": settings.ALLOWED_TARGET_HOSTS,
        "available_adapters": [
            {
                "id": "mock-secure",
                "name": "Deterministic Mock Target (Secure Mode)",
                "type": "mock_target",
                "description": "In-memory target with strict policy enforcement and zero vulnerabilities.",
                "safe_mode_compatible": True,
            },
            {
                "id": "mock-vulnerable",
                "name": "Deterministic Mock Target (Vulnerable Mode)",
                "type": "mock_target",
                "description": "In-memory target with known vulnerabilities across all 6 attack categories.",
                "safe_mode_compatible": True,
            },
            {
                "id": "ai-iam-local",
                "name": "AI-IAM Platform Adapter (Local MCP)",
                "type": "ai_iam_adapter",
                "description": "Pre-execution tool authorization and delegation policy inspection on http://localhost:8000.",
                "safe_mode_compatible": True,
            },
        ],
    }
