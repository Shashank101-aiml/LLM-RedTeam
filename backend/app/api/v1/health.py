"""
Health and readiness endpoints for LLM Sentinel.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db.session import get_db
from app.schemas.health import HealthStatus

router = APIRouter()


@router.get("/health", response_model=HealthStatus)
def health_check(db: Session = Depends(get_db)):
    """Liveness and readiness check reporting component status and safe-mode status."""
    db_status = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return HealthStatus(
        status="ok" if db_status == "ok" else "degraded",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        safe_mode=settings.SAFE_MODE,
        components={
            "database": db_status,
            "evaluation_engine": "ready",
            "mock_target": "ready",
        },
    )
