"""
Run Comparison and Regression Analysis Endpoints.
"""

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.security import verify_api_key
from app.db.session import get_db
from app.schemas.evaluation_run import RunComparisonResult
from app.services.comparison_service import ComparisonService

router = APIRouter()


class CompareRequest(BaseModel):
    baseline_run_id: str = Field(..., description="Run ID of the reference/baseline run")
    candidate_run_id: str = Field(..., description="Run ID of the new candidate evaluation run")


@router.post("/compare", response_model=RunComparisonResult, dependencies=[Depends(verify_api_key)])
def compare_runs(req: CompareRequest, db: Session = Depends(get_db)):
    """
    Compares two evaluation runs, calculates metric deltas (ASR, FPR, STPR),
    and highlights regressions (tests that passed in baseline but failed in candidate).
    """
    try:
        result = ComparisonService.compare_runs(
            db=db,
            baseline_run_id=req.baseline_run_id,
            candidate_run_id=req.candidate_run_id,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
