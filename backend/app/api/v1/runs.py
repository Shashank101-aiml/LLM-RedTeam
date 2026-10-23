"""
Evaluation Run management and execution endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from app.core.security import validate_target_url_safe_mode, verify_api_key
from app.db.session import get_db
from app.models.evaluation_run import EvaluationRun
from app.models.finding import Finding
from app.schemas.evaluation_run import EvaluationRunCreate, EvaluationRunRead
from app.schemas.finding import FindingRead
from app.schemas.metric_snapshot import MetricSnapshotRead
from app.services.export_service import ExportService
from app.services.run_service import RunService

router = APIRouter()


@router.post("/runs", response_model=EvaluationRunRead, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_api_key)])
async def create_evaluation_run(
    run_in: EvaluationRunCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Creates and initiates an evaluation run.
    Validates Safe Mode constraints before launching background execution.
    """
    # Safe-mode check if target URL is specified
    if run_in.target_name.startswith("http"):
        validate_target_url_safe_mode(run_in.target_name)

    run = RunService.create_run(db, run_in)

    # Launch background task for execution
    background_tasks.add_task(RunService.execute_run_async, run.id)

    return run


@router.get("/runs", response_model=List[EvaluationRunRead], dependencies=[Depends(verify_api_key)])
def list_evaluation_runs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
):
    """Lists historical evaluation runs with pagination and optional status filter."""
    query = db.query(EvaluationRun)
    if status_filter:
        query = query.filter(EvaluationRun.status == status_filter)
    runs = query.order_by(EvaluationRun.created_at.desc()).offset(skip).limit(limit).all()
    return runs


@router.get("/runs/{run_id}", response_model=EvaluationRunRead, dependencies=[Depends(verify_api_key)])
def get_evaluation_run(run_id: str, db: Session = Depends(get_db)):
    """Retrieves full evaluation run details, status, progress, executions, and metrics."""
    run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Evaluation run not found")
    return run


@router.get("/runs/{run_id}/findings", response_model=List[FindingRead], dependencies=[Depends(verify_api_key)])
def get_run_findings(run_id: str, db: Session = Depends(get_db)):
    """Retrieves findings for an evaluation run with sanitized/redacted evidence."""
    run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Evaluation run not found")
    findings = db.query(Finding).filter(Finding.run_id == run_id).all()
    return findings


@router.get("/runs/{run_id}/metrics", response_model=MetricSnapshotRead, dependencies=[Depends(verify_api_key)])
def get_run_metrics(run_id: str, db: Session = Depends(get_db)):
    """Retrieves computed statistical metric snapshot for an evaluation run."""
    run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Evaluation run not found")
    if not run.metric_snapshot:
        raise HTTPException(status_code=400, detail="Metrics not yet available. Run may still be pending or running.")
    return run.metric_snapshot


@router.get("/runs/{run_id}/export/json", dependencies=[Depends(verify_api_key)])
def export_run_json(run_id: str, db: Session = Depends(get_db)):
    """Exports sanitized evaluation run report as JSON."""
    try:
        json_data = ExportService.export_json(db, run_id)
        return Response(
            content=json_data,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=sentinel-run-{run_id}.json"},
        )
    except ValueError:
        raise HTTPException(status_code=404, detail="Evaluation run not found")


@router.get("/runs/{run_id}/export/csv", dependencies=[Depends(verify_api_key)])
def export_run_csv(run_id: str, db: Session = Depends(get_db)):
    """Exports sanitized evaluation run executions as CSV."""
    try:
        csv_data = ExportService.export_csv(db, run_id)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=sentinel-run-{run_id}.csv"},
        )
    except ValueError:
        raise HTTPException(status_code=404, detail="Evaluation run not found")
