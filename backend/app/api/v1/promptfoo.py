"""
Promptfoo Executable Evaluation API Router.

Provides endpoints to check Promptfoo status, launch Promptfoo evaluations
against validated targets, list Promptfoo runs, and inspect detailed assertion outcomes.
"""

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.logging_config import redact_sensitive_text
from app.core.security import verify_api_key
from app.db.session import get_db
from app.integrations.promptfoo.runner import (
    PromptfooRunner,
    get_artifacts_dir,
    get_promptfoo_status,
)
from app.integrations.promptfoo.validators import (
    validate_promptfoo_target,
    validate_selected_categories,
)
from app.models.evaluation_run import EvaluationRun
from app.schemas.evaluation_run import EvaluationRunRead

router = APIRouter(prefix="/evaluations/promptfoo")


class PromptfooRunRequest(BaseModel):
    """Request schema for initiating a Promptfoo security evaluation run."""
    target: str = Field(
        default="mock-secure",
        min_length=1,
        max_length=128,
        description="Target identifier ('mock-secure', 'mock-vulnerable', 'ai-iam-local', or 'external-http')",
    )
    selected_categories: List[str] = Field(
        default_factory=list,
        description="Optional list of evaluation categories to run (empty runs all 6 categories)",
    )
    endpoint_url: Optional[str] = Field(
        default=None,
        max_length=512,
        description="Optional target endpoint URL (strictly validated against Safe Mode)",
    )
    authorize_external: bool = Field(
        default=False,
        description="Explicit operator authorization flag required for external targets when SAFE_MODE=false",
    )
    timeout_seconds: float = Field(
        default=90.0,
        gt=0.0,
        le=300.0,
        description="Execution timeout in seconds (bounded between 1 and 300s)",
    )
    async_execution: bool = Field(
        default=False,
        description="If true, queues evaluation in background task and returns immediately",
    )
    notes: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional run notes",
    )


def _serialize_promptfoo_run(run: EvaluationRun) -> Dict[str, Any]:
    """Serializes an EvaluationRun along with saved Promptfoo assertion details."""
    base_data = EvaluationRunRead.model_validate(run).model_dump()
    if run.metric_snapshot:
        from app.schemas.metric_snapshot import MetricSnapshotRead
        base_data["metrics"] = MetricSnapshotRead.model_validate(run.metric_snapshot).model_dump()

    summary_path = get_artifacts_dir() / run.id / "sentinel_summary.json"
    detailed_results: List[Dict[str, Any]] = []
    duration_ms = 0.0
    target_id = None
    model_identifier = None

    if summary_path.exists():
        try:
            summary_json = json.loads(summary_path.read_text(encoding="utf-8"))
            detailed_results = summary_json.get("detailed_results", [])
            duration_ms = float(summary_json.get("duration_ms", 0.0) or 0.0)
            target_id = summary_json.get("target_id")
            model_identifier = summary_json.get("model_identifier")
        except Exception:
            detailed_results = []

    if not duration_ms and run.executions:
        duration_ms = round(sum(e.duration_ms for e in run.executions), 2)

    base_data["duration_ms"] = duration_ms
    base_data["target_id"] = target_id
    base_data["model_identifier"] = model_identifier
    base_data["detailed_results"] = detailed_results
    return base_data


@router.get(
    "/status",
    response_model=Dict[str, Any],
    dependencies=[Depends(verify_api_key)],
)
def get_promptfoo_integration_status() -> Dict[str, Any]:
    """Returns Promptfoo CLI availability, version, Safe-Mode status, targets, and categories."""
    return get_promptfoo_status()


@router.post(
    "/run",
    status_code=status.HTTP_201_CREATED,
    response_model=Dict[str, Any],
    dependencies=[Depends(verify_api_key)],
)
def trigger_promptfoo_evaluation(
    req: PromptfooRunRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Validates target and categories, creates an EvaluationRun, and executes Promptfoo.
    Enforces Safe Mode SSRF guardrails and prevents arbitrary command execution.
    """
    try:
        target_meta = validate_promptfoo_target(
            target=req.target,
            endpoint_url=req.endpoint_url,
            authorize_external=req.authorize_external,
        )
        validated_cats = validate_selected_categories(req.selected_categories)
    except PermissionError as perm_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=redact_sensitive_text(str(perm_err)),
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=redact_sensitive_text(str(val_err)),
        )

    try:
        run = PromptfooRunner.create_pending_run(
            db=db,
            target=target_meta["id"],
            selected_categories=validated_cats,
            endpoint_url=target_meta.get("endpoint_url"),
            authorize_external=req.authorize_external,
            notes=req.notes,
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=redact_sensitive_text(str(val_err)),
        )

    if req.async_execution:
        background_tasks.add_task(
            PromptfooRunner.execute_run_task,
            run_id=run.id,
            target=target_meta["id"],
            selected_categories=validated_cats,
            endpoint_url=target_meta.get("endpoint_url"),
            authorize_external=req.authorize_external,
            timeout_seconds=req.timeout_seconds,
        )
        return _serialize_promptfoo_run(run)

    # Synchronous execution
    run.status = "running"
    db.commit()

    runner = PromptfooRunner()
    summary = runner.run_evaluation(
        target=target_meta["id"],
        selected_categories=validated_cats,
        endpoint_url=target_meta.get("endpoint_url"),
        authorize_external=req.authorize_external,
        timeout_seconds=req.timeout_seconds,
        run_id=run.id,
    )
    updated_run = PromptfooRunner.persist_summary_to_run(db, run, summary)
    return _serialize_promptfoo_run(updated_run)


@router.get(
    "/runs",
    response_model=List[Dict[str, Any]],
    dependencies=[Depends(verify_api_key)],
)
def list_promptfoo_runs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Lists Promptfoo evaluation runs ordered from newest to oldest."""
    query = db.query(EvaluationRun).filter(
        (EvaluationRun.dataset_version.like("promptfoo%"))
        | (EvaluationRun.target_name.like("Promptfoo%"))
    )
    if status_filter:
        query = query.filter(EvaluationRun.status == status_filter)
    runs = query.order_by(EvaluationRun.created_at.desc()).offset(skip).limit(limit).all()
    return [_serialize_promptfoo_run(r) for r in runs]


@router.get(
    "/runs/{run_id}",
    response_model=Dict[str, Any],
    dependencies=[Depends(verify_api_key)],
)
def get_promptfoo_run_details(
    run_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieves full details, metrics, findings, and assertion results for a Promptfoo run."""
    run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Promptfoo evaluation run not found")
    return _serialize_promptfoo_run(run)
