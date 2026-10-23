"""
Integration test verifying persistent evaluation history across engine restarts.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
from app.db.session import init_db
from app.models.evaluation_run import EvaluationRun
from app.services.run_service import RunService


@pytest.mark.asyncio
async def test_persistence_across_session_restarts():
    init_db()

    # 1. Start session 1: create and complete evaluation run
    engine_1 = create_engine(settings.SYNC_DATABASE_URL)
    Session1 = sessionmaker(bind=engine_1)
    db1 = Session1()

    from app.schemas.evaluation_run import EvaluationRunCreate
    run = RunService.create_run(db1, EvaluationRunCreate(target_name="Persistence Test Target", notes="Session 1"))
    run_id = run.id
    db1.close()
    engine_1.dispose()

    # Execute run
    await RunService.execute_run_async(run_id, mode="vulnerable")

    # 2. Simulate complete restart: new database engine and fresh session
    engine_2 = create_engine(settings.SYNC_DATABASE_URL)
    Session2 = sessionmaker(bind=engine_2)
    db2 = Session2()

    persisted_run = db2.query(EvaluationRun).filter(EvaluationRun.id == run_id).first()
    assert persisted_run is not None
    assert persisted_run.id == run_id
    assert persisted_run.target_name == "Persistence Test Target"
    assert persisted_run.status == "failed"  # 13 vulnerabilities detected in vulnerable mode
    assert persisted_run.findings_count == 13
    assert len(persisted_run.executions) == 17
    assert persisted_run.metric_snapshot is not None
    assert persisted_run.metric_snapshot.attack_success_rate == 1.0

    db2.close()
    engine_2.dispose()
