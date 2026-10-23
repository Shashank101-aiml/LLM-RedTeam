"""
FastAPI API v1 Master Router mounting all resource endpoints.
"""

from fastapi import APIRouter
from app.api.v1 import comparison, health, integrations, runs, targets, test_cases

api_router = APIRouter()

api_router.include_router(health.router, tags=["health"])
api_router.include_router(runs.router, tags=["runs"])
api_router.include_router(comparison.router, tags=["comparison"])
api_router.include_router(test_cases.router, tags=["test-cases"])
api_router.include_router(targets.router, tags=["targets"])
api_router.include_router(integrations.router, tags=["integrations"])

