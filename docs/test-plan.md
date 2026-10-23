# LLM Sentinel — Acceptance Checklist and Test Plan

## 1. Acceptance Checklist by Phase

| Phase | Description | Acceptance Criteria | Status |
|---|---|---|---|
| **Phase 0** | Repository Inspection & Planning | Workspace inspected, companion AI-IAM structure verified, architecture, threat model, metrics, and plan committed. | **IN PROGRESS** |
| **Phase 1** | Project Skeleton & Core Schemas | Backend package configured, FastAPI app running with `/health`, Pydantic models & SQLAlchemy tables defined, initial pytest suite passes. | Pending Approval |
| **Phase 2** | Evaluation Engine & Metrics | Test-case validation, outcome evaluation, mock target execution, Wilson-score confidence intervals, zero-denominator tests pass. | Pending Approval |
| **Phase 3** | Attack Corpus & Mock Targets | 6 attack categories + benign controls implemented; deterministic secure vs vulnerable mock targets verify known detections. | Pending Approval |
| **Phase 4** | Database & FastAPI v1 API | Relational persistence, migrations, run endpoints, metrics trends, comparisons, JSON/CSV exports, safe-mode guards. | Pending Approval |
| **Phase 5** | Frontend Dashboard | Overview, Runs, Findings, Metrics, Comparison, TestSuites pages populated with real API data, responsive Tailwind CSS UI. | Pending Approval |
| **Phase 6** | Security & Regression Testing | Comprehensive pytest suite covering canary extraction, tenant isolation, tool invocation, false positives, and self-security. | Pending Approval |
| **Phase 7** | AI-IAM & Scanner Integrations | Adapter verified against `d:\ai-iam-platform` interface; optional Promptfoo/Garak normalization interface. | Pending Approval |
| **Phase 8** | Docker, CI/CD, & Observability | Dockerfile, docker-compose.yml, GitHub Actions workflow, structured logging, health checks. | Pending Approval |
| **Phase 9** | Documentation & Verification | Complete README, clean zero-token demo run, dashboard validation, final verification report. | Pending Approval |

---

## 2. Test Suite Organization

```text
backend/tests/
├── unit/
│   ├── test_metrics.py         # ASR, Precision, Recall, FPR, Wilson intervals, zero denominators
│   ├── test_schemas.py         # Pydantic v2 validation and serialization
│   ├── test_canary.py          # Canary generation, extraction detection, evidence masking
│   ├── test_evaluator.py       # Outcome scoring logic, status assignment
│   └── test_safe_mode.py       # Safe mode address filtering and domain allowlists
├── integration/
│   ├── test_api_health.py      # /api/v1/health liveness & readiness
│   ├── test_runs_lifecycle.py  # Create run, poll status, retrieve executions & findings
│   ├── test_export.py          # JSON and CSV export endpoints and schema integrity
│   └── test_db_persistence.py  # SQLite/PostgreSQL persistence across sessions
├── security/
│   ├── test_redaction.py       # Verification that raw API keys / canaries are redacted
│   ├── test_tool_boundary.py   # Verification that unauthorized tool execution is blocked
│   └── test_tenant_boundary.py # Cross-tenant isolation verification
└── regression/
    ├── test_known_vulnerable.py# Known vulnerable mock target produces expected failed tests
    └── test_run_comparison.py  # Baseline vs candidate regression diff accuracy
```

---

## 3. Test Execution Commands

```bash
# Run complete test suite with coverage
pytest backend/tests -v --cov=backend/app --cov-report=term-missing

# Run unit tests only
pytest backend/tests/unit -v

# Run security boundary & regression tests
pytest backend/tests/security backend/tests/regression -v
```
