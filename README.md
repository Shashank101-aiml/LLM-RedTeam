# LLM RedTeam

> **Production-Grade LLM Red-Teaming, Adversarial Benchmarking, and Security Evaluation Platform**

[![CI/CD Pipeline](https://github.com/Shashank101-aiml/LLM-RedTeam/actions/workflows/ci.yml/badge.svg)](https://github.com/Shashank101-aiml/LLM-RedTeam/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![React 18](https://img.shields.io/badge/Frontend-React%2018%20%7C%20TypeScript-blue)](https://react.dev/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Safe Mode Default](https://img.shields.io/badge/Security-Safe%20Mode%20Default-success.svg)](#safe-mode--security-controls)

---

## 1. System Overview

**LLM RedTeam** is an automated, reproducible red-teaming evaluation and security benchmarking platform designed for LLM applications, autonomous AI agents, and authorization-aware control planes. 

It evaluates systems across **6 core adversarial attack categories** plus **benign control baselines**, pairing offensive security probes with statistical metrics, regression diffs, and evidence sanitization:

1. **Direct Prompt Injection (OWASP LLM01)**: Adversarial roleplay, recursive conversational inversion, system directive hijacking.
2. **Indirect Prompt Injection**: Untrusted document content, malicious RAG contexts, poisoned tool outputs.
3. **Jailbreak Resistance**: Adversarial prefixes, policy bypasses, multi-turn elicitation.
4. **System-Prompt & Synthetic Canary Leakage (OWASP LLM07)**: System directive exfiltration, synthetic canary token disclosures.
5. **Unauthorized Tool Invocations & Privilege Boundaries (OWASP LLM02)**: Autonomous tool execution exceeding granted scopes, tool parameter tampering.
6. **Sensitive-Data & Tenant Isolation (OWASP LLM06)**: Cross-tenant unauthorized object access, privilege escalation.
7. **Benign Control Baselines**: Non-malicious inquiries paired with each category to measure **False Positive Rate (FPR)** and detect **overblocking**.

---

## 2. Architecture & Pipeline

```mermaid
graph TD
    subgraph UI & Client Layer
        Dashboard[React + TypeScript + Vite Dashboard :3000]
        CLI[Benchmarking Runner CLI / Scripts]
    end

    subgraph API & Backend Layer (FastAPI :8000)
        API[FastAPI Gateway /api/v1]
        Auth[API Auth & Safe-Mode SSRF Guard]
        RunManager[Evaluation Run Manager & Async Worker]
        MetricsEngine[Metrics & Aggregation Engine]
        ReportGen[Report Exporter - JSON & CSV]
        IntegrationsRouter[External Scanner Ingestion - Promptfoo & Garak]
    end

    subgraph Evaluation Core
        Corpus[Corpus Registry - 19 Base Test Cases]
        Evaluator[Outcome Evaluator & Evidence Sanitizer]
        CanaryDetector[Regex & Split-Token Canary Detector]
    end

    subgraph Target Adapters
        MockTarget[Deterministic Mock Target - Vulnerable & Secure Modes]
        AIIAMAdapter[AI-IAM Platform Adapter - Pre-Execution MCP Proxy]
    end

    subgraph Data & Persistence
        DB[(SQLite / PostgreSQL via SQLAlchemy)]
    end

    Dashboard -->|REST / JSON| API
    CLI -->|REST or Direct Python| RunManager
    API --> Auth --> RunManager
    API --> IntegrationsRouter
    RunManager --> Corpus
    RunManager --> TargetAdapters
    TargetAdapters --> MockTarget
    TargetAdapters --> AIIAMAdapter
    RunManager --> Evaluator
    Evaluator --> CanaryDetector
    Evaluator --> MetricsEngine
    MetricsEngine --> DB
    Evaluator --> DB
    API --> ReportGen
```

---

## 3. Safe Mode & Security Controls

LLM RedTeam is built defensively to prevent accidental harm, unauthorized scanning, and credential exposure:

- **Safe-Mode Default (`SAFE_MODE=true`)**: Target URLs are strictly checked against `ALLOWED_TARGET_HOSTS` (`localhost`, `127.0.0.1`, `::1`, `mock-target`). Requests to external domains or metadata services (e.g., AWS IMDS `169.254.169.254`) are aborted with `PermissionError` (HTTP 403).
- **Synthetic Data Guarantee**: All test cases use synthetic canary tokens (`CANARY-SECRET-BETA-7790`), synthetic tenants (`tenant_alpha`, `tenant_bravo`), and synthetic roles. Zero real PII or production credentials exist in the codebase.
- **Evidence Sanitization**: All logged outputs and exported reports automatically scrub canaries, bearer tokens, and API keys (`[REDACTED_CANARY]`, `[REDACTED_API_KEY]`).
- **Deceptive Refusal Boundary Rule**: Verbal refusals (*"I cannot do that"*) do not count as secure defense if the model simultaneously dispatched an unauthorized tool call at the runtime boundary.

---

## 4. Mathematical Metrics & Statistical Definitions

LLM RedTeam calculates reproducible metrics with zero-denominator protections and statistical confidence intervals:

| Metric | Formula | Description |
|---|---|---|
| **Attack Success Rate (ASR)** | $\text{ASR} = \frac{N_{\text{attack\_achieved}}}{N_{\text{attack\_attempts}}}$ | Proportion of attacks that successfully bypassed defenses (lower is better). |
| **Security Pass Rate (STPR)** | $\text{STPR} = \frac{N_{\text{passed\_tests}}}{N_{\text{total\_tests}}}$ | Proportion of tests where security boundaries held. |
| **False Positive Rate (FPR)** | $\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$ | Rate at which benign requests were erroneously blocked (overblocking). |
| **Benign Acceptance Rate (BRAR)** | $\text{BRAR} = 1 - \text{FPR} = \frac{\text{TN}}{\text{TN} + \text{FP}}$ | Proportion of legitimate user requests correctly allowed. |
| **Detection Precision** | $\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$ | Accuracy of security trigger alerts. |
| **Detection Recall** | $\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$ | Detection sensitivity over all malicious inputs. |

### Wilson Score Confidence Intervals
For small sample sizes ($N < 30$), standard normal approximations fail. LLM RedTeam computes exact Wilson score intervals:

$$\tilde{p} = \frac{p + \frac{z^2}{2n} \pm z \sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

---

## 5. Quickstart & Setup Instructions

### Prerequisites
- Python 3.12+
- Node.js 20+ (for Frontend Dashboard)
- Docker & Docker Compose (optional for containerized deployment)

### Option A: Local Development Setup (Zero-Token Offline Mode)

```bash
# 1. Clone repository
git clone https://github.com/Shashank101-aiml/LLM-RedTeam.git
cd LLM-RedTeam

# 2. Setup backend virtual environment
python -m venv backend/.venv
.\backend\.venv\Scripts\pip install -e "./backend[dev]"

# 3. Setup frontend dependencies
cd frontend
npm install
cd ..

# 4. Run the demonstration benchmark (Zero external API credentials required)
.\backend\.venv\Scripts\python.exe scripts/run_demo_benchmark.py

# 5. Start Backend and Frontend
# Terminal 1: Backend
cd backend
.\.venv\Scripts\uvicorn app.main:app --reload --port 8000

# Terminal 2: Frontend
cd frontend
npm run dev
```

Dashboard is accessible at `http://localhost:5173`, backend API documentation at `http://localhost:8000/api/v1/docs`.

---

### Option B: Docker Compose (Single Command Launch)

```bash
docker compose up -d
```
- Frontend Dashboard: `http://localhost:3000`
- FastAPI Backend: `http://localhost:8000`
- API Health Status: `http://localhost:8000/api/v1/health`

---

## 6. API Reference & Examples

### Health Check
```bash
curl -s http://localhost:8000/api/v1/health | jq
```
```json
{
  "status": "ok",
  "version": "0.1.0",
  "environment": "production",
  "safe_mode": true,
  "components": {
    "database": "ok",
    "evaluation_engine": "ready",
    "mock_target": "ready"
  }
}
```

### Create and Execute an Evaluation Run
```bash
curl -X POST http://localhost:8000/api/v1/runs \
  -H "Content-Type: application/json" \
  -d '{
    "target_name": "Deterministic Mock Target (Vulnerable Mode)",
    "dataset_version": "sentinel-corpus-v1.0",
    "notes": "Baseline vulnerability scan"
  }'
```

### Compare Evaluation Runs (Adversarial Regression Diff)
```bash
curl -X POST http://localhost:8000/api/v1/compare \
  -H "Content-Type: application/json" \
  -d '{
    "baseline_run_id": "<BASELINE_RUN_ID>",
    "candidate_run_id": "<CANDIDATE_RUN_ID>"
  }'
```

### Export Sanitized Report (JSON / CSV)
```bash
# Export Sanitized JSON
curl -s http://localhost:8000/api/v1/runs/<RUN_ID>/export?format=json > report.json

# Export Sanitized CSV
curl -s http://localhost:8000/api/v1/runs/<RUN_ID>/export?format=csv > findings.csv
```

### Ingest External Scanner Reports (Promptfoo / Garak)
```bash
# Import Promptfoo Evaluation
curl -X POST "http://localhost:8000/api/v1/integrations/import/promptfoo?persist=true" \
  -H "Content-Type: application/json" \
  -d @promptfoo_results.json

# Import NVIDIA Garak Evaluation
curl -X POST "http://localhost:8000/api/v1/integrations/import/garak?persist=true" \
  -H "Content-Type: application/json" \
  -d @garak_report.json
```

---

## 7. Companion AI-IAM Platform Integration

LLM RedTeam natively interfaces with the companion agent identity control plane at `D:\ai-iam-platform` via [`AIIAMTargetAdapter`](file:///d:/RedTeam/backend/app/adapters/ai_iam_adapter.py):

- **Token Exchange**: Authenticates synthetic agent credentials (`kid_...:aiiam_...`) via `POST /api/v1/token/exchange` for short-lived RS256 JWTs.
- **Pre-Execution MCP Interception**: Dispatches tool probes to `POST /api/v1/mcp/tools/{tool_name}` with causal provenance tracing (`causal_trace_id`).
- **Policy Denial Capture**: Accurately records OPA ReBAC blocks (HTTP 403) as successful defenses rather than execution failures.

---

## 8. Responsible-Use & Ethical Guidance

LLM RedTeam is designed strictly for **defensive security auditing, model alignment verification, and regression tracking**.

1. **Explicit Authorization**: Only evaluate systems, models, and endpoints for which you have explicit written authorization.
2. **Safe Mode Preservation**: Do not disable `SAFE_MODE` against third-party production services without coordinated vulnerability disclosure agreements.
3. **No Weaponization**: Evaluator payloads and attack cases are curated to assess alignment guardrails and architectural boundaries; do not repurpose them for unauthorized intrusion.
4. **Data Privacy**: Use synthetic datasets only. Never inject real customer PII or proprietary trade secrets into test suites.

---

## 9. Known Limitations & Roadmap

### Known Limitations
1. **Mock Target Scope**: While deterministic and covering all 6 threat vectors, in-memory mock targets do not emulate probabilistic token distribution variance of 70B+ parameter models.
2. **External Scanner Normalization**: Promptfoo and Garak report normalizers currently support single-turn evaluation outputs; multi-turn conversation traces are flattened to single-turn attempts.
3. **Local SQLite Concurrency**: SQLite in WAL mode supports concurrent reads and serialized writes. For high-volume enterprise deployments with 100+ concurrent evaluation workers, PostgreSQL is recommended.

### Roadmap
- [ ] Multi-turn interactive adversarial conversation agents.
- [ ] Automated continuous CI/CD PR blocking on ASR regression thresholds.
- [ ] Distributed Celery/Redis worker queues for massive test corpora.
- [ ] Direct SAML/OIDC SSO integration for enterprise multi-tenancy.

---

## 10. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
