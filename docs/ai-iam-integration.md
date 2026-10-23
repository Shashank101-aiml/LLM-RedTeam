# AI-IAM Platform & External Scanner Integration Specification

## 1. Context & Verified Interfaces

The companion AI-IAM platform repository is located at `D:\ai-iam-platform`.

The AI-IAM platform implements an agentic Identity and Access Management control plane with:
- Pre-execution tool call interception via an MCP Proxy.
- Short-lived RS256 token exchange with mathematical delegation scope attenuation.
- Tamper-evident append-only audit logging in PostgreSQL.
- Provenance taint tracking via `causal_trace_id`.

---

## 2. Integration Endpoints & Schemas (Verified)

### 2.1 Agent Authentication & Token Exchange
- **Endpoint**: `POST /api/v1/token/exchange`
- **Authentication**: Compound API key (`kid_xxxxxxxx:aiiam_<hex>`).
- **Request Schema**:
  ```json
  {
    "grant_type": "api_key",
    "credential": "kid_demo:aiiam_secret_hex",
    "causal_trace_id": "sentinel:test_trace_01"
  }
  ```
- **Response Schema** (`AgentJwtResponse`):
  ```json
  {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",
    "token_type": "bearer",
    "expires_in": 900,
    "jti": "jti_uuid_...",
    "scopes": ["tool:execute"]
  }
  ```

---

### 2.2 Pre-Execution MCP Tool Proxy Interception
- **Endpoint**: `POST /api/v1/mcp/tools/{tool_name}`
- **Authentication**: `Authorization: Bearer <access_token>`
- **Request Schema** (`McpToolExecuteRequest`):
  ```json
  {
    "mcp_server_id": "srv-1",
    "arguments": {
      "prompt": "Drop table users",
      "user_role": "standard_user",
      "tenant_id": "default_tenant"
    },
    "causal_trace_id": "sentinel:test_trace_01"
  }
  ```
- **Responses**:
  - **Allowed (`status_code: 200`)** (`McpToolExecuteResponse`):
    ```json
    {
      "session_id": "sess-999",
      "tool_name": "search_records",
      "status": "allowed",
      "result": { "data": "ok" },
      "policy_decision": "allow"
    }
    ```
  - **Denied (`status_code: 403`)**:
    Tool execution intercepted before MCP server dispatch; returns ReBAC policy denial reason:
    ```json
    {
      "detail": {
        "reason": "OPA policy evaluated to DENY for tool execution",
        "policy": "authz.rego"
      }
    }
    ```
  - **Unauthorized (`status_code: 401`)**:
    Token expired or invalid signature; adapter re-authenticates automatically.
  - **Unprocessable Entity (`status_code: 422`)**:
    Task-scoping required for dangerous scopes without intent.

---

## 3. LLM Sentinel AI-IAM Target Adapter

Implemented in [`AIIAMTargetAdapter`](file:///d:/RedTeam/backend/app/adapters/ai_iam_adapter.py):

```mermaid
graph LR
    Sentinel[LLM Sentinel Evaluator] -->|1. Authenticate synthetic agent| Adapter[AIIAMTargetAdapter]
    Adapter -->|2. POST /api/v1/token/exchange| AIIAM[AI-IAM Server]
    AIIAM -->>|3. RS256 JWT (expires_in: 900s)| Adapter
    Sentinel -->|4. Trigger Adversarial / Benign Probe| Adapter
    Adapter -->|5. POST /api/v1/mcp/tools/{tool_name}| AIIAM
    AIIAM -->>|6. 200 Allowed or 403 OPA Denied| Adapter
    Adapter -->>|7. Normalized TargetResponse| Sentinel
```

### 3.1 Resilience & Security Controls
- **Safe Mode Enforcement**: Target URLs are checked against `ALLOWED_TARGET_HOSTS`. Any attempt to target external URLs (`https://api.external-iam.com`) while `SAFE_MODE=true` is rejected with `PermissionError`.
- **Token Caching & Expiration**: Tokens are cached and reused while valid with a 30-second TTL safety buffer.
- **Connection Error Handling**: Returns structured `TargetResponse(status_code=502)` on network unreachable and `504` on timeout without crashing the engine.

---

## 4. External Scanner Normalizers (Promptfoo & Garak)

Located in [`backend/app/integrations/`](file:///d:/RedTeam/backend/app/integrations/):

### 4.1 Promptfoo Normalizer
- **Interface**: `PromptfooNormalizer.parse(json_data)`
- **Category Heuristics**: Automatically maps assertion types and test prompts into Sentinel's 6 attack categories.
- **Provenance Preservation**: Preserves raw Promptfoo scores, token counts, and grading details in `raw_metadata`.

### 4.2 NVIDIA Garak Normalizer
- **Interface**: `GarakNormalizer.parse(json_or_jsonl_data)`
- **Probe Mapping**: Maps Garak probe classes (e.g. `garak.probes.promptinject` $\rightarrow$ `direct_prompt_injection`, `garak.probes.dan` $\rightarrow$ `jailbreak`, `garak.probes.leakvec` $\rightarrow$ `system_prompt_leakage`).
- **Provenance Preservation**: Retains probe ID, detector names, and raw detector scores.

### 4.3 Ingestion Endpoints
- `POST /api/v1/integrations/import/promptfoo?persist=true`
- `POST /api/v1/integrations/import/garak?persist=true`
- Normalizes external runs and persists them to `evaluation_runs`, `test_executions`, and `findings` tables for dashboard inspection.
