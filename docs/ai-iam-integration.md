# AI-IAM Platform Integration Specification

## 1. Context & Verified Interfaces

During Phase 0 inspection, the companion AI-IAM platform repository was located at `D:\ai-iam-platform`.

The AI-IAM platform implements an agentic Identity and Access Management control plane with:
- Pre-execution tool call interception via an MCP Proxy.
- RS256 token exchange (`/token/exchange`).
- Mathematical delegation scope attenuation.
- Tamper-evident append-only audit logging in PostgreSQL.
- Provenance taint tracking to detect prompt-injected causal traces.

---

## 2. Integration Endpoints & Schemas

### 2.1 Agent Authentication & Token Exchange
- **Endpoint**: `POST /token/exchange`
- **Authentication**: Compound API key header or body (`kid_xxxxxxxx:aiiam_<hex>`).
- **Request Schema**:
  ```json
  {
    "grant_type": "api_key",
    "credential": "kid_demo:aiiam_secret_hex",
    "causal_trace_id": "sentinel:test_trace_01"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",
    "token_type": "bearer",
    "expires_in": 900
  }
  ```

---

### 2.2 MCP Tool Proxy Interception
- **Endpoint**: `POST /tools/{tool_name}`
- **Authentication**: `Authorization: Bearer <access_token>`
- **Request Schema**:
  ```json
  {
    "mcp_server_id": "00000000-0000-0000-0000-000000000001",
    "arguments": {
      "record_id": "rec_financial_991"
    },
    "causal_trace_id": "sentinel:test_trace_01"
  }
  ```
- **Response**:
  - **Allowed (`status: "allowed"`)**: Tool execution forwarded to target MCP server, returning output payload.
  - **Denied (`status: "denied"`)**: Tool execution intercepted before execution; returns `block_reason` (e.g. `policy_denial`, `provenance_taint`, `tool_filter_violation`) and audit ID.

---

## 3. LLM Sentinel AI-IAM Adapter Architecture

```mermaid
graph LR
    Evaluator[LLM Sentinel Evaluator] -->|1. Authenticate synthetic agent| Adapter[AIIAMTargetAdapter]
    Adapter -->|2. POST /token/exchange| AIIAM[AI-IAM Server]
    AIIAM -->>|3. RS256 JWT| Adapter
    Evaluator -->|4. Trigger Adversarial Scenario| Adapter
    Adapter -->|5. POST /tools/{tool_name}| AIIAM
    AIIAM -->>|6. McpToolExecuteResponse| Adapter
    Adapter -->>|7. Normalized ExecutionResult| Evaluator
```

### 3.1 Adapter Modes
1. **Mock AI-IAM Adapter**: Fully deterministic in-memory simulator of AI-IAM's token exchange, OPA policy evaluation, and tool block behavior for zero-dependency local runs.
2. **Live AI-IAM Adapter**: Real HTTP client interacting with a live AI-IAM container (`http://localhost:8000` or Docker network service `ai-iam-platform`), testing real token exchange, delegation attenuation, and pre-execution tool interception.
