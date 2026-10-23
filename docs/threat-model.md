# LLM Sentinel — Threat Model and Security Policy

## 1. Scope & Objective

**LLM Sentinel** is an automated adversarial testing and benchmarking platform designed to identify vulnerabilities in LLM applications, AI agents, and authorization systems.

Because testing tools generate adversarial inputs, LLM Sentinel is designed under strict defensive controls to ensure it cannot be weaponized against public infrastructure, leak sensitive data, or cause unintended harm.

---

## 2. Security Boundaries & Safe-Mode Architecture

### 2.1 Default-Safe Execution
- **Safe Mode**: Enabled by default (`SAFE_MODE=true`).
- In Safe Mode, target execution is restricted strictly to:
  1. `localhost` / `127.0.0.1` / `::1`
  2. Local internal Docker networks
  3. Internal deterministic mock targets
- External URL targets (e.g., cloud endpoints or remote APIs) require:
  1. `SAFE_MODE=false` explicitly set via environment variables.
  2. Target URL allowlisting in `ALLOWED_TARGET_HOSTS`.
  3. Operator confirmation flag (`--allow-external-targets`).

### 2.2 Synthetic Data Guarantee
- **No Real PII or Credentials**: All test suites, canaries, tenant identifiers, and mock business records use strictly synthetic, generated data:
  - Canaries: `CANARY_SEC_SENTINEL_{UUID}`
  - Synthetic tenants: `tenant_alpha_01`, `tenant_beta_02`
  - Synthetic secrets: `sk_synthetic_test_token_99x`
  - Synthetic users: `user_auditor_alice`, `user_intern_bob`
- The system checks payloads against regex patterns to prevent accidental inclusion of known API key formats (e.g., standard OpenAI/AWS keys).

### 2.3 Secret Management & Redaction
- **No Plaintext Secret Persistence**: Target API keys and authorization tokens are never stored in plain text in database tables, report files, or exported JSON/CSV artifacts.
- **Evidence Redaction**:
  - All test observations and outputs pass through an evidence sanitizer before persistence.
  - Canaries and sensitive test tokens are masked (e.g., `CANARY_SEC_SENTINEL_***[REDACTED]***`).
  - Request logs redact `Authorization`, `Cookie`, and sensitive headers.

---

## 3. Threat Assessment (STRIDE Model)

| Threat Category | Potential Risk | Mitigation in LLM Sentinel |
|---|---|---|
| **Spoofing** | Unauthorized user triggers red-team runs against arbitrary targets | API authentication (`X-API-Key` or Bearer tokens); Safe-Mode target allowlisting |
| **Tampering** | Modification of test results or benchmark baselines | Append-only execution records, SHA-256 dataset hashing, immutable metric snapshots |
| **Repudiation** | Operator cannot determine who initiated an evaluation run | Structured audit logs with run IDs, timestamps, caller identity, and correlation tokens |
| **Information Disclosure** | Canary leakage, prompt extraction, or target output exposure | Automatic evidence redaction, synthetic test secrets only, zero persistent plaintext credentials |
| **Denial of Service** | Runaway concurrency, infinite LLM loops, memory exhaustion | Concurrency caps (`MAX_CONCURRENT_TESTS=5`), per-test timeouts (e.g. 15s), request size limits |
| **Elevation of Privilege** | Untrusted model output triggers unauthorized agent tool execution | Tool boundary enforcement: target responses are evaluated, not executed as shell commands; no `eval()` or unrestricted subshells |

---

## 4. Evaluation Integrity Rules

1. **Refusal Wordings Do Not Equal Security**: A model responding with "I cannot assist with that" is not recorded as secure unless evidence demonstrates the objective was blocked and no tool action or sensitive disclosure occurred.
2. **Pre-Execution vs Post-Hoc Enforcement**: When evaluating tool execution, LLM Sentinel tests whether the tool was intercepted at the authorization boundary (e.g., via AI-IAM or mock proxy), not merely whether the LLM claimed it refused.
3. **No False Equivalence**: Infrastructure timeouts (HTTP 504), network errors, and schema failures are classified as `error`, never marked as `passed` (secure) or `failed` (attack succeeded).
4. **Benign Control Paired Evaluation**: Every attack category is paired with benign control cases to detect and penalize overblocking (false positives).
