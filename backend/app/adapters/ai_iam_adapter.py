"""
AI-IAM Target Adapter.

Interfaces with the companion AI-IAM agent authorization platform (D:\\ai-iam-platform).
Verified against the actual AI-IAM endpoints:
  - POST /api/v1/token/exchange (Agent authentication via compound API key kid_...:aiiam_...)
  - POST /api/v1/mcp/tools/{tool_name} (Pre-execution ReBAC tool interception)

Enforces Safe-Mode URL validation, automatic RS256 token caching with re-authentication,
and structured policy decision capture.
"""

from datetime import datetime, timezone, timedelta
import logging
from typing import Optional
import httpx
from app.adapters.base import TargetAdapter, TargetResponse
from app.evaluation.context import ExecutionContext

logger = logging.getLogger("llm_sentinel.adapters.ai_iam")


class AIIAMAuthError(Exception):
    """Raised when authentication or token exchange with AI-IAM fails due to invalid credentials."""
    pass


class AIIAMConnectionError(Exception):
    """Raised when network connection or transport to AI-IAM fails."""
    pass


class AIIAMTargetAdapter(TargetAdapter):
    """
    Adapter interfacing with the AI-IAM Agent Identity & Access Management platform.
    Supports both live HTTP communication and injected test clients.
    """

    def __init__(
        self,
        name: str = "AI-IAM Platform Adapter",
        base_url: str = "http://localhost:8000",
        credential: Optional[str] = None,
        default_mcp_server_id: str = "srv-1",
        client: Optional[httpx.AsyncClient] = None,
        safe_mode: bool = True,
        timeout_seconds: float = 10.0,
    ):
        super().__init__(name=name, endpoint_url=base_url, safe_mode=safe_mode)
        self.base_url = base_url.rstrip("/")
        self.credential = credential or "kid_sentinel:aiiam_synthetic_secret_01"
        self.default_mcp_server_id = default_mcp_server_id
        self._custom_client = client
        self.timeout_seconds = timeout_seconds
        self._access_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._custom_client is not None:
            return self._custom_client
        return httpx.AsyncClient(timeout=self.timeout_seconds)

    async def authenticate(self, client: Optional[httpx.AsyncClient] = None) -> str:
        """
        Authenticates against AI-IAM via /api/v1/token/exchange.
        Uses cached access token if still valid (with a 30s buffer).
        """
        now = datetime.now(timezone.utc)
        if self._access_token and self._token_expires_at and self._token_expires_at > (now + timedelta(seconds=30)):
            return self._access_token

        self.validate_target_safety(self.base_url)
        c = client or self._get_client()
        exchange_url = f"{self.base_url}/api/v1/token/exchange"

        payload = {
            "grant_type": "api_key",
            "credential": self.credential,
        }

        try:
            resp = await c.post(exchange_url, json=payload)
            if resp.status_code != 200:
                raise AIIAMAuthError(
                    f"AI-IAM token exchange failed with status {resp.status_code}: {resp.text}"
                )
            data = resp.json()
            self._access_token = data["access_token"]
            expires_in = data.get("expires_in", 900)
            self._token_expires_at = now + timedelta(seconds=expires_in)
            return self._access_token
        except httpx.RequestError as exc:
            raise AIIAMConnectionError(f"Network error during AI-IAM token exchange: {str(exc)}") from exc
        finally:
            if self._custom_client is None and client is None:
                await c.aclose()

    async def execute(self, context: ExecutionContext) -> TargetResponse:
        """
        Executes an evaluation probe against AI-IAM's pre-execution MCP proxy router.
        Endpoints: POST /api/v1/mcp/tools/{tool_name}
        """
        self.validate_target_safety(self.base_url)
        tc = context.test_case
        tool_name = tc.target_tool_name or "mcp_tool_action"
        mcp_meta = getattr(tc, "metadata", None) or {}
        mcp_server_id = mcp_meta.get("mcp_server_id", self.default_mcp_server_id)
        causal_trace_id = context.correlation_id or f"sentinel:{tc.test_id}"

        c = self._get_client()
        should_close_client = (self._custom_client is None)

        try:
            # 1. Obtain token
            try:
                token = await self.authenticate(client=c)
            except AIIAMAuthError as auth_err:
                return TargetResponse(
                    output_text=f"Authentication Failure: {str(auth_err)}",
                    status_code=401,
                    error=str(auth_err),
                    duration_ms=0.0,
                )
            except AIIAMConnectionError as conn_err:
                return TargetResponse(
                    output_text=f"Connection Error: {str(conn_err)}",
                    status_code=502,
                    error=str(conn_err),
                    duration_ms=0.0,
                )

            # 2. Prepare MCP execute tool payload
            tool_url = f"{self.base_url}/api/v1/mcp/tools/{tool_name}"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            body = {
                "mcp_server_id": mcp_server_id,
                "arguments": {
                    "prompt": tc.input_prompt,
                    "user_role": tc.user_role or "standard_user",
                    "tenant_id": tc.tenant_id or "default_tenant",
                },
                "causal_trace_id": causal_trace_id,
            }

            start_time = datetime.now(timezone.utc)
            resp = await c.post(tool_url, json=body, headers=headers)
            duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            # 3. Analyze response
            if resp.status_code == 200:
                data = resp.json()
                return TargetResponse(
                    output_text=f"Tool '{tool_name}' executed successfully by AI-IAM. Result: {data.get('result')}",
                    tool_calls_attempted=[{
                        "tool": tool_name,
                        "status": "executed",
                        "arguments": body["arguments"],
                        "result": data.get("result"),
                        "policy_decision": data.get("policy_decision", "allow"),
                    }],
                    duration_ms=duration_ms,
                    status_code=200,
                    raw_response=data,
                )
            elif resp.status_code == 403:
                # OPA Policy Denial pre-execution intercept
                try:
                    data = resp.json()
                except Exception:
                    data = {"detail": resp.text}

                reason = "OPA policy evaluated to DENY"
                if isinstance(data.get("detail"), dict):
                    reason = data["detail"].get("reason", reason)
                elif isinstance(data.get("detail"), str):
                    reason = data["detail"]

                return TargetResponse(
                    output_text=f"Tool '{tool_name}' execution denied by AI-IAM OPA policy: {reason}",
                    tool_calls_attempted=[{
                        "tool": tool_name,
                        "status": "blocked",
                        "reason": reason,
                        "policy_decision": "deny",
                    }],
                    duration_ms=duration_ms,
                    status_code=403,
                    raw_response=data,
                )
            elif resp.status_code == 401:
                # Token expired or invalid
                self._access_token = None
                return TargetResponse(
                    output_text="AI-IAM returned 401 Unauthorized during tool execution.",
                    status_code=401,
                    error="Unauthorized",
                    duration_ms=duration_ms,
                    raw_response={"text": resp.text},
                )
            elif resp.status_code == 422:
                # Task-scoping or validation error
                try:
                    data = resp.json()
                except Exception:
                    data = {"detail": resp.text}
                return TargetResponse(
                    output_text=f"AI-IAM validation/task-scoping requirement: {data}",
                    tool_calls_attempted=[{
                        "tool": tool_name,
                        "status": "blocked",
                        "reason": "validation_error_task_scoping_required",
                    }],
                    duration_ms=duration_ms,
                    status_code=422,
                    raw_response=data,
                )
            else:
                return TargetResponse(
                    output_text=f"AI-IAM returned unexpected HTTP {resp.status_code}: {resp.text}",
                    status_code=resp.status_code,
                    error=f"HTTP_{resp.status_code}",
                    duration_ms=duration_ms,
                    raw_response={"status_code": resp.status_code, "text": resp.text},
                )

        except httpx.TimeoutException:
            return TargetResponse(
                output_text="",
                error="AI-IAM target request timed out",
                status_code=504,
                duration_ms=self.timeout_seconds * 1000,
            )
        except httpx.RequestError as exc:
            return TargetResponse(
                output_text="",
                error=f"AI-IAM target connection error: {str(exc)}",
                status_code=502,
                duration_ms=0.0,
            )
        finally:
            if should_close_client:
                await c.aclose()
