"""
Promptfoo Custom Python Provider bridging Promptfoo to LLM-RedTeam Target Adapters.

Supports:
1. Deterministic MockTargetAdapter (secure and vulnerable modes).
2. AIIAMTargetAdapter (pre-execution MCP tool authorization proxy).
3. ExternalAuthorizedHTTPAdapter (for explicitly authorized external LLM endpoints when SAFE_MODE=false).

Enforces Safe-Mode SSRF guardrails, target validation, and structured metadata capture
including runtime tool_calls_attempted.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

# Ensure backend directory is on sys.path when invoked by Promptfoo CLI subprocess
_BACKEND_DIR = Path(__file__).resolve().parents[3]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import httpx  # noqa: E402
from app.adapters.ai_iam_adapter import AIIAMTargetAdapter  # noqa: E402
from app.adapters.base import TargetAdapter, TargetResponse  # noqa: E402
from app.adapters.mock_adapter import MockTargetAdapter  # noqa: E402
from app.evaluation.context import ExecutionContext  # noqa: E402
from app.integrations.promptfoo.validators import validate_promptfoo_target  # noqa: E402
from app.schemas.enums import AttackCategory, Severity  # noqa: E402
from app.schemas.test_case import ExpectedOutcome, TestCaseBase  # noqa: E402


class ExternalAuthorizedHTTPAdapter(TargetAdapter):
    """
    Future-compatible TargetAdapter for explicitly authorized external LLM HTTP providers.
    Strictly enforces Safe Mode and requires explicit configuration and authorization.
    """

    def __init__(
        self,
        name: str = "Authorized External LLM Provider",
        endpoint_url: Optional[str] = None,
        safe_mode: bool = True,
        authorize_external: bool = False,
        timeout_seconds: float = 15.0,
        headers: Optional[Dict[str, str]] = None,
        client: Optional[httpx.AsyncClient] = None,
    ):
        super().__init__(name=name, endpoint_url=endpoint_url, safe_mode=safe_mode)
        self.authorize_external = authorize_external
        self.timeout_seconds = timeout_seconds
        self.headers = headers or {}
        self._custom_client = client

    async def execute(self, context: ExecutionContext) -> TargetResponse:
        # Enforce Safe Mode and explicit authorization
        self.validate_target_safety(self.endpoint_url)
        if not self.authorize_external:
            raise PermissionError(
                "External provider execution blocked: explicit authorization (authorize_external=True) is required."
            )
        if not self.endpoint_url:
            raise ValueError("External provider execution blocked: endpoint_url must be configured.")

        tc = context.test_case
        payload = {
            "prompt": tc.input_prompt,
            "system_prompt": tc.system_prompt,
            "retrieved_context": tc.retrieved_context,
            "tenant_id": tc.tenant_id,
            "user_role": tc.user_role,
            "target_tool_name": tc.target_tool_name,
        }

        c = self._custom_client or httpx.AsyncClient(timeout=self.timeout_seconds)
        should_close = self._custom_client is None
        start_time = datetime.now(timezone.utc)
        try:
            resp = await c.post(self.endpoint_url, json=payload, headers=self.headers)
            duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            if resp.status_code >= 400:
                return TargetResponse(
                    output_text=resp.text,
                    status_code=resp.status_code,
                    error=f"HTTP_{resp.status_code}",
                    duration_ms=duration_ms,
                )
            data = resp.json() if resp.content else {}
            return TargetResponse(
                output_text=str(data.get("output", data.get("content", resp.text))),
                tool_calls_attempted=data.get("tool_calls", []),
                duration_ms=duration_ms,
                status_code=resp.status_code,
                raw_response=data if isinstance(data, dict) else {"raw": data},
            )
        except httpx.RequestError as exc:
            return TargetResponse(
                output_text="",
                status_code=502,
                error=f"External target connection error: {str(exc)}",
                duration_ms=0.0,
            )
        finally:
            if should_close:
                await c.aclose()


def _parse_str_list(val: Any, default: Optional[List[str]] = None) -> List[str]:
    if isinstance(val, list):
        return [str(x) for x in val]
    if isinstance(val, str):
        sep = "|" if "|" in val else ","
        return [s.strip() for s in val.split(sep) if s.strip()]
    return list(default or [])


def build_test_case_from_vars(prompt: str, vars_dict: Dict[str, Any]) -> TestCaseBase:
    """Constructs a validated TestCaseBase from Promptfoo test vars."""
    spec = vars_dict.get("spec", {}) if isinstance(vars_dict.get("spec"), dict) else {}
    merged = {**spec, **vars_dict}

    raw_cat = str(merged.get("category", AttackCategory.DIRECT_PROMPT_INJECTION.value)).lower()
    try:
        category = AttackCategory(raw_cat)
    except ValueError:
        category = AttackCategory.DIRECT_PROMPT_INJECTION

    raw_sev = str(merged.get("severity", Severity.HIGH.value)).lower()
    try:
        severity = Severity(raw_sev)
    except ValueError:
        severity = Severity.HIGH

    is_benign = bool(merged.get("is_benign_control", category == AttackCategory.BENIGN_CONTROL))
    must_block = bool(merged.get("must_block_action", not is_benign))
    forbidden: List[str] = _parse_str_list(merged.get("forbidden_substrings"), [])
    required: List[str] = _parse_str_list(merged.get("required_substrings"), [])
    tags: List[str] = _parse_str_list(merged.get("tags"), ["promptfoo"])

    test_id = str(merged.get("test_id", "PF-DYNAMIC-001"))
    name = str(merged.get("name", f"Promptfoo Probe {test_id}"))
    if len(name) < 3:
        name = f"Probe {name}"
    description = str(merged.get("description", name))

    return TestCaseBase(
        test_id=test_id,
        category=category,
        name=name[:150],
        description=description,
        severity=severity,
        is_benign_control=is_benign,
        tags=tags,
        input_prompt=prompt or str(merged.get("prompt", "")),
        system_prompt=merged.get("system_prompt"),
        retrieved_context=merged.get("retrieved_context"),
        synthetic_canary=merged.get("synthetic_canary"),
        tenant_id=merged.get("tenant_id"),
        user_role=str(merged.get("user_role") or "standard_user"),
        target_tool_name=merged.get("target_tool_name"),
        expected_outcome=ExpectedOutcome(
            must_block_action=must_block,
            must_not_contain_canaries=True,
            forbidden_substrings=forbidden,
            required_substrings=required,
            expected_tool_name=merged.get("expected_tool_name"),
            expected_tenant_id=merged.get("expected_tenant_id"),
        ),
    )


def resolve_adapter_from_config(provider_config: Dict[str, Any]) -> Tuple[TargetAdapter, Dict[str, Any]]:
    """
    Validates target config and instantiates the appropriate TargetAdapter.
    """
    target_id = str(provider_config.get("target", os.environ.get("PROMPTFOO_TARGET", "mock-secure")))
    endpoint_url = provider_config.get("endpoint_url")
    safe_mode = provider_config.get("safe_mode")
    authorize_external = bool(provider_config.get("authorize_external", False))

    target_meta = validate_promptfoo_target(
        target=target_id,
        endpoint_url=endpoint_url,
        safe_mode=safe_mode,
        authorize_external=authorize_external,
    )

    adapter_type = target_meta["adapter_type"]
    if adapter_type == "mock_target":
        mode = str(provider_config.get("mode") or target_meta["mode"])
        adapter: TargetAdapter = MockTargetAdapter(mode=mode, name=target_meta["name"])
        adapter.safe_mode = target_meta["safe_mode"]
    elif adapter_type == "ai_iam_adapter":
        base_url = target_meta["endpoint_url"] or "http://localhost:8000"
        adapter = AIIAMTargetAdapter(
            name=target_meta["name"],
            base_url=base_url,
            safe_mode=target_meta["safe_mode"],
        )
    else:
        adapter = ExternalAuthorizedHTTPAdapter(
            name=target_meta["name"],
            endpoint_url=target_meta["endpoint_url"],
            safe_mode=target_meta["safe_mode"],
            authorize_external=authorize_external,
        )

    return adapter, target_meta


async def execute_promptfoo_probe_async(
    prompt: str,
    options: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Asynchronously executes a Promptfoo test probe through the LLM-RedTeam TargetAdapter.
    """
    opts = options or {}
    ctx = context or {}
    provider_config = opts.get("config", {}) if isinstance(opts.get("config"), dict) else {}
    vars_dict = ctx.get("vars", {}) if isinstance(ctx.get("vars"), dict) else {}

    adapter, target_meta = resolve_adapter_from_config(provider_config)
    test_case = build_test_case_from_vars(prompt, vars_dict)

    exec_context = ExecutionContext(
        test_case=test_case,
        correlation_id=f"promptfoo:{test_case.test_id}",
        model_name=target_meta.get("model_identifier", "sentinel-mock-v1"),
        target_options=provider_config,
    )

    response: TargetResponse = await adapter.execute(exec_context)

    result: Dict[str, Any] = {
        "output": response.output_text,
        "metadata": {
            "test_id": test_case.test_id,
            "category": test_case.category.value,
            "is_benign_control": test_case.is_benign_control,
            "tool_calls_attempted": response.tool_calls_attempted,
            "duration_ms": response.duration_ms,
            "status_code": response.status_code,
            "is_error": response.is_error,
            "target_id": target_meta["id"],
            "target_name": target_meta["name"],
            "model_identifier": target_meta.get("model_identifier"),
            "synthetic_canary": test_case.synthetic_canary,
            "tenant_id": test_case.tenant_id,
            "user_role": test_case.user_role,
            "target_tool_name": test_case.target_tool_name,
        },
    }

    if response.is_error:
        result["error"] = response.error or f"Target returned HTTP {response.status_code}"

    return result


def call_api(
    prompt: str,
    options: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Official Promptfoo Python Provider entrypoint: call_api(prompt, options, context).
    """
    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, execute_promptfoo_probe_async(prompt, options, context))
                return future.result()
        else:
            return asyncio.run(execute_promptfoo_probe_async(prompt, options, context))
    except PermissionError as perm_err:
        return {
            "output": "",
            "error": f"SafeMode/PermissionError: {str(perm_err)}",
            "metadata": {"is_error": True, "error_type": "PermissionError"},
        }
    except Exception as exc:
        return {
            "output": "",
            "error": f"ProviderExecutionError: {str(exc)}",
            "metadata": {"is_error": True, "error_type": type(exc).__name__},
        }
