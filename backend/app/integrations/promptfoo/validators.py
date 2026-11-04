"""
Validators and Security Guards for the Promptfoo Integration.

Enforces Safe Mode SSRF protection, target allowlisting, YAML configuration validation,
and safe subprocess argument verification.
"""

from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.core.config import settings
from app.schemas.enums import AttackCategory

# Supported built-in target identifiers
SUPPORTED_TARGETS: Dict[str, Dict[str, Any]] = {
    "mock-secure": {
        "id": "mock-secure",
        "name": "Deterministic Mock Target (Secure Mode)",
        "mode": "secure",
        "adapter_type": "mock_target",
        "endpoint_url": "http://localhost:8000/mock",
        "model_identifier": "sentinel-mock-secure-v1",
        "safe_mode_compatible": True,
    },
    "mock-vulnerable": {
        "id": "mock-vulnerable",
        "name": "Deterministic Mock Target (Vulnerable Mode)",
        "mode": "vulnerable",
        "adapter_type": "mock_target",
        "endpoint_url": "http://localhost:8000/mock",
        "model_identifier": "sentinel-mock-vulnerable-v1",
        "safe_mode_compatible": True,
    },
    "ai-iam-local": {
        "id": "ai-iam-local",
        "name": "AI-IAM Authorization Adapter (Local MCP)",
        "mode": "secure",
        "adapter_type": "ai_iam_adapter",
        "endpoint_url": "http://localhost:8000",
        "model_identifier": "ai-iam-mcp-proxy-v1",
        "safe_mode_compatible": True,
    },
    "external-http": {
        "id": "external-http",
        "name": "Authorized External LLM Provider",
        "mode": "external",
        "adapter_type": "external_http",
        "endpoint_url": None,
        "model_identifier": "external-llm-provider",
        "safe_mode_compatible": False,
    },
}

# Mapping of category aliases and enum values to dataset files and AttackCategory enums
CATEGORY_FILE_MAP: Dict[str, str] = {
    "injection": "injection.yaml",
    "prompt_injection": "injection.yaml",
    AttackCategory.DIRECT_PROMPT_INJECTION.value: "injection.yaml",
    AttackCategory.INDIRECT_PROMPT_INJECTION.value: "injection.yaml",
    "jailbreak": "jailbreak.yaml",
    AttackCategory.JAILBREAK.value: "jailbreak.yaml",
    "data_leakage": "data_leakage.yaml",
    "canary_leakage": "data_leakage.yaml",
    "sensitive_data_leakage": "data_leakage.yaml",
    AttackCategory.SYSTEM_PROMPT_LEAKAGE.value: "data_leakage.yaml",
    AttackCategory.TENANT_ISOLATION.value: "data_leakage.yaml",
    "tool_authorization": "tool_authorization.yaml",
    AttackCategory.UNAUTHORIZED_TOOL_INVOCATION.value: "tool_authorization.yaml",
    "benign": "benign.yaml",
    AttackCategory.BENIGN_CONTROL.value: "benign.yaml",
}

UNSAFE_ARG_PATTERN = re.compile(r"[;&|`$><\n\r]")


def validate_safe_cli_arg(value: str, field_name: str = "argument") -> str:
    """
    Ensures a string used in CLI/file parameters contains no shell metacharacters or null bytes.
    """
    if not isinstance(value, str):
        raise ValueError(f"Invalid type for {field_name}: expected string.")
    if "\x00" in value or UNSAFE_ARG_PATTERN.search(value):
        raise ValueError(
            f"Unsafe characters detected in {field_name}: shell metacharacters or control sequences are prohibited."
        )
    return value


def validate_promptfoo_target(
    target: str,
    endpoint_url: Optional[str] = None,
    safe_mode: Optional[bool] = None,
    authorize_external: bool = False,
) -> Dict[str, Any]:
    """
    Validates target identifier and endpoint URL against Safe Mode and SSRF protections.
    Raises PermissionError if Safe Mode is violated, or ValueError if target is invalid.
    """
    validate_safe_cli_arg(target, "target")
    effective_safe_mode = settings.SAFE_MODE if safe_mode is None else bool(safe_mode)

    # Check if target is a raw URL
    if target.startswith("http://") or target.startswith("https://"):
        endpoint_url = target
        target_key = "external-http"
    else:
        # Normalize common display names to target IDs
        lower_t = target.strip().lower()
        if lower_t in SUPPORTED_TARGETS:
            target_key = lower_t
        elif "vulnerable" in lower_t and "mock" in lower_t:
            target_key = "mock-vulnerable"
        elif "secure" in lower_t and "mock" in lower_t:
            target_key = "mock-secure"
        elif "mock" in lower_t:
            target_key = "mock-secure"
        elif "ai-iam" in lower_t or "aiiam" in lower_t:
            target_key = "ai-iam-local"
        else:
            raise ValueError(
                f"Unsupported or unrecognized target '{target}'. "
                f"Supported targets: {list(SUPPORTED_TARGETS.keys())}"
            )

    target_meta = dict(SUPPORTED_TARGETS[target_key])
    effective_url = endpoint_url or target_meta.get("endpoint_url")

    # Enforce SSRF / Safe-Mode checks on any URL
    if effective_url:
        validate_safe_cli_arg(effective_url, "endpoint_url")
        parsed = urlparse(effective_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid target URL scheme '{parsed.scheme}'. Only http and https are allowed.")
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ValueError(f"Invalid target URL '{effective_url}': missing hostname.")

        allowed_hosts = [h.lower() for h in settings.ALLOWED_TARGET_HOSTS]
        if effective_safe_mode and hostname not in allowed_hosts:
            raise PermissionError(
                f"Safe Mode Violation: Target host '{hostname}' is not in the allowed local hosts list "
                f"({settings.ALLOWED_TARGET_HOSTS}). External targets require SAFE_MODE=false."
            )

    # External provider requires explicit configuration and authorization
    if not target_meta["safe_mode_compatible"]:
        if effective_safe_mode:
            raise PermissionError(
                f"Safe Mode Violation: External target '{target}' is blocked while SAFE_MODE is enabled."
            )
        if not authorize_external:
            raise PermissionError(
                "External provider requires explicit authorization (authorize_external=True) and configuration."
            )
        if not effective_url:
            raise ValueError("External HTTP provider requires an explicit endpoint_url.")

    target_meta["endpoint_url"] = effective_url
    target_meta["safe_mode"] = effective_safe_mode
    return target_meta


def validate_selected_categories(categories: Optional[List[str]]) -> List[str]:
    """
    Validates requested evaluation categories and returns canonical category names.
    """
    if not categories:
        return []

    validated: List[str] = []
    for cat in categories:
        validate_safe_cli_arg(cat, "category")
        norm = cat.strip().lower()
        if norm not in CATEGORY_FILE_MAP:
            raise ValueError(
                f"Unsupported evaluation category '{cat}'. "
                f"Allowed categories: {sorted(set(CATEGORY_FILE_MAP.keys()))}"
            )
        validated.append(norm)
    return validated


def validate_promptfoo_config_dict(config: Dict[str, Any]) -> None:
    """
    Validates a Promptfoo configuration dictionary to ensure required keys and safe provider definitions.
    Raises ValueError on malformed configurations.
    """
    if not isinstance(config, dict):
        raise ValueError("Promptfoo configuration must be a YAML/JSON object (dict).")

    providers = config.get("providers")
    if not providers or not isinstance(providers, list):
        raise ValueError("Malformed Promptfoo configuration: 'providers' must be a non-empty list.")

    for prov in providers:
        if isinstance(prov, dict):
            prov_id = prov.get("id")
            if not prov_id or not isinstance(prov_id, str):
                raise ValueError("Malformed Promptfoo provider: missing string 'id'.")
            prov_cfg = prov.get("config", {})
            if isinstance(prov_cfg, dict) and prov_cfg.get("endpoint_url"):
                validate_promptfoo_target(
                    target=str(prov_cfg.get("target", "mock-secure")),
                    endpoint_url=str(prov_cfg["endpoint_url"]),
                    safe_mode=bool(prov_cfg.get("safe_mode", True)),
                    authorize_external=bool(prov_cfg.get("authorize_external", False)),
                )
        elif isinstance(prov, str):
            if not prov.strip():
                raise ValueError("Malformed Promptfoo provider: provider string cannot be empty.")
        else:
            raise ValueError("Malformed Promptfoo provider entry.")

    tests = config.get("tests")
    if tests is None or not isinstance(tests, list) or len(tests) == 0:
        raise ValueError("Malformed Promptfoo configuration: 'tests' must be a non-empty list.")

    for idx, t in enumerate(tests):
        if isinstance(t, str):
            if not t.strip():
                raise ValueError(f"Test entry at index {idx} cannot be empty.")
        elif isinstance(t, dict):
            if "vars" not in t and "assert" not in t and "description" not in t:
                raise ValueError(f"Test entry at index {idx} is missing 'vars', 'assert', or 'description'.")
        else:
            raise ValueError(f"Test entry at index {idx} has invalid type '{type(t).__name__}'.")


def validate_path_within_directory(file_path: Path, base_dir: Path) -> Path:
    """Ensures a resolved path stays strictly within base_dir to prevent path traversal."""
    resolved_file = file_path.resolve()
    resolved_base = base_dir.resolve()
    try:
        resolved_file.relative_to(resolved_base)
    except ValueError as exc:
        raise PermissionError(
            f"Path traversal blocked: '{resolved_file}' is outside allowed directory '{resolved_base}'."
        ) from exc
    return resolved_file
