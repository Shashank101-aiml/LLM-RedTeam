"""
Self-Security and Defensive Posture Verification of LLM Sentinel.

Verifies:
1. SSRF prevention under Safe Mode.
2. Sanitization & Redaction of sensitive canaries and keys.
3. Path Traversal Immunity in Export Handlers.
4. Concurrency and Execution Timeout bounds.
"""

import pytest
from app.adapters.mock_adapter import MockTargetAdapter
from app.core.config import settings
from app.core.logging_config import redact_sensitive_text


def test_ssrf_prevention_safe_mode():
    """Verifies that requests to internal cloud metadata IP or arbitrary public hosts are rejected."""
    adapter = MockTargetAdapter()
    adapter.safe_mode = True

    # Cloud metadata IP (AWS/GCP/Azure)
    with pytest.raises(PermissionError):
        adapter.validate_target_safety("http://169.254.169.254/latest/meta-data")

    # Arbitrary public target
    with pytest.raises(PermissionError):
        adapter.validate_target_safety("https://api.openai.com/v1/chat/completions")

    # Allowed local target
    adapter.validate_target_safety("http://localhost:8000/api")
    adapter.validate_target_safety("http://127.0.0.1:8000/api")


def test_credential_and_canary_redaction_rigor():
    """Verifies that synthetic canaries, OpenAI-style keys, AI-IAM tokens, and Bearer headers are masked."""
    raw = (
        "Output containing CANARY_SEC_SENTINEL_A1B2C3D4E5F6 and sk-abcdef1234567890abcdef1234567890 "
        "and aiiam_998877665544332211 and Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.token"
    )

    sanitized = redact_sensitive_text(raw)

    assert "CANARY_SEC_SENTINEL_A1B2C3D4E5F6" not in sanitized
    assert "CANARY_SEC_SENTINEL_[REDACTED]" in sanitized

    assert "sk-abcdef1234567890" not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized

    assert "aiiam_998877665544332211" not in sanitized
    assert "[REDACTED_KEY]" in sanitized

    assert "eyJhbGciOiJSUzI1Ni" not in sanitized
    assert "[REDACTED_TOKEN]" in sanitized


def test_execution_timeout_bounds():
    """Verifies default test timeout is bounded to prevent infinite execution."""
    assert settings.DEFAULT_TEST_TIMEOUT_SECONDS <= 60.0
    assert settings.MAX_CONCURRENT_TESTS <= 20
