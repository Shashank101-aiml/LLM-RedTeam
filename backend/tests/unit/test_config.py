"""
Unit tests for configuration, Safe Mode guardrails, and secret redaction.
"""

from app.core.config import settings
from app.core.logging_config import redact_sensitive_text


def test_safe_mode_default():
    # Verify Safe Mode is True by default
    assert settings.SAFE_MODE is True
    assert "localhost" in settings.ALLOWED_TARGET_HOSTS
    assert "127.0.0.1" in settings.ALLOWED_TARGET_HOSTS


def test_redact_sensitive_text():
    text = "User submitted CANARY_SEC_SENTINEL_a1b2c3d4 with token Bearer eyJhbGciOiJSUzI1NiIs and key aiiam_991823ab"
    redacted = redact_sensitive_text(text)
    assert "CANARY_SEC_SENTINEL_a1b2c3d4" not in redacted
    assert "CANARY_SEC_SENTINEL_[REDACTED]" in redacted
    assert "Bearer [REDACTED_TOKEN]" in redacted
    assert "aiiam_991823ab" not in redacted
    assert "[REDACTED_KEY]" in redacted
