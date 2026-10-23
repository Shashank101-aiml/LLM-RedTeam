"""
Structured Logging Configuration with Secret and Canary Redaction.
"""

import logging
import re
import sys
from typing import Any, Dict


# Redaction patterns for tokens, secrets, canaries
REDACTION_PATTERNS = [
    (re.compile(r"CANARY_SEC_SENTINEL_[a-zA-Z0-9_\-]+", re.IGNORECASE), "CANARY_SEC_SENTINEL_[REDACTED]"),
    (re.compile(r"(Bearer\s+)[a-zA-Z0-9\._\-]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(aiiam_[a-zA-Z0-9_\-]+)", re.IGNORECASE), "[REDACTED_KEY]"),
    (re.compile(r"(sk-[a-zA-Z0-9_\-]{20,})", re.IGNORECASE), "[REDACTED_API_KEY]"),
]


def redact_sensitive_text(text: str) -> str:
    """Redacts known secrets, bearer tokens, API keys, and synthetic canaries."""
    if not isinstance(text, str):
        return text
    sanitized = text
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class RedactingFormatter(logging.Formatter):
    """Custom logging formatter that automatically strips sensitive content."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return redact_sensitive_text(original)


def setup_logging(level: str = "INFO") -> None:
    """Configures structured root logging."""
    logger = logging.getLogger()
    logger.setLevel(level)

    # Avoid adding duplicate handlers if already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] [corr=%(correlation_id)s]: %(message)s",
            defaults={"correlation_id": "sentinel-system"},
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
