"""
API Authentication and Safe-Mode Target Authorization Guards.
"""

from typing import Optional
from urllib.parse import urlparse
from fastapi import Header, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from app.core.config import settings

api_key_header_auth = APIKeyHeader(name=settings.API_KEY_HEADER, auto_error=False)


def verify_api_key(
    x_sentinel_api_key: Optional[str] = Security(api_key_header_auth),
    authorization: Optional[str] = Header(None),
) -> bool:
    """
    Validates API key if configured in settings.
    Accepts key via X-Sentinel-API-Key or Authorization: Bearer <key>.
    If SENTINEL_API_KEY is not configured, allows requests in local development mode.
    """
    if not settings.SENTINEL_API_KEY:
        return True

    provided_key = x_sentinel_api_key
    if not provided_key and authorization and authorization.startswith("Bearer "):
        provided_key = authorization.split("Bearer ", 1)[1].strip()

    if not provided_key or provided_key != settings.SENTINEL_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key. Provide via X-Sentinel-API-Key or Bearer token.",
        )
    return True


def validate_target_url_safe_mode(url: Optional[str]) -> None:
    """
    Validates that target endpoint is permissible under Safe Mode.
    Raises HTTPException(403) if an external target is requested while SAFE_MODE is True.
    """
    if not url or not settings.SAFE_MODE:
        return

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return

    allowed = [h.lower() for h in settings.ALLOWED_TARGET_HOSTS]
    if hostname not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Safe Mode Violation: Target host '{hostname}' is not in the allowed local hosts list "
                f"({settings.ALLOWED_TARGET_HOSTS}). Evaluation of external targets requires SAFE_MODE=false."
            ),
        )
