"""
General helper utilities used across the VibeSecure platform.
"""

import json
import logging
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


def safe_json_loads(raw: str | None) -> dict | None:
    """Safely parse a JSON string, returning None on failure."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def utcnow() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(UTC)


def truncate(text: str, max_length: int = 200) -> str:
    """Truncate a string to max_length, adding ellipsis if needed."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."
