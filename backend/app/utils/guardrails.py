"""
Input guardrails and validation utilities for the VibeSecure platform.
Provides URL validation, domain sanitization, and input safety checks.
"""

from urllib.parse import urlparse


def validate_url(url: str) -> bool:
    """Validate that a URL is well-formed and uses http/https."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def sanitize_domain(domain: str) -> str:
    """Strip protocol, path and query from a domain string."""
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc or domain
    domain = domain.split("/")[0].split("?")[0]
    return domain


def validate_file_type(content_type: str, allowed_types: list[str]) -> bool:
    """Check if a file's content type is in the allowed list."""
    return content_type in allowed_types


def validate_file_size(size: int, max_bytes: int) -> bool:
    """Check if a file size is within the allowed limit."""
    return 0 < size <= max_bytes


def sanitize_text_input(text: str, max_length: int = 10000) -> str:
    """Basic sanitization of text input: strip and truncate."""
    return text.strip()[:max_length]
