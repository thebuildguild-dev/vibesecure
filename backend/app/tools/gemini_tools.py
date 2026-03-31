"""
Gemini model client with automatic fallback chain.

Brain agents (Supervisor): gemini-3.1-pro-preview -> gemini-2.5-pro -> gemini-2.5-flash
Normal agents: gemini-3-flash-preview -> gemini-2.5-flash
"""

import json
import logging
import time
from functools import lru_cache

from google import genai
from pydantic import BaseModel

from app.core.config import settings

logger = logging.getLogger(__name__)

BRAIN_MODELS = [
    # "gemini-3.1-pro-preview",
    # "gemini-2.5-pro",
    "gemini-2.5-flash",
]

AGENT_MODELS = [
    # "gemini-3-flash-preview",
    "gemini-2.5-flash",
]

_TRANSIENT_KEYWORDS = frozenset(
    [
        "rate limit",
        "429",
        "503",
        "500",
        "quota",
        "overloaded",
        "timeout",
    ]
)


@lru_cache(maxsize=1)
def _get_client() -> genai.Client:
    if not settings.gemini_api_key:
        raise RuntimeError("GEMINI_API_KEY is required for agent operations")
    return genai.Client(api_key=settings.gemini_api_key)


def _log_usage(model_name: str, response, elapsed: float) -> None:
    """Log token usage and latency when available."""
    try:
        usage = getattr(response, "usage_metadata", None)
        if usage:
            logger.info(
                "Gemini [%s] tokens in=%s out=%s latency=%.2fs",
                model_name,
                getattr(usage, "prompt_token_count", "?"),
                getattr(usage, "candidates_token_count", "?"),
                elapsed,
            )
        else:
            logger.info("Gemini [%s] latency=%.2fs (no token metadata)", model_name, elapsed)
    except Exception:
        pass


def _is_transient(error: Exception) -> bool:
    error_str = str(error).lower()
    return any(kw in error_str for kw in _TRANSIENT_KEYWORDS)


def generate_with_fallback(
    prompt: str,
    models: list[str],
    system_instruction: str | None = None,
    response_mime_type: str | None = None,
    max_retries_per_model: int = 2,
    retry_delay: float = 1.0,
) -> str:
    """
    Call Gemini with automatic model fallback.
    Tries each model in order, retrying on transient errors before falling back.
    """
    client = _get_client()
    last_error = None

    for model_name in models:
        for attempt in range(max_retries_per_model):
            try:
                config = {}
                if system_instruction:
                    config["system_instruction"] = system_instruction
                if response_mime_type:
                    config["response_mime_type"] = response_mime_type

                t0 = time.time()
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config if config else None,
                )
                elapsed = time.time() - t0

                text = response.text
                if text:
                    _log_usage(model_name, response, elapsed)
                    return text

                logger.warning(f"Empty response from {model_name}, attempt {attempt + 1}")

            except Exception as e:
                last_error = e
                logger.warning(f"Model {model_name} attempt {attempt + 1} failed: {e}")

                if _is_transient(e) and attempt < max_retries_per_model - 1:
                    wait = retry_delay * (2**attempt)
                    logger.info(f"Retrying {model_name} in {wait:.1f}s...")
                    time.sleep(wait)
                    continue

                # Non-transient error or out of retries: move to next model
                break

        logger.warning(f"Model {model_name} exhausted, falling back to next model")

    raise RuntimeError(f"All models exhausted. Last error: {last_error}")


def generate_multimodal_with_fallback(
    contents: list,
    models: list[str],
    system_instruction: str | None = None,
    response_mime_type: str | None = None,
    max_retries_per_model: int = 2,
    retry_delay: float = 1.0,
) -> str:
    """
    Call Gemini with multimodal content (text + images).

    ``contents`` is a list of content parts accepted by the Gemini SDK,
    e.g. strings, ``genai.types.Part`` objects, or ``PIL.Image``.
    """
    client = _get_client()
    last_error = None

    for model_name in models:
        for attempt in range(max_retries_per_model):
            try:
                config = {}
                if system_instruction:
                    config["system_instruction"] = system_instruction
                if response_mime_type:
                    config["response_mime_type"] = response_mime_type

                t0 = time.time()
                response = client.models.generate_content(
                    model=model_name,
                    contents=contents,
                    config=config if config else None,
                )
                elapsed = time.time() - t0

                text = response.text
                if text:
                    _log_usage(model_name, response, elapsed)
                    return text

                logger.warning(
                    f"Empty multimodal response from {model_name}, attempt {attempt + 1}"
                )

            except Exception as e:
                last_error = e
                logger.warning(f"Multimodal {model_name} attempt {attempt + 1} failed: {e}")

                if _is_transient(e) and attempt < max_retries_per_model - 1:
                    wait = retry_delay * (2**attempt)
                    time.sleep(wait)
                    continue
                break

        logger.warning(f"Multimodal {model_name} exhausted, falling back")

    raise RuntimeError(f"All models exhausted (multimodal). Last error: {last_error}")


def brain_generate(
    prompt: str,
    system_instruction: str | None = None,
    response_mime_type: str | None = None,
) -> str:
    """Generate using brain-tier models (Supervisor Agent)."""
    return generate_with_fallback(
        prompt=prompt,
        models=BRAIN_MODELS,
        system_instruction=system_instruction,
        response_mime_type=response_mime_type,
    )


def agent_generate(
    prompt: str,
    system_instruction: str | None = None,
    response_mime_type: str | None = None,
) -> str:
    """Generate using agent-tier models (all other agents)."""
    return generate_with_fallback(
        prompt=prompt,
        models=AGENT_MODELS,
        system_instruction=system_instruction,
        response_mime_type=response_mime_type,
    )


def agent_generate_multimodal(
    contents: list,
    system_instruction: str | None = None,
    response_mime_type: str | None = None,
) -> str:
    """Generate using agent-tier models with multimodal content."""
    return generate_multimodal_with_fallback(
        contents=contents,
        models=AGENT_MODELS,
        system_instruction=system_instruction,
        response_mime_type=response_mime_type,
    )


def brain_generate_multimodal(
    contents: list,
    system_instruction: str | None = None,
    response_mime_type: str | None = None,
) -> str:
    """Generate using brain-tier models with multimodal content."""
    return generate_multimodal_with_fallback(
        contents=contents,
        models=BRAIN_MODELS,
        system_instruction=system_instruction,
        response_mime_type=response_mime_type,
    )


def parse_json_response(text: str) -> dict:
    """Parse a JSON response from Gemini, handling markdown code fences."""
    cleaned = text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Gemini JSON (first 200 chars): %s", cleaned[:200])
        raise ValueError(f"Gemini returned invalid JSON: {exc}") from exc


def parse_validated_response(text: str, model_class: type[BaseModel]) -> BaseModel:
    """Parse Gemini text into a Pydantic model, raising ``ValidationError`` on bad shape."""
    raw = parse_json_response(text)
    return model_class.model_validate(raw)
