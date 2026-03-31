"""
Gemini model client with automatic fallback chain.

Brain agents (Supervisor): gemini-3.1-pro-preview -> gemini-2.5-pro -> gemini-2.5-flash
Normal agents: gemini-3-flash-preview -> gemini-2.5-flash
"""

import json
import logging
import time

from google import genai

from app.core.config import settings

logger = logging.getLogger(__name__)

BRAIN_MODELS = [
    "gemini-3.1-pro-preview",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
]

AGENT_MODELS = [
    "gemini-3-flash-preview",
    "gemini-2.5-flash",
]


def _get_client() -> genai.Client:
    if not settings.gemini_api_key:
        raise RuntimeError("GEMINI_API_KEY is required for agent operations")
    return genai.Client(api_key=settings.gemini_api_key)


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

                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config if config else None,
                )

                text = response.text
                if text:
                    logger.info(f"Gemini response from {model_name} (attempt {attempt + 1})")
                    return text

                logger.warning(f"Empty response from {model_name}, attempt {attempt + 1}")

            except Exception as e:
                last_error = e
                error_str = str(e).lower()
                is_transient = any(
                    keyword in error_str
                    for keyword in [
                        "rate limit",
                        "429",
                        "503",
                        "500",
                        "quota",
                        "overloaded",
                        "timeout",
                    ]
                )

                logger.warning(f"Model {model_name} attempt {attempt + 1} failed: {e}")

                if is_transient and attempt < max_retries_per_model - 1:
                    wait = retry_delay * (2**attempt)
                    logger.info(f"Retrying {model_name} in {wait:.1f}s...")
                    time.sleep(wait)
                    continue

                # Non-transient error or out of retries: move to next model
                break

        logger.warning(f"Model {model_name} exhausted, falling back to next model")

    raise RuntimeError(f"All models exhausted. Last error: {last_error}")


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


def parse_json_response(text: str) -> dict:
    """Parse a JSON response from Gemini, handling markdown code fences."""
    cleaned = text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    return json.loads(cleaned.strip())
