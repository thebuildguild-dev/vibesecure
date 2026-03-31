"""
Base agent class for all swarm agents.

Returns partial state deltas so LangGraph reducers (merge_dicts for results,
operator.add for messages and completed_agents) handle merging correctly.

Features:
  - Automatic retry with exponential backoff for transient failures
  - Circuit breaker integration (Gemini calls route through the breaker)
  - Metrics recording for execution duration and success/failure
  - Event bus emission for agent lifecycle events
"""

import logging
import random
import time
import traceback

from pydantic import BaseModel, ValidationError

from app.agents.errors import AgentExecutionError
from app.agents.messaging import publish_agent_complete, publish_agent_error, publish_agent_start
from app.core.circuit_breaker import CircuitOpenError, gemini_breaker
from app.core.events import (
    AgentCompletedEvent,
    AgentFailedEvent,
    AgentStartedEvent,
    event_bus,
)
from app.core.metrics import metrics
from app.graphs.state import AgentState
from app.tools.gemini_tools import (
    agent_generate,
    agent_generate_multimodal,
    brain_generate,
    brain_generate_multimodal,
    parse_json_response,
    parse_validated_response,
)

logger = logging.getLogger(__name__)

_VALIDATED_MAX_RETRIES = 2

# Retry settings for the run() lifecycle
_RUN_MAX_RETRIES = 2
_RUN_BASE_DELAY = 1.5  # seconds
_RUN_MAX_DELAY = 15.0

_TRANSIENT_ERRORS = (
    ConnectionError,
    TimeoutError,
    OSError,
    CircuitOpenError,
)


def _is_retryable(exc: Exception) -> bool:
    """Determine if an exception warrants a retry."""
    if isinstance(exc, _TRANSIENT_ERRORS):
        return True
    msg = str(exc).lower()
    return any(kw in msg for kw in ("rate limit", "429", "503", "timeout", "overloaded"))


class BaseAgent:
    """Base class for all agents in the swarm.

    Subclasses implement ``process()`` and return a dict of results.
    The ``run()`` wrapper handles retries, circuit breakers, metrics,
    event publishing, and error packaging.
    """

    name: str = "base_agent"
    description: str = "Base agent"
    is_brain: bool = False  # If True, uses brain-tier models
    max_retries: int = _RUN_MAX_RETRIES

    def __init__(self):
        self.logger = logging.getLogger(f"agent.{self.name}")

    # ── Text generation (circuit breaker protected) ────────────

    def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
        response_mime_type: str | None = None,
    ) -> str:
        """Generate text using the appropriate model tier, routed through the circuit breaker."""

        def _call():
            if self.is_brain:
                return brain_generate(prompt, system_instruction, response_mime_type)
            return agent_generate(prompt, system_instruction, response_mime_type)

        return gemini_breaker.call(_call)

    def generate_json(
        self,
        prompt: str,
        system_instruction: str | None = None,
    ) -> dict:
        """Generate and parse a JSON response."""
        text = self.generate(
            prompt,
            system_instruction=system_instruction,
            response_mime_type="application/json",
        )
        return parse_json_response(text)

    def generate_validated(
        self,
        prompt: str,
        response_model: type[BaseModel],
        system_instruction: str | None = None,
    ) -> BaseModel:
        """Generate a JSON response and validate it against a Pydantic model.

        On ``ValidationError`` the request is retried up to
        ``_VALIDATED_MAX_RETRIES`` times with the validation errors appended
        to the prompt so the LLM can self-correct.
        """
        last_error: ValidationError | None = None
        current_prompt = prompt

        for attempt in range(_VALIDATED_MAX_RETRIES + 1):
            text = self.generate(
                current_prompt,
                system_instruction=system_instruction,
                response_mime_type="application/json",
            )
            try:
                return parse_validated_response(text, response_model)
            except ValidationError as exc:
                last_error = exc
                self.logger.warning(
                    "[%s] Pydantic validation failed (attempt %d): %s",
                    self.name,
                    attempt + 1,
                    exc.error_count(),
                )
                # Append validation feedback so the LLM can self-correct
                current_prompt = (
                    f"{prompt}\n\n"
                    f"Your previous response had validation errors:\n{exc}\n"
                    "Please fix these issues and return valid JSON."
                )

        raise AgentExecutionError(
            self.name,
            f"LLM output failed Pydantic validation after {_VALIDATED_MAX_RETRIES + 1} attempts",
            original=last_error,
        )

    # ── Multimodal generation ────────────────────────────────────

    def generate_multimodal(
        self,
        contents: list,
        system_instruction: str | None = None,
        response_mime_type: str | None = None,
    ) -> str:
        """Generate text from multimodal content (text + images)."""
        if self.is_brain:
            return brain_generate_multimodal(contents, system_instruction, response_mime_type)
        return agent_generate_multimodal(contents, system_instruction, response_mime_type)

    def generate_multimodal_json(
        self,
        contents: list,
        system_instruction: str | None = None,
    ) -> dict:
        """Generate and parse a JSON response from multimodal content."""
        text = self.generate_multimodal(
            contents,
            system_instruction=system_instruction,
            response_mime_type="application/json",
        )
        return parse_json_response(text)

    def generate_multimodal_validated(
        self,
        contents: list,
        response_model: type[BaseModel],
        system_instruction: str | None = None,
    ) -> BaseModel:
        """Multimodal variant of :meth:`generate_validated`."""
        last_error: ValidationError | None = None

        for attempt in range(_VALIDATED_MAX_RETRIES + 1):
            text = self.generate_multimodal(
                contents,
                system_instruction=system_instruction,
                response_mime_type="application/json",
            )
            try:
                return parse_validated_response(text, response_model)
            except ValidationError as exc:
                last_error = exc
                self.logger.warning(
                    "[%s] Multimodal Pydantic validation failed (attempt %d): %s",
                    self.name,
                    attempt + 1,
                    exc.error_count(),
                )
                # Append a text correction hint for the next attempt
                contents = [
                    *contents,
                    f"\nYour previous response had validation errors:\n{exc}\n"
                    "Please fix these issues and return valid JSON.",
                ]

        raise AgentExecutionError(
            self.name,
            f"Multimodal LLM output failed validation after {_VALIDATED_MAX_RETRIES + 1} attempts",
            original=last_error,
        )

    # ── Core lifecycle ───────────────────────────────────────────

    def process(self, state: AgentState) -> dict:
        """
        Core processing logic. Override in subclasses.
        Should return a dict of results to merge into state.results.
        """
        raise NotImplementedError(f"{self.name} must implement process()")

    def run(self, state: AgentState) -> dict:
        """
        Execute the agent with retry, circuit breaker awareness, metrics,
        event publishing, and error handling.

        Transient failures (network, rate limits, circuit open) are retried
        with exponential backoff + jitter.  Non-retryable errors fail
        immediately.

        Returns a **partial state delta** -- only the keys that changed.
        LangGraph applies the Annotated reducers (merge_dicts for results,
        operator.add for completed_agents and messages) automatically.
        """
        job_id = state.get("job_id", "unknown")
        self.logger.info("[%s] Agent %s starting", job_id, self.name)

        publish_agent_start(job_id, self.name)
        event_bus.emit_sync(
            AgentStartedEvent(
                source=self.name,
                data={"job_id": job_id, "agent": self.name},
            )
        )

        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            start_time = time.time()
            try:
                result = self.process(state)
                elapsed = time.time() - start_time

                # Record success metrics
                metrics.record_agent_execution(self.name, elapsed, success=True)

                self.logger.info(
                    "[%s] Agent %s completed in %.2fs (attempt %d)",
                    job_id,
                    self.name,
                    elapsed,
                    attempt + 1,
                )
                publish_agent_complete(
                    job_id,
                    self.name,
                    {
                        "duration_seconds": round(elapsed, 2),
                        "has_results": bool(result),
                        "attempt": attempt + 1,
                    },
                )
                event_bus.emit_sync(
                    AgentCompletedEvent(
                        source=self.name,
                        data={
                            "job_id": job_id,
                            "agent": self.name,
                            "duration": round(elapsed, 2),
                        },
                    )
                )

                return {
                    "results": {self.name: result},
                    "messages": [
                        {
                            "agent": self.name,
                            "event": "completed",
                            "duration": round(elapsed, 2),
                            "attempt": attempt + 1,
                            "timestamp": time.time(),
                        }
                    ],
                    "completed_agents": [self.name],
                    "current_agent": self.name,
                }

            except Exception as e:
                elapsed = time.time() - start_time
                last_error = e

                if attempt < self.max_retries and _is_retryable(e):
                    delay = min(
                        _RUN_BASE_DELAY * (2**attempt) + random.uniform(0, 1),
                        _RUN_MAX_DELAY,
                    )
                    self.logger.warning(
                        "[%s] Agent %s transient failure (attempt %d), retrying in %.1fs: %s",
                        job_id,
                        self.name,
                        attempt + 1,
                        delay,
                        e,
                    )
                    time.sleep(delay)
                    continue

                # Non-retryable or final attempt
                break

        # All retries exhausted -- produce error delta
        elapsed = time.time() - start_time
        error_msg = f"{self.name} failed: {last_error}"
        self.logger.error("[%s] %s\n%s", job_id, error_msg, traceback.format_exc())

        metrics.record_agent_execution(self.name, elapsed, success=False)
        publish_agent_error(job_id, self.name, str(last_error))
        event_bus.emit_sync(
            AgentFailedEvent(
                source=self.name,
                data={
                    "job_id": job_id,
                    "agent": self.name,
                    "error": str(last_error),
                },
            )
        )

        return {
            "results": {self.name: {"error": str(last_error)}},
            "messages": [
                {
                    "agent": self.name,
                    "event": "error",
                    "error": str(last_error),
                    "duration": round(elapsed, 2),
                    "attempts": self.max_retries + 1,
                    "timestamp": time.time(),
                }
            ],
            "completed_agents": [self.name],
            "current_agent": self.name,
        }
