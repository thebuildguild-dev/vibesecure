"""
Base agent class for all swarm agents.

Returns partial state deltas so LangGraph reducers (merge_dicts for results,
operator.add for messages and completed_agents) handle merging correctly.
"""

import logging
import time
import traceback

from pydantic import BaseModel, ValidationError

from app.agents.errors import AgentExecutionError
from app.agents.messaging import publish_agent_complete, publish_agent_error, publish_agent_start
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


class BaseAgent:
    """Base class for all agents in the swarm."""

    name: str = "base_agent"
    description: str = "Base agent"
    is_brain: bool = False  # If True, uses brain-tier models

    def __init__(self):
        self.logger = logging.getLogger(f"agent.{self.name}")

    # ── Text generation ──────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
        response_mime_type: str | None = None,
    ) -> str:
        """Generate text using the appropriate model tier."""
        if self.is_brain:
            return brain_generate(prompt, system_instruction, response_mime_type)
        return agent_generate(prompt, system_instruction, response_mime_type)

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
        Execute the agent with event publishing and error handling.

        Returns a **partial state delta** -- only the keys that changed.
        LangGraph applies the Annotated reducers (merge_dicts for results,
        operator.add for completed_agents and messages) automatically.
        """
        job_id = state.get("job_id", "unknown")
        self.logger.info(f"[{job_id}] Agent {self.name} starting")

        publish_agent_start(job_id, self.name)

        start_time = time.time()

        try:
            result = self.process(state)
            elapsed = time.time() - start_time

            self.logger.info(f"[{job_id}] Agent {self.name} completed in {elapsed:.2f}s")
            publish_agent_complete(
                job_id,
                self.name,
                {
                    "duration_seconds": round(elapsed, 2),
                    "has_results": bool(result),
                },
            )

            return {
                "results": {self.name: result},
                "messages": [
                    {
                        "agent": self.name,
                        "event": "completed",
                        "duration": round(elapsed, 2),
                        "timestamp": time.time(),
                    }
                ],
                "completed_agents": [self.name],
                "current_agent": self.name,
            }

        except Exception as e:
            elapsed = time.time() - start_time
            error_msg = f"{self.name} failed: {str(e)}"
            self.logger.error(f"[{job_id}] {error_msg}\n{traceback.format_exc()}")

            publish_agent_error(job_id, self.name, str(e))

            return {
                "results": {self.name: {"error": str(e)}},
                "messages": [
                    {
                        "agent": self.name,
                        "event": "error",
                        "error": str(e),
                        "duration": round(elapsed, 2),
                        "timestamp": time.time(),
                    }
                ],
                "completed_agents": [self.name],
                "current_agent": self.name,
            }
