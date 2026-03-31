"""
Base agent class for all swarm agents.
"""

import logging
import time
import traceback

from src.agents.gemini_client import agent_generate, brain_generate, parse_json_response
from src.agents.messaging import publish_agent_complete, publish_agent_error, publish_agent_start
from src.agents.state import AgentState

logger = logging.getLogger(__name__)


class BaseAgent:
    """Base class for all agents in the swarm."""

    name: str = "base_agent"
    description: str = "Base agent"
    is_brain: bool = False  # If True, uses brain-tier models

    def __init__(self):
        self.logger = logging.getLogger(f"agent.{self.name}")

    def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
        response_mime_type: str | None = None,
        image_paths: list[str] | None = None,
    ) -> str:
        """Generate text using the appropriate model tier."""
        if self.is_brain:
            return brain_generate(prompt, system_instruction, response_mime_type, image_paths)
        return agent_generate(prompt, system_instruction, response_mime_type, image_paths)

    def generate_json(
        self,
        prompt: str,
        system_instruction: str | None = None,
        image_paths: list[str] | None = None,
    ) -> dict:
        """Generate and parse a JSON response."""
        text = self.generate(
            prompt,
            system_instruction=system_instruction,
            response_mime_type="application/json",
            image_paths=image_paths,
        )
        return parse_json_response(text)

    def process(self, state: AgentState) -> dict:
        """
        Core processing logic. Override in subclasses.
        Should return a dict of results to merge into state.results.
        """
        raise NotImplementedError(f"{self.name} must implement process()")

    def run(self, state: AgentState) -> AgentState:
        """
        Execute the agent with event publishing and error handling.
        Returns updated state.
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

            # Build updated state
            new_messages = [
                {
                    "agent": self.name,
                    "event": "completed",
                    "duration": round(elapsed, 2),
                    "timestamp": time.time(),
                }
            ]

            completed = list(state.get("completed_agents", []))
            completed.append(self.name)

            return {
                **state,
                "results": {**state.get("results", {}), self.name: result},
                "messages": state.get("messages", []) + new_messages,
                "completed_agents": completed,
                "current_agent": self.name,
            }

        except Exception as e:
            elapsed = time.time() - start_time
            error_msg = f"{self.name} failed: {str(e)}"
            self.logger.error(f"[{job_id}] {error_msg}\n{traceback.format_exc()}")

            publish_agent_error(job_id, self.name, str(e))

            new_messages = [
                {
                    "agent": self.name,
                    "event": "error",
                    "error": str(e),
                    "duration": round(elapsed, 2),
                    "timestamp": time.time(),
                }
            ]

            completed = list(state.get("completed_agents", []))
            completed.append(self.name)

            return {
                **state,
                "results": {**state.get("results", {}), self.name: {"error": str(e)}},
                "messages": state.get("messages", []) + new_messages,
                "completed_agents": completed,
                "current_agent": self.name,
            }
