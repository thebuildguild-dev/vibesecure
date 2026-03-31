"""
Unified error type for agent failures.
"""


class AgentExecutionError(Exception):
    """Raised when an agent's ``process()`` fails in an expected way.

    Attributes:
        agent_name: Name of the agent that failed.
        original: The underlying exception, if any.
    """

    def __init__(self, agent_name: str, message: str, *, original: Exception | None = None):
        self.agent_name = agent_name
        self.original = original
        super().__init__(f"[{agent_name}] {message}")
