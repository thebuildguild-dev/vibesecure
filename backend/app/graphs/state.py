"""
Shared state definition for the LangGraph agent swarm.
"""

from operator import add
from typing import Annotated, TypedDict


def merge_dicts(a: dict, b: dict) -> dict:
    """Merge two dicts, with b overwriting a."""
    merged = {**a}
    merged.update(b)
    return merged


class AgentState(TypedDict, total=False):
    """Shared state passed between all agents in the swarm."""

    # Job identity
    job_id: str
    service_type: str  # deepfake | threat_intel | responsible_ai | privacy | digital_asset | all

    # Input data
    input_data: dict  # file paths, URLs, API endpoints, options, etc.
    user_email: str

    # Agent orchestration
    active_agents: list[str]
    completed_agents: Annotated[list[str], add]
    current_agent: str

    # Accumulated results from each agent (keyed by agent name)
    results: Annotated[dict, merge_dicts]

    # Messages / event log (append-only)
    messages: Annotated[list[dict], add]

    # Final output
    governance_bundle: dict
    status: str  # pending | running | completed | failed
    error: str | None


SERVICE_AGENT_MAP = {
    "deepfake": [
        "keyframe_extractor",
        "deepfake_triage",
        "forensic_artifact",
        "ensemble_voter",
    ],
    "threat_intel": [
        "threat_pattern",
        "predictive_risk",
    ],
    "responsible_ai": [
        "responsible_ai_auditor",
        "bias_fairness",
    ],
    "privacy": [
        "privacy_scanner",
        "regulatory_mapper",
    ],
    "digital_asset": [
        "digital_asset_governance",
    ],
}

ALL_AGENTS = []
for agents in SERVICE_AGENT_MAP.values():
    ALL_AGENTS.extend(agents)
