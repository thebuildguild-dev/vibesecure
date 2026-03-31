"""
LangGraph workflow definition for the VibeSecure agent swarm.
Implements a stateful graph where the Supervisor agent orchestrates
11 domain-specific agents based on service type.
"""

import logging

from langgraph.graph import END, StateGraph

from src.agents.deepfake.ensemble_voter import ensemble_voter_agent
from src.agents.deepfake.forensic_agent import forensic_artifact_agent

# Import all agent instances
from src.agents.deepfake.keyframe_extractor import keyframe_extractor_agent
from src.agents.deepfake.triage_agent import deepfake_triage_agent
from src.agents.digital_asset.digital_asset_agent import digital_asset_governance_agent
from src.agents.messaging import publish_event
from src.agents.privacy.privacy_scanner_agent import privacy_scanner_agent
from src.agents.privacy.regulatory_mapper_agent import regulatory_mapper_agent
from src.agents.responsible_ai.auditor_agent import responsible_ai_auditor_agent
from src.agents.responsible_ai.bias_fairness_agent import bias_fairness_agent
from src.agents.state import SERVICE_AGENT_MAP, AgentState
from src.agents.supervisor import supervisor_agent
from src.agents.threat_intel.predictive_risk_agent import predictive_risk_agent
from src.agents.threat_intel.threat_pattern_agent import threat_pattern_agent

logger = logging.getLogger(__name__)

# Agent instance registry
AGENT_REGISTRY = {
    "keyframe_extractor": keyframe_extractor_agent,
    "deepfake_triage": deepfake_triage_agent,
    "forensic_artifact": forensic_artifact_agent,
    "ensemble_voter": ensemble_voter_agent,
    "threat_pattern": threat_pattern_agent,
    "predictive_risk": predictive_risk_agent,
    "responsible_ai_auditor": responsible_ai_auditor_agent,
    "bias_fairness": bias_fairness_agent,
    "privacy_scanner": privacy_scanner_agent,
    "regulatory_mapper": regulatory_mapper_agent,
    "digital_asset_governance": digital_asset_governance_agent,
}


# ─── Node Functions ─────────────────────────────────────────────


def supervisor_plan_node(state: AgentState) -> AgentState:
    """Supervisor plans which agents to run."""
    result = supervisor_agent.run(state)
    planned = result.get("results", {}).get("supervisor", {}).get("planned_agents", [])
    return {
        **result,
        "active_agents": planned,
        "status": "running",
    }


def _make_agent_node(agent_name: str):
    """Factory: create a graph node function for a given agent."""

    def node_fn(state: AgentState) -> AgentState:
        agent = AGENT_REGISTRY.get(agent_name)
        if agent is None:
            logger.error(f"Agent {agent_name} not found in registry")
            return state
        return agent.run(state)

    node_fn.__name__ = f"node_{agent_name}"
    return node_fn


def synthesize_node(state: AgentState) -> AgentState:
    """Supervisor synthesizes all results into governance bundle."""
    bundle = supervisor_agent.synthesize_bundle(state)

    publish_event(
        state.get("job_id", ""),
        "supervisor",
        "synthesis_complete",
        {"overall_risk": bundle.get("overall_risk_level", "unknown")},
    )

    return {
        **state,
        "governance_bundle": bundle,
        "status": "completed",
    }


# ─── Router Functions ────────────────────────────────────────────


def route_after_plan(state: AgentState) -> str:
    """Route to the first service group that has active agents."""
    active = state.get("active_agents", [])
    if not active:
        return "synthesize"

    # Determine which service groups are needed
    for service, agents in SERVICE_AGENT_MAP.items():
        if any(a in active for a in agents):
            return f"run_{service}"

    return "synthesize"


def route_after_deepfake(state: AgentState) -> str:
    active = state.get("active_agents", [])
    for service in ["threat_intel", "responsible_ai", "privacy", "digital_asset"]:
        if any(a in active for a in SERVICE_AGENT_MAP.get(service, [])):
            return f"run_{service}"
    return "synthesize"


def route_after_threat(state: AgentState) -> str:
    active = state.get("active_agents", [])
    for service in ["responsible_ai", "privacy", "digital_asset"]:
        if any(a in active for a in SERVICE_AGENT_MAP.get(service, [])):
            return f"run_{service}"
    return "synthesize"


def route_after_responsible(state: AgentState) -> str:
    active = state.get("active_agents", [])
    for service in ["privacy", "digital_asset"]:
        if any(a in active for a in SERVICE_AGENT_MAP.get(service, [])):
            return f"run_{service}"
    return "synthesize"


def route_after_privacy(state: AgentState) -> str:
    active = state.get("active_agents", [])
    if any(a in active for a in SERVICE_AGENT_MAP.get("digital_asset", [])):
        return "run_digital_asset"
    return "synthesize"


def route_after_digital_asset(state: AgentState) -> str:
    return "synthesize"


# ─── Service group runners ──────────────────────────────────────


def run_deepfake_group(state: AgentState) -> AgentState:
    """Run deepfake agents in sequence: keyframe -> triage -> forensic -> voter."""
    active = state.get("active_agents", [])
    deepfake_agents = [
        "keyframe_extractor",
        "deepfake_triage",
        "forensic_artifact",
        "ensemble_voter",
    ]

    for agent_name in deepfake_agents:
        if agent_name in active:
            agent = AGENT_REGISTRY.get(agent_name)
            if agent:
                state = agent.run(state)

    return state


def run_threat_intel_group(state: AgentState) -> AgentState:
    """Run threat intel agents: threat_pattern -> predictive_risk."""
    active = state.get("active_agents", [])
    threat_agents = ["threat_pattern", "predictive_risk"]

    for agent_name in threat_agents:
        if agent_name in active:
            agent = AGENT_REGISTRY.get(agent_name)
            if agent:
                state = agent.run(state)

    return state


def run_responsible_ai_group(state: AgentState) -> AgentState:
    """Run responsible AI agents: auditor -> bias_fairness."""
    active = state.get("active_agents", [])
    rai_agents = ["responsible_ai_auditor", "bias_fairness"]

    for agent_name in rai_agents:
        if agent_name in active:
            agent = AGENT_REGISTRY.get(agent_name)
            if agent:
                state = agent.run(state)

    return state


def run_privacy_group(state: AgentState) -> AgentState:
    """Run privacy agents: privacy_scanner -> regulatory_mapper."""
    active = state.get("active_agents", [])
    privacy_agents = ["privacy_scanner", "regulatory_mapper"]

    for agent_name in privacy_agents:
        if agent_name in active:
            agent = AGENT_REGISTRY.get(agent_name)
            if agent:
                state = agent.run(state)

    return state


def run_digital_asset_group(state: AgentState) -> AgentState:
    """Run digital asset governance agent."""
    active = state.get("active_agents", [])
    if "digital_asset_governance" in active:
        agent = AGENT_REGISTRY["digital_asset_governance"]
        state = agent.run(state)
    return state


# ─── Build the Graph ─────────────────────────────────────────────


def build_swarm_graph() -> StateGraph:
    """Build the LangGraph state machine for the agent swarm."""
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("supervisor_plan", supervisor_plan_node)
    graph.add_node("run_deepfake", run_deepfake_group)
    graph.add_node("run_threat_intel", run_threat_intel_group)
    graph.add_node("run_responsible_ai", run_responsible_ai_group)
    graph.add_node("run_privacy", run_privacy_group)
    graph.add_node("run_digital_asset", run_digital_asset_group)
    graph.add_node("synthesize", synthesize_node)

    # Set entry point
    graph.set_entry_point("supervisor_plan")

    # Conditional routing after supervisor plan
    graph.add_conditional_edges(
        "supervisor_plan",
        route_after_plan,
        {
            "run_deepfake": "run_deepfake",
            "run_threat_intel": "run_threat_intel",
            "run_responsible_ai": "run_responsible_ai",
            "run_privacy": "run_privacy",
            "run_digital_asset": "run_digital_asset",
            "synthesize": "synthesize",
        },
    )

    # Chain service groups
    graph.add_conditional_edges(
        "run_deepfake",
        route_after_deepfake,
        {
            "run_threat_intel": "run_threat_intel",
            "run_responsible_ai": "run_responsible_ai",
            "run_privacy": "run_privacy",
            "run_digital_asset": "run_digital_asset",
            "synthesize": "synthesize",
        },
    )

    graph.add_conditional_edges(
        "run_threat_intel",
        route_after_threat,
        {
            "run_responsible_ai": "run_responsible_ai",
            "run_privacy": "run_privacy",
            "run_digital_asset": "run_digital_asset",
            "synthesize": "synthesize",
        },
    )

    graph.add_conditional_edges(
        "run_responsible_ai",
        route_after_responsible,
        {
            "run_privacy": "run_privacy",
            "run_digital_asset": "run_digital_asset",
            "synthesize": "synthesize",
        },
    )

    graph.add_conditional_edges(
        "run_privacy",
        route_after_privacy,
        {
            "run_digital_asset": "run_digital_asset",
            "synthesize": "synthesize",
        },
    )

    graph.add_conditional_edges(
        "run_digital_asset",
        route_after_digital_asset,
        {
            "synthesize": "synthesize",
        },
    )

    # End after synthesis
    graph.add_edge("synthesize", END)

    return graph


def compile_swarm():
    """Compile and return the runnable swarm graph."""
    graph = build_swarm_graph()
    return graph.compile()


# Pre-compile the graph for reuse
swarm_app = compile_swarm()


def run_swarm(
    job_id: str,
    service_type: str,
    input_data: dict,
    user_email: str = "",
) -> dict:
    """
    Main entry point: run the agent swarm.

    Args:
        job_id: Unique job identifier
        service_type: One of "deepfake", "threat_intel", "responsible_ai", "privacy", "digital_asset", "all"
        input_data: Dict with file_path, url, content, api_endpoint, etc.
        user_email: User's email for notifications

    Returns:
        Final state dict with governance_bundle
    """
    initial_state: AgentState = {
        "job_id": job_id,
        "service_type": service_type,
        "input_data": input_data,
        "user_email": user_email,
        "active_agents": [],
        "completed_agents": [],
        "current_agent": "",
        "results": {},
        "messages": [],
        "governance_bundle": {},
        "status": "pending",
        "error": None,
    }

    publish_event(
        job_id,
        "system",
        "swarm_started",
        {
            "service_type": service_type,
            "user_email": user_email,
        },
    )

    try:
        final_state = swarm_app.invoke(initial_state)

        publish_event(
            job_id,
            "system",
            "swarm_completed",
            {
                "status": final_state.get("status", "unknown"),
                "agents_completed": len(final_state.get("completed_agents", [])),
            },
        )

        return final_state

    except Exception as e:
        logger.exception(f"Swarm execution failed for job {job_id}: {e}")

        publish_event(job_id, "system", "swarm_failed", {"error": str(e)})

        return {
            **initial_state,
            "status": "failed",
            "error": str(e),
        }
