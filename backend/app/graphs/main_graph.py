"""
LangGraph workflow definition for the VibeSecure agent swarm.

Every agent is its own graph node so LangGraph manages state transitions,
checkpointing, and reducer application at the per-agent level.

Graph structure:
  supervisor_plan --> [agent nodes chained per service group] --> synthesize --> END

Within each service group the agents run in a fixed sequence.  Conditional
edges skip inactive agents and jump to the next active service group (or
straight to synthesis when nothing more is planned).
"""

import logging

from langgraph.graph import END, StateGraph

from app.agents.auditor_agent import responsible_ai_auditor_agent
from app.agents.bias_fairness_agent import bias_fairness_agent
from app.agents.deepfake_triage_agent import deepfake_triage_agent
from app.agents.digital_asset_agent import digital_asset_governance_agent
from app.agents.ensemble_voter_agent import ensemble_voter_agent
from app.agents.forensic_analysis_agent import forensic_artifact_agent
from app.agents.keyframe_extractor_agent import keyframe_extractor_agent
from app.agents.messaging import publish_event
from app.agents.predictive_risk_agent import predictive_risk_agent
from app.agents.privacy_scanner_agent import privacy_scanner_agent
from app.agents.regulatory_mapper_agent import regulatory_mapper_agent
from app.agents.supervisor import supervisor_agent
from app.agents.threat_pattern_agent import threat_pattern_agent
from app.graphs.state import SERVICE_AGENT_MAP, AgentState

logger = logging.getLogger(__name__)

# ─── Agent instance registry ────────────────────────────────────

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

# Ordered list of (service_group, [agents_in_sequence]).
# Defines the global execution order across service groups.
SERVICE_ORDER: list[tuple[str, list[str]]] = [
    ("deepfake", SERVICE_AGENT_MAP["deepfake"]),
    ("threat_intel", SERVICE_AGENT_MAP["threat_intel"]),
    ("responsible_ai", SERVICE_AGENT_MAP["responsible_ai"]),
    ("privacy", SERVICE_AGENT_MAP["privacy"]),
    ("digital_asset", SERVICE_AGENT_MAP["digital_asset"]),
]

# Flattened ordered list of every agent name in execution order.
_ALL_ORDERED: list[str] = []
for _svc, _agents in SERVICE_ORDER:
    _ALL_ORDERED.extend(_agents)


# ─── Helper: find next active node after a given agent ──────────


def _next_active_node(state: AgentState, after_agent: str) -> str:
    """Return the node name of the next active agent after *after_agent*,
    or ``"synthesize"`` if there are none left."""
    active = set(state.get("active_agents", []))
    found = False
    for name in _ALL_ORDERED:
        if name == after_agent:
            found = True
            continue
        if found and name in active:
            return name
    return "synthesize"


# ─── Node functions ─────────────────────────────────────────────


def supervisor_plan_node(state: AgentState) -> dict:
    """Supervisor plans which agents to run.

    Returns a partial delta -- ``active_agents`` is set (not appended) because
    the supervisor is the sole writer and it needs a full replacement, which is
    correct since ``active_agents`` has no reducer (plain overwrite).
    """
    delta = supervisor_agent.run(state)
    planned = delta.get("results", {}).get("supervisor", {}).get("planned_agents", [])
    # Merge the delta from supervisor.run() with the plan metadata.
    return {
        **delta,
        "active_agents": planned,
        "status": "running",
    }


def _make_agent_node(agent_name: str):
    """Factory: create a LangGraph node function for a single agent.

    If the agent is not in ``active_agents`` the node is a no-op (returns
    an empty delta) so the graph can unconditionally wire every agent as a
    node and let the routing edges handle skipping.
    """

    def node_fn(state: AgentState) -> dict:
        agent = AGENT_REGISTRY.get(agent_name)
        if agent is None:
            logger.error(f"Agent {agent_name} not found in registry")
            return {}
        return agent.run(state)

    node_fn.__name__ = f"node_{agent_name}"
    return node_fn


def synthesize_node(state: AgentState) -> dict:
    """Supervisor synthesizes all results into the governance bundle."""
    bundle = supervisor_agent.synthesize_bundle(state)

    publish_event(
        state.get("job_id", ""),
        "supervisor",
        "synthesis_complete",
        {"overall_risk": bundle.get("overall_risk_level", "unknown")},
    )

    return {
        "governance_bundle": bundle,
        "status": "completed",
    }


# ─── Routing functions ──────────────────────────────────────────
# Each agent node gets a conditional-edge router that either goes to
# the next active agent or skips ahead to synthesize.


def _make_router(agent_name: str):
    """Create a router that picks the next active node after *agent_name*."""

    def router(state: AgentState) -> str:
        return _next_active_node(state, agent_name)

    router.__name__ = f"route_after_{agent_name}"
    return router


def route_after_plan(state: AgentState) -> str:
    """Route from supervisor_plan to the first active agent (or synthesize)."""
    active = set(state.get("active_agents", []))
    for name in _ALL_ORDERED:
        if name in active:
            return name
    return "synthesize"


# ─── Build the graph ────────────────────────────────────────────


def build_swarm_graph() -> StateGraph:
    """Build the LangGraph state machine with every agent as its own node."""
    graph = StateGraph(AgentState)

    # --- Add nodes ---
    graph.add_node("supervisor_plan", supervisor_plan_node)

    for agent_name in _ALL_ORDERED:
        graph.add_node(agent_name, _make_agent_node(agent_name))

    graph.add_node("synthesize", synthesize_node)

    # --- Entry point ---
    graph.set_entry_point("supervisor_plan")

    # --- Edges from supervisor_plan ---
    # Can jump to any agent or straight to synthesize.
    plan_targets = {name: name for name in _ALL_ORDERED}
    plan_targets["synthesize"] = "synthesize"
    graph.add_conditional_edges("supervisor_plan", route_after_plan, plan_targets)

    # --- Edges from each agent node ---
    # After each agent, jump to the next active agent or to synthesize.
    for idx, agent_name in enumerate(_ALL_ORDERED):
        # Possible targets: any agent that comes *after* this one, plus synthesize.
        targets = {name: name for name in _ALL_ORDERED[idx + 1 :]}
        targets["synthesize"] = "synthesize"
        graph.add_conditional_edges(
            agent_name,
            _make_router(agent_name),
            targets,
        )

    # --- Terminal edge ---
    graph.add_edge("synthesize", END)

    return graph


def compile_swarm():
    """Compile and return the runnable swarm graph."""
    return build_swarm_graph().compile()


# Pre-compile the graph for reuse across jobs.
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
        job_id: Unique job identifier.
        service_type: One of ``deepfake``, ``threat_intel``, ``responsible_ai``,
                       ``privacy``, ``digital_asset``, or ``all``.
        input_data: Dict with file_path, url, content, api_endpoint, etc.
        user_email: User's email for notifications.

    Returns:
        Final state dict with ``governance_bundle``.
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
