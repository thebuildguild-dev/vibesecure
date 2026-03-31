"""
LangGraph workflow definition for the VibeSecure agent swarm.

Every agent is its own graph node so LangGraph manages state transitions,
checkpointing, and reducer application at the per-agent level.

Agents are created lazily (on first use) to avoid heavy module-level
instantiation and to keep import time fast.

Graph structure:
  supervisor_plan --> [agent nodes chained per service group] --> synthesize --> END

Within each service group the agents run in a fixed sequence.  Conditional
edges skip inactive agents and jump to the next active service group (or
straight to synthesis when nothing more is planned).
"""

import logging
from functools import lru_cache

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from app.agents.messaging import publish_event
from app.graphs.state import SERVICE_AGENT_MAP, AgentState

logger = logging.getLogger(__name__)

# ─── Lazy agent factories ───────────────────────────────────────
# Each factory is cached so only one instance is ever created.


@lru_cache(maxsize=1)
def _get_supervisor():
    from app.agents.supervisor import SupervisorAgent

    return SupervisorAgent()


@lru_cache(maxsize=1)
def _get_keyframe_extractor():
    from app.agents.keyframe_extractor_agent import KeyframeExtractorAgent

    return KeyframeExtractorAgent()


@lru_cache(maxsize=1)
def _get_deepfake_triage():
    from app.agents.deepfake_triage_agent import DeepfakeTriageAgent

    return DeepfakeTriageAgent()


@lru_cache(maxsize=1)
def _get_forensic_artifact():
    from app.agents.forensic_analysis_agent import ForensicArtifactAgent

    return ForensicArtifactAgent()


@lru_cache(maxsize=1)
def _get_ensemble_voter():
    from app.agents.ensemble_voter_agent import EnsembleVoterAgent

    return EnsembleVoterAgent()


@lru_cache(maxsize=1)
def _get_threat_pattern():
    from app.agents.threat_pattern_agent import ThreatPatternAgent

    return ThreatPatternAgent()


@lru_cache(maxsize=1)
def _get_predictive_risk():
    from app.agents.predictive_risk_agent import PredictiveRiskAgent

    return PredictiveRiskAgent()


@lru_cache(maxsize=1)
def _get_responsible_ai_auditor():
    from app.agents.auditor_agent import ResponsibleAIAuditorAgent

    return ResponsibleAIAuditorAgent()


@lru_cache(maxsize=1)
def _get_bias_fairness():
    from app.agents.bias_fairness_agent import BiasFairnessAgent

    return BiasFairnessAgent()


@lru_cache(maxsize=1)
def _get_privacy_scanner():
    from app.agents.privacy_scanner_agent import PrivacyScannerAgent

    return PrivacyScannerAgent()


@lru_cache(maxsize=1)
def _get_regulatory_mapper():
    from app.agents.regulatory_mapper_agent import RegulatoryMapperAgent

    return RegulatoryMapperAgent()


@lru_cache(maxsize=1)
def _get_digital_asset_governance():
    from app.agents.digital_asset_agent import DigitalAssetGovernanceAgent

    return DigitalAssetGovernanceAgent()


# Maps agent name to its lazy factory.
AGENT_FACTORIES: dict[str, callable] = {
    "keyframe_extractor": _get_keyframe_extractor,
    "deepfake_triage": _get_deepfake_triage,
    "forensic_artifact": _get_forensic_artifact,
    "ensemble_voter": _get_ensemble_voter,
    "threat_pattern": _get_threat_pattern,
    "predictive_risk": _get_predictive_risk,
    "responsible_ai_auditor": _get_responsible_ai_auditor,
    "bias_fairness": _get_bias_fairness,
    "privacy_scanner": _get_privacy_scanner,
    "regulatory_mapper": _get_regulatory_mapper,
    "digital_asset_governance": _get_digital_asset_governance,
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
    """Supervisor plans which agents to run."""
    delta = _get_supervisor().run(state)
    planned = delta.get("results", {}).get("supervisor", {}).get("planned_agents", [])
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
        factory = AGENT_FACTORIES.get(agent_name)
        if factory is None:
            logger.error(f"Agent {agent_name} not found in factories")
            return {}
        return factory().run(state)

    node_fn.__name__ = f"node_{agent_name}"
    return node_fn


def synthesize_node(state: AgentState) -> dict:
    """Supervisor synthesizes all results into the governance bundle."""
    bundle = _get_supervisor().synthesize_bundle(state)

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
    """Compile and return the runnable swarm graph with in-memory checkpointing."""
    checkpointer = MemorySaver()
    return build_swarm_graph().compile(checkpointer=checkpointer)


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
        final_state = swarm_app.invoke(
            initial_state,
            config={"configurable": {"thread_id": job_id}},
        )

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
