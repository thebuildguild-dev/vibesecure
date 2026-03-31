"""
Supervisor Agent - the brain of the swarm.
Uses brain-tier Gemini models to orchestrate all other agents.
"""

import json
import logging

from app.agents.base_agent import BaseAgent
from app.agents.messaging import publish_event
from app.graphs.state import SERVICE_AGENT_MAP, AgentState
from app.tools.gemini_tools import parse_json_response

logger = logging.getLogger(__name__)


class SupervisorAgent(BaseAgent):
    name = "supervisor"
    description = "Orchestrates the agent swarm, decides which agents to activate and in what order"
    is_brain = True

    def plan_agents(self, state: AgentState) -> list[str]:
        """Determine which agents to run based on service type and input data."""
        service_type = state.get("service_type", "")
        input_data = state.get("input_data", {})

        if service_type == "all":
            agents = []
            # Determine which services apply based on input
            has_media = bool(
                input_data.get("file_path") or input_data.get("file_type") in ("image", "video")
            )
            has_url = bool(input_data.get("url"))
            has_api_endpoint = bool(input_data.get("api_endpoint"))
            has_content = bool(input_data.get("content") or input_data.get("ai_system_description"))

            if has_media:
                agents.extend(SERVICE_AGENT_MAP["deepfake"])
            if has_api_endpoint or has_content:
                agents.extend(SERVICE_AGENT_MAP["threat_intel"])
            if has_content or has_media:
                agents.extend(SERVICE_AGENT_MAP["responsible_ai"])
            if has_url or has_content:
                agents.extend(SERVICE_AGENT_MAP["privacy"])
            if has_url:
                agents.extend(SERVICE_AGENT_MAP["digital_asset"])

            # If nothing matched, run all
            if not agents:
                for svc_agents in SERVICE_AGENT_MAP.values():
                    agents.extend(svc_agents)
            return agents

        if service_type in SERVICE_AGENT_MAP:
            return list(SERVICE_AGENT_MAP[service_type])

        return []

    def synthesize_bundle(self, state: AgentState) -> dict:
        """Create the final governance bundle from all agent results."""
        results = state.get("results", {})
        service_type = state.get("service_type", "")
        input_data = state.get("input_data", {})

        prompt = f"""You are the Supervisor Agent of VibeSecure, an AI-native governance platform.
Synthesize the following agent results into a unified Governance Bundle.

Service Type: {service_type}
Input: {json.dumps(input_data, default=str)[:2000]}

Agent Results:
{json.dumps(results, default=str)[:8000]}

Create a governance bundle with:
1. "executive_summary": A clear 3-5 sentence summary of all findings
2. "overall_risk_level": One of "critical", "high", "medium", "low"
3. "confidence_score": 0-100 indicating overall confidence
4. "key_findings": List of the most important findings across all services
5. "recommended_actions": Prioritized list of actions the user should take
6. "service_summaries": Brief summary for each service that was run

Return valid JSON."""

        try:
            text = self.generate(prompt, response_mime_type="application/json")
            return parse_json_response(text)
        except Exception as e:
            logger.error(f"Failed to synthesize bundle: {e}")
            return {
                "executive_summary": "Analysis completed. See individual service results for details.",
                "overall_risk_level": "medium",
                "confidence_score": 50,
                "key_findings": [],
                "recommended_actions": [],
                "service_summaries": {},
                "raw_results": {k: str(v)[:500] for k, v in results.items()},
            }

    def process(self, state: AgentState) -> dict:
        """Plan which agents to run. The graph handles actual execution."""
        agents = self.plan_agents(state)
        self.logger.info(f"Planned agents: {agents}")

        publish_event(
            state.get("job_id", ""),
            self.name,
            "plan",
            {"agents": agents, "service_type": state.get("service_type", "")},
        )

        return {
            "planned_agents": agents,
            "service_type": state.get("service_type", ""),
        }
