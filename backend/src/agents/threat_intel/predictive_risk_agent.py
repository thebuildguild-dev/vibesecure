"""
Predictive Risk Agent - attack forecasting and risk prediction.
Analyzes patterns and predicts potential future attacks.
"""

import json
import logging

from src.agents.base_agent import BaseAgent
from src.agents.state import AgentState

logger = logging.getLogger(__name__)


class PredictiveRiskAgent(BaseAgent):
    name = "predictive_risk"
    description = "AI attack forecasting and risk prediction"

    def process(self, state: AgentState) -> dict:
        input_data = state.get("input_data", {})
        results = state.get("results", {})

        threat_results = results.get("threat_pattern", {})
        content = input_data.get("content", "")
        api_endpoint = input_data.get("api_endpoint", "")
        ai_system_description = input_data.get("ai_system_description", "")

        # Gather all findings so far
        existing_findings = json.dumps(
            {
                k: v
                for k, v in results.items()
                if k != "supervisor" and isinstance(v, dict) and v.get("status") != "error"
            },
            default=str,
        )[:5000]

        prompt = f"""You are a predictive AI security analyst specializing in attack forecasting.

Based on the current threat analysis results, predict potential future attack vectors and risks.

Context:
- AI System Description: {ai_system_description[:1000] if ai_system_description else "N/A"}
- API Endpoint Tested: {api_endpoint or "N/A"}
- Current Findings: {existing_findings}

Perform these analyses:
1. ATTACK VECTOR PREDICTION: Based on current vulnerabilities, what attacks are most likely?
2. RISK TRAJECTORY: Is the risk level increasing, stable, or decreasing?
3. ATTACK SURFACE MAP: What components are most exposed?
4. THREAT ACTOR PROFILING: What type of attacker would target this system?
5. MITIGATION PRIORITY: Which fixes have the highest impact?

Return JSON:
{{
    "predicted_attacks": [
        {{
            "attack_type": "type of attack",
            "probability": "high|medium|low",
            "impact": "critical|high|medium|low",
            "timeframe": "immediate|short_term|long_term",
            "description": "How this attack would work",
            "prevention": "How to prevent it"
        }}
    ],
    "risk_score": 0-100,
    "risk_level": "critical|high|medium|low",
    "risk_trajectory": "increasing|stable|decreasing",
    "attack_surface": [
        {{
            "component": "component name",
            "exposure_level": "critical|high|medium|low",
            "vulnerabilities": ["vuln 1"]
        }}
    ],
    "threat_actor_profile": {{
        "likely_type": "script_kiddie|organized_crime|nation_state|insider|automated_bot",
        "motivation": "financial|espionage|disruption|data_theft",
        "capability_required": "low|medium|high|very_high"
    }},
    "priority_mitigations": [
        {{
            "action": "What to do",
            "impact": "critical|high|medium|low",
            "effort": "quick|medium|long_term",
            "reduces_risk_by": 0-100
        }}
    ],
    "executive_summary": "2-3 sentence summary"
}}"""

        try:
            prediction = self.generate_json(
                prompt,
                system_instruction="You are a predictive AI security analyst. Be realistic and evidence-based in your predictions.",
            )
            prediction["status"] = "success"
            return prediction

        except Exception as e:
            logger.error(f"Predictive risk analysis failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "risk_score": 50,
                "risk_level": "medium",
            }


predictive_risk_agent = PredictiveRiskAgent()
