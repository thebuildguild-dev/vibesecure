"""
Predictive Risk Agent - attack forecasting and risk prediction.
Analyzes patterns and predicts potential future attacks using threat intelligence RAG.
"""

import json
import logging

from src.agents.base_agent import BaseAgent
from src.agents.state import AgentState
from src.rag import search_similar

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

        # Query RAG for similar attack forecasting patterns
        rag_context = ""
        try:
            rag_query = f"{content[:500]} {ai_system_description[:500]}".strip()
            if rag_query:
                rag_results = search_similar(
                    query=rag_query,
                    top_k=5,
                    category_filter="threat_intel",
                )
                if rag_results:
                    rag_articles = "\n".join(
                        [
                            f"- [{r['dataset_name']}] {r['content'][:180]}... (relevance: {r['similarity']:.2f})"
                            for r in rag_results
                        ]
                    )
                    rag_context = (
                        f"\n\nHistorical patterns from threat intelligence:\n{rag_articles}"
                    )
                    logger.info(f"Found {len(rag_results)} similar attack patterns for forecasting")
        except Exception as e:
            logger.warning(f"RAG pattern lookup failed: {e}. Continuing with available data.")

        prompt = f"""You are a predictive AI security analyst specializing in attack forecasting.

Based on the current threat analysis results, predict potential future attack vectors and risks.

Context:
- AI System Description: {ai_system_description[:1000] if ai_system_description else "N/A"}
- API Endpoint Tested: {api_endpoint or "N/A"}
- Current Findings: {existing_findings}{rag_context}

Perform these analyses:
1. ATTACK VECTOR PREDICTION: Based on current vulnerabilities and historical patterns, what attacks are most likely?
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
                system_instruction="You are a predictive AI security analyst. Be realistic and evidence-based in your predictions, informed by historical attack patterns.",
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
