"""
Responsible AI Auditor Agent - evaluates AI systems against NIST AI RMF and Google SAIF.
"""

import json
import logging

from src.agents.base_agent import BaseAgent
from src.agents.state import AgentState

logger = logging.getLogger(__name__)

NIST_AI_RMF_FUNCTIONS = {
    "GOVERN": "Policies, processes, procedures, and practices for AI risk management",
    "MAP": "Risks identified and documented in context",
    "MEASURE": "Risks analyzed and tracked with metrics",
    "MANAGE": "Risks prioritized and acted upon",
}

GOOGLE_SAIF_PRINCIPLES = [
    "Expand strong security foundations to the AI ecosystem",
    "Extend detection and response to bring AI into an org threat universe",
    "Automate defenses to keep pace with existing and new threats",
    "Harmonize platform-level controls to ensure consistent security",
    "Adapt controls to adjust mitigations and create faster feedback loops",
    "Contextualize AI system risks in surrounding business processes",
]

SCORECARD_DIMENSIONS = [
    "transparency",
    "fairness",
    "accountability",
    "safety",
    "privacy",
    "security",
    "robustness",
    "explainability",
]


class ResponsibleAIAuditorAgent(BaseAgent):
    name = "responsible_ai_auditor"
    description = "Evaluates AI systems against NIST AI RMF and Google SAIF frameworks"

    def process(self, state: AgentState) -> dict:
        input_data = state.get("input_data", {})

        content = input_data.get("content", "")
        ai_system_description = input_data.get("ai_system_description", "")
        url = input_data.get("url", "")

        # Gather context from other agents
        results = state.get("results", {})
        threat_results = results.get("threat_pattern", {})
        deepfake_results = results.get("ensemble_voter", {})

        context_summary = ""
        if threat_results and threat_results.get("status") == "success":
            context_summary += f"Threat analysis found: {json.dumps(threat_results.get('content_analysis', {}), default=str)[:1000]}\n"
        if deepfake_results and deepfake_results.get("status") == "success":
            context_summary += (
                f"Deepfake analysis: verdict={deepfake_results.get('final_verdict', 'N/A')}\n"
            )

        prompt = f"""You are a Responsible AI Auditor evaluating an AI system or AI-generated content.

Evaluate against TWO frameworks:

**1. NIST AI Risk Management Framework (AI RMF 1.0)**
Functions: {json.dumps(NIST_AI_RMF_FUNCTIONS, indent=2)}

**2. Google Secure AI Framework (SAIF)**
Principles: {json.dumps(GOOGLE_SAIF_PRINCIPLES, indent=2)}

Content/System to evaluate:
- Description: {ai_system_description[:2000] if ai_system_description else "N/A"}
- Content: {content[:2000] if content else "N/A"}
- URL: {url if url else "N/A"}
- Additional context: {context_summary[:1000]}

Score each dimension (0-100):
{json.dumps(SCORECARD_DIMENSIONS)}

Return JSON:
{{
    "scorecard": {{
        "transparency": {{"score": 0-100, "findings": "explanation", "recommendations": ["rec"]}},
        "fairness": {{"score": 0-100, "findings": "explanation", "recommendations": ["rec"]}},
        "accountability": {{"score": 0-100, "findings": "explanation", "recommendations": ["rec"]}},
        "safety": {{"score": 0-100, "findings": "explanation", "recommendations": ["rec"]}},
        "privacy": {{"score": 0-100, "findings": "explanation", "recommendations": ["rec"]}},
        "security": {{"score": 0-100, "findings": "explanation", "recommendations": ["rec"]}},
        "robustness": {{"score": 0-100, "findings": "explanation", "recommendations": ["rec"]}},
        "explainability": {{"score": 0-100, "findings": "explanation", "recommendations": ["rec"]}}
    }},
    "nist_assessment": {{
        "govern": {{"rating": "adequate|needs_improvement|not_addressed", "notes": "explanation"}},
        "map": {{"rating": "adequate|needs_improvement|not_addressed", "notes": "explanation"}},
        "measure": {{"rating": "adequate|needs_improvement|not_addressed", "notes": "explanation"}},
        "manage": {{"rating": "adequate|needs_improvement|not_addressed", "notes": "explanation"}}
    }},
    "saif_assessment": [
        {{"principle": "principle text", "compliance": "compliant|partial|non_compliant", "notes": "explanation"}}
    ],
    "overall_score": 0-100,
    "overall_grade": "A|B|C|D|F",
    "plain_english_summary": "2-3 sentence summary a non-expert can understand",
    "top_recommendations": ["rec 1", "rec 2", "rec 3"],
    "reasoning_trace": "Detailed reasoning for the expert audience"
}}"""

        try:
            audit_result = self.generate_json(
                prompt,
                system_instruction="You are a Responsible AI auditor certified in NIST AI RMF and Google SAIF. Be thorough but fair.",
            )
            audit_result["status"] = "success"
            return audit_result

        except Exception as e:
            logger.error(f"Responsible AI audit failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "overall_score": 0,
                "overall_grade": "N/A",
            }


responsible_ai_auditor_agent = ResponsibleAIAuditorAgent()
