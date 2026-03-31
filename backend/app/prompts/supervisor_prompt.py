"""Prompt templates for the Supervisor Agent."""

import json

SYNTHESIS_SYSTEM_INSTRUCTION = None  # uses default


def build_synthesis_prompt(
    *,
    service_type: str,
    input_data: dict,
    results: dict,
) -> str:
    return f"""You are the Supervisor Agent of VibeSecure, an AI-native governance platform.
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
