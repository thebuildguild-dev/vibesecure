"""Prompt templates for the Predictive Risk Agent."""

SYSTEM_INSTRUCTION = (
    "You are a predictive AI security analyst. Be realistic and evidence-based in your predictions."
)


def build_prompt(
    *,
    ai_system_description: str,
    api_endpoint: str,
    existing_findings: str,
) -> str:
    return f"""You are a predictive AI security analyst specializing in attack forecasting.

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
