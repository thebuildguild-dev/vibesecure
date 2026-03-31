"""Prompt templates for the Regulatory Mapper Agent."""

REGULATIONS_SUMMARY = {
    "GDPR": "EU data protection regulation",
    "CCPA": "California Consumer Privacy Act",
    "DPDP": "India Digital Personal Data Protection Act",
    "EU_AI_ACT": "EU AI Act",
}

SYSTEM_INSTRUCTION = (
    "You are a regulatory compliance expert with deep knowledge of GDPR, CCPA, "
    "India's DPDP Act, and the EU AI Act. Be specific about article references."
)


def build_prompt(*, all_findings: str, regulations_json: str) -> str:
    return f"""You are a regulatory compliance expert mapping security and privacy findings to international regulations.

Findings to map:
{all_findings}

Regulations to check against:
{regulations_json[:3000]}

For each regulation, identify:
1. Which specific articles/sections are relevant
2. Current compliance status
3. What needs to change for compliance
4. Priority level

Return JSON:
{{
    "gdpr_mapping": {{
        "applicable": true/false,
        "compliance_score": 0-100,
        "violations": [
            {{
                "article": "Art. X",
                "title": "Article title",
                "status": "compliant|partial|non_compliant",
                "finding": "What was found",
                "required_action": "What to do",
                "priority": "critical|high|medium|low"
            }}
        ],
        "recommendations": ["rec"]
    }},
    "ccpa_mapping": {{
        "applicable": true/false,
        "compliance_score": 0-100,
        "violations": [
            {{
                "section": "1798.XXX",
                "title": "Section title",
                "status": "compliant|partial|non_compliant",
                "finding": "What was found",
                "required_action": "What to do",
                "priority": "critical|high|medium|low"
            }}
        ],
        "recommendations": ["rec"]
    }},
    "dpdp_mapping": {{
        "applicable": true/false,
        "compliance_score": 0-100,
        "violations": [
            {{
                "section": "Section X",
                "title": "Section title",
                "status": "compliant|partial|non_compliant",
                "finding": "What was found",
                "required_action": "What to do",
                "priority": "critical|high|medium|low"
            }}
        ],
        "recommendations": ["rec"]
    }},
    "eu_ai_act_mapping": {{
        "applicable": true/false,
        "risk_category": "unacceptable|high|limited|minimal",
        "compliance_score": 0-100,
        "obligations": [
            {{
                "obligation": "description",
                "status": "met|partial|not_met",
                "required_action": "What to do"
            }}
        ],
        "recommendations": ["rec"]
    }},
    "overall_compliance_score": 0-100,
    "overall_compliance_grade": "A|B|C|D|F",
    "critical_non_compliance": ["most urgent items"],
    "executive_summary": "2-3 sentence regulatory compliance summary",
    "report_metadata": {{
        "assessment_date": "today's date",
        "regulations_checked": ["GDPR", "CCPA", "DPDP", "EU AI Act"],
        "confidence_level": "high|medium|low"
    }}
}}"""
