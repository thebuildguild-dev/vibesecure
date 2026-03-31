"""
Regulatory Mapper Agent - maps findings to GDPR, CCPA, DPDP Act, EU AI Act.
Enriched with RAG knowledge base for exact article references and precedents.
Generates professional compliance reports.
"""

import json
import logging

from src.agents.base_agent import BaseAgent
from src.agents.state import AgentState
from src.rag import search_similar

logger = logging.getLogger(__name__)

REGULATIONS = {
    "GDPR": {
        "name": "General Data Protection Regulation",
        "jurisdiction": "European Union",
        "key_articles": {
            "Art. 5": "Principles relating to processing of personal data",
            "Art. 6": "Lawfulness of processing",
            "Art. 7": "Conditions for consent",
            "Art. 12-14": "Transparency and information",
            "Art. 15-22": "Data subject rights",
            "Art. 25": "Data protection by design and default",
            "Art. 32": "Security of processing",
            "Art. 33-34": "Breach notification",
            "Art. 35": "Data protection impact assessment",
            "Art. 44-49": "International data transfers",
        },
    },
    "CCPA": {
        "name": "California Consumer Privacy Act",
        "jurisdiction": "California, USA",
        "key_sections": {
            "1798.100": "Right to know",
            "1798.105": "Right to delete",
            "1798.110": "Right to know what personal information is collected",
            "1798.115": "Right to know what personal information is sold",
            "1798.120": "Right to opt-out of sale",
            "1798.125": "Non-discrimination",
            "1798.130": "Notice requirements",
            "1798.135": "Methods of submitting requests",
        },
    },
    "DPDP": {
        "name": "Digital Personal Data Protection Act",
        "jurisdiction": "India",
        "key_sections": {
            "Section 4": "Grounds for processing personal data",
            "Section 5": "Notice requirements",
            "Section 6": "Consent",
            "Section 7": "Legitimate uses",
            "Section 8": "General obligations of data fiduciary",
            "Section 9": "Processing of children's data",
            "Section 11-14": "Rights of data principal",
            "Section 15": "Duties of data principal",
        },
    },
    "EU_AI_ACT": {
        "name": "EU AI Act",
        "jurisdiction": "European Union",
        "risk_categories": {
            "Unacceptable Risk": "Prohibited AI practices (social scoring, real-time biometric ID in public)",
            "High Risk": "AI in critical infrastructure, education, employment, law enforcement",
            "Limited Risk": "Chatbots, emotion recognition - transparency obligations",
            "Minimal Risk": "AI-enabled games, spam filters - no specific obligations",
        },
    },
}


class RegulatoryMapperAgent(BaseAgent):
    name = "regulatory_mapper"
    description = "Maps privacy findings to GDPR, CCPA, DPDP Act, and EU AI Act regulations"

    def process(self, state: AgentState) -> dict:
        input_data = state.get("input_data", {})
        results = state.get("results", {})

        privacy_results = results.get("privacy_scanner", {})
        auditor_results = results.get("responsible_ai_auditor", {})
        bias_results = results.get("bias_fairness", {})
        threat_results = results.get("threat_pattern", {})

        # Gather all findings
        all_findings = json.dumps(
            {
                "privacy": privacy_results,
                "responsible_ai": auditor_results,
                "bias_fairness": bias_results,
                "threats": threat_results,
            },
            default=str,
        )[:6000]

        # Query RAG for regulatory knowledge and precedents
        rag_context = ""
        try:
            rag_results = search_similar(
                query="GDPR CCPA compliance articles requirements data protection",
                top_k=5,
                category_filter="regulatory",
            )
            if rag_results:
                rag_articles = "\n".join(
                    [f"- [{r['dataset_name']}] {r['content'][:250]}..." for r in rag_results]
                )
                rag_context = f"\n\nRegulatory knowledge base references:\n{rag_articles}"
                logger.info(
                    f"Found {len(rag_results)} regulatory references for compliance mapping"
                )
        except Exception as e:
            logger.warning(f"RAG regulatory lookup failed: {e}. Continuing with base regulations.")

        prompt = f"""You are a regulatory compliance expert mapping security and privacy findings to international regulations.

Findings to map:
{all_findings}

Regulations to check against:
{json.dumps(REGULATIONS, indent=2)[:3000]}{rag_context}

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

        try:
            result = self.generate_json(
                prompt,
                system_instruction="You are a regulatory compliance expert with deep knowledge of GDPR, CCPA, India's DPDP Act, and the EU AI Act. Be specific about article references. Use regulatory knowledge base to cite precedents.",
            )
            result["status"] = "success"
            return result

        except Exception as e:
            logger.error(f"Regulatory mapping failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "overall_compliance_score": 0,
            }


regulatory_mapper_agent = RegulatoryMapperAgent()
