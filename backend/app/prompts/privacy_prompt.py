"""Prompt templates for the Privacy Scanner Agent."""

import json

URL_SYSTEM_INSTRUCTION = (
    "You are a data privacy analyst. Be thorough and identify real privacy issues."
)

CONTENT_SYSTEM_INSTRUCTION = "You are a data privacy analyst."


def build_url_prompt(
    *,
    url: str,
    text: str,
    consent_banner: dict,
    privacy_policy: dict,
) -> str:
    return f"""You are a data privacy analyst scanning a website for privacy issues.

URL: {url}

Page text (sample):
{text[:3000]}

HTML indicators found:
- Consent banner: {json.dumps(consent_banner, indent=2)}
- Privacy policy: {json.dumps(privacy_policy, indent=2)}

Analyze for:
1. PII EXPOSURE: Visible personal data (emails, phone numbers, addresses, names)
2. CONSENT MECHANISMS: Cookie consent quality and compliance
3. PRIVACY POLICY: Completeness and accessibility
4. DATA COLLECTION: Forms collecting personal data, tracking scripts
5. THIRD-PARTY SHARING: Evidence of data sharing with third parties
6. DATA STORAGE: Client-side storage (cookies, localStorage) usage

Return JSON:
{{
    "pii_findings": [
        {{
            "type": "email|phone|address|name|other",
            "severity": "critical|high|medium|low",
            "location": "where found",
            "recommendation": "how to fix"
        }}
    ],
    "consent_assessment": {{
        "grade": "A|B|C|D|F",
        "is_compliant": true/false,
        "issues": ["issue"],
        "recommendations": ["rec"]
    }},
    "privacy_policy_assessment": {{
        "exists": true/false,
        "grade": "A|B|C|D|F",
        "missing_sections": ["section"],
        "recommendations": ["rec"]
    }},
    "tracking_scripts": ["script name or domain"],
    "data_collection_forms": {{"count": 0, "fields": ["field"]}},
    "overall_privacy_score": 0-100,
    "summary": "Brief summary of privacy posture"
}}"""


def build_content_prompt(*, content: str) -> str:
    return f"""You are a data privacy analyst scanning content for privacy issues.

Content:
{content[:5000]}

Check for:
1. PII exposure (personal data visible in content)
2. Privacy implications of the content
3. Data handling concerns

Return JSON:
{{
    "pii_findings": [{{"type": "type", "severity": "level", "location": "where", "recommendation": "fix"}}],
    "privacy_concerns": ["concern"],
    "overall_privacy_score": 0-100,
    "summary": "Brief summary"
}}"""
