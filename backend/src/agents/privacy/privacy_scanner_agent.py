"""
Privacy Scanner Agent - detects PII, consent banner issues, and privacy policy gaps.
Uses Gemini vision capabilities for page analysis.
Enriched with regulatory knowledge from RAG.
"""

import json
import logging

import httpx
from bs4 import BeautifulSoup

from src.agents.base_agent import BaseAgent
from src.agents.state import AgentState
from src.rag import search_similar

logger = logging.getLogger(__name__)


class PrivacyScannerAgent(BaseAgent):
    name = "privacy_scanner"
    description = "Detects PII exposure, consent banner issues, and privacy policy gaps"

    def _fetch_page_content(self, url: str) -> tuple[str, str]:
        """Fetch page HTML and extract text content."""
        try:
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                response = client.get(url)
                html = response.text
                soup = BeautifulSoup(html, "html.parser")
                text = soup.get_text(separator="\n", strip=True)
                return html[:10000], text[:5000]
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return "", ""

    def _check_consent_banner(self, html: str) -> dict:
        """Check for cookie consent banner implementation."""
        soup = BeautifulSoup(html, "html.parser")

        indicators = {
            "has_cookie_banner": False,
            "has_consent_manager": False,
            "consent_mechanisms": [],
        }

        # Look for common consent banner patterns
        consent_classes = ["cookie", "consent", "gdpr", "privacy-banner", "cc-banner"]
        consent_ids = ["cookie-consent", "gdpr-consent", "cookie-banner", "consent-banner"]

        for cls in consent_classes:
            if soup.find(class_=lambda c: c and cls in c.lower() if isinstance(c, str) else False):
                indicators["has_cookie_banner"] = True
                indicators["consent_mechanisms"].append(f"CSS class containing '{cls}'")

        for id_val in consent_ids:
            if soup.find(id=lambda i: i and id_val in i.lower() if isinstance(i, str) else False):
                indicators["has_cookie_banner"] = True
                indicators["consent_mechanisms"].append(f"Element with ID containing '{id_val}'")

        # Check for common consent management platforms
        cmp_scripts = ["cookiebot", "onetrust", "osano", "termly", "cookieconsent", "cookieyes"]
        scripts = soup.find_all("script")
        for script in scripts:
            src = script.get("src", "")
            for cmp in cmp_scripts:
                if cmp in src.lower():
                    indicators["has_consent_manager"] = True
                    indicators["consent_mechanisms"].append(f"CMP: {cmp}")

        return indicators

    def _check_privacy_policy(self, html: str, url: str) -> dict:
        """Check for privacy policy link and content."""
        soup = BeautifulSoup(html, "html.parser")

        policy_links = []
        privacy_keywords = [
            "privacy",
            "data protection",
            "cookie policy",
            "privacy-policy",
            "datenschutz",
        ]

        for link in soup.find_all("a", href=True):
            text = link.get_text(strip=True).lower()
            href = link["href"].lower()
            if any(kw in text or kw in href for kw in privacy_keywords):
                policy_links.append(
                    {
                        "text": link.get_text(strip=True),
                        "href": link["href"],
                    }
                )

        return {
            "has_privacy_policy_link": len(policy_links) > 0,
            "policy_links": policy_links[:5],
        }

    def process(self, state: AgentState) -> dict:
        input_data = state.get("input_data", {})
        url = input_data.get("url", "")
        content = input_data.get("content", "")

        results = {}

        # Query RAG for regulatory standards
        rag_context = ""
        try:
            rag_results = search_similar(
                query="privacy policy consent banner GDPR requirements regulations",
                top_k=3,
                category_filter="regulatory",
            )
            if rag_results:
                rag_articles = "\n".join(
                    [
                        f"- [{r['dataset_name']}] Section: {r['content'][:200]}..."
                        for r in rag_results
                    ]
                )
                rag_context = f"\n\nRegulatory requirements from knowledge base:\n{rag_articles}"
                logger.info(f"Found {len(rag_results)} regulatory references for privacy scan")
        except Exception as e:
            logger.warning(f"RAG regulatory lookup failed: {e}. Continuing without context.")

        if url:
            html, text = self._fetch_page_content(url)

            if html:
                # Automated checks
                results["consent_banner"] = self._check_consent_banner(html)
                results["privacy_policy"] = self._check_privacy_policy(html, url)

                # AI-powered analysis with RAG context
                prompt = f"""You are a data privacy analyst scanning a website for privacy issues.

URL: {url}

Page text (sample):
{text[:3000]}

HTML indicators found:
- Consent banner: {json.dumps(results.get("consent_banner", {}), indent=2)}
- Privacy policy: {json.dumps(results.get("privacy_policy", {}), indent=2)}{rag_context}

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

                try:
                    ai_analysis = self.generate_json(
                        prompt,
                        system_instruction="You are a data privacy analyst. Be thorough and identify real privacy issues. Consider regulatory requirements from the knowledge base.",
                    )
                    results["ai_analysis"] = ai_analysis
                except Exception as e:
                    logger.error(f"AI privacy analysis failed: {e}")
                    results["ai_analysis"] = {"error": str(e)}
            else:
                results["error"] = "Could not fetch page content"

        elif content:
            prompt = f"""You are a data privacy analyst scanning content for privacy issues.

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

            try:
                results["ai_analysis"] = self.generate_json(
                    prompt,
                    system_instruction="You are a data privacy analyst.",
                )
            except Exception as e:
                results["ai_analysis"] = {"error": str(e)}

        results["status"] = "success"
        return results


privacy_scanner_agent = PrivacyScannerAgent()
