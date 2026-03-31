"""
Digital Asset Governance Agent - Owner-verified website security scanning.
Integrates with the scanning infrastructure (Playwright + ZAP + all checkers).
Can trigger Privacy Scanner and Regulatory Mapper for cross-service collaboration.
"""

import json
import logging

from sqlmodel import Session, create_engine, select

from app.agents.base_agent import BaseAgent
from app.graphs.state import AgentState
from app.core.config import settings
from app.models import Consent, DomainVerification

logger = logging.getLogger(__name__)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(settings.database_url, echo=False, pool_pre_ping=True)
    return _engine


class DigitalAssetGovernanceAgent(BaseAgent):
    name = "digital_asset_governance"
    description = (
        "Owner-verified website security scanning using Playwright, ZAP, and 9 security checkers"
    )

    def _verify_ownership(self, domain: str, user_email: str) -> dict:
        """Check if the domain is verified for this user."""
        engine = _get_engine()
        with Session(engine) as session:
            verification = session.exec(
                select(DomainVerification)
                .where(DomainVerification.domain == domain)
                .where(DomainVerification.user_email == user_email)
                .where(DomainVerification.verified == True)
            ).first()

            if not verification:
                return {"verified": False, "reason": "Domain not verified for this user"}

            return {
                "verified": True,
                "verification_id": verification.id,
                "domain": verification.domain,
                "method": verification.verified_by_method,
            }

    def _check_active_consent(self, domain: str, user_email: str) -> bool:
        """Check if active scan consent exists."""
        engine = _get_engine()
        with Session(engine) as session:
            consent = session.exec(
                select(Consent)
                .where(Consent.domain == domain)
                .where(Consent.user_email == user_email)
                .where(Consent.active_allowed == True)
            ).first()
            return consent is not None

    def _run_security_checks(self, url: str, options: dict) -> dict:
        """Run all security checkers against the URL."""
        from app.worker.checks.cors_checker import check_cors
        from app.worker.checks.directory_checker import check_directory_listing
        from app.worker.checks.endpoint_checker import check_endpoints
        from app.worker.checks.header_checker import check_headers
        from app.worker.checks.https_checker import check_https_redirect
        from app.worker.checks.library_checker import check_libraries
        from app.worker.checks.reflection_checker import check_reflections
        from app.worker.checks.tls_checker import check_tls

        all_findings = []
        check_errors = []

        checks = [
            ("tls", check_tls),
            ("cors", check_cors),
            ("endpoints", check_endpoints),
            ("headers", check_headers),
            ("https", check_https_redirect),
            ("directory", check_directory_listing),
            ("libraries", check_libraries),
            ("reflections", check_reflections),
        ]

        for name, check_fn in checks:
            try:
                findings = check_fn(url)
                all_findings.extend(findings)
            except Exception as e:
                logger.error(f"Check {name} failed: {e}")
                check_errors.append(name)

        # Run ZAP if active scanning is allowed
        zap_findings = []
        if options.get("allow_active", False):
            try:
                from app.worker.zap_client import is_zap_available, zap_baseline_scan

                if is_zap_available():
                    zap_findings = zap_baseline_scan(
                        target_url=url,
                        verification_id=options.get("verification_id", ""),
                    )
                    all_findings.extend(zap_findings)
            except Exception as e:
                logger.error(f"ZAP scan failed: {e}")
                check_errors.append("zap")

        # Calculate severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Calculate risk score
        weights = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 1}
        raw_score = sum(severity_counts.get(s, 0) * w for s, w in weights.items())
        risk_score = min(100, int((raw_score / 100) * 100)) if raw_score > 0 else 0

        return {
            "findings": all_findings,
            "findings_count": len(all_findings),
            "zap_findings_count": len(zap_findings),
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "check_errors": check_errors,
            "checks_completed": len(checks) - len(check_errors),
            "checks_total": len(checks),
        }

    def process(self, state: AgentState) -> dict:
        input_data = state.get("input_data", {})
        url = input_data.get("url", "")
        user_email = state.get("user_email", "")
        options = input_data.get("scan_options", {})

        if not url:
            return {"status": "error", "error": "No URL provided"}

        # Extract domain
        from urllib.parse import urlparse

        parsed = urlparse(url)
        domain = parsed.hostname or ""

        # Step 1: Verify ownership
        ownership = self._verify_ownership(domain, user_email)
        if not ownership.get("verified"):
            return {
                "status": "error",
                "error": "domain_not_verified",
                "message": f"Domain {domain} is not verified for this user. Use POST /api/domains/verify/request first.",
            }

        # Step 2: Check active consent if active scanning requested
        allow_active = options.get("allow_active", False)
        if allow_active:
            has_consent = self._check_active_consent(domain, user_email)
            if not has_consent:
                allow_active = False
                logger.warning(f"Active scan disabled for {domain}: no consent")

        options["allow_active"] = allow_active
        options["verification_id"] = ownership.get("verification_id", "")

        # Step 3: Run security checks
        target_url = url
        if "localhost" in url or "127.0.0.1" in url:
            target_url = url.replace("localhost", "host.docker.internal").replace(
                "127.0.0.1", "host.docker.internal"
            )

        scan_results = self._run_security_checks(target_url, options)

        # Step 4: AI-powered analysis of findings
        if scan_results["findings"]:
            findings_summary = json.dumps(scan_results["findings"][:20], default=str)[:4000]
            prompt = f"""You are a website security expert analyzing scan results for {url}.

Findings ({scan_results["findings_count"]} total):
{findings_summary}

Risk Score: {scan_results["risk_score"]}/100
Severity Breakdown: {json.dumps(scan_results["severity_counts"])}

Provide:
1. Executive summary
2. Top 5 most critical issues
3. Platform-specific fix configs (Vercel, Netlify, Nginx, Apache)

Return JSON:
{{
    "executive_summary": "summary",
    "critical_issues": [{{"title": "title", "severity": "level", "fix": "fix"}}],
    "platform_configs": {{
        "vercel": "vercel.json config snippet",
        "netlify": "netlify.toml config snippet",
        "nginx": "nginx.conf snippet",
        "apache": ".htaccess snippet"
    }},
    "overall_assessment": "Brief overall assessment"
}}"""

            try:
                ai_analysis = self.generate_json(
                    prompt,
                    system_instruction="You are a web security expert. Provide actionable, platform-specific fixes.",
                )
                scan_results["ai_analysis"] = ai_analysis
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
                scan_results["ai_analysis"] = {"error": str(e)}

        scan_results["status"] = "success"
        scan_results["domain"] = domain
        scan_results["ownership_verified"] = True
        scan_results["active_scan_enabled"] = allow_active
        return scan_results


digital_asset_governance_agent = DigitalAssetGovernanceAgent()
