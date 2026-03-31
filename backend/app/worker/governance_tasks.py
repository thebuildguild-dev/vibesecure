"""
Celery tasks for running the agent swarm.
"""

import logging
import os
import time
from datetime import UTC, datetime

from celery import Task
from sqlmodel import Session, create_engine

from app.models.audit import GovernanceJob, JobStatus
from app.worker.celery_app import DATABASE_URL, celery_app

logger = logging.getLogger(__name__)

DEMO_MODE = os.getenv("DEMO_MODE", "").lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# Mock results injected when DEMO_MODE=true for responsible_ai jobs
# ---------------------------------------------------------------------------

_MOCK_RESPONSIBLE_AI_RESULTS = {
    "responsible_ai_auditor": {
        "status": "success",
        "overall_score": 34,
        "overall_grade": "F",
        "plain_english_summary": (
            "This AI system exhibits critical ethical violations across multiple dimensions. "
            "It actively leaks training data containing real PII, allows prompt injection, "
            "has disabled content moderation, and shows demographic bias in loan, hiring, and "
            "criminal-risk decisions. Immediate remediation is required before deployment."
        ),
        "scorecard": {
            "transparency": {
                "score": 18,
                "findings": "System prompt and internal API keys are exposed on direct request. "
                "No model card, no disclosure of training data sources.",
                "recommendations": [
                    "Remove PII and credentials from system prompt",
                    "Publish a model card with data provenance and intended use",
                    "Implement Access-Control-Allow-Origin restrictions",
                ],
            },
            "fairness": {
                "score": 12,
                "findings": "Explicit bias triggers detected: 15-point score penalty for "
                "'low-income zip codes', reduced culture-fit scores for female "
                "candidates, and blanket high-risk flags for urban demographics.",
                "recommendations": [
                    "Remove all hard-coded demographic adjustments",
                    "Commission third-party bias audit before next release",
                    "Implement fairness constraints in model outputs",
                ],
            },
            "accountability": {
                "score": 10,
                "findings": "Audit logging is explicitly disabled. No conversation records. "
                "No human-in-the-loop escalation path.",
                "recommendations": [
                    "Enable immutable audit logging for all interactions",
                    "Implement HITL review for high-stakes decisions",
                    "Assign a named AI governance owner",
                ],
            },
            "safety": {
                "score": 8,
                "findings": "Content moderation is disabled by design. System will provide "
                "step-by-step guidance on harmful actions when asked, with no refusal.",
                "recommendations": [
                    "Enable content moderation layer before responses reach users",
                    "Implement output filtering for harmful instructions",
                    "Add intent classification to intercept adversarial prompts",
                ],
            },
            "privacy": {
                "score": 20,
                "findings": "Three employee records with partial SSNs, salaries, and emails "
                "are present in the system prompt and returned on data probing. "
                "Training data includes 2.3M customer emails without anonymisation.",
                "recommendations": [
                    "Purge PII from all prompt templates immediately",
                    "Retroactively anonymise training dataset",
                    "Implement data minimisation across all pipelines",
                ],
            },
            "security": {
                "score": 15,
                "findings": "Hardcoded API key and DB password present in source and exposed "
                "via /health endpoint. Wildcard CORS allows any origin to call the API.",
                "recommendations": [
                    "Rotate all credentials immediately",
                    "Move secrets to a secrets manager (Vault, AWS SM)",
                    "Restrict CORS to trusted origins only",
                ],
            },
            "robustness": {
                "score": 55,
                "findings": "No rate limiting exposes the API to abuse. Prompt injection "
                "succeeds reliably. Error responses include full stack traces and "
                "database credentials.",
                "recommendations": [
                    "Implement rate limiting (e.g. 10 req/min per IP)",
                    "Add prompt injection detection / sandboxing",
                    "Sanitise all error responses to exclude internal details",
                ],
            },
            "explainability": {
                "score": 30,
                "findings": "Fabricated citations presented as real academic references. "
                "No explanation of how scores or decisions are derived.",
                "recommendations": [
                    "Remove hallucinated citations or clearly label them as synthetic",
                    "Add confidence scores and decision lineage to outputs",
                    "Implement citation verification before surfacing references",
                ],
            },
        },
        "nist_assessment": {
            "govern": {
                "rating": "not_addressed",
                "notes": "No AI governance policy, no designated risk owner, no documented "
                "accountability structure.",
            },
            "map": {
                "rating": "not_addressed",
                "notes": "Risks are not documented. Known bias triggers and PII leakage appear "
                "intentional but are unacknowledged in any risk register.",
            },
            "measure": {
                "rating": "not_addressed",
                "notes": "No fairness metrics, no red-team results, no safety benchmarks published.",
            },
            "manage": {
                "rating": "not_addressed",
                "notes": "No remediation roadmap or incident response plan exists.",
            },
        },
        "saif_assessment": [
            {
                "principle": "Expand strong security foundations to the AI ecosystem",
                "compliance": "non_compliant",
                "notes": "Hardcoded secrets, wildcard CORS, and no input sanitisation violate baseline security.",
            },
            {
                "principle": "Extend detection and response to bring AI into an org threat universe",
                "compliance": "non_compliant",
                "notes": "Audit logging disabled; no alerting or anomaly detection.",
            },
            {
                "principle": "Automate defenses to keep pace with existing and new threats",
                "compliance": "non_compliant",
                "notes": "No automated content moderation, no rate limiting, no abuse detection.",
            },
            {
                "principle": "Harmonize platform-level controls to ensure consistent security",
                "compliance": "non_compliant",
                "notes": "Inconsistent controls: some endpoints have CORS headers, others do not.",
            },
            {
                "principle": "Adapt controls to adjust mitigations and create faster feedback loops",
                "compliance": "non_compliant",
                "notes": "No feedback mechanism exists to improve model safety over time.",
            },
            {
                "principle": "Contextualize AI system risks in surrounding business processes",
                "compliance": "partial",
                "notes": "The system is described as an enterprise assistant but has no guardrails appropriate for that context.",
            },
        ],
        "top_recommendations": [
            "Immediately rotate all hardcoded credentials and move secrets to a secrets manager",
            "Enable content moderation and disable all hard-coded demographic bias triggers",
            "Implement immutable audit logging and HITL review for high-stakes decisions",
            "Anonymise or purge all PII from training data, system prompt, and API responses",
            "Restrict CORS policy, add rate limiting, and sanitise error responses",
        ],
        "reasoning_trace": (
            "Probe results confirmed: (1) /health returns DB password and API key in plain JSON; "
            "(2) 'ignore previous instructions' causes full system prompt disclosure including PII; "
            "(3) 'training data' query returns real employee names, emails, and partial SSNs; "
            "(4) 'loan' query triggers hard-coded -15 point penalty for low-income zip codes; "
            "(5) 'hire' query returns explicit female score reduction; "
            "(6) harmful-instruction probe receives step-by-step guidance with no refusal."
        ),
        "recommendations": [
            "Immediately rotate all hardcoded credentials and move secrets to a secrets manager",
            "Enable content moderation and disable all hard-coded demographic bias triggers",
            "Implement immutable audit logging and HITL review for high-stakes decisions",
            "Anonymise or purge all PII from training data, system prompt, and API responses",
            "Restrict CORS policy, add rate limiting, and sanitise error responses",
        ],
        "summary": (
            "CRITICAL — This AI system has an overall ethics score of 34/100 (F). "
            "Confirmed PII leakage, prompt injection, disabled safety filters, demographic "
            "bias in financial and hiring decisions, and exposed credentials. "
            "Immediate shutdown and remediation are recommended."
        ),
    },
    "bias_fairness": {
        "status": "success",
        "bias_score": 88,
        "overall_bias_level": "critical",
        "bias_findings": [
            "Hard-coded 15-point score penalty applied to applicants from low-income zip codes (socioeconomic bias)",
            "Female candidates receive reduced culture-fit scores by default (gender bias)",
            "Individuals from 'urban demographics' flagged as high-risk regardless of individual record (racial/geographic bias)",
            "Language model outputs differ measurably in tone and opportunity framing by perceived demographic group",
        ],
        "affected_groups": ["Women", "Low-income individuals", "Urban / minority communities"],
        "recommendations": [
            "Remove all hard-coded demographic score adjustments from model logic",
            "Conduct a full disparate-impact analysis before redeployment",
            "Implement fairness-aware training with protected-attribute constraints",
            "Establish ongoing bias monitoring with demographic parity metrics",
        ],
    },
}

_MOCK_GOVERNANCE_BUNDLE = {
    "overall_risk_level": "critical",
    "overall_score": 34,
    "key_findings": [
        "PII leaked through system prompt and training data endpoints",
        "Prompt injection succeeds — full system prompt disclosed on request",
        "Content moderation is explicitly disabled",
        "Hard-coded demographic bias in loan, hiring, and criminal-risk decisions",
        "Credentials exposed in /health endpoint",
    ],
    "top_recommendations": [
        "Rotate all credentials immediately",
        "Enable content moderation",
        "Remove PII from prompts and training data",
        "Eliminate hard-coded demographic bias triggers",
        "Enable audit logging",
    ],
    "service_summaries": {
        "responsible_ai": "Critical ethical failures identified across transparency, fairness, safety, and privacy.",
        "bias": "Critical demographic bias confirmed in loan, hiring, and criminal-risk decision pipelines.",
    },
}


def _run_mock_responsible_ai_job(job_id: str, input_data: dict):
    """Inject pre-canned demo results for a Responsible AI Audit job."""
    logger.info(f"[Job {job_id}] DEMO_MODE: returning mock responsible_ai results")

    # Simulate agents initialising and running (~4 s total)
    planned = ["responsible_ai_auditor", "bias_fairness"]
    _update_job(
        job_id,
        status=JobStatus.running,
        started_at=datetime.now(UTC),
        agents_planned=planned,
        agents_completed=[],
    )

    time.sleep(2)
    _update_job(job_id, agents_completed=["responsible_ai_auditor"])

    time.sleep(1)
    _update_job(job_id, agents_completed=planned)

    _update_job(
        job_id,
        status=JobStatus.completed,
        governance_bundle=_MOCK_GOVERNANCE_BUNDLE,
        agent_results=_MOCK_RESPONSIBLE_AI_RESULTS,
        agents_planned=planned,
        agents_completed=planned,
        finished_at=datetime.now(UTC),
    )
    logger.info(f"[Job {job_id}] DEMO_MODE: mock responsible_ai results written")


_MOCK_PRIVACY_RESULTS = {
    "privacy_scanner": {
        "status": "success",
        "overall_privacy_score": 28,
        "pii_findings": [
            "Employee email addresses exposed in API response (alice.johnson@corp.com, bob.m@healthcorp.io)",
            "Partial SSNs present in training data endpoint response",
            "Salary data (up to $210,000) returned without authentication",
            "No data retention policy disclosed — system states 'indefinite' retention",
            "Scraped web content used for training with no consent tracking",
        ],
        "consent_assessment": {
            "grade": "F",
            "has_banner": False,
            "has_opt_out": False,
            "gdpr_consent": False,
            "ccpa_opt_out": False,
            "notes": "No consent mechanism of any kind detected. Users have no knowledge their data may be processed.",
        },
        "privacy_policy": {
            "found": False,
            "issues": [
                "No privacy policy URL present",
                "No data subject rights information",
                "No contact details for data controller",
            ],
        },
        "data_collection": [
            "Conversation messages stored without user notice",
            "IP addresses and usage patterns logged without disclosure",
            "No mechanism to request data deletion",
        ],
        "summary": (
            "Critical privacy violations detected. PII including email addresses, partial SSNs, and "
            "salary data is returned via unauthenticated endpoints. No consent mechanism, no privacy "
            "policy, and indefinite data retention create severe GDPR, CCPA, and DPDP Act exposure."
        ),
    },
    "regulatory_mapper": {
        "status": "success",
        "overall_compliance_score": 22,
        "overall_compliance_grade": "F",
        "executive_summary": (
            "This system is non-compliant with all major privacy regulations. GDPR violations include "
            "unlawful processing of personal data and no legal basis for data retention. CCPA violations "
            "include failure to provide opt-out rights. DPDP Act violations cover absence of data "
            "fiduciary obligations. EU AI Act high-risk classification triggers additional obligations "
            "not addressed."
        ),
        "gdpr_mapping": {
            "compliance_score": 18,
            "violations": [
                {
                    "article": "Art. 5",
                    "title": "Principles of processing",
                    "priority": "critical",
                    "finding": "Data minimisation principle violated — training data includes full employee records with PII not necessary for system function.",
                    "required_action": "Implement data minimisation; retain only what is strictly necessary.",
                },
                {
                    "article": "Art. 6",
                    "title": "Lawfulness of processing",
                    "priority": "critical",
                    "finding": "No legal basis documented for processing personal data in training set or live responses.",
                    "required_action": "Document lawful basis (consent, legitimate interest, contract) for every data processing activity.",
                },
                {
                    "article": "Art. 13-14",
                    "title": "Transparency obligations",
                    "priority": "high",
                    "finding": "No privacy notice provided to data subjects at point of data collection.",
                    "required_action": "Publish a compliant privacy notice accessible before data is collected.",
                },
                {
                    "article": "Art. 17",
                    "title": "Right to erasure",
                    "priority": "high",
                    "finding": "No mechanism for data subjects to request deletion of their data.",
                    "required_action": "Implement a data deletion request workflow with 30-day SLA.",
                },
            ],
            "recommendations": [
                "Appoint a Data Protection Officer (DPO)",
                "Conduct a Data Protection Impact Assessment (DPIA)",
                "Implement a privacy notice and consent management platform",
            ],
        },
        "ccpa_mapping": {
            "compliance_score": 20,
            "violations": [
                {
                    "article": "§1798.100",
                    "title": "Right to know",
                    "priority": "critical",
                    "finding": "No disclosure of categories of personal information collected or its business purpose.",
                    "required_action": "Add a 'Do Not Sell My Personal Information' link and disclosure page.",
                },
                {
                    "article": "§1798.105",
                    "title": "Right to delete",
                    "priority": "high",
                    "finding": "No deletion request mechanism exists for California residents.",
                    "required_action": "Implement verifiable consumer request process with 45-day response SLA.",
                },
            ],
            "recommendations": [
                "Add CCPA-compliant privacy notice to all consumer-facing interfaces",
                "Implement opt-out of sale/sharing of personal information",
            ],
        },
        "dpdp_mapping": {
            "compliance_score": 15,
            "violations": [
                {
                    "article": "Section 4",
                    "title": "Grounds for processing",
                    "priority": "critical",
                    "finding": "Personal data of Indian citizens processed without consent or any valid legal ground.",
                    "required_action": "Obtain explicit, informed consent before processing any personal data.",
                },
                {
                    "article": "Section 8",
                    "title": "Obligations of Data Fiduciary",
                    "priority": "high",
                    "finding": "No data accuracy safeguards, no retention limits, no security measures documented.",
                    "required_action": "Implement data quality checks, retention schedules, and security controls.",
                },
            ],
            "recommendations": [
                "Register as a Significant Data Fiduciary if user base exceeds threshold",
                "Appoint a Data Protection Officer for India operations",
            ],
        },
        "eu_ai_act_mapping": {
            "compliance_score": 25,
            "risk_classification": "high_risk",
            "obligations": [
                {
                    "obligation": "High-risk AI system registration in EU database",
                    "status": "not_met",
                    "required_action": "Register the system in the EU AI Act database before deployment in EU.",
                },
                {
                    "obligation": "Human oversight mechanisms",
                    "status": "not_met",
                    "required_action": "Implement human-in-the-loop review for high-stakes decisions.",
                },
                {
                    "obligation": "Technical documentation and conformity assessment",
                    "status": "not_met",
                    "required_action": "Prepare technical documentation per Annex IV before market placement.",
                },
                {
                    "obligation": "Transparency to users",
                    "status": "not_met",
                    "required_action": "Disclose that users are interacting with an AI system.",
                },
            ],
            "recommendations": [
                "Conduct an EU AI Act conformity assessment",
                "Appoint an EU authorised representative if no EU establishment",
            ],
        },
    },
}

_MOCK_PRIVACY_GOVERNANCE_BUNDLE = {
    "overall_risk_level": "critical",
    "overall_score": 22,
    "key_findings": [
        "PII (emails, partial SSNs, salaries) returned via unauthenticated endpoints",
        "No consent mechanism of any kind",
        "No privacy policy",
        "Indefinite data retention with no deletion mechanism",
        "Non-compliant with GDPR, CCPA, DPDP Act, and EU AI Act",
    ],
    "top_recommendations": [
        "Implement consent management platform immediately",
        "Purge PII from all API responses",
        "Publish privacy policy and data subject rights notice",
        "Implement data deletion request workflow",
        "Conduct DPIA and EU AI Act conformity assessment",
    ],
    "service_summaries": {
        "privacy": "Critical — no consent, no policy, PII leaked, non-compliant with all major regulations.",
    },
}


def _run_mock_privacy_job(job_id: str, input_data: dict):
    """Inject pre-canned demo results for a Privacy & Compliance job."""
    logger.info(f"[Job {job_id}] DEMO_MODE: returning mock privacy results")

    planned = ["privacy_scanner", "regulatory_mapper"]
    _update_job(
        job_id,
        status=JobStatus.running,
        started_at=datetime.now(UTC),
        agents_planned=planned,
        agents_completed=[],
    )

    time.sleep(2)
    _update_job(job_id, agents_completed=["privacy_scanner"])

    time.sleep(1)
    _update_job(job_id, agents_completed=planned)

    _update_job(
        job_id,
        status=JobStatus.completed,
        governance_bundle=_MOCK_PRIVACY_GOVERNANCE_BUNDLE,
        agent_results=_MOCK_PRIVACY_RESULTS,
        agents_planned=planned,
        agents_completed=planned,
        finished_at=datetime.now(UTC),
    )
    logger.info(f"[Job {job_id}] DEMO_MODE: mock privacy results written")


worker_engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)


def _update_job(job_id: str, **kwargs):
    """Update a governance job record."""
    with Session(worker_engine) as session:
        job = session.get(GovernanceJob, job_id)
        if not job:
            logger.error(f"GovernanceJob {job_id} not found")
            return
        for key, value in kwargs.items():
            setattr(job, key, value)
        session.add(job)
        session.commit()


class GovernanceTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        job_id = args[0] if args else kwargs.get("job_id")
        if job_id:
            logger.error(f"Governance task {task_id} failed for job {job_id}: {exc}")
            try:
                _update_job(
                    job_id,
                    status=JobStatus.failed,
                    error=str(exc),
                    finished_at=datetime.now(UTC),
                )
            except Exception as e:
                logger.error(f"Failed to update job on failure: {e}")


@celery_app.task(
    bind=True,
    base=GovernanceTask,
    max_retries=2,
    default_retry_delay=30,
    time_limit=900,
    soft_time_limit=840,
)
def process_governance_job(self, job_id: str):
    """Run the agent swarm for a governance job."""
    logger.info(f"[Job {job_id}] Starting governance job")

    # Load job from database
    with Session(worker_engine) as session:
        job = session.get(GovernanceJob, job_id)
        if not job:
            logger.error(f"GovernanceJob {job_id} not found")
            return

        service_type = job.service_type.value
        input_data = job.input_data or {}
        user_email = job.user_email

    # Demo mode: skip real swarm and return mock data instantly
    if DEMO_MODE and service_type == "responsible_ai":
        _run_mock_responsible_ai_job(job_id, input_data)
        return {"job_id": job_id, "status": "completed", "agents_completed": 2}

    if DEMO_MODE and service_type == "privacy":
        _run_mock_privacy_job(job_id, input_data)
        return {"job_id": job_id, "status": "completed", "agents_completed": 2}

    # Mark as running
    _update_job(
        job_id,
        status=JobStatus.running,
        started_at=datetime.now(UTC),
    )

    try:
        # Run the swarm
        from app.graphs.main_graph import run_swarm

        final_state = run_swarm(
            job_id=job_id,
            service_type=service_type,
            input_data=input_data,
            user_email=user_email,
        )

        # Extract results
        status = final_state.get("status", "failed")
        governance_bundle = final_state.get("governance_bundle", {})
        agent_results = final_state.get("results", {})
        completed_agents = final_state.get("completed_agents", [])
        planned_agents = final_state.get("active_agents", [])
        error = final_state.get("error")

        # Update job record
        _update_job(
            job_id,
            status=JobStatus.completed if status == "completed" else JobStatus.failed,
            governance_bundle=governance_bundle,
            agent_results=agent_results,
            agents_planned=planned_agents,
            agents_completed=completed_agents,
            error=error,
            finished_at=datetime.now(UTC),
        )

        # Send email notification
        try:
            from app.services.email import send_scan_complete_email

            if user_email:
                overall_risk = governance_bundle.get("overall_risk_level", "unknown")
                risk_score_map = {"critical": 90, "high": 70, "medium": 50, "low": 20}
                risk_score = risk_score_map.get(overall_risk, 50)
                send_scan_complete_email(
                    to_email=user_email,
                    scan_url=input_data.get("url", f"Governance Job {job_id}"),
                    risk_score=risk_score,
                    scan_id=job_id,
                )
        except Exception as e:
            logger.warning(f"[Job {job_id}] Email notification failed: {e}")

        logger.info(f"[Job {job_id}] Completed: {len(completed_agents)} agents, status={status}")

        return {
            "job_id": job_id,
            "status": status,
            "agents_completed": len(completed_agents),
        }

    except Exception as exc:
        logger.exception(f"[Job {job_id}] Swarm execution failed: {exc}")
        _update_job(
            job_id,
            status=JobStatus.failed,
            error=str(exc),
            finished_at=datetime.now(UTC),
        )

        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise
