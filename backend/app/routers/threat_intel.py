"""
AI Threat Intelligence Service API
Agents: Threat Pattern Agent, Predictive Risk Agent
Special: Can test user's own AI system with safe probes (requires explicit consent).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from app.agents.messaging import read_events
from app.core.database import get_session
from app.dependencies import get_current_user
from app.models.audit import GovernanceJob, ServiceType
from app.routers._service_helpers import create_and_dispatch_job, get_user_job, job_to_base
from app.schemas.services import ServiceJobBase, ThreatIntelRequest, ThreatIntelResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/services/threat-intel", tags=["threat-intelligence"])


@router.post("/analyze", response_model=ServiceJobBase)
async def analyze_threats(
    body: ThreatIntelRequest,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Analyse content or an AI system for security threats.

    Provide text content for analysis, or supply an API endpoint (with auth and
    explicit consent) to let the swarm run safe test attacks against your AI system.

    The Threat Pattern Agent searches the MITRE ATLAS knowledge base and optionally
    probes your system. The Predictive Risk Agent then forecasts risk and suggests fixes.
    """
    user_email = user.get("email", "")

    if body.api_endpoint and not body.ai_system_consent:
        raise HTTPException(
            status_code=400,
            detail="Explicit consent (ai_system_consent=true) is required to test an external AI system.",
        )

    input_data = {}
    if body.content:
        input_data["content"] = body.content
    if body.ai_system_description:
        input_data["ai_system_description"] = body.ai_system_description
    if body.api_endpoint:
        input_data["api_endpoint"] = body.api_endpoint
    if body.ai_system_auth:
        input_data["ai_system_auth"] = body.ai_system_auth
    if body.ai_system_consent:
        input_data["ai_system_consent"] = True

    job = create_and_dispatch_job(
        session=session,
        user_email=user_email,
        service_type=ServiceType.threat_intel,
        input_data=input_data,
    )
    return job_to_base(job)


@router.get("", response_model=list[ServiceJobBase])
async def list_threat_intel_jobs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """List all threat intelligence jobs for the current user."""
    user_email = user.get("email", "")
    jobs = session.exec(
        select(GovernanceJob)
        .where(GovernanceJob.user_email == user_email)
        .where(GovernanceJob.service_type == ServiceType.threat_intel)
        .order_by(GovernanceJob.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).all()
    return [job_to_base(j) for j in jobs]


@router.get("/{job_id}", response_model=ThreatIntelResult)
async def get_threat_intel_result(
    job_id: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get full results for a threat intelligence job.

    Includes MITRE ATLAS mappings, risk scores, and mitigation recommendations.
    """
    user_email = user.get("email", "")
    job = get_user_job(session, job_id, user_email, ServiceType.threat_intel)

    bundle = job.governance_bundle or {}
    agent_results = job.agent_results or {}
    predictive = agent_results.get("predictive_risk", {})
    threat = agent_results.get("threat_pattern", {})

    return ThreatIntelResult(
        job_id=job.id,
        service_type=job.service_type.value,
        status=job.status.value,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        agents_planned=job.agents_planned,
        agents_completed=job.agents_completed,
        error=job.error,
        governance_bundle=bundle,
        agent_results=agent_results,
        input_data=job.input_data,
        risk_score=predictive.get("risk_score") or threat.get("overall_threat_level"),
        threats_found=len(threat.get("identified_threats", [])),
    )


@router.get("/{job_id}/events")
async def get_threat_intel_events(
    job_id: str,
    last_id: str = Query(default="0-0"),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Stream real-time agent events for a threat intelligence job (poll-based)."""
    user_email = user.get("email", "")
    get_user_job(session, job_id, user_email, ServiceType.threat_intel)
    events = read_events(job_id, last_id=last_id)
    return {"job_id": job_id, "events": events, "count": len(events)}


@router.get("/{job_id}/agent/{agent_name}")
async def get_threat_intel_agent_result(
    job_id: str,
    agent_name: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get result from a specific agent in the threat intelligence pipeline.

    Valid agent names: threat_pattern, predictive_risk
    """
    user_email = user.get("email", "")
    job = get_user_job(session, job_id, user_email, ServiceType.threat_intel)
    agent_results = job.agent_results or {}
    if agent_name not in agent_results:
        raise HTTPException(
            status_code=404,
            detail=f"No results for agent '{agent_name}'. Completed: {job.agents_completed or []}",
        )
    return {"job_id": job.id, "agent_name": agent_name, "result": agent_results[agent_name]}
