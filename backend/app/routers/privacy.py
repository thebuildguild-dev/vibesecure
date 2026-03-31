"""
Data Privacy & Regulatory Compliance Service API
Agents: Privacy Scanner Agent, Regulatory Mapper Agent
Detects PII, consent issues, and maps findings to GDPR/CCPA/DPDP/EU AI Act.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from app.agents.messaging import read_events
from app.core.database import get_session
from app.dependencies import get_current_user
from app.models.audit import GovernanceJob, ServiceType
from app.routers._service_helpers import create_and_dispatch_job, get_user_job, job_to_base
from app.schemas.services import PrivacyScanRequest, PrivacyScanResult, ServiceJobBase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/services/privacy", tags=["privacy-compliance"])


@router.post("/scan", response_model=ServiceJobBase)
async def scan_privacy(
    body: PrivacyScanRequest,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Scan a website or text for PII exposure and privacy compliance issues.

    The Privacy Scanner uses Gemini vision to detect PII (names, emails, phone
    numbers, faces), analyse consent banners, and review privacy policies.
    The Regulatory Mapper then maps every finding to specific GDPR, CCPA,
    DPDP Act, and EU AI Act articles.
    """
    user_email = user.get("email", "")

    input_data = {}
    if body.url:
        input_data["url"] = body.url
    if body.content:
        input_data["content"] = body.content

    job = create_and_dispatch_job(
        session=session,
        user_email=user_email,
        service_type=ServiceType.privacy,
        input_data=input_data,
    )
    return job_to_base(job)


@router.get("", response_model=list[ServiceJobBase])
async def list_privacy_jobs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """List all privacy scan jobs for the current user."""
    user_email = user.get("email", "")
    jobs = session.exec(
        select(GovernanceJob)
        .where(GovernanceJob.user_email == user_email)
        .where(GovernanceJob.service_type == ServiceType.privacy)
        .order_by(GovernanceJob.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).all()
    return [job_to_base(j) for j in jobs]


@router.get("/{job_id}", response_model=PrivacyScanResult)
async def get_privacy_result(
    job_id: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get full results for a privacy scan job.

    Includes PII findings, consent assessment, privacy policy analysis,
    and regulatory compliance mapping with exact law references.
    """
    user_email = user.get("email", "")
    job = get_user_job(session, job_id, user_email, ServiceType.privacy)

    bundle = job.governance_bundle or {}
    agent_results = job.agent_results or {}
    privacy = agent_results.get("privacy_scanner", {})
    mapper = agent_results.get("regulatory_mapper", {})

    mapped_regs = []
    if mapper.get("gdpr_mapping"):
        mapped_regs.append("GDPR")
    if mapper.get("ccpa_mapping"):
        mapped_regs.append("CCPA")
    if mapper.get("dpdp_mapping"):
        mapped_regs.append("DPDP")
    if mapper.get("eu_ai_act_mapping"):
        mapped_regs.append("EU AI Act")

    return PrivacyScanResult(
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
        overall_privacy_score=privacy.get("overall_privacy_score"),
        regulations_mapped=mapped_regs or None,
    )


@router.get("/{job_id}/events")
async def get_privacy_events(
    job_id: str,
    last_id: str = Query(default="0-0"),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Stream real-time agent events for a privacy scan job (poll-based)."""
    user_email = user.get("email", "")
    get_user_job(session, job_id, user_email, ServiceType.privacy)
    events = read_events(job_id, last_id=last_id)
    return {"job_id": job_id, "events": events, "count": len(events)}


@router.get("/{job_id}/agent/{agent_name}")
async def get_privacy_agent_result(
    job_id: str,
    agent_name: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get result from a specific agent in the privacy pipeline.

    Valid agent names: privacy_scanner, regulatory_mapper
    """
    user_email = user.get("email", "")
    job = get_user_job(session, job_id, user_email, ServiceType.privacy)
    agent_results = job.agent_results or {}
    if agent_name not in agent_results:
        raise HTTPException(
            status_code=404,
            detail=f"No results for agent '{agent_name}'. Completed: {job.agents_completed or []}",
        )
    return {"job_id": job.id, "agent_name": agent_name, "result": agent_results[agent_name]}
