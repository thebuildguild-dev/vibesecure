"""
Responsible AI Frameworks Service API
Agents: Responsible AI Auditor Agent, Bias & Fairness Agent
Evaluates AI against NIST AI RMF and Google SAIF, detects bias.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from app.agents.messaging import read_events
from app.core.database import get_session
from app.dependencies import get_current_user
from app.models.audit import GovernanceJob, ServiceType
from app.routers._service_helpers import create_and_dispatch_job, get_user_job, job_to_base
from app.schemas.services import ResponsibleAIRequest, ResponsibleAIResult, ServiceJobBase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/services/responsible-ai", tags=["responsible-ai"])


@router.post("/audit", response_model=ServiceJobBase)
async def audit_ai_system(
    body: ResponsibleAIRequest,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Audit AI-generated content or an AI system against ethical frameworks.

    The Responsible AI Auditor evaluates against NIST AI RMF (GOVERN, MAP,
    MEASURE, MANAGE) and Google SAIF. The Bias & Fairness Agent checks for
    gender, racial, age, socioeconomic, geographic, disability, language,
    and cultural bias. Returns a unified scorecard.
    """
    user_email = user.get("email", "")

    input_data = {}
    if body.content:
        input_data["content"] = body.content
    if body.ai_system_description:
        input_data["ai_system_description"] = body.ai_system_description
    if body.url:
        input_data["url"] = body.url

    job = create_and_dispatch_job(
        session=session,
        user_email=user_email,
        service_type=ServiceType.responsible_ai,
        input_data=input_data,
    )
    return job_to_base(job)


@router.get("", response_model=list[ServiceJobBase])
async def list_responsible_ai_jobs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """List all responsible AI audit jobs for the current user."""
    user_email = user.get("email", "")
    jobs = session.exec(
        select(GovernanceJob)
        .where(GovernanceJob.user_email == user_email)
        .where(GovernanceJob.service_type == ServiceType.responsible_ai)
        .order_by(GovernanceJob.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).all()
    return [job_to_base(j) for j in jobs]


@router.get("/{job_id}", response_model=ResponsibleAIResult)
async def get_responsible_ai_result(
    job_id: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get full results for a responsible AI audit job.

    Includes NIST assessment, SAIF assessment, bias analysis, and overall scorecard.
    """
    user_email = user.get("email", "")
    job = get_user_job(session, job_id, user_email, ServiceType.responsible_ai)

    bundle = job.governance_bundle or {}
    agent_results = job.agent_results or {}
    auditor = agent_results.get("responsible_ai_auditor", {})

    return ResponsibleAIResult(
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
        overall_grade=auditor.get("overall_grade"),
        scorecard=auditor.get("scorecard"),
    )


@router.get("/{job_id}/events")
async def get_responsible_ai_events(
    job_id: str,
    last_id: str = Query(default="0-0"),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Stream real-time agent events for a responsible AI job (poll-based)."""
    user_email = user.get("email", "")
    get_user_job(session, job_id, user_email, ServiceType.responsible_ai)
    events = read_events(job_id, last_id=last_id)
    return {"job_id": job_id, "events": events, "count": len(events)}


@router.get("/{job_id}/agent/{agent_name}")
async def get_responsible_ai_agent_result(
    job_id: str,
    agent_name: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get result from a specific agent in the responsible AI pipeline.

    Valid agent names: responsible_ai_auditor, bias_fairness
    """
    user_email = user.get("email", "")
    job = get_user_job(session, job_id, user_email, ServiceType.responsible_ai)
    agent_results = job.agent_results or {}
    if agent_name not in agent_results:
        raise HTTPException(
            status_code=404,
            detail=f"No results for agent '{agent_name}'. Completed: {job.agents_completed or []}",
        )
    return {"job_id": job.id, "agent_name": agent_name, "result": agent_results[agent_name]}
