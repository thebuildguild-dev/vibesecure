"""
Digital Asset Governance Service API
Agents: Digital Asset Governance Agent (+ optional Privacy Scanner)
Owner-verified website security scanning via Playwright, OWASP ZAP, and 8+ checkers.
"""

import logging
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from app.agents.messaging import read_events
from app.core.database import get_session
from app.dependencies import get_current_user
from app.models.audit import GovernanceJob, ServiceType
from app.models.domain import DomainVerification
from app.routers._service_helpers import create_and_dispatch_job, get_user_job, job_to_base
from app.schemas.services import DigitalAssetResult, DigitalAssetScanRequest, ServiceJobBase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/services/digital-asset", tags=["digital-asset-governance"])


@router.post("/scan", response_model=ServiceJobBase)
async def scan_digital_asset(
    body: DigitalAssetScanRequest,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Run a full security scan on your verified website.

    Requires prior domain verification via POST /api/domains/verify/request.
    Checks security headers, TLS, CORS, cookies, exposed endpoints, frontend
    library vulnerabilities. If allow_active=true in scan_options and active
    consent is granted, also runs OWASP ZAP baseline scan.

    Set scan_options.run_privacy=true to trigger the Privacy Scanner Agent
    for consent banner and PII analysis.
    """
    user_email = user.get("email", "")

    parsed = urlparse(body.url)
    domain = parsed.hostname or ""

    # Verify domain ownership before dispatching
    verification = session.exec(
        select(DomainVerification)
        .where(DomainVerification.domain == domain)
        .where(DomainVerification.user_email == user_email)
        .where(DomainVerification.verified == True)
    ).first()

    if not verification:
        raise HTTPException(
            status_code=403,
            detail=f"Domain '{domain}' is not verified. "
            "Use POST /api/domains/verify/request to prove ownership first.",
        )

    input_data = {"url": body.url}
    if body.scan_options:
        input_data["scan_options"] = body.scan_options

    job = create_and_dispatch_job(
        session=session,
        user_email=user_email,
        service_type=ServiceType.digital_asset,
        input_data=input_data,
    )
    return job_to_base(job)


@router.get("", response_model=list[ServiceJobBase])
async def list_digital_asset_jobs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """List all digital asset governance jobs for the current user."""
    user_email = user.get("email", "")
    jobs = session.exec(
        select(GovernanceJob)
        .where(GovernanceJob.user_email == user_email)
        .where(GovernanceJob.service_type == ServiceType.digital_asset)
        .order_by(GovernanceJob.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).all()
    return [job_to_base(j) for j in jobs]


@router.get("/{job_id}", response_model=DigitalAssetResult)
async def get_digital_asset_result(
    job_id: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get full results for a digital asset governance job.

    Includes findings, severity breakdown, risk score, and platform-specific
    security configuration fixes (Vercel, Netlify, Nginx, Apache).
    """
    user_email = user.get("email", "")
    job = get_user_job(session, job_id, user_email, ServiceType.digital_asset)

    bundle = job.governance_bundle or {}
    agent_results = job.agent_results or {}
    da = agent_results.get("digital_asset_governance", {})

    return DigitalAssetResult(
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
        risk_score=da.get("risk_score"),
        findings_count=da.get("findings_count"),
        severity_counts=da.get("severity_counts"),
    )


@router.get("/{job_id}/events")
async def get_digital_asset_events(
    job_id: str,
    last_id: str = Query(default="0-0"),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Stream real-time agent events for a digital asset job (poll-based)."""
    user_email = user.get("email", "")
    get_user_job(session, job_id, user_email, ServiceType.digital_asset)
    events = read_events(job_id, last_id=last_id)
    return {"job_id": job_id, "events": events, "count": len(events)}


@router.get("/{job_id}/agent/{agent_name}")
async def get_digital_asset_agent_result(
    job_id: str,
    agent_name: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get result from a specific agent in the digital asset pipeline.

    Valid agent names: digital_asset_governance, privacy_scanner (if cross-scan triggered)
    """
    user_email = user.get("email", "")
    job = get_user_job(session, job_id, user_email, ServiceType.digital_asset)
    agent_results = job.agent_results or {}
    if agent_name not in agent_results:
        raise HTTPException(
            status_code=404,
            detail=f"No results for agent '{agent_name}'. Completed: {job.agents_completed or []}",
        )
    return {"job_id": job.id, "agent_name": agent_name, "result": agent_results[agent_name]}
