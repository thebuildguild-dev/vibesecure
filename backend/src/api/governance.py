"""
Governance API - endpoints for the agent swarm system.
Handles job creation, status tracking, file uploads, and result retrieval.
"""

import logging
import os
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse
from sqlmodel import Session, select

from src.agents.messaging import read_events
from src.auth.dependencies import get_current_user
from src.core.database import get_session
from src.core.models import (
    GovernanceJob,
    GovernanceJobCreate,
    GovernanceJobDetail,
    GovernanceJobRead,
    JobStatus,
    ServiceType,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/governance", tags=["governance"])

UPLOAD_DIR = "uploads/governance"
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
ALLOWED_VIDEO_TYPES = {"video/mp4", "video/webm", "video/quicktime", "video/x-msvideo"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB


@router.post("", response_model=GovernanceJobRead)
async def create_governance_job(
    job_data: GovernanceJobCreate,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Create a new governance job and dispatch it to the agent swarm."""
    user_email = user.get("email", "")

    # Build input_data for the swarm
    input_data = {}
    if job_data.url:
        input_data["url"] = job_data.url
    if job_data.content:
        input_data["content"] = job_data.content
    if job_data.ai_system_description:
        input_data["ai_system_description"] = job_data.ai_system_description
    if job_data.api_endpoint:
        input_data["api_endpoint"] = job_data.api_endpoint
    if job_data.ai_system_auth:
        input_data["ai_system_auth"] = job_data.ai_system_auth
    if job_data.ai_system_consent:
        input_data["ai_system_consent"] = True
    if job_data.scan_options:
        input_data["scan_options"] = job_data.scan_options

    # Validate: at least some input is provided
    if not input_data:
        raise HTTPException(
            status_code=400,
            detail="At least one input is required: url, content, ai_system_description, or api_endpoint",
        )

    # Create job record
    job = GovernanceJob(
        user_email=user_email,
        service_type=job_data.service_type,
        input_data=input_data,
        status=JobStatus.pending,
    )
    session.add(job)
    session.commit()
    session.refresh(job)

    # Dispatch to Celery
    from src.worker.governance_tasks import process_governance_job

    task = process_governance_job.delay(job.id)

    job.celery_task_id = task.id
    session.add(job)
    session.commit()
    session.refresh(job)

    return GovernanceJobRead(
        id=job.id,
        service_type=job.service_type,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        agents_planned=job.agents_planned,
        agents_completed=job.agents_completed,
        error=job.error,
    )


@router.post("/upload", response_model=GovernanceJobRead)
async def create_governance_job_with_upload(
    file: UploadFile = File(...),
    service_type: str = Form(default="deepfake"),
    content: str | None = Form(default=None),
    ai_system_description: str | None = Form(default=None),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Create a governance job with file upload (for deepfake detection)."""
    user_email = user.get("email", "")

    # Validate file
    if (
        file.content_type not in ALLOWED_IMAGE_TYPES
        and file.content_type not in ALLOWED_VIDEO_TYPES
    ):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file.content_type}. Allowed: images (JPEG, PNG, WebP, GIF) and videos (MP4, WebM, MOV, AVI)",
        )

    # Determine file type
    if file.content_type in ALLOWED_IMAGE_TYPES:
        file_type = "image"
    else:
        file_type = "video"

    # Save file
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file_ext = os.path.splitext(file.filename or "upload")[1] or ".bin"
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}{file_ext}")

    total_size = 0
    with open(file_path, "wb") as f:
        while chunk := await file.read(8192):
            total_size += len(chunk)
            if total_size > MAX_FILE_SIZE:
                os.remove(file_path)
                raise HTTPException(status_code=413, detail="File too large (max 100MB)")
            f.write(chunk)

    # Build input
    input_data = {
        "file_path": file_path,
        "file_type": file_type,
        "file_name": file.filename,
    }
    if content:
        input_data["content"] = content
    if ai_system_description:
        input_data["ai_system_description"] = ai_system_description

    try:
        svc = ServiceType(service_type)
    except ValueError:
        svc = ServiceType.deepfake

    job = GovernanceJob(
        user_email=user_email,
        service_type=svc,
        input_data=input_data,
        status=JobStatus.pending,
        file_path=file_path,
        file_type=file_type,
    )
    session.add(job)
    session.commit()
    session.refresh(job)

    from src.worker.governance_tasks import process_governance_job

    task = process_governance_job.delay(job.id)

    job.celery_task_id = task.id
    session.add(job)
    session.commit()
    session.refresh(job)

    return GovernanceJobRead(
        id=job.id,
        service_type=job.service_type,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        agents_planned=job.agents_planned,
        agents_completed=job.agents_completed,
        error=job.error,
    )


@router.get("", response_model=list[GovernanceJobRead])
async def list_governance_jobs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    service_type: str | None = Query(default=None),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """List all governance jobs for the authenticated user."""
    user_email = user.get("email", "")

    query = (
        select(GovernanceJob)
        .where(GovernanceJob.user_email == user_email)
        .order_by(GovernanceJob.created_at.desc())
    )

    if service_type:
        try:
            svc = ServiceType(service_type)
            query = query.where(GovernanceJob.service_type == svc)
        except ValueError:
            pass

    query = query.offset(skip).limit(limit)
    jobs = session.exec(query).all()

    return [
        GovernanceJobRead(
            id=j.id,
            service_type=j.service_type,
            status=j.status,
            created_at=j.created_at,
            started_at=j.started_at,
            finished_at=j.finished_at,
            agents_planned=j.agents_planned,
            agents_completed=j.agents_completed,
            error=j.error,
        )
        for j in jobs
    ]


@router.get("/{job_id}", response_model=GovernanceJobDetail)
async def get_governance_job(
    job_id: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get full details of a governance job including agent results."""
    user_email = user.get("email", "")

    job = session.get(GovernanceJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.user_email != user_email:
        raise HTTPException(status_code=403, detail="Not authorized to view this job")

    return GovernanceJobDetail(
        id=job.id,
        service_type=job.service_type,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        agents_planned=job.agents_planned,
        agents_completed=job.agents_completed,
        error=job.error,
        governance_bundle=job.governance_bundle,
        agent_results=job.agent_results,
        input_data=job.input_data,
    )


@router.get("/{job_id}/events")
async def get_job_events(
    job_id: str,
    last_id: str = Query(default="0-0"),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get real-time agent events for a job via Redis Streams."""
    user_email = user.get("email", "")

    job = session.get(GovernanceJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.user_email != user_email:
        raise HTTPException(status_code=403, detail="Not authorized")

    events = read_events(job_id, last_id=last_id)

    return {
        "job_id": job_id,
        "events": events,
        "count": len(events),
    }


@router.get("/{job_id}/bundle")
async def get_governance_bundle(
    job_id: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get the final governance bundle for a completed job."""
    user_email = user.get("email", "")

    job = session.get(GovernanceJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.user_email != user_email:
        raise HTTPException(status_code=403, detail="Not authorized")

    if job.status != JobStatus.completed:
        raise HTTPException(
            status_code=400,
            detail=f"Job is not completed yet. Current status: {job.status.value}",
        )

    return JSONResponse(
        content={
            "job_id": job.id,
            "service_type": job.service_type.value,
            "governance_bundle": job.governance_bundle or {},
            "agents_completed": job.agents_completed or [],
            "completed_at": job.finished_at.isoformat() if job.finished_at else None,
        }
    )


@router.get("/{job_id}/agent/{agent_name}")
async def get_agent_result(
    job_id: str,
    agent_name: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get results from a specific agent for a job."""
    user_email = user.get("email", "")

    job = session.get(GovernanceJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.user_email != user_email:
        raise HTTPException(status_code=403, detail="Not authorized")

    agent_results = job.agent_results or {}
    if agent_name not in agent_results:
        raise HTTPException(
            status_code=404,
            detail=f"No results found for agent '{agent_name}'. Completed agents: {job.agents_completed or []}",
        )

    return JSONResponse(
        content={
            "job_id": job.id,
            "agent_name": agent_name,
            "result": agent_results[agent_name],
        }
    )
