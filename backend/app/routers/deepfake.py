"""
Deepfake Detection Service API
Agents: Keyframe Extractor, Deepfake Triage, Forensic Artifact, Ensemble Voter
"""

import logging
import os
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlmodel import Session, select

from app.agents.messaging import read_events
from app.core.database import get_session
from app.dependencies import get_current_user
from app.models.audit import GovernanceJob, ServiceType
from app.routers._service_helpers import create_and_dispatch_job, get_user_job, job_to_base
from app.schemas.services import DeepfakeAnalyzeRequest, DeepfakeResult, ServiceJobBase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/services/deepfake", tags=["deepfake-detection"])

UPLOAD_DIR = "uploads/governance"
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
ALLOWED_VIDEO_TYPES = {"video/mp4", "video/webm", "video/quicktime", "video/x-msvideo"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


@router.post("/upload", response_model=ServiceJobBase)
async def analyze_media_upload(
    file: UploadFile = File(...),
    content: str | None = Form(default=None),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Upload a photo or video for deepfake analysis.

    Accepts JPEG, PNG, WebP, GIF images and MP4, WebM, MOV, AVI videos (max 100 MB).
    The agent swarm will extract keyframes, run triage, forensic analysis, and ensemble voting.
    """
    user_email = user.get("email", "")

    if (
        file.content_type not in ALLOWED_IMAGE_TYPES
        and file.content_type not in ALLOWED_VIDEO_TYPES
    ):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file.content_type}. "
            "Allowed: images (JPEG, PNG, WebP, GIF) and videos (MP4, WebM, MOV, AVI)",
        )

    file_type = "image" if file.content_type in ALLOWED_IMAGE_TYPES else "video"

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
                raise HTTPException(status_code=413, detail="File too large (max 100 MB)")
            f.write(chunk)

    input_data = {
        "file_path": file_path,
        "file_type": file_type,
        "file_name": file.filename,
    }
    if content:
        input_data["content"] = content

    job = create_and_dispatch_job(
        session=session,
        user_email=user_email,
        service_type=ServiceType.deepfake,
        input_data=input_data,
        file_path=file_path,
        file_type=file_type,
    )
    return job_to_base(job)


@router.post("/analyze", response_model=ServiceJobBase)
async def analyze_media_url(
    body: DeepfakeAnalyzeRequest,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Analyse media at a public URL for deepfake indicators.

    Provide a direct link to an image or video. The swarm will download, extract
    keyframes, and run the full deepfake detection pipeline.
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
        service_type=ServiceType.deepfake,
        input_data=input_data,
    )
    return job_to_base(job)


@router.get("", response_model=list[ServiceJobBase])
async def list_deepfake_jobs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """List all deepfake detection jobs for the current user."""
    user_email = user.get("email", "")
    jobs = session.exec(
        select(GovernanceJob)
        .where(GovernanceJob.user_email == user_email)
        .where(GovernanceJob.service_type == ServiceType.deepfake)
        .order_by(GovernanceJob.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).all()
    return [job_to_base(j) for j in jobs]


@router.get("/{job_id}", response_model=DeepfakeResult)
async def get_deepfake_result(
    job_id: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get full results for a deepfake detection job.

    Includes per-agent results, confidence score, verdict, and heatmap data.
    """
    user_email = user.get("email", "")
    job = get_user_job(session, job_id, user_email, ServiceType.deepfake)

    bundle = job.governance_bundle or {}
    agent_results = job.agent_results or {}
    ensemble = agent_results.get("ensemble_voter", {})

    return DeepfakeResult(
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
        confidence_score=ensemble.get("confidence_score"),
        verdict=ensemble.get("final_verdict"),
        frames_analyzed=agent_results.get("keyframe_extractor", {}).get("frames_extracted"),
    )


@router.get("/{job_id}/events")
async def get_deepfake_events(
    job_id: str,
    last_id: str = Query(default="0-0"),
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Stream real-time agent events for a deepfake job (poll-based)."""
    user_email = user.get("email", "")
    get_user_job(session, job_id, user_email, ServiceType.deepfake)
    events = read_events(job_id, last_id=last_id)
    return {"job_id": job_id, "events": events, "count": len(events)}


@router.get("/{job_id}/agent/{agent_name}")
async def get_deepfake_agent_result(
    job_id: str,
    agent_name: str,
    user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Get result from a specific agent in the deepfake pipeline.

    Valid agent names: keyframe_extractor, deepfake_triage, forensic_artifact, ensemble_voter
    """
    user_email = user.get("email", "")
    job = get_user_job(session, job_id, user_email, ServiceType.deepfake)
    agent_results = job.agent_results or {}
    if agent_name not in agent_results:
        raise HTTPException(
            status_code=404,
            detail=f"No results for agent '{agent_name}'. Completed: {job.agents_completed or []}",
        )
    return {"job_id": job.id, "agent_name": agent_name, "result": agent_results[agent_name]}
