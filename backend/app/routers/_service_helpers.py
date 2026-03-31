"""
Shared helpers for service routers.
All 5 services use the same GovernanceJob + Celery dispatch pattern.
"""

import logging

from fastapi import HTTPException
from sqlmodel import Session

from app.models.audit import GovernanceJob, JobStatus, ServiceType
from app.schemas.services import ServiceJobBase

logger = logging.getLogger(__name__)


def create_and_dispatch_job(
    session: Session,
    user_email: str,
    service_type: ServiceType,
    input_data: dict,
    file_path: str | None = None,
    file_type: str | None = None,
) -> GovernanceJob:
    """Create a GovernanceJob, dispatch to Celery, and return the job record."""
    if not input_data:
        raise HTTPException(
            status_code=400,
            detail="At least one input field is required.",
        )

    job = GovernanceJob(
        user_email=user_email,
        service_type=service_type,
        input_data=input_data,
        status=JobStatus.pending,
        file_path=file_path,
        file_type=file_type,
    )
    session.add(job)
    session.commit()
    session.refresh(job)

    from app.worker.governance_tasks import process_governance_job

    task = process_governance_job.delay(job.id)

    job.celery_task_id = task.id
    session.add(job)
    session.commit()
    session.refresh(job)

    return job


def job_to_base(job: GovernanceJob) -> ServiceJobBase:
    """Convert a GovernanceJob to the shared base response."""
    return ServiceJobBase(
        job_id=job.id,
        service_type=job.service_type.value,
        status=job.status.value,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        agents_planned=job.agents_planned,
        agents_completed=job.agents_completed,
        error=job.error,
    )


def get_user_job(
    session: Session,
    job_id: str,
    user_email: str,
    service_type: ServiceType | None = None,
) -> GovernanceJob:
    """Fetch a job with ownership + optional service_type check."""
    job = session.get(GovernanceJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.user_email != user_email:
        raise HTTPException(status_code=403, detail="Not authorized to view this job")
    if service_type and job.service_type != service_type:
        raise HTTPException(
            status_code=404,
            detail=f"Job {job_id} is not a {service_type.value} job",
        )
    return job
