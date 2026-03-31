"""
Celery tasks for running the agent swarm.
"""

import logging
from datetime import UTC, datetime

from celery import Task
from sqlmodel import Session, create_engine

from src.core.models import GovernanceJob, JobStatus
from src.worker.celery_app import DATABASE_URL, celery_app

logger = logging.getLogger(__name__)

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

    # Mark as running
    _update_job(
        job_id,
        status=JobStatus.running,
        started_at=datetime.now(UTC),
    )

    try:
        from src.agents.graph import swarm_app
        from src.agents.messaging import publish_event

        initial_state = {
            "job_id": job_id,
            "service_type": service_type,
            "input_data": input_data,
            "user_email": user_email,
            "active_agents": [],
            "completed_agents": [],
            "current_agent": "",
            "results": {},
            "messages": [],
            "governance_bundle": {},
            "status": "pending",
            "error": None,
        }

        publish_event(job_id, "system", "swarm_started", {"service_type": service_type})

        final_state = initial_state
        for step in swarm_app.stream(initial_state):
            for node_name, node_state in step.items():
                final_state = node_state
                # Write agents_planned to DB immediately after supervisor decides
                if node_name == "supervisor_plan":
                    planned = node_state.get("active_agents", [])
                    _update_job(job_id, agents_planned=planned)
                    logger.info(
                        f"[Job {job_id}] Supervisor planned {len(planned)} agents: {planned}"
                    )
                # Write agents_completed progressively after each service group
                elif node_name in (
                    "run_deepfake",
                    "run_threat_intel",
                    "run_responsible_ai",
                    "run_privacy",
                    "run_digital_asset",
                ):
                    completed = node_state.get("completed_agents", [])
                    _update_job(job_id, agents_completed=completed)
                    logger.info(f"[Job {job_id}] After {node_name}: {len(completed)} agents done")

        publish_event(
            job_id,
            "system",
            "swarm_completed",
            {
                "status": final_state.get("status", "unknown"),
                "agents_completed": len(final_state.get("completed_agents", [])),
            },
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
            from src.services.email import send_scan_complete_email

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
