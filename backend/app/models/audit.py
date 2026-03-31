import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import JSON
from sqlmodel import Column, Field, SQLModel

from app.models.scan import now_utc


class JobStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class ServiceType(str, Enum):
    deepfake = "deepfake"
    threat_intel = "threat_intel"
    responsible_ai = "responsible_ai"
    privacy = "privacy"
    digital_asset = "digital_asset"
    all = "all"


class GovernanceJob(SQLModel, table=True):
    """A governance job that runs the agent swarm."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    user_email: str = Field(index=True)
    service_type: ServiceType
    status: JobStatus = JobStatus.pending
    input_data: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    governance_bundle: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    agent_results: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    agents_planned: list[str] | None = Field(default=None, sa_column=Column(JSON))
    agents_completed: list[str] | None = Field(default=None, sa_column=Column(JSON))
    error: str | None = None
    created_at: datetime = Field(default_factory=now_utc)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    celery_task_id: str | None = None

    # Media file info (for deepfake service)
    file_path: str | None = None
    file_type: str | None = None  # image, video
