"""Pydantic schemas for AI governance test (agent swarm) API requests and responses."""

from datetime import datetime
from typing import Any

from pydantic import field_validator
from sqlmodel import SQLModel

from app.models.audit import JobStatus, ServiceType


class GovernanceJobCreate(SQLModel):
    service_type: ServiceType
    url: str | None = None
    content: str | None = None
    ai_system_description: str | None = None
    api_endpoint: str | None = None
    ai_system_auth: dict[str, Any] | None = None
    ai_system_consent: bool = False
    scan_options: dict[str, Any] | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class GovernanceJobRead(SQLModel):
    id: str
    service_type: ServiceType
    status: JobStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    agents_planned: list[str] | None = None
    agents_completed: list[str] | None = None
    error: str | None = None


class GovernanceJobDetail(GovernanceJobRead):
    governance_bundle: dict[str, Any] | None = None
    agent_results: dict[str, Any] | None = None
    input_data: dict[str, Any] | None = None
