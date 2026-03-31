"""
Webhook registration model.

Users can register HTTPS webhook endpoints to receive real-time notifications
when scans complete, governance jobs finish, or security alerts fire.
"""

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from sqlalchemy import JSON
from sqlmodel import Column, Field, SQLModel


def _now_utc() -> datetime:
    return datetime.now(UTC)


class WebhookEventType(str, Enum):
    scan_completed = "scan.completed"
    scan_failed = "scan.failed"
    governance_completed = "governance.job.completed"
    governance_failed = "governance.job.failed"
    domain_verified = "domain.verified"
    security_alert = "security.alert"
    all = "*"


class WebhookStatus(str, Enum):
    active = "active"
    paused = "paused"
    disabled = "disabled"  # auto-disabled after repeated failures


class Webhook(SQLModel, table=True):
    """A registered webhook endpoint."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    user_email: str = Field(index=True)
    url: str  # HTTPS callback URL
    secret: str = Field(default_factory=lambda: uuid.uuid4().hex)
    event_types: list[str] = Field(sa_column=Column(JSON), default=["*"])
    description: str | None = None
    status: WebhookStatus = WebhookStatus.active
    created_at: datetime = Field(default_factory=_now_utc)
    updated_at: datetime = Field(default_factory=_now_utc)

    # Delivery tracking
    total_deliveries: int = 0
    total_failures: int = 0
    consecutive_failures: int = 0
    last_delivered_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_response_code: int | None = None


class WebhookDelivery(SQLModel, table=True):
    """Log of every webhook delivery attempt."""

    __tablename__ = "webhook_delivery"

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    webhook_id: str = Field(foreign_key="webhook.id", index=True)
    event_type: str
    payload: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    response_code: int | None = None
    response_body: str | None = None
    success: bool = False
    attempt: int = 1
    duration_ms: float | None = None
    created_at: datetime = Field(default_factory=_now_utc)
    error: str | None = None
