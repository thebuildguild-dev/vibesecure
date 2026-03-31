"""
Webhook management endpoints.

Allows users to register, list, update, and delete webhook endpoints
for real-time notifications of scan and governance job events.
"""

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl
from sqlmodel import Session, select

from app.core.audit import audit
from app.core.database import get_session
from app.dependencies import get_current_user
from app.models.webhook import Webhook, WebhookDelivery, WebhookEventType, WebhookStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

MAX_WEBHOOKS_PER_USER = 10


# ── Schemas ──────────────────────────────────────────────────────


class WebhookCreate(BaseModel):
    url: HttpUrl
    event_types: list[str] = ["*"]
    description: str | None = None


class WebhookUpdate(BaseModel):
    url: HttpUrl | None = None
    event_types: list[str] | None = None
    status: WebhookStatus | None = None
    description: str | None = None


class WebhookRead(BaseModel):
    id: str
    url: str
    event_types: list[str]
    status: WebhookStatus
    description: str | None
    created_at: datetime
    total_deliveries: int
    total_failures: int
    consecutive_failures: int
    last_delivered_at: datetime | None
    last_response_code: int | None


class WebhookDeliveryRead(BaseModel):
    id: str
    event_type: str
    response_code: int | None
    success: bool
    duration_ms: float | None
    attempt: int
    created_at: datetime
    error: str | None


class WebhookSecretRead(BaseModel):
    id: str
    secret: str


# ── Endpoints ────────────────────────────────────────────────────


@router.post("", response_model=WebhookSecretRead, status_code=status.HTTP_201_CREATED)
def create_webhook(
    body: WebhookCreate,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user),
):
    user_email = current_user["email"]

    # Enforce per-user limit
    count = len(session.exec(select(Webhook).where(Webhook.user_email == user_email)).all())
    if count >= MAX_WEBHOOKS_PER_USER:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Maximum {MAX_WEBHOOKS_PER_USER} webhooks per user",
        )

    # Validate URL is HTTPS
    url_str = str(body.url)
    if not url_str.startswith("https://"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook URL must use HTTPS",
        )

    # Validate event types
    valid_types = {e.value for e in WebhookEventType}
    for et in body.event_types:
        if et not in valid_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid event type: {et}. Valid types: {sorted(valid_types)}",
            )

    webhook = Webhook(
        user_email=user_email,
        url=url_str,
        event_types=body.event_types,
        description=body.description,
    )
    session.add(webhook)
    session.commit()
    session.refresh(webhook)

    audit.webhook_registered(actor=user_email, webhook_id=webhook.id, session=session)

    return WebhookSecretRead(id=webhook.id, secret=webhook.secret)


@router.get("", response_model=list[WebhookRead])
def list_webhooks(
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user),
):
    user_email = current_user["email"]
    webhooks = session.exec(
        select(Webhook).where(Webhook.user_email == user_email).order_by(Webhook.created_at.desc())
    ).all()
    return webhooks


@router.get("/{webhook_id}", response_model=WebhookRead)
def get_webhook(
    webhook_id: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user),
):
    webhook = session.get(Webhook, webhook_id)
    if not webhook or webhook.user_email != current_user["email"]:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return webhook


@router.patch("/{webhook_id}", response_model=WebhookRead)
def update_webhook(
    webhook_id: str,
    body: WebhookUpdate,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user),
):
    webhook = session.get(Webhook, webhook_id)
    if not webhook or webhook.user_email != current_user["email"]:
        raise HTTPException(status_code=404, detail="Webhook not found")

    if body.url is not None:
        url_str = str(body.url)
        if not url_str.startswith("https://"):
            raise HTTPException(status_code=400, detail="Webhook URL must use HTTPS")
        webhook.url = url_str

    if body.event_types is not None:
        webhook.event_types = body.event_types

    if body.status is not None:
        webhook.status = body.status
        # Reset failure counter when re-enabling
        if body.status == WebhookStatus.active:
            webhook.consecutive_failures = 0

    if body.description is not None:
        webhook.description = body.description

    webhook.updated_at = datetime.now(UTC)
    session.add(webhook)
    session.commit()
    session.refresh(webhook)
    return webhook


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(
    webhook_id: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user),
):
    webhook = session.get(Webhook, webhook_id)
    if not webhook or webhook.user_email != current_user["email"]:
        raise HTTPException(status_code=404, detail="Webhook not found")
    session.delete(webhook)
    session.commit()


@router.get("/{webhook_id}/deliveries", response_model=list[WebhookDeliveryRead])
def list_deliveries(
    webhook_id: str,
    limit: int = 50,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user),
):
    webhook = session.get(Webhook, webhook_id)
    if not webhook or webhook.user_email != current_user["email"]:
        raise HTTPException(status_code=404, detail="Webhook not found")

    deliveries = session.exec(
        select(WebhookDelivery)
        .where(WebhookDelivery.webhook_id == webhook_id)
        .order_by(WebhookDelivery.created_at.desc())
        .limit(min(limit, 100))
    ).all()
    return deliveries


@router.post("/{webhook_id}/test", status_code=status.HTTP_200_OK)
def test_webhook(
    webhook_id: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user),
):
    """Send a test delivery to verify the webhook endpoint."""
    from app.services.webhook_service import deliver_webhook

    webhook = session.get(Webhook, webhook_id)
    if not webhook or webhook.user_email != current_user["email"]:
        raise HTTPException(status_code=404, detail="Webhook not found")

    test_payload = {
        "event": "webhook.test",
        "message": "This is a test delivery from VibeSecure",
        "webhook_id": webhook.id,
    }

    success = deliver_webhook(webhook, "webhook.test", test_payload, session)
    session.add(webhook)
    session.commit()

    return {
        "success": success,
        "message": "Test delivery sent" if success else "Test delivery failed",
    }
