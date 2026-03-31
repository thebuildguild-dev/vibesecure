"""
Webhook management and delivery service.

Handles webhook CRUD, HMAC-signed delivery with retries, and automatic
disabling of endpoints that fail repeatedly.
"""

import hashlib
import hmac
import json
import logging
import time
from datetime import UTC, datetime

import httpx
from sqlmodel import Session, select

from app.core.events import DomainEvent, event_bus
from app.models.webhook import Webhook, WebhookDelivery, WebhookStatus

logger = logging.getLogger(__name__)

MAX_CONSECUTIVE_FAILURES = 10
DELIVERY_TIMEOUT = 10  # seconds
MAX_DELIVERY_RETRIES = 3


def _sign_payload(payload: str, secret: str) -> str:
    """Create an HMAC-SHA256 signature for the webhook payload."""
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def deliver_webhook(
    webhook: Webhook,
    event_type: str,
    payload: dict,
    session: Session,
) -> bool:
    """Deliver a single webhook with retries and signature."""
    payload_json = json.dumps(payload, default=str)
    signature = _sign_payload(payload_json, webhook.secret)

    headers = {
        "Content-Type": "application/json",
        "X-VibeSecure-Event": event_type,
        "X-VibeSecure-Signature": f"sha256={signature}",
        "X-VibeSecure-Delivery": str(time.time()),
        "User-Agent": "VibeSecure-Webhook/3.0",
    }

    for attempt in range(1, MAX_DELIVERY_RETRIES + 1):
        delivery = WebhookDelivery(
            webhook_id=webhook.id,
            event_type=event_type,
            payload=payload,
            attempt=attempt,
        )

        start = time.perf_counter()
        try:
            with httpx.Client(timeout=DELIVERY_TIMEOUT) as client:
                resp = client.post(webhook.url, content=payload_json, headers=headers)

            duration_ms = (time.perf_counter() - start) * 1000
            delivery.response_code = resp.status_code
            delivery.response_body = resp.text[:1000]
            delivery.duration_ms = round(duration_ms, 1)

            if 200 <= resp.status_code < 300:
                delivery.success = True
                _record_success(webhook, resp.status_code)
                session.add(delivery)
                session.commit()
                return True

            logger.warning(
                "Webhook %s delivery attempt %d returned %d",
                webhook.id,
                attempt,
                resp.status_code,
            )

        except Exception as e:
            duration_ms = (time.perf_counter() - start) * 1000
            delivery.duration_ms = round(duration_ms, 1)
            delivery.error = str(e)[:500]
            logger.warning(
                "Webhook %s delivery attempt %d failed: %s",
                webhook.id,
                attempt,
                e,
            )

        session.add(delivery)
        session.commit()

        # Exponential backoff between retries
        if attempt < MAX_DELIVERY_RETRIES:
            time.sleep(min(2**attempt, 10))

    # All retries exhausted
    _record_failure(webhook, session)
    return False


def _record_success(webhook: Webhook, status_code: int) -> None:
    webhook.total_deliveries += 1
    webhook.consecutive_failures = 0
    webhook.last_delivered_at = datetime.now(UTC)
    webhook.last_response_code = status_code


def _record_failure(webhook: Webhook, session: Session) -> None:
    webhook.total_failures += 1
    webhook.consecutive_failures += 1
    webhook.last_failure_at = datetime.now(UTC)

    if webhook.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
        webhook.status = WebhookStatus.disabled
        logger.warning(
            "Webhook %s auto-disabled after %d consecutive failures",
            webhook.id,
            webhook.consecutive_failures,
        )

    session.add(webhook)
    session.commit()


def dispatch_webhooks_for_event(
    event_type: str, payload: dict, user_email: str, session: Session
) -> int:
    """Find all active webhooks for a user/event and deliver."""
    statement = select(Webhook).where(
        Webhook.user_email == user_email,
        Webhook.status == WebhookStatus.active,
    )
    webhooks = session.exec(statement).all()

    delivered = 0
    for wh in webhooks:
        # Check if this webhook subscribes to this event type
        if "*" not in wh.event_types and event_type not in wh.event_types:
            continue
        if deliver_webhook(wh, event_type, payload, session):
            delivered += 1

    return delivered


# ── Event bus integration ────────────────────────────────────────


@event_bus.on("scan.completed")
async def _on_scan_completed(event: DomainEvent) -> None:
    _dispatch_from_event(event)


@event_bus.on("scan.failed")
async def _on_scan_failed(event: DomainEvent) -> None:
    _dispatch_from_event(event)


@event_bus.on("governance.job.completed")
async def _on_governance_completed(event: DomainEvent) -> None:
    _dispatch_from_event(event)


@event_bus.on("governance.job.failed")
async def _on_governance_failed(event: DomainEvent) -> None:
    _dispatch_from_event(event)


def _dispatch_from_event(event: DomainEvent) -> None:
    """Best-effort webhook dispatch triggered by the event bus."""
    user_email = event.data.get("user_email", "")
    if not user_email:
        return

    try:
        from app.core.database import engine

        with Session(engine) as session:
            dispatch_webhooks_for_event(
                event_type=event.event_type,
                payload=event.data,
                user_email=user_email,
                session=session,
            )
    except Exception:
        logger.exception("Failed to dispatch webhooks for event %s", event.event_type)
