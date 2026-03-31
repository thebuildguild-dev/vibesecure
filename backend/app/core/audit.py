"""
Structured audit logging.

Every security-relevant action is recorded to both the application log and
the ``audit_log`` database table. The audit logger is wired as an event bus
subscriber so it automatically captures domain events, but can also be called
directly for imperative audit entries.

Audit entries include:
  - Correlation ID (ties to the originating HTTP request)
  - Actor (user email or system identifier)
  - Action (what happened)
  - Resource (what was affected)
  - Outcome (success / failure)
  - Metadata (freeform JSON details)
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Text
from sqlmodel import Column, Field, Session, SQLModel

from app.core.tracing import get_request_id

logger = logging.getLogger("audit")


class AuditLog(SQLModel, table=True):
    """Persistent audit trail stored in PostgreSQL."""

    __tablename__ = "audit_log"

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    correlation_id: str = Field(default="", index=True)
    actor: str = Field(default="system", index=True)
    action: str = Field(index=True)
    resource_type: str = Field(default="")
    resource_id: str = Field(default="", index=True)
    outcome: str = Field(default="success")  # success | failure | denied
    ip_address: str = Field(default="")
    user_agent: str = Field(default="")
    metadata_json: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    details: str | None = Field(default=None, sa_column=Column(Text))


class AuditLogger:
    """High-level audit logging interface.

    Works both with and without a live database session. When no session is
    provided the entry is only logged; when a session is available it is also
    persisted to the ``audit_log`` table.
    """

    def log(
        self,
        action: str,
        *,
        actor: str = "system",
        resource_type: str = "",
        resource_id: str = "",
        outcome: str = "success",
        ip_address: str = "",
        user_agent: str = "",
        metadata: dict[str, Any] | None = None,
        details: str | None = None,
        session: Session | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            correlation_id=get_request_id(),
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata_json=metadata,
            details=details,
        )

        # Always log to the application logger
        logger.info(
            "AUDIT action=%s actor=%s resource=%s/%s outcome=%s correlation=%s",
            action,
            actor,
            resource_type,
            resource_id,
            outcome,
            entry.correlation_id,
        )

        # Persist to database if a session is available
        if session is not None:
            try:
                session.add(entry)
                session.commit()
                session.refresh(entry)
            except Exception:
                logger.exception("Failed to persist audit entry to database")
                session.rollback()

        return entry

    # ── Convenience methods ──────────────────────────────────────

    def auth_success(self, actor: str, ip: str = "", **kw: Any) -> AuditLog:
        return self.log("auth.login", actor=actor, resource_type="user", ip_address=ip, **kw)

    def auth_failure(self, actor: str, ip: str = "", reason: str = "", **kw: Any) -> AuditLog:
        return self.log(
            "auth.login_failed",
            actor=actor,
            resource_type="user",
            outcome="failure",
            ip_address=ip,
            details=reason,
            **kw,
        )

    def scan_created(self, actor: str, scan_id: str, **kw: Any) -> AuditLog:
        return self.log(
            "scan.created", actor=actor, resource_type="scan", resource_id=scan_id, **kw
        )

    def scan_completed(self, actor: str, scan_id: str, **kw: Any) -> AuditLog:
        return self.log(
            "scan.completed", actor=actor, resource_type="scan", resource_id=scan_id, **kw
        )

    def governance_job_created(self, actor: str, job_id: str, **kw: Any) -> AuditLog:
        return self.log(
            "governance.job.created",
            actor=actor,
            resource_type="governance_job",
            resource_id=job_id,
            **kw,
        )

    def domain_verified(self, actor: str, domain: str, **kw: Any) -> AuditLog:
        return self.log(
            "domain.verified", actor=actor, resource_type="domain", resource_id=domain, **kw
        )

    def webhook_registered(self, actor: str, webhook_id: str, **kw: Any) -> AuditLog:
        return self.log(
            "webhook.registered", actor=actor, resource_type="webhook", resource_id=webhook_id, **kw
        )

    def access_denied(
        self, actor: str, resource_type: str = "", resource_id: str = "", **kw: Any
    ) -> AuditLog:
        return self.log(
            "access.denied",
            actor=actor,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome="denied",
            **kw,
        )


# Module-level singleton
audit = AuditLogger()
