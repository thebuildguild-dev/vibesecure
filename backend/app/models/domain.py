import uuid
from datetime import datetime

from sqlmodel import Field, SQLModel

from app.models.scan import now_utc


class DomainVerification(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    domain: str = Field(index=True)
    user_email: str = Field(index=True)
    token_hash: str
    token_created_at: datetime = Field(default_factory=now_utc)
    token_expires_at: datetime
    verified: bool = False
    verified_at: datetime | None = None
    verified_by_method: str | None = None
    last_checked_at: datetime | None = None


class DomainVerificationAudit(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    verification_id: str = Field(foreign_key="domainverification.id", index=True)
    action: str
    details: str | None = None
    created_at: datetime = Field(default_factory=now_utc)
