import uuid
from datetime import datetime

from sqlmodel import Field, SQLModel

from app.models.scan import now_utc


class Consent(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    domain: str = Field(index=True)
    user_email: str = Field(index=True)
    active_allowed: bool = Field(default=False)
    verified_at: datetime | None = None
    method: str = Field(default="well-known")
    created_at: datetime = Field(default_factory=now_utc)
