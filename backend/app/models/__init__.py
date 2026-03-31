"""Models package - SQLAlchemy/SQLModel table definitions.

All models are imported here so that ``SQLModel.metadata.create_all()``
picks up every table.
"""

# Import audit log table so it is created alongside everything else
from app.core.audit import AuditLog  # noqa: F401
from app.models.audit import GovernanceJob  # noqa: F401
from app.models.consent import Consent  # noqa: F401
from app.models.domain import DomainVerification, DomainVerificationAudit  # noqa: F401
from app.models.scan import Finding, Scan  # noqa: F401
from app.models.webhook import Webhook, WebhookDelivery  # noqa: F401
