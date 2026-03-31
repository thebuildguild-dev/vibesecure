"""
Models package - re-exports all models, enums, and CRUD functions for backward compatibility.
Also re-exports Pydantic schemas for consumers that import from app.models.
"""

from app.models.audit import (
    GovernanceJob,
    JobStatus,
    ServiceType,
)
from app.models.consent import (
    Consent,
)
from app.models.domain import (
    DomainVerification,
    DomainVerificationAudit,
)
from app.models.scan import (
    Finding,
    FindingBase,
    Scan,
    ScanStatus,
    Severity,
    create_finding,
    create_findings_bulk,
    create_scan,
    get_finding,
    get_findings_for_scan,
    get_risk_label,
    get_scan,
    get_scans,
    now_utc,
    update_scan_status,
)
from app.schemas.ai_test import (
    GovernanceJobCreate,
    GovernanceJobDetail,
    GovernanceJobRead,
)

# Re-export schemas for backward compatibility
from app.schemas.scan import (
    FindingCreate,
    FindingRead,
    ScanCreate,
    ScanCreateResponse,
    ScanDetail,
    ScanExport,
    ScanRead,
)

__all__ = [
    # Scan
    "Scan",
    "Finding",
    "FindingBase",
    "ScanStatus",
    "Severity",
    "create_scan",
    "get_scan",
    "get_scans",
    "update_scan_status",
    "create_finding",
    "get_finding",
    "get_findings_for_scan",
    "create_findings_bulk",
    "get_risk_label",
    "now_utc",
    # Domain
    "DomainVerification",
    "DomainVerificationAudit",
    # Consent
    "Consent",
    # Audit / Governance
    "GovernanceJob",
    "JobStatus",
    "ServiceType",
]
