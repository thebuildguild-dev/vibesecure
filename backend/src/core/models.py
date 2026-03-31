import json
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Optional

from pydantic import field_validator
from sqlalchemy import JSON
from sqlmodel import Column, Field, Relationship, SQLModel


def now_utc() -> datetime:
    return datetime.now(UTC)


def get_risk_label(score: int | None) -> str:
    if score is None:
        return "Unknown"

    if score <= 30:
        return "Low"
    elif score <= 60:
        return "Medium"
    elif score <= 80:
        return "High"
    else:
        return "Critical"


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingBase(SQLModel):
    title: str
    severity: Severity = Severity.info
    remediation: str | None = None
    confidence: int = Field(default=50, ge=0, le=100)
    path: str | None = None


class Finding(FindingBase, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    created_at: datetime = Field(default_factory=now_utc)

    scan: Optional["Scan"] = Relationship(back_populates="findings_rel")


class FindingCreate(FindingBase):
    scan_id: str


class FindingRead(FindingBase):
    id: str
    scan_id: str
    created_at: datetime


class ScanBase(SQLModel):
    url: str
    description: str | None = None


class Scan(ScanBase, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    status: ScanStatus = ScanStatus.queued
    user_email: str | None = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=now_utc)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    celery_task_id: str | None = None
    result: str | None = None
    risk_score: int | None = Field(default=None)
    scan_confidence: str | None = Field(default=None)
    options: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    verification_id: str | None = Field(default=None, foreign_key="domainverification.id")

    findings_rel: list[Finding] = Relationship(back_populates="scan")


class ScanCreate(SQLModel):
    url: str
    description: str | None = None
    options: dict[str, Any] | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class ScanRead(SQLModel):
    id: str
    url: str
    description: str | None = None
    status: ScanStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    risk_score: int | None = None
    risk_label: str | None = None
    scan_confidence: str | None = None


class ScanDetail(ScanRead):
    findings: list[FindingRead] = []
    result: dict | None = None

    @classmethod
    def from_scan(cls, scan: Scan) -> "ScanDetail":
        result = None
        if scan.result:
            try:
                result = json.loads(scan.result)
            except json.JSONDecodeError:
                result = {}

        findings = [
            FindingRead(
                id=f.id,
                scan_id=f.scan_id,
                title=f.title,
                severity=f.severity,
                remediation=f.remediation,
                confidence=f.confidence,
                path=f.path,
                created_at=f.created_at,
            )
            for f in scan.findings_rel
        ]

        return cls(
            id=scan.id,
            url=scan.url,
            description=scan.description,
            status=scan.status,
            created_at=scan.created_at,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            findings=findings,
            result=result,
            risk_score=scan.risk_score,
            risk_label=get_risk_label(scan.risk_score),
            scan_confidence=scan.scan_confidence,
        )


class ScanCreateResponse(SQLModel):
    id: str
    status: ScanStatus


def create_scan(session, scan_data: ScanCreate) -> Scan:
    db_scan = Scan(
        url=scan_data.url,
        description=scan_data.description,
        status=ScanStatus.queued,
    )
    session.add(db_scan)
    session.commit()
    session.refresh(db_scan)
    return db_scan


def get_scan(session, scan_id: str) -> Scan | None:
    return session.get(Scan, scan_id)


def get_scans(session, skip: int = 0, limit: int = 20) -> list[Scan]:
    from sqlmodel import select

    statement = select(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit)
    return session.exec(statement).all()


def update_scan_status(
    session, scan_id: str, status: ScanStatus, started: bool = False, finished: bool = False
) -> Scan | None:
    scan = session.get(Scan, scan_id)
    if scan:
        scan.status = status
        if started:
            scan.started_at = datetime.now(UTC)
        if finished:
            scan.finished_at = datetime.now(UTC)
        session.add(scan)
        session.commit()
        session.refresh(scan)
    return scan


def create_finding(session, finding_data: FindingCreate) -> Finding:
    db_finding = Finding.model_validate(finding_data)
    session.add(db_finding)
    session.commit()
    session.refresh(db_finding)
    return db_finding


def get_finding(session, finding_id: str) -> Finding | None:
    return session.get(Finding, finding_id)


def get_findings_for_scan(session, scan_id: str) -> list[Finding]:
    from sqlmodel import select

    statement = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at)
    return session.exec(statement).all()


def create_findings_bulk(session, scan_id: str, findings_data: list[dict]) -> list[Finding]:
    findings = []
    for data in findings_data:
        finding = Finding(
            scan_id=scan_id,
            title=data.get("title", "Untitled"),
            severity=Severity(data.get("severity", "info")),
            remediation=data.get("remediation"),
            confidence=data.get("confidence", 50),
            path=data.get("path"),
        )
        session.add(finding)
        findings.append(finding)
    session.commit()
    for f in findings:
        session.refresh(f)
    return findings


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


class Consent(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    domain: str = Field(index=True)
    user_email: str = Field(index=True)
    active_allowed: bool = Field(default=False)
    verified_at: datetime | None = None
    method: str = Field(default="well-known")
    created_at: datetime = Field(default_factory=now_utc)


class ScanExport(SQLModel):
    scan_id: str
    url: str
    description: str | None
    status: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    findings: list | None = None
    generated_at: str
    format: str = "json"


# ─── Agent Swarm Models ─────────────────────────────────────


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
