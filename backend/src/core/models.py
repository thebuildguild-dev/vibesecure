from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from sqlmodel import SQLModel, Field, Relationship, Column
from sqlalchemy import JSON
from pydantic import field_validator
import json
import uuid


def get_risk_label(score: Optional[int]) -> str:
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
    remediation: Optional[str] = None
    confidence: int = Field(default=50, ge=0, le=100)
    path: Optional[str] = None


class Finding(FindingBase, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    scan: Optional["Scan"] = Relationship(back_populates="findings_rel")


class FindingCreate(FindingBase):
    scan_id: str


class FindingRead(FindingBase):
    id: str
    scan_id: str
    created_at: datetime


class ScanBase(SQLModel):
    url: str
    description: Optional[str] = None


class Scan(ScanBase, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    status: ScanStatus = ScanStatus.queued
    user_email: Optional[str] = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    celery_task_id: Optional[str] = None
    result: Optional[str] = None
    risk_score: Optional[int] = Field(default=None)
    scan_confidence: Optional[str] = Field(default=None)
    options: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    verification_id: Optional[str] = Field(default=None, foreign_key="domainverification.id")
    
    findings_rel: List[Finding] = Relationship(back_populates="scan")


class ScanCreate(SQLModel):
    url: str
    description: Optional[str] = None
    options: Optional[Dict[str, Any]] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class ScanRead(SQLModel):
    id: str
    url: str
    description: Optional[str] = None
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    risk_score: Optional[int] = None
    risk_label: Optional[str] = None
    scan_confidence: Optional[str] = None


class ScanDetail(ScanRead):
    findings: List[FindingRead] = []
    result: Optional[dict] = None

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


def get_scan(session, scan_id: str) -> Optional[Scan]:
    return session.get(Scan, scan_id)


def get_scans(session, skip: int = 0, limit: int = 20) -> List[Scan]:
    from sqlmodel import select
    statement = select(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit)
    return session.exec(statement).all()


def update_scan_status(session, scan_id: str, status: ScanStatus, started: bool = False, finished: bool = False) -> Optional[Scan]:
    scan = session.get(Scan, scan_id)
    if scan:
        scan.status = status
        if started:
            scan.started_at = datetime.utcnow()
        if finished:
            scan.finished_at = datetime.utcnow()
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


def get_finding(session, finding_id: str) -> Optional[Finding]:
    return session.get(Finding, finding_id)


def get_findings_for_scan(session, scan_id: str) -> List[Finding]:
    from sqlmodel import select
    statement = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at)
    return session.exec(statement).all()


def create_findings_bulk(session, scan_id: str, findings_data: List[dict]) -> List[Finding]:
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
    token_created_at: datetime = Field(default_factory=datetime.utcnow)
    token_expires_at: datetime
    verified: bool = False
    verified_at: Optional[datetime] = None
    verified_by_method: Optional[str] = None
    last_checked_at: Optional[datetime] = None


class DomainVerificationAudit(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    verification_id: str = Field(foreign_key="domainverification.id", index=True)
    action: str
    details: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Consent(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    domain: str = Field(index=True)
    user_email: str = Field(index=True)
    active_allowed: bool = Field(default=False)
    verified_at: Optional[datetime] = None
    method: str = Field(default="well-known")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanExport(SQLModel):
    scan_id: str
    url: str
    description: Optional[str]
    status: str
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    findings: Optional[list] = None
    generated_at: str
    format: str = "json"
