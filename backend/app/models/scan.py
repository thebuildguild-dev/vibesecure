import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Optional

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


class Scan(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    url: str
    description: str | None = None
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


# ─── CRUD Functions ──────────────────────────────────────────


def create_scan(session, scan_data) -> Scan:
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


def create_finding(session, finding_data) -> Finding:
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
