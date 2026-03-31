"""Pydantic schemas for scan-related API requests and responses."""

import json
from datetime import datetime

from pydantic import field_validator
from sqlmodel import SQLModel

from app.models.scan import (
    FindingBase,
    Scan,
    ScanStatus,
    get_risk_label,
)


class FindingCreate(FindingBase):
    scan_id: str


class FindingRead(FindingBase):
    id: str
    scan_id: str
    created_at: datetime


class ScanCreate(SQLModel):
    url: str
    description: str | None = None
    options: dict | None = None

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
