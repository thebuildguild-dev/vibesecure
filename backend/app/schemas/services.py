"""Pydantic schemas for the 5 service-specific API endpoints."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Shared base: every service job returns this core shape
# ---------------------------------------------------------------------------
class ServiceJobBase(BaseModel):
    job_id: str
    service_type: str
    status: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    agents_planned: list[str] | None = None
    agents_completed: list[str] | None = None
    error: str | None = None


class ServiceJobDetail(ServiceJobBase):
    governance_bundle: dict[str, Any] | None = None
    agent_results: dict[str, Any] | None = None
    input_data: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Service 1: Deepfake Detection
# ---------------------------------------------------------------------------
class DeepfakeAnalyzeRequest(BaseModel):
    """JSON body when no file upload (external URL reference)."""

    url: str | None = Field(None, description="Public URL to media (image/video)")
    content: str | None = Field(None, description="Additional context or description")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class DeepfakeResult(ServiceJobDetail):
    """Extended detail for deepfake service."""

    confidence_score: float | None = None
    verdict: str | None = None
    frames_analyzed: int | None = None


# ---------------------------------------------------------------------------
# Service 2: AI Threat Intelligence
# ---------------------------------------------------------------------------
class ThreatIntelRequest(BaseModel):
    content: str | None = Field(None, description="Text content to analyse for threats")
    ai_system_description: str | None = Field(
        None, description="Description of the AI system to evaluate"
    )
    api_endpoint: str | None = Field(
        None, description="AI system API endpoint to test (requires consent)"
    )
    ai_system_auth: dict[str, Any] | None = Field(
        None, description="Authentication config for the AI system API"
    )
    ai_system_consent: bool = Field(
        False, description="Explicit consent to perform safe test attacks on the AI system"
    )

    @field_validator("api_endpoint")
    @classmethod
    def validate_endpoint(cls, v: str | None) -> str | None:
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("API endpoint must start with http:// or https://")
        return v


class ThreatIntelResult(ServiceJobDetail):
    """Extended detail for threat intelligence service."""

    risk_score: str | None = None
    threats_found: int | None = None


# ---------------------------------------------------------------------------
# Service 3: Responsible AI Frameworks
# ---------------------------------------------------------------------------
class ResponsibleAIRequest(BaseModel):
    content: str | None = Field(None, description="AI-generated content to audit")
    ai_system_description: str | None = Field(
        None, description="Description of the AI system to evaluate"
    )
    url: str | None = Field(None, description="URL of AI application to audit")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class ResponsibleAIResult(ServiceJobDetail):
    """Extended detail for responsible AI audit."""

    overall_grade: str | None = None
    scorecard: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Service 4: Data Privacy & Regulatory Compliance
# ---------------------------------------------------------------------------
class PrivacyScanRequest(BaseModel):
    url: str | None = Field(None, description="Website URL to scan for privacy issues")
    content: str | None = Field(None, description="Text content to scan for PII")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class PrivacyScanResult(ServiceJobDetail):
    """Extended detail for privacy scan."""

    overall_privacy_score: float | None = None
    regulations_mapped: list[str] | None = None


# ---------------------------------------------------------------------------
# Service 5: Digital Asset Governance
# ---------------------------------------------------------------------------
class DigitalAssetScanRequest(BaseModel):
    url: str = Field(..., description="Website URL to scan (must be domain-verified)")
    scan_options: dict[str, Any] | None = Field(
        None,
        description="Options: allow_active (bool) for ZAP scanning, run_privacy (bool) for privacy co-scan",
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class DigitalAssetResult(ServiceJobDetail):
    """Extended detail for digital asset scan."""

    risk_score: int | None = None
    findings_count: int | None = None
    severity_counts: dict[str, int] | None = None
