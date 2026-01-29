from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from src.auth.dependencies import get_current_user_email
from src.core.database import get_session
from src.core.models import Consent, DomainVerification
from src.utils.consent import check_active_consent, consent_file_url, extract_domain

router = APIRouter(prefix="/consent", tags=["consent"])


class ConsentRequestBody(BaseModel):
    domain: str = Field(..., description="Domain for active scan consent (e.g., example.com)")


class ConsentInstructions(BaseModel):
    path: str
    content: str


class ConsentRequestResponse(BaseModel):
    domain: str
    user_email: str
    instructions: ConsentInstructions
    message: str = "Place the consent file at the specified path, then call POST /api/consent/check"


class ConsentCheckBody(BaseModel):
    domain: str = Field(..., description="Domain to check for active scan consent")


class ConsentCheckResponse(BaseModel):
    domain: str
    active_consent_verified: bool
    verified_at: Optional[datetime] = None
    message: str


@router.post("/request", response_model=ConsentRequestResponse)
async def request_active_consent(
    request: ConsentRequestBody,
    user_email: str = Depends(get_current_user_email),
    session: Session = Depends(get_session),
):
    domain = request.domain.strip().lower()
    
    if domain.startswith(("http://", "https://")):
        domain = extract_domain(domain)
    
    verification = session.exec(
        select(DomainVerification)
        .where(DomainVerification.domain == domain)
        .where(DomainVerification.user_email == user_email)
        .where(DomainVerification.verified == True)
    ).first()
    
    if not verification:
        raise HTTPException(
            status_code=400,
            detail=f"Domain {domain} is not verified. Complete domain verification first at POST /api/domains/verify/request"
        )
    
    consent_content = f"""vibesecure-active-consent=YES
domain={domain}
requested_by={user_email}
consent_date={datetime.utcnow().strftime('%Y-%m-%d')}

# This file authorizes VibeSecure to perform active security scanning
# Active scanning generates potentially malicious payloads (SQL injection, XSS, etc.)
# Only authorize if you have legal permission and understand the risks
"""
    
    instructions = ConsentInstructions(
        path="/.well-known/vibesecure-consent.txt",
        content=consent_content,
    )
    
    return ConsentRequestResponse(
        domain=domain,
        user_email=user_email,
        instructions=instructions,
        message=f"Place the consent file at https://{domain}/.well-known/vibesecure-consent.txt, then call POST /api/consent/check",
    )


@router.post("/check", response_model=ConsentCheckResponse)
async def check_consent(
    request: ConsentCheckBody,
    user_email: str = Depends(get_current_user_email),
    session: Session = Depends(get_session),
):
    domain = request.domain.strip().lower()
    
    if domain.startswith(("http://", "https://")):
        domain = extract_domain(domain)
    
    verification = session.exec(
        select(DomainVerification)
        .where(DomainVerification.domain == domain)
        .where(DomainVerification.user_email == user_email)
        .where(DomainVerification.verified == True)
    ).first()
    
    if not verification:
        raise HTTPException(
            status_code=400,
            detail=f"Domain {domain} is not verified. Complete domain verification first."
        )
    
    is_valid = check_active_consent(domain, user_email)
    
    if not is_valid:
        return ConsentCheckResponse(
            domain=domain,
            active_consent_verified=False,
            verified_at=None,
            message=f"Active scan consent NOT found. Place consent file at {consent_file_url(domain)}",
        )
    
    existing_consent = session.exec(
        select(Consent)
        .where(Consent.domain == domain)
        .where(Consent.user_email == user_email)
    ).first()
    
    if existing_consent:
        existing_consent.active_allowed = True
        existing_consent.verified_at = datetime.utcnow()
        existing_consent.method = "well-known"
        session.add(existing_consent)
        session.commit()
        session.refresh(existing_consent)
        
        return ConsentCheckResponse(
            domain=domain,
            active_consent_verified=True,
            verified_at=existing_consent.verified_at,
            message=f"Active scan consent verified for {domain}. You can now create scans with allow_active: true",
        )
    else:
        consent = Consent(
            domain=domain,
            user_email=user_email,
            active_allowed=True,
            verified_at=datetime.utcnow(),
            method="well-known",
        )
        session.add(consent)
        session.commit()
        session.refresh(consent)
        
        return ConsentCheckResponse(
            domain=domain,
            active_consent_verified=True,
            verified_at=consent.verified_at,
            message=f"Active scan consent verified for {domain}. You can now create scans with allow_active: true",
        )


@router.get("/{domain}/status")
async def get_consent_status(
    domain: str,
    user_email: str = Depends(get_current_user_email),
    session: Session = Depends(get_session),
):
    domain = domain.strip().lower()
    
    if domain.startswith(("http://", "https://")):
        domain = extract_domain(domain)
    
    consent = session.exec(
        select(Consent)
        .where(Consent.domain == domain)
        .where(Consent.user_email == user_email)
    ).first()
    
    if not consent:
        return {
            "domain": domain,
            "active_allowed": False,
            "active_consent_verified": False,
            "verified_at": None,
            "message": "No active scan consent found. Call POST /api/consent/request to get started.",
        }
    
    return {
        "id": consent.id,
        "domain": consent.domain,
        "user_email": consent.user_email,
        "active_allowed": consent.active_allowed,
        "active_consent_verified": consent.active_allowed,
        "verified_at": consent.verified_at,
        "method": consent.method,
        "created_at": consent.created_at,
    }


@router.get("/list")
async def list_consents(
    user_email: str = Depends(get_current_user_email),
    session: Session = Depends(get_session),
):
    consents = session.exec(
        select(Consent)
        .where(Consent.user_email == user_email)
        .order_by(Consent.created_at.desc())
    ).all()
    
    return {
        "consents": [
            {
                "id": c.id,
                "domain": c.domain,
                "active_allowed": c.active_allowed,
                "verified_at": c.verified_at,
                "method": c.method,
                "created_at": c.created_at,
            }
            for c in consents
        ],
        "total": len(consents),
    }
