from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from src.auth import get_current_user
from src.core.database import get_session
from src.core.models import DomainVerification
from src.core.config import settings
from src.utils.verification import save_verification_request, check_token_on_site


router = APIRouter(prefix="/domains", tags=["domains"])


class VerifyRequestBody(BaseModel):
    domain: str = Field(..., description="Domain to verify (e.g., example.com)")


class InstructionsFile(BaseModel):
    path: str
    content: str


class InstructionsHeader(BaseModel):
    name: str
    value: str


class Instructions(BaseModel):
    file: InstructionsFile
    meta: str
    header: InstructionsHeader


class VerifyRequestResponse(BaseModel):
    domain: str
    token: str
    instructions: Instructions
    expires_at: str
    message: str = "Place the token using one of the methods below, then call POST /api/domains/verify/check"


class VerifyCheckBody(BaseModel):
    domain: Optional[str] = Field(None, description="Domain to check (will use latest token)")
    verification_id: Optional[str] = Field(None, description="Specific verification ID to check")


class VerifyCheckResponse(BaseModel):
    domain: str
    verified: bool
    method: str | None
    details: str
    verified_at: str | None = None


class DomainStatusResponse(BaseModel):
    domain: str
    verified: bool
    verified_at: str | None = None
    verified_by_method: str | None = None
    expires_at: str | None = None


class DomainListItem(BaseModel):
    domain: str
    verified: bool
    verified_at: str | None
    verified_by_method: str | None
    expires_at: str


@router.post("/verify/request", response_model=VerifyRequestResponse, status_code=201)
def request_verification(
    body: VerifyRequestBody,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    domain = body.domain.lower().strip()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0] 
    user_email = current_user["email"]
    
    try:
        token, verification_record = save_verification_request(session, domain, user_email)
        
        # Handle case where existing unexpired token was found (idempotent behavior)
        if not token:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "token_exists",
                    "message": f"An unexpired verification token already exists for {domain}. Use POST /api/domains/verify/check to verify it, or wait for expiry.",
                    "expires_at": verification_record.token_expires_at.isoformat()
                }
            )
        
        instructions = Instructions(
            file=InstructionsFile(
                path="/.well-known/vibesecure-verification.txt",
                content=f"vibesecure-verify={token}"
            ),
            meta=f"<meta name='vibesecure-verify' content='{token}' />",
            header=InstructionsHeader(
                name="X-VibeSecure-Verify",
                value=token
            )
        )
        
        return VerifyRequestResponse(
            domain=domain,
            token=token,
            instructions=instructions,
            expires_at=verification_record.token_expires_at.isoformat()
        )
    
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate verification token: {str(e)}"
        )


@router.delete("/verify/request")
def delete_verification_request(
    domain: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    domain = domain.lower().strip()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0]
    user_email = current_user["email"]
    
    pending_verifications = session.exec(
        select(DomainVerification)
        .where(DomainVerification.domain == domain)
        .where(DomainVerification.user_email == user_email)
        .where(DomainVerification.verified == False)
    ).all()
    
    if not pending_verifications:
        raise HTTPException(
            status_code=404,
            detail=f"No pending verification requests found for {domain}"
        )
    
    from ..core.models import DomainVerificationAudit
    
    for verification in pending_verifications:
        audit_records = session.exec(
            select(DomainVerificationAudit)
            .where(DomainVerificationAudit.verification_id == verification.id)
        ).all()
        for audit in audit_records:
            session.delete(audit)
    
    session.commit()
    
    for verification in pending_verifications:
        session.delete(verification)
    
    session.commit()
    
    return {
        "message": f"Deleted {len(pending_verifications)} pending verification request(s) for {domain}. You can now request a new token.",
        "domain": domain,
        "deleted_count": len(pending_verifications)
    }


@router.post("/verify/check", response_model=VerifyCheckResponse)
def check_verification(
    body: VerifyCheckBody,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    user_email = current_user["email"]
    
    if body.verification_id:
        verification = session.get(DomainVerification, body.verification_id)
        if not verification or verification.user_email != user_email:
            raise HTTPException(
                status_code=404,
                detail="Verification record not found or does not belong to you"
            )
        domain = verification.domain
    elif body.domain:
        domain = body.domain.lower().strip()
        domain = domain.replace("http://", "").replace("https://", "")
        domain = domain.split("/")[0]
        verification = session.exec(
            select(DomainVerification)
            .where(DomainVerification.domain == domain)
            .where(DomainVerification.user_email == user_email)
            .where(DomainVerification.token_expires_at > datetime.utcnow())
            .order_by(DomainVerification.token_created_at.desc())
        ).first()
        
        if not verification:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "no_token_found",
                    "message": f"No valid verification request found for {domain}. Please request a token first using POST /api/domains/verify/request",
                    "domain": domain
                }
            )
    else:
        raise HTTPException(
            status_code=400,
            detail="Either 'domain' or 'verification_id' must be provided"
        )
    
    result = check_token_on_site(session, verification.id)
    
    return VerifyCheckResponse(
        domain=domain,
        verified=result["verified"],
        method=result.get("method"),
        details=result["details"],
        verified_at=result.get("verified_at")
    )


@router.get("/{domain}/status", response_model=DomainStatusResponse)
def get_domain_status(
    domain: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    domain = domain.lower().strip()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0]
    user_email = current_user["email"]
    
    verification = session.exec(
        select(DomainVerification)
        .where(DomainVerification.domain == domain)
        .where(DomainVerification.user_email == user_email)
        .where(DomainVerification.verified == True)
        .order_by(DomainVerification.verified_at.desc())
    ).first()
    
    if not verification:
        return DomainStatusResponse(
            domain=domain,
            verified=False,
            verified_at=None,
            verified_by_method=None,
            expires_at=None
        )
    
    return DomainStatusResponse(
        domain=domain,
        verified=True,
        verified_at=verification.verified_at.isoformat() if verification.verified_at else None,
        verified_by_method=verification.verified_by_method,
        expires_at=verification.token_expires_at.isoformat()
    )


@router.get("/list", response_model=List[DomainListItem])
def list_verified_domains(
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    user_email = current_user["email"]
    
    verifications = session.exec(
        select(DomainVerification)
        .where(DomainVerification.user_email == user_email)
        .where(DomainVerification.verified == True)
        .order_by(DomainVerification.verified_at.desc())
    ).all()
    
    return [
        DomainListItem(
            domain=v.domain,
            verified=v.verified,
            verified_at=v.verified_at.isoformat() if v.verified_at else None,
            verified_by_method=v.verified_by_method,
            expires_at=v.token_expires_at.isoformat()
        )
        for v in verifications
    ]
