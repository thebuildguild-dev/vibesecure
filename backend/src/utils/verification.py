import hashlib
import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import httpx
from sqlmodel import Session, select
from fastapi import HTTPException

from src.core.models import DomainVerification, DomainVerificationAudit
from src.core.config import settings
from src.utils.errors import rate_limit_error
from src.utils.domain import handle_localhost
from src.utils.http_client import HTTPClientFactory

logger = logging.getLogger(__name__)


def generate_token() -> str:
    return str(uuid.uuid4())


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def save_verification_request(
    session: Session, 
    domain: str, 
    user_email: str
) -> Tuple[str, DomainVerification]:
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)
    
    existing_unexpired = session.exec(
        select(DomainVerification)
        .where(DomainVerification.domain == domain)
        .where(DomainVerification.user_email == user_email)
        .where(DomainVerification.token_expires_at > now)
        .where(DomainVerification.verified == False)
        .order_by(DomainVerification.token_created_at.desc())
    ).first()
    
    if existing_unexpired:
        return "", existing_unexpired
    
    domain_requests_count = session.exec(
        select(DomainVerification)
        .where(DomainVerification.domain == domain)
        .where(DomainVerification.token_created_at >= yesterday)
    ).all()
    
    if len(domain_requests_count) >= settings.domain_verification_max_requests_per_domain_per_day:
        logger.warning(f"Rate limit exceeded for domain {domain}")
        raise rate_limit_error(
            f"domain {domain}",
            settings.domain_verification_max_requests_per_domain_per_day
        )
    
    user_requests_count = session.exec(
        select(DomainVerification)
        .where(DomainVerification.user_email == user_email)
        .where(DomainVerification.token_created_at >= yesterday)
    ).all()
    
    if len(user_requests_count) >= settings.domain_verification_max_requests_per_user_per_day:
        logger.warning(f"Rate limit exceeded for user {user_email}")
        raise rate_limit_error(
            "user",
            settings.domain_verification_max_requests_per_user_per_day
        )
    
    token = generate_token()
    token_hash_value = hash_token(token)
    expires_at = now + timedelta(days=settings.domain_verification_token_ttl_days)
    
    verification_record = DomainVerification(
        domain=domain,
        user_email=user_email,
        token_hash=token_hash_value,
        token_created_at=now,
        token_expires_at=expires_at,
        verified=False
    )
    
    session.add(verification_record)
    session.commit()
    session.refresh(verification_record)
    
    audit_entry = DomainVerificationAudit(
        verification_id=verification_record.id,
        action="request_token",
        details=f"Token generated for domain {domain} by user {user_email}"
    )
    session.add(audit_entry)
    session.commit()
    
    return token, verification_record


def check_token_on_site(session: Session, verification_id: str) -> dict:
    verification = session.get(DomainVerification, verification_id)
    if not verification:
        logger.error(f"Verification record {verification_id} not found")
        return {
            "verified": False,
            "method": None,
            "details": "Verification record not found"
        }
    
    domain = verification.domain
    verification.last_checked_at = datetime.now(timezone.utc)
    
    base_urls = []
    
    candidates = handle_localhost(domain)
        
    for d in candidates:
        if ':' in d and not d.startswith('['):
            base_urls.extend([f"https://{d}", f"http://{d}"])
        else:
            base_urls.extend([f"https://{d}", f"http://{d}"])
    
    methods_to_try = []
    for base_url in base_urls:
        methods_to_try.append(("file", f"{base_url}/.well-known/vibesecure-verification.txt"))
        methods_to_try.append(("meta", f"{base_url}/"))
        methods_to_try.append(("header", f"{base_url}/"))
    
    mismatch_details = []

    with HTTPClientFactory.get_client(timeout=5.0) as client:
        for method, url in methods_to_try:
            try:
                response = client.get(url)
                token_from_site = None
                
                if method == "file":
                    content = response.text
                    if "vibesecure-verify=" in content:
                        token_from_site = content.split("vibesecure-verify=")[1].strip().split()[0]
                
                elif method == "meta":
                    content = response.text.lower()
                    if "vibesecure-verify" in content:
                        import re
                        match = re.search(r'vibesecure-verify["\']?\s*[=:]\s*["\']?([a-f0-9-]{36})', content, re.IGNORECASE)
                        if match:
                            token_from_site = match.group(1)
                
                elif method == "header" and settings.domain_verification_allow_header:
                    header_value = response.headers.get("X-VibeSecure-Verify", "")
                    if header_value:
                        token_from_site = header_value.strip()

                if token_from_site:
                    matched_record = None
                    hashed_token = hash_token(token_from_site)
                    
                    if hashed_token == verification.token_hash:
                        matched_record = verification
                    else:
                        others = session.exec(
                            select(DomainVerification)
                            .where(DomainVerification.domain == verification.domain)
                            .where(DomainVerification.user_email == verification.user_email)
                            .where(DomainVerification.verified == False)
                            .where(DomainVerification.id != verification.id)
                        ).all()
                        
                        for other in others:
                            if hashed_token == other.token_hash:
                                matched_record = other
                                break
                    
                    if matched_record:
                        matched_record.verified = True
                        matched_record.verified_at = datetime.now(timezone.utc)
                        matched_record.verified_by_method = method
                        session.add(matched_record)
                        session.commit()
                        
                        audit_entry = DomainVerificationAudit(
                            verification_id=matched_record.id,
                            action="verified",
                            details=f"Domain {domain} verified via {method}"
                        )
                        session.add(audit_entry)
                        session.commit()
                        
                        return {
                            "verified": True,
                            "method": method,
                            "details": f"Successfully verified via {method}",
                            "verified_at": matched_record.verified_at.isoformat()
                        }
                    else:
                        msg = f"Token hash mismatch for {domain} via {method}. Site has {token_from_site[:8]}..."
                        logger.warning(msg)
                        mismatch_details.append(msg)
            
            except httpx.TimeoutException as e:
                error_msg = f"Timeout checking {method} for {domain}: {str(e)}"
                logger.warning(error_msg)
                audit_entry = DomainVerificationAudit(
                    verification_id=verification_id,
                    action="failed_check",
                    details=error_msg
                )
                session.add(audit_entry)
                continue
            except httpx.HTTPStatusError as e:
                error_msg = f"HTTP {e.response.status_code} checking {method} for {domain}"
                logger.warning(error_msg)
                audit_entry = DomainVerificationAudit(
                    verification_id=verification_id,
                    action="failed_check",
                    details=error_msg
                )
                session.add(audit_entry)
                continue
            except httpx.RequestError as e:
                error_msg = f"Request error checking {method} for {domain}: {str(e)}"
                logger.warning(error_msg)
                audit_entry = DomainVerificationAudit(
                    verification_id=verification_id,
                    action="failed_check",
                    details=error_msg
                )
                session.add(audit_entry)
                continue
            except Exception as e:
                error_msg = f"Unexpected error checking {method} for {domain}: {str(e)}"
                logger.error(error_msg)
                audit_entry = DomainVerificationAudit(
                    verification_id=verification_id,
                    action="failed_check",
                    details=error_msg
                )
                session.add(audit_entry)
                continue
    session.add(verification)
    
    audit_entry = DomainVerificationAudit(
        verification_id=verification_id,
        action="failed_check",
        details=f"Verification failed for domain {domain}. Token not found via any method."
    )
    session.add(audit_entry)
    session.commit()
    
    details_msg = "Token not found via file, meta tag, or header. Please ensure the token is correctly placed."
    if mismatch_details:
        details_msg = f"Token found but mismatched: {'; '.join(mismatch_details)}"

    return {
        "verified": False,
        "method": None,
        "details": details_msg
    }


def domain_is_verified(
    session: Session,
    domain: str,
    user_email: str
) -> Optional[DomainVerification]:
    now = datetime.now(timezone.utc)
    
    verification = session.exec(
        select(DomainVerification)
        .where(DomainVerification.domain == domain)
        .where(DomainVerification.user_email == user_email)
        .where(DomainVerification.verified == True)
        .where(DomainVerification.token_expires_at > now)
        .order_by(DomainVerification.verified_at.desc())
    ).first()
    
    return verification
