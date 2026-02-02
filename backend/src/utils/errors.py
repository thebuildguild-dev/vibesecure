from typing import Optional, Dict, Any
from fastapi import HTTPException, status


def domain_not_verified_error(domain: str, instructions: Optional[Dict[str, Any]] = None) -> HTTPException:
    detail = {
        "error": "domain_verification_required",
        "message": f"Domain {domain} is not verified. Complete domain verification first.",
        "domain": domain
    }
    
    if instructions:
        detail["verification"] = instructions
    
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=detail
    )


def active_consent_required_error(domain: str, user_email: str) -> HTTPException:
    from src.utils.consent import generate_consent_file_content
    
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "active_consent_required",
            "message": f"Active scanning requires explicit consent for {domain}. Please verify consent before enabling active scans.",
            "consent": {
                "domain": domain,
                "allow_active": False,
                "next_steps": [
                    "1. Request active scan consent: POST /api/consent/request with domain",
                    "2. Place consent file at /.well-known/vibesecure-consent.txt",
                    "3. Verify consent: POST /api/consent/check with domain",
                    "4. Retry scan with allow_active: true"
                ],
                "consent_file_path": "/.well-known/vibesecure-consent.txt",
                "consent_file_content": generate_consent_file_content(domain, user_email)
            }
        }
    )


def invalid_url_error(url: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "error": "invalid_url",
            "message": "Invalid URL provided. Please provide a valid URL with domain.",
            "url": url
        }
    )


def token_exists_error(domain: str, expires_at: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": "token_exists",
            "message": f"An unexpired verification token already exists for {domain}. Use POST /api/domains/verify/check to verify it, or wait for expiry.",
            "expires_at": expires_at
        }
    )


def no_token_found_error(domain: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": "no_token_found",
            "message": f"No valid verification request found for {domain}. Please request a token first using POST /api/domains/verify/request",
            "domain": domain
        }
    )


def rate_limit_error(entity: str, limit: int, period: str = "day") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"Rate limit exceeded for {entity}. Maximum {limit} requests per {period}."
    )
