import json
import logging
import time
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from sqlmodel import Session, select, SQLModel

from src.auth import get_current_user

from src.core.database import get_session
from src.core.models import (
    Scan,
    Finding,
    ScanCreate,
    ScanRead,
    ScanDetail,
    ScanCreateResponse,
    ScanStatus,
    FindingRead,
    FindingCreate,
    DomainVerification,
    create_scan as db_create_scan,
    get_scan as db_get_scan,
    get_scans as db_get_scans,
    get_findings_for_scan,
    create_finding as db_create_finding,
    update_scan_status as db_update_scan_status,
    get_risk_label,
)
from src.core.config import settings
from src.utils.reports import generate_json_report, generate_pdf_report
from src.utils.cache import cache, CacheKeys
from src.utils.verification import save_verification_request, domain_is_verified
from src.utils.errors import (
    invalid_url_error,
    active_consent_required_error
)

logger = logging.getLogger(__name__)

try:
    from google import genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


router = APIRouter(tags=["scans"])


def get_user_scan(session: Session, scan_id: str, user_email: str) -> Scan:
    scan = db_get_scan(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.user_email != user_email:
        raise HTTPException(status_code=403, detail="Access denied to this scan")
    
    return scan


@router.post("/scans", response_model=ScanCreateResponse)
def create_scan(
    scan: ScanCreate,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    user_email = current_user["email"]
    parsed_url = urlparse(scan.url)
    domain = parsed_url.netloc.lower()
    
    if not domain:
        raise invalid_url_error(scan.url)
    
    if parsed_url.scheme == "http":
        logger.warning(f"User {user_email} is scanning HTTP (not HTTPS) domain: {domain}")
    
    is_verified = domain_is_verified(session, domain, user_email)
    
    if not is_verified:
        logger.warning(f"Domain {domain} not verified for user {user_email}, blocking scan")
        
        unexpired_token = session.exec(
            select(DomainVerification)
            .where(DomainVerification.domain == domain)
            .where(DomainVerification.user_email == user_email)
            .where(DomainVerification.token_expires_at > datetime.now(timezone.utc))
            .where(DomainVerification.verified == False)
            .order_by(DomainVerification.token_created_at.desc())
        ).first()
        
        if unexpired_token:
            instructions = {
                "file": {
                    "path": "/.well-known/vibesecure-verification.txt",
                    "content": "vibesecure-verify=<your-token>"
                },
                "meta": "<meta name='vibesecure-verify' content='<your-token>' />",
                "header": {
                    "name": "X-VibeSecure-Verify",
                    "value": "<your-token>"
                }
            }
            
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "domain_verification_required",
                    "message": f"You must verify ownership of {domain} before scanning. A verification token was already generated. Place the token using one of the methods below, then call POST /api/domains/verify/check",
                    "verification": {
                        "domain": domain,
                        "instructions": instructions,
                        "expires_at": unexpired_token.token_expires_at.isoformat(),
                        "help": "Use POST /api/domains/verify/request to get the token again if needed"
                    }
                }
            )
        
        try:
            token, verification_record = save_verification_request(session, domain, user_email)
            
            if not token:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "domain_verification_required",
                        "message": f"Domain {domain} requires verification. A token already exists.",
                        "help": "Use POST /api/domains/verify/request to manage your verification token"
                    }
                )
            
            instructions = {
                "file": {
                    "path": "/.well-known/vibesecure-verification.txt",
                    "content": f"vibesecure-verify={token}"
                },
                "meta": f"<meta name='vibesecure-verify' content='{token}' />",
                "header": {
                    "name": "X-VibeSecure-Verify",
                    "value": token
                }
            }
            
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "domain_verification_required",
                    "message": f"Verify ownership of {domain} before scanning. A verification token has been generated.",
                    "verification": {
                        "domain": domain,
                        "token": token,
                        "instructions": instructions,
                        "expires_at": verification_record.token_expires_at.isoformat(),
                        "next_steps": [
                            "1. Place the token using one of the three methods (file, meta tag, or header)",
                            "2. Call POST /api/domains/verify/check with your domain",
                            "3. Once verified, retry your scan request"
                        ]
                    }
                }
            )
        except HTTPException as he:
            raise he
        except Exception as e:
            logger.error(f"Failed to generate verification token for {domain}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to generate verification token: {str(e)}"
            )
    
    scan_options: Optional[Dict[str, Any]] = getattr(scan, 'options', None) or {}
    
    allow_active = scan_options.get("allow_active", False)
    
    if allow_active:
        logger.warning(f"Active scanning requested for {domain} by {user_email}")
        from src.core.models import Consent
        
        consent = session.exec(
            select(Consent)
            .where(Consent.domain == domain)
            .where(Consent.user_email == user_email)
            .where(Consent.active_allowed == True)
        ).first()
        
        if not consent:
            logger.error(f"Active scanning BLOCKED for {domain} - no consent found")
            raise active_consent_required_error(domain, user_email)
    
    db_scan = db_create_scan(session, scan)
    db_scan.user_email = user_email
    db_scan.verification_id = is_verified.id
    db_scan.options = scan_options
    
    session.add(db_scan)
    session.commit()
    session.refresh(db_scan)

    try:
        from celery import Celery
        celery_app = Celery(broker=settings.redis_url)
        task = celery_app.send_task("src.worker.tasks.process_scan", args=[db_scan.id, db_scan.url])
        db_scan.celery_task_id = task.id
        session.add(db_scan)
        session.commit()
    except Exception as e:
        logger.error(f"Could not enqueue Celery task for scan {db_scan.id}: {e}")
        print(f"Warning: Could not enqueue Celery task: {e}")

    return ScanCreateResponse(id=db_scan.id, status=db_scan.status)


@router.get("/scans", response_model=List[ScanRead])
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    user_email = current_user["email"]
    statement = select(Scan).where(Scan.user_email == user_email).offset(skip).limit(limit)
    scans = session.exec(statement).all()
    
    scan_reads = []
    for scan in scans:
        scan_dict = scan.model_dump()
        scan_dict["risk_label"] = get_risk_label(scan.risk_score)
        scan_dict["scan_confidence"] = scan.scan_confidence
        scan_reads.append(ScanRead(**scan_dict))
    
    return scan_reads


@router.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    user_email = current_user["email"]
    scan = get_user_scan(session, scan_id, user_email)
    scan_detail = ScanDetail.from_scan(scan)
    return scan_detail


@router.get("/scans/{scan_id}/findings", response_model=List[FindingRead])
def get_scan_findings(
    scan_id: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    user_email = current_user["email"]
    get_user_scan(session, scan_id, user_email)
    findings = get_findings_for_scan(session, scan_id)
    return findings


@router.post("/scans/{scan_id}/findings", response_model=FindingRead)
def create_finding(
    scan_id: str,
    finding: FindingCreate,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    user_email = current_user["email"]
    get_user_scan(session, scan_id, user_email)
    
    finding.scan_id = scan_id
    return db_create_finding(session, finding)


class ScanStatusUpdate(SQLModel):
    status: str
    started: bool = False
    finished: bool = False
    result: Optional[dict] = None


@router.patch("/internal/scans/{scan_id}/status")
def update_scan_status_internal(
    scan_id: str,
    update: ScanStatusUpdate,
    session: Session = Depends(get_session),
):
    scan = db_get_scan(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        status_enum = ScanStatus(update.status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {update.status}")
    
    updated_scan = db_update_scan_status(
        session, scan_id, status=status_enum, started=update.started, finished=update.finished
    )
    
    if update.result and updated_scan:
        updated_scan.result = json.dumps(update.result)
        session.add(updated_scan)
        session.commit()
    
    CacheKeys.invalidate_scan(scan_id)
    
    return {"status": "ok", "scan_id": scan_id, "new_status": update.status}


@router.get("/scans/{scan_id}/report")
def get_scan_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|pdf)$"),
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    user_email = current_user["email"]
    scan = get_user_scan(session, scan_id, user_email)
    
    if format == "pdf":
        cache_key = CacheKeys.SCAN_REPORT_PDF.format(scan_id=scan_id)
        cached_pdf = cache.get_binary(cache_key)
        
        if cached_pdf:
            return Response(
                content=cached_pdf,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="vibesecure_security_report_{scan_id}.pdf"',
                },
            )
        
        findings = get_findings_for_scan(session, scan_id)
        pdf_bytes = generate_pdf_report(scan, findings)
        
        if scan.status in [ScanStatus.done, ScanStatus.failed]:
            cache.set_binary(cache_key, pdf_bytes, ttl=86400)
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="vibesecure_security_report_{scan_id}.pdf"',
            },
        )
    
    cache_key = CacheKeys.SCAN_REPORT_JSON.format(scan_id=scan_id)
    cached_report = cache.get_json(cache_key)
    
    if cached_report:
        return JSONResponse(
            content=cached_report,
            headers={"Content-Disposition": f'attachment; filename="vibesecure_security_report_{scan_id}.json"'},
        )
    
    findings = get_findings_for_scan(session, scan_id)
    report = generate_json_report(scan, findings)
    
    if scan.status in [ScanStatus.done, ScanStatus.failed]:
        cache.set_json(cache_key, report, ttl=86400)
    
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="vibesecure_security_report_{scan_id}.json"'},
    )


@router.get("/scans/{scan_id}/ai-summary")
def get_ai_summary(
    scan_id: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    user_email = current_user["email"]
    
    if not GEMINI_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="AI summary feature is not available. Missing google-generativeai package."
        )
    
    if not settings.gemini_api_key:
        raise HTTPException(
            status_code=503,
            detail="AI summary feature is not configured. GEMINI_API_KEY is required."
        )
    
    scan = db_get_scan(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.user_email != user_email:
        raise HTTPException(status_code=403, detail="Access denied to this scan")
    
    if scan.status != ScanStatus.done:
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not completed yet. Current status: {scan.status}"
        )
    
    cache_key = CacheKeys.SCAN_AI_SUMMARY.format(scan_id=scan_id)
    cached_summary = cache.get_json(cache_key)
    if cached_summary:
        return JSONResponse(content=cached_summary)
    
    findings = get_findings_for_scan(session, scan_id)
    
    if not findings:
        return JSONResponse(content={
            "scan_id": scan_id,
            "url": scan.url,
            "summary": "No security findings detected. The scan completed successfully with no vulnerabilities identified.",
            "checklist": []
        })
    
    findings_data = []
    for finding in findings:
        findings_data.append({
            "title": finding.title,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "path": finding.path,
            "remediation": finding.remediation
        })
    
    client = genai.Client(api_key=settings.gemini_api_key)
    
    prompt = f"""You are a security expert analyzing web application security findings. 
    
Generate a prioritized fix checklist for the following security findings. Focus ONLY on safe remediation steps.

IMPORTANT RULES:
- DO NOT include any exploit code, payloads, or attack examples
- DO NOT show how to exploit the vulnerabilities
- ONLY provide safe, actionable remediation steps
- Prioritize by severity and confidence
- Be specific and practical

Scan URL: {scan.url}
Risk Score: {scan.risk_score or "N/A"}

Findings:
{json.dumps(findings_data, indent=2)}

Please provide:
1. A brief executive summary (2-3 sentences)
2. A prioritized checklist of fixes with:
   - Priority level (Critical/High/Medium/Low)
   - Finding title
   - Specific remediation action
   - Estimated effort (Quick/Medium/Long-term)

Format your response as JSON with this structure:
{{
  "summary": "Executive summary text",
  "checklist": [
    {{
      "priority": "Critical|High|Medium|Low",
      "title": "Finding title",
      "action": "Specific remediation step",
      "effort": "Quick|Medium|Long-term",
      "details": "Additional context if needed"
    }}
  ],
  "recommendations": ["General security best practice 1", "General security best practice 2"]
}}"""
    
    max_retries = 3
    retry_delay = 1 
    
    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model='gemini-3-flash-preview',
                contents=prompt
            )
            
            response_text = response.text
            
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            elif response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            
            response_text = response_text.strip()
            
            ai_summary = json.loads(response_text)
            
            ai_summary["scan_id"] = scan_id
            ai_summary["url"] = scan.url
            ai_summary["risk_score"] = scan.risk_score
            ai_summary["total_findings"] = len(findings)
            
            cache.set_json(cache_key, ai_summary, ttl=86400)
            
            return JSONResponse(content=ai_summary)
            
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to parse AI response: {str(e)}"
            )
        except Exception as e:
            error_msg = str(e).lower()
            is_retryable = any(code in error_msg for code in ['503', '500', '502', '504', '429', 'timeout', 'unavailable'])
            
            if attempt < max_retries - 1 and is_retryable:
                logger.warning(
                    f"AI summary attempt {attempt + 1} failed with retryable error: {str(e)}. "
                    f"Retrying in {retry_delay}s..."
                )
                time.sleep(retry_delay)
                retry_delay *= 2 
                continue
            
            logger.error(f"AI summary generation failed after {attempt + 1} attempts: {str(e)}")
            raise HTTPException(
                status_code=503 if is_retryable else 500,
                detail=f"AI summary generation failed: {str(e)}. Please try again later." if is_retryable else f"AI summary generation failed: {str(e)}"
            )


@router.get("/scans/{scan_id}/fix-config")
def get_fix_config(
    scan_id: str,
    platform: str = Query(..., description="Platform: vercel, netlify, nginx, or apache"),
    session: Session = Depends(get_session),
    current_user: dict = Depends(get_current_user)
):
    valid_platforms = ["vercel", "netlify", "nginx", "apache"]
    platform = platform.lower()
    if platform not in valid_platforms:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid platform. Must be one of: {', '.join(valid_platforms)}"
        )
    
    scan = db_get_scan(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.user_email != current_user["email"]:
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    
    findings = get_findings_for_scan(session, scan_id)
    
    missing_headers = {
        "hsts": False,
        "csp": False,
        "x_frame_options": False,
        "x_content_type_options": False,
        "referrer_policy": False,
        "permissions_policy": False,
    }
    
    for finding in findings:
        title_lower = finding.title.lower()
        if "hsts" in title_lower or "strict-transport-security" in title_lower:
            missing_headers["hsts"] = True
        if "content-security-policy" in title_lower or "csp" in title_lower:
            missing_headers["csp"] = True
        if "x-frame-options" in title_lower or "clickjacking" in title_lower:
            missing_headers["x_frame_options"] = True
        if "x-content-type-options" in title_lower or "mime" in title_lower:
            missing_headers["x_content_type_options"] = True
        if "referrer-policy" in title_lower:
            missing_headers["referrer_policy"] = True
        if "permissions-policy" in title_lower:
            missing_headers["permissions_policy"] = True
    
    config = generate_platform_config(platform, missing_headers, scan.url)
    
    return JSONResponse(content={
        "scan_id": scan_id,
        "platform": platform,
        "url": scan.url,
        "config": config,
        "filename": get_config_filename(platform),
        "instructions": get_platform_instructions(platform)
    })


def generate_platform_config(platform: str, missing_headers: dict, url: str) -> str:
    
    if platform == "vercel":
        return generate_vercel_config(missing_headers, url)
    elif platform == "netlify":
        return generate_netlify_config(missing_headers, url)
    elif platform == "nginx":
        return generate_nginx_config(missing_headers, url)
    elif platform == "apache":
        return generate_apache_config(missing_headers, url)
    
    return ""


def generate_vercel_config(headers: dict, url: str) -> str:
    
    header_configs = []
    
    if headers["hsts"]:
        header_configs.append('      { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" }')
    
    if headers["csp"]:
        header_configs.append('      { "key": "Content-Security-Policy", "value": "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:; font-src \'self\' data:; connect-src \'self\'; frame-ancestors \'none\'" }')
    
    if headers["x_frame_options"]:
        header_configs.append('      { "key": "X-Frame-Options", "value": "DENY" }')
    
    if headers["x_content_type_options"]:
        header_configs.append('      { "key": "X-Content-Type-Options", "value": "nosniff" }')
    
    if headers["referrer_policy"]:
        header_configs.append('      { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }')
    
    if headers["permissions_policy"]:
        header_configs.append('      { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" }')
    
    headers_json = ",\n".join(header_configs) if header_configs else '      { "key": "X-Content-Type-Options", "value": "nosniff" }'
    
    return f"""{{
  "headers": [
    {{
      "source": "/(.*)",
      "headers": [
{headers_json}
      ]
    }}
  ]
}}"""


def generate_netlify_config(headers: dict, url: str) -> str:
    
    header_lines = ["/*"]
    
    if headers["hsts"]:
        header_lines.append("  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
    
    if headers["csp"]:
        header_lines.append("  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
    
    if headers["x_frame_options"]:
        header_lines.append("  X-Frame-Options: DENY")
    
    if headers["x_content_type_options"]:
        header_lines.append("  X-Content-Type-Options: nosniff")
    
    if headers["referrer_policy"]:
        header_lines.append("  Referrer-Policy: strict-origin-when-cross-origin")
    
    if headers["permissions_policy"]:
        header_lines.append("  Permissions-Policy: camera=(), microphone=(), geolocation=()")
    
    if len(header_lines) == 1:
        header_lines.append("  X-Content-Type-Options: nosniff")
    
    return "\n".join(header_lines)


def generate_nginx_config(headers: dict, url: str) -> str:
    
    header_lines = []
    
    if headers["hsts"]:
        header_lines.append('    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;')
    
    if headers["csp"]:
        header_lines.append('    add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:; font-src \'self\' data:; connect-src \'self\'; frame-ancestors \'none\'" always;')
    
    if headers["x_frame_options"]:
        header_lines.append('    add_header X-Frame-Options "DENY" always;')
    
    if headers["x_content_type_options"]:
        header_lines.append('    add_header X-Content-Type-Options "nosniff" always;')
    
    if headers["referrer_policy"]:
        header_lines.append('    add_header Referrer-Policy "strict-origin-when-cross-origin" always;')
    
    if headers["permissions_policy"]:
        header_lines.append('    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;')
    
    if not header_lines:
        header_lines.append('    add_header X-Content-Type-Options "nosniff" always;')
    
    config_block = "\n".join(header_lines)
    
    return f"""# Add this to your nginx server block
server {{
    # ... your existing configuration ...
    
{config_block}
    
    # ... rest of your configuration ...
}}"""


def generate_apache_config(headers: dict, url: str) -> str:
    
    header_lines = ["<IfModule mod_headers.c>"]
    
    if headers["hsts"]:
        header_lines.append('    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"')
    
    if headers["csp"]:
        header_lines.append('    Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:; font-src \'self\' data:; connect-src \'self\'; frame-ancestors \'none\'"')
    
    if headers["x_frame_options"]:
        header_lines.append('    Header always set X-Frame-Options "DENY"')
    
    if headers["x_content_type_options"]:
        header_lines.append('    Header always set X-Content-Type-Options "nosniff"')
    
    if headers["referrer_policy"]:
        header_lines.append('    Header always set Referrer-Policy "strict-origin-when-cross-origin"')
    
    if headers["permissions_policy"]:
        header_lines.append('    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"')
    
    if len(header_lines) == 1:
        header_lines.append('    Header always set X-Content-Type-Options "nosniff"')
    
    header_lines.append("</IfModule>")
    
    return "\n".join(header_lines)


def get_config_filename(platform: str) -> str:
    filenames = {
        "vercel": "vercel.json",
        "netlify": "_headers",
        "nginx": "nginx.conf",
        "apache": ".htaccess"
    }
    return filenames.get(platform, "config.txt")


def get_platform_instructions(platform: str) -> str:
    instructions = {
        "vercel": "1. Copy the configuration above\n2. Create/update vercel.json in your project root\n3. Commit and push to trigger deployment\n4. Vercel will automatically apply these headers",
        
        "netlify": "1. Copy the configuration above\n2. Create/update _headers file in your publish directory\n3. Commit and push to trigger deployment\n4. Netlify will automatically apply these headers",
        
        "nginx": "1. Copy the configuration above\n2. Add to your nginx server block configuration\n3. Test configuration: sudo nginx -t\n4. Reload nginx: sudo systemctl reload nginx",
        
        "apache": "1. Copy the configuration above\n2. Create/update .htaccess in your web root\n3. Ensure mod_headers is enabled: sudo a2enmod headers\n4. Restart Apache: sudo systemctl restart apache2"
    }
    return instructions.get(platform, "Copy the configuration and apply to your server")
