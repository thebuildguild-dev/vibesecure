import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
from celery import Task
from celery.exceptions import SoftTimeLimitExceeded

from src.worker.celery_app import celery_app, DATABASE_URL, BACKEND_URL
from src.worker.scanner import scan_url, ScanResult
from src.worker.checks.tls_checker import TLSChecker, check_tls
from src.worker.checks.cors_checker import CORSChecker, check_cors
from src.worker.checks.endpoint_checker import EndpointChecker, check_endpoints
from src.worker.checks.header_checker import HeaderChecker, check_headers
from src.worker.checks.https_checker import HTTPSChecker, check_https_redirect
from src.worker.checks.directory_checker import DirectoryChecker, check_directory_listing
from src.worker.checks.library_checker import LibraryChecker, check_libraries
from src.worker.checks.reflection_checker import ReflectionChecker, check_reflections
from src.services.email import send_scan_complete_email
from src.core.models import (
    Scan, 
    Finding, 
    ScanStatus, 
    Severity, 
    DomainVerification, 
    DomainVerificationAudit, 
    Consent
)
from sqlmodel import Session, create_engine, select

logger = logging.getLogger(__name__)
USE_DIRECT_DB = "postgresql" in DATABASE_URL.lower()

worker_engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

SEVERITY_PRIORITY = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

SECURITY_HEADER_KEYWORDS = [
    "hsts", "strict-transport-security", "content-security-policy", "csp",
    "x-frame-options", "clickjacking", "x-content-type-options",
    "mime-sniffing", "referrer-policy", "permissions-policy", "x-xss-protection",
]


def normalize_severity(severity: str) -> str:
    normalized = severity.lower().strip()
    
    if normalized not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of: "
            f"{', '.join(sorted(VALID_SEVERITIES))}"
        )
    
    return normalized


def deduplicate_findings(findings: list) -> list:
    if not findings:
        return []
    
    findings_by_title = {}
    
    for finding in findings:
        title = finding.get("title", "Untitled")
        severity_raw = finding.get("severity", "info")
        
        try:
            severity = normalize_severity(severity_raw)
            finding["severity"] = severity
        except ValueError:
            severity = "info"
            finding["severity"] = severity
        
        if title not in findings_by_title:
            findings_by_title[title] = finding
        else:
            existing_severity = findings_by_title[title].get("severity", "info")
            existing_priority = SEVERITY_PRIORITY.get(existing_severity, 0)
            new_priority = SEVERITY_PRIORITY.get(severity, 0)
            
            if new_priority > existing_priority:
                findings_by_title[title] = finding
    
    deduplicated = list(findings_by_title.values())
    
    return deduplicated


def classify_findings(all_findings: list) -> dict:
    categorized = {
        "tls_findings": 0,
        "cors_findings": 0,
        "endpoint_findings": 0,
        "header_findings": 0,
        "https_findings": 0,
        "directory_findings": 0,
        "library_findings": 0,
        "reflection_findings": 0,
        "other_findings": 0,
    }
    
    for finding in all_findings:
        title = finding.get("title", "").lower()
        
        is_header_finding = any(keyword in title for keyword in SECURITY_HEADER_KEYWORDS)
        
        if is_header_finding:
            categorized["header_findings"] += 1
        elif "tls" in title or "ssl" in title or "certificate" in title:
            categorized["tls_findings"] += 1
        elif "cors" in title or "cross-origin" in title:
            categorized["cors_findings"] += 1
        elif "endpoint" in title or "exposed" in title and ("path" in title or "api" in title):
            categorized["endpoint_findings"] += 1
        elif "https" in title or "redirect" in title and "http" in title:
            categorized["https_findings"] += 1
        elif "directory" in title or "listing" in title:
            categorized["directory_findings"] += 1
        elif "library" in title or "outdated" in title or "vulnerable" in title:
            categorized["library_findings"] += 1
        elif "reflection" in title or "reflected" in title or "parameter" in title:
            categorized["reflection_findings"] += 1
        else:
            categorized["other_findings"] += 1
    
    return categorized


def get_db_session():
    return Session(worker_engine)


def update_scan_status_db(
    scan_id: str,
    status: str,
    started: bool = False,
    finished: bool = False,
    result: Optional[dict] = None,
    risk_score: Optional[int] = None,
    scan_confidence: Optional[str] = None,
):
    
    with Session(worker_engine) as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found in database")
            return False
        
        scan.status = ScanStatus(status)
        if started:
            scan.started_at = datetime.now(timezone.utc)
        if finished:
            scan.finished_at = datetime.now(timezone.utc)
        if result:
            scan.result = json.dumps(result)
        if risk_score is not None:
            scan.risk_score = risk_score
        if scan_confidence is not None:
            scan.scan_confidence = scan_confidence
        
        session.add(scan)
        session.commit()
        logger.info(f"Updated scan {scan_id} status to {status} via DB")
        
        return {
            "success": True,
            "url": scan.url,
            "user_email": scan.user_email,
            "risk_score": scan.risk_score,
        }


def create_findings_db(scan_id: str, findings: list):
    
    with Session(worker_engine) as session:
        for f in findings:
            finding = Finding(
                scan_id=scan_id,
                title=f.get("title", "Untitled"),
                severity=Severity(f.get("severity", "info")),
                remediation=f.get("remediation"),
                confidence=f.get("confidence", 50),
                path=f.get("path"),
            )
            session.add(finding)
        session.commit()
        logger.info(f"Created {len(findings)} findings for scan {scan_id} via DB")


def update_scan_status_http(
    scan_id: str,
    status: str,
    started: bool = False,
    finished: bool = False,
    result: Optional[dict] = None,
    risk_score: Optional[int] = None,
    scan_confidence: Optional[str] = None,
):
    try:
        with httpx.Client(timeout=10) as client:
            payload = {
                "status": status,
                "started": started,
                "finished": finished,
                "result": result,
            }
            if risk_score is not None:
                payload["risk_score"] = risk_score
            if scan_confidence is not None:
                payload["scan_confidence"] = scan_confidence
                
            response = client.patch(
                f"{BACKEND_URL}/api/internal/scans/{scan_id}/status",
                json=payload,
            )
            response.raise_for_status()
            logger.info(f"Updated scan {scan_id} status to {status} via HTTP")
            
            if status == "done" and risk_score is not None:
                try:
                    scan_response = client.get(f"{BACKEND_URL}/api/scans/{scan_id}")
                    scan_response.raise_for_status()
                    scan_data = scan_response.json()
                    return {
                        "success": True,
                        "url": scan_data.get("url"),
                        "user_email": scan_data.get("user_email"),
                        "risk_score": risk_score,
                    }
                except Exception as fetch_error:
                    logger.warning(f"Could not fetch scan data for email: {fetch_error}")
            
            return True
    except Exception as e:
        logger.error(f"Failed to update scan {scan_id} via HTTP: {e}")
        return False


def create_findings_http(scan_id: str, findings: list):
    try:
        with httpx.Client(timeout=30) as client:
            for finding in findings:
                finding["scan_id"] = scan_id
                response = client.post(
                    f"{BACKEND_URL}/api/findings",
                    json=finding,
                )
                response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to create findings via HTTP: {e}")


def update_scan_status(scan_id: str, status: str, **kwargs):
    if USE_DIRECT_DB:
        return update_scan_status_db(scan_id, status, **kwargs)
    else:
        return update_scan_status_http(scan_id, status, **kwargs)


def create_findings(scan_id: str, findings: list):
    if USE_DIRECT_DB:
        return create_findings_db(scan_id, findings)
    else:
        return create_findings_http(scan_id, findings)


class ScanTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        scan_id = args[0] if args else kwargs.get("scan_id")
        if scan_id:
            logger.error(f"Task {task_id} failed for scan {scan_id}: {exc}")
            try:
                update_scan_status(
                    scan_id,
                    status="failed",
                    finished=True,
                    result={"error": str(exc)},
                )
            except Exception as e:
                logger.error(f"Failed to update scan status on failure: {e}")


@celery_app.task(
    bind=True,
    base=ScanTask,
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(httpx.ConnectError, httpx.TimeoutException),
    retry_backoff=True,
)
def process_scan(self, scan_id: int, url: str):
    logger.info(f"[Scan {scan_id}] Starting scan of {url}")
    
    with Session(worker_engine) as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found in database")
            return
        
        user_email = scan.user_email
        verification_id = scan.verification_id
        
        if not verification_id:
            logger.error(f"[Scan {scan_id}] No verification_id set on scan record")
            update_scan_status(
                scan_id,
                status="failed",
                finished=True,
                result={
                    "error": "domain_verification_missing_at_execution",
                    "message": "Scan was created without domain verification. This should not happen."
                }
            )
            return
        
        verification = session.get(DomainVerification, verification_id)
        
        if not verification:
            logger.error(f"[Scan {scan_id}] Verification {verification_id} not found")
            update_scan_status(
                scan_id,
                status="failed",
                finished=True,
                result={
                    "error": "domain_verification_missing_at_execution",
                    "message": f"Verification record {verification_id} not found in database"
                }
            )
            
            audit_entry = DomainVerificationAudit(
                verification_id=verification_id,
                action="scan_blocked",
                details=f"Scan {scan_id} blocked: verification record not found"
            )
            session.add(audit_entry)
            session.commit()
            return
        
        if not verification.verified:
            logger.error(f"[Scan {scan_id}] Verification {verification_id} not verified")
            update_scan_status(
                scan_id,
                status="failed",
                finished=True,
                result={
                    "error": "domain_verification_missing_at_execution",
                    "message": f"Domain {verification.domain} verification is not completed"
                }
            )
            
            audit_entry = DomainVerificationAudit(
                verification_id=verification_id,
                action="scan_blocked",
                details=f"Scan {scan_id} blocked: domain not verified"
            )
            session.add(audit_entry)
            session.commit()
            return
        
        now = datetime.now(timezone.utc)
        token_expires_at = verification.token_expires_at
        if token_expires_at.tzinfo is None:
            token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)
        
        if token_expires_at < now:
            logger.error(f"[Scan {scan_id}] Verification {verification_id} expired")
            update_scan_status(
                scan_id,
                status="failed",
                finished=True,
                result={
                    "error": "domain_verification_missing_at_execution",
                    "message": f"Domain {verification.domain} verification has expired. Please re-verify.",
                    "expired_at": verification.token_expires_at.isoformat()
                }
            )
            
            audit_entry = DomainVerificationAudit(
                verification_id=verification_id,
                action="scan_blocked",
                details=f"Scan {scan_id} blocked: verification expired"
            )
            session.add(audit_entry)
            session.commit()
            return
        
        logger.info(f"[Scan {scan_id}] Domain {verification.domain} verified")
        
        scan_options = scan.options or {}
        allow_active = scan_options.get("allow_active", False)
        
        if allow_active:
            logger.warning(f"[Scan {scan_id}] Active scanning requested")
            
            consent = session.exec(
                select(Consent)
                .where(Consent.domain == verification.domain)
                .where(Consent.user_email == user_email)
                .where(Consent.active_allowed == True)
            ).first()
            
            if not consent:
                logger.error(f"[Scan {scan_id}] Active scan blocked - no consent")
                update_scan_status(
                    scan_id,
                    status="failed",
                    finished=True,
                    result={
                        "error": "active_consent_required",
                        "message": f"Active scanning requires explicit consent. Please verify consent at POST /api/consent/check for domain {verification.domain}",
                        "domain": verification.domain,
                        "allow_active": True,
                    }
                )
                
                audit_entry = DomainVerificationAudit(
                    verification_id=verification_id,
                    action="active_scan_blocked",
                    details=f"Scan {scan_id} blocked: active scanning requested but no consent found for {verification.domain}"
                )
                session.add(audit_entry)
                session.commit()
                return
            
            logger.warning(f"[Scan {scan_id}] Active scan consent GRANTED for {verification.domain} (verified_at={consent.verified_at})")
            
            audit_entry_active = DomainVerificationAudit(
                verification_id=verification_id,
                action="active_scan_authorized",
                details=f"Scan {scan_id} authorized for ACTIVE scanning on {verification.domain} (consent_id={consent.id}, user={user_email})"
            )
            session.add(audit_entry_active)
            session.commit()
        
        scan.result = json.dumps({
            "verification_id": verification_id,
            "verification_domain": verification.domain,
            "verification_method": verification.verified_by_method,
            "verification_timestamp": verification.verified_at.isoformat() if verification.verified_at else None
        })
        session.add(scan)
        session.commit()
        
        audit_entry = DomainVerificationAudit(
            verification_id=verification_id,
            action="scan_started",
            details=f"Scan {scan_id} started for domain {verification.domain} (user: {user_email})"
        )
        session.add(audit_entry)
        session.commit()

        target_url = url
        if "localhost" in url or "127.0.0.1" in url:
            target_url = url.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")
            logger.info(f"[Scan {scan_id}] Adjusted URL for Docker environment: {url} -> {target_url}")
    
    try:
        update_scan_status(scan_id, status="running", started=True)
        
        check_errors = []
        
        tls_findings = []
        try:
            tls_findings = check_tls(target_url)
        except Exception:
            check_errors.append("tls")
        
        cors_findings = []
        try:
            cors_findings = check_cors(target_url)
        except Exception:
            check_errors.append("cors")
        
        endpoint_findings = []
        try:
            endpoint_findings = check_endpoints(target_url)
        except Exception:
            check_errors.append("endpoint")
        
        header_findings = []
        try:
            header_findings = check_headers(target_url)
        except Exception:
            check_errors.append("header")
        
        https_findings = []
        try:
            https_findings = check_https_redirect(target_url)
        except Exception:
            check_errors.append("https")
        
        directory_findings = []
        try:
            directory_findings = check_directory_listing(target_url)
        except Exception:
            check_errors.append("directory")
        
        library_findings = []
        try:
            library_findings = check_libraries(target_url)
        except Exception:
            check_errors.append("library")
        
        reflection_findings = []
        try:
            reflection_findings = check_reflections(target_url)
        except Exception:
            check_errors.append("reflection")
        
        with Session(worker_engine) as session:
            scan = session.get(Scan, scan_id)
            scan_options = scan.options if scan else {}
            verification = session.get(DomainVerification, verification_id)
        
        result: ScanResult = scan_url(
            target_url,
            timeout=60,
            options=scan_options,
            verification=verification,
        )
        
        if not result.success:
            logger.warning(f"[Scan {scan_id}] Scan failed: {result.error}")
            update_scan_status(
                scan_id,
                status="failed",
                finished=True,
                scan_confidence="low",
                result={
                    "error": result.error,
                    "duration_seconds": result.duration_seconds,
                },
            )
            return {
                "status": "failed",
                "scan_id": scan_id,
                "error": result.error,
            }
        
        total_checks = 9
        error_count = len(check_errors)
        
        if error_count <= 1:
            scan_confidence = "high"
        elif error_count <= 3:
            scan_confidence = "medium"
        else:
            scan_confidence = "low"
        
        all_findings = tls_findings + cors_findings + endpoint_findings + header_findings + https_findings + directory_findings + library_findings + reflection_findings + (result.findings if result.findings else [])
        
        all_findings = deduplicate_findings(all_findings)
        
        zap_findings_count = 0
        if allow_active:
            try:
                from src.worker.zap_client import zap_baseline_scan, is_zap_available
                
                if is_zap_available():
                    zap_findings = zap_baseline_scan(
                        target_url=target_url,
                        verification_id=verification_id,
                    )
                    
                    zap_findings_count = len(zap_findings)
                    
                    for finding in zap_findings:
                        if "details" not in finding:
                            finding["details"] = {}
                        finding["details"]["source"] = "zap"
                    
                    existing_keys = set()
                    for f in all_findings:
                        key = (f.get("title", ""), f.get("path", f.get("url", "")))
                        existing_keys.add(key)
                    
                    new_zap_findings = []
                    for zap_finding in zap_findings:
                        key = (zap_finding.get("title", ""), zap_finding.get("path", zap_finding.get("url", "")))
                        if key not in existing_keys:
                            new_zap_findings.append(zap_finding)
                            existing_keys.add(key)
                    
                    all_findings.extend(new_zap_findings)
                    
                else:
                    all_findings.append({
                        "title": "ZAP active scan unavailable",
                        "severity": "info",
                        "remediation": "ZAP container is not running. Start with: docker-compose up -d zap",
                        "confidence": 100,
                        "path": url,
                        "details": {
                            "source": "zap",
                            "error": "ZAP service not accessible",
                        }
                    })
                    
            except Exception as e:
                logger.error(f"[Scan {scan_id}] ZAP scan failed: {e}")
                all_findings.append({
                    "title": "ZAP active scan error",
                    "severity": "info",
                    "remediation": f"ZAP scan encountered an error: {str(e)}",
                    "confidence": 100,
                    "path": url,
                    "details": {
                        "source": "zap",
                        "error": str(e),
                    }
                })
        
        finding_categories = classify_findings(all_findings)
        
        if all_findings:
            create_findings(scan_id, all_findings)
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in all_findings:
            severity = finding.get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        severity_weights = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 1}
        risk_score = sum(severity_counts.get(sev, 0) * weight for sev, weight in severity_weights.items())
        max_possible = 100
        normalized_risk = min(100, int((risk_score / max_possible) * 100)) if risk_score > 0 else 0
        
        scan_data = update_scan_status(
            scan_id,
            status="done",
            finished=True,
            risk_score=normalized_risk,
            scan_confidence=scan_confidence,
            result={
                "findings_count": len(all_findings),
                "tls_findings": finding_categories["tls_findings"],
                "cors_findings": finding_categories["cors_findings"],
                "endpoint_findings": finding_categories["endpoint_findings"],
                "header_findings": finding_categories["header_findings"],
                "https_findings": finding_categories["https_findings"],
                "directory_findings": finding_categories["directory_findings"],
                "library_findings": finding_categories["library_findings"],
                "reflection_findings": finding_categories["reflection_findings"],
                "other_findings": finding_categories["other_findings"],
                "zap_findings_count": zap_findings_count,
                "active_scan_enabled": allow_active,
                "duration_seconds": result.duration_seconds,
                "metadata": result.metadata,
                "scan_confidence": scan_confidence,
                "errors_encountered": error_count,
            },
        )
        
        try:
            if scan_data and isinstance(scan_data, dict) and scan_data.get("user_email"):
                send_scan_complete_email(
                    to_email=scan_data["user_email"],
                    scan_url=scan_data["url"],
                    risk_score=normalized_risk,
                    scan_id=scan_id
                )
        except Exception:
            pass
        
        logger.info(f"[Scan {scan_id}] Completed: {len(all_findings)} findings in {result.duration_seconds:.2f}s")
        
        return {
            "status": "done",
            "scan_id": scan_id,
            "findings_count": len(all_findings),
            "finding_categories": finding_categories,
            "duration_seconds": result.duration_seconds,
            "scan_confidence": scan_confidence,
        }
        
    except SoftTimeLimitExceeded:
        logger.error(f"[Scan {scan_id}] Task timed out")
        update_scan_status(
            scan_id,
            status="failed",
            finished=True,
            result={"error": "Scan timed out"},
        )
        raise
        
    except Exception as exc:
        logger.exception(f"[Scan {scan_id}] Unexpected error: {exc}")
        
        if self.request.retries < self.max_retries:
            logger.info(f"[Scan {scan_id}] Retrying ({self.request.retries + 1}/{self.max_retries})...")
            raise self.retry(exc=exc)
        
        update_scan_status(
            scan_id,
            status="failed",
            finished=True,
            result={"error": str(exc)},
        )
        raise


@celery_app.task(bind=True)
def health_check(self):
    """Health check task for monitoring."""
    return {
        "status": "ok",
        "task_id": self.request.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db_mode": "direct" if USE_DIRECT_DB else "http",
    }
