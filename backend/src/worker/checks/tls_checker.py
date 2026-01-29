import ssl
import socket
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, field
from enum import Enum

import httpx

try:
    from src.core.config import settings
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
    from src.core.config import settings

logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT = settings.security_check_default_timeout
CERT_EXPIRY_WARNING_DAYS = settings.tls_cert_expiry_warning_days
CERT_EXPIRY_CRITICAL_DAYS = settings.tls_cert_expiry_critical_days


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TLSFinding:
    title: str
    severity: str
    description: str
    remediation: str
    confidence: int = 90
    path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "path": self.path,
        }


@dataclass
class CertificateInfo:
    subject: Dict[str, str]
    issuer: Dict[str, str]
    version: int
    serial_number: str
    not_before: datetime
    not_after: datetime
    subject_alt_names: List[str]
    is_valid: bool = True
    validation_error: Optional[str] = None


class TLSChecker:
    def __init__(self, target: str, port: int = 443, timeout: int = DEFAULT_TIMEOUT):
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            self.hostname = parsed.hostname or target
            self.original_url = target
        else:
            self.hostname = target
            self.original_url = f"https://{target}"
        
        self.port = port
        self.timeout = timeout
        self.findings: List[TLSFinding] = []
        self.cert_info: Optional[CertificateInfo] = None
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        self.check_certificate()
        self.check_https_redirect()
        self.check_protocol_versions()
        logger.info(f"TLS checks for {self.hostname}: {len(self.findings)} findings")
        return [f.to_dict() for f in self.findings]
    
    def check_certificate(self) -> List[TLSFinding]:
        cert_findings: List[TLSFinding] = []
        
        try:
            cert_info = self._get_certificate_info(verify=True)
            self.cert_info = cert_info
            expiry_findings = self._check_expiration(cert_info)
            cert_findings.extend(expiry_findings)
            
        except ssl.SSLCertVerificationError as e:
            finding = self._handle_verification_error(e)
            cert_findings.append(finding)
            
            try:
                cert_info = self._get_certificate_info(verify=False)
                self.cert_info = cert_info
                cert_info.is_valid = False
                cert_info.validation_error = str(e)
                expiry_findings = self._check_expiration(cert_info)
                cert_findings.extend(expiry_findings)
            except Exception:
                pass
                
        except ssl.SSLError as e:
            cert_findings.append(TLSFinding(
                title="SSL/TLS Connection Error",
                severity=Severity.HIGH.value,
                description=f"Could not establish SSL connection: {str(e)}",
                remediation="Verify SSL/TLS is properly configured on the server. Check that the port is correct and TLS is enabled.",
                confidence=95,
                path=f"{self.hostname}:{self.port}",
            ))
            
        except socket.timeout:
            cert_findings.append(TLSFinding(
                title="SSL Connection Timeout",
                severity=Severity.MEDIUM.value,
                description=f"Connection to {self.hostname}:{self.port} timed out after {self.timeout}s",
                remediation="Server may be slow or unreachable. Verify the hostname and network connectivity.",
                confidence=80,
                path=f"{self.hostname}:{self.port}",
            ))
            
        except socket.gaierror as e:
            cert_findings.append(TLSFinding(
                title="DNS Resolution Failed",
                severity=Severity.HIGH.value,
                description=f"Could not resolve hostname {self.hostname}: {str(e)}",
                remediation="Verify the hostname is correct and DNS is properly configured.",
                confidence=95,
                path=self.hostname,
            ))
            
        except ConnectionRefusedError:
            cert_findings.append(TLSFinding(
                title="Connection Refused",
                severity=Severity.MEDIUM.value,
                description=f"Connection to {self.hostname}:{self.port} was refused",
                remediation="Verify that HTTPS is enabled on port 443 (or the specified port).",
                confidence=90,
                path=f"{self.hostname}:{self.port}",
            ))
            
        except Exception as e:
            logger.error(f"Unexpected error checking certificate: {e}")
            cert_findings.append(TLSFinding(
                title="Certificate Check Error",
                severity=Severity.LOW.value,
                description=f"Could not complete certificate check: {str(e)}",
                remediation="Manual verification of SSL certificate recommended.",
                confidence=50,
                path=self.hostname,
            ))
        
        self.findings.extend(cert_findings)
        return cert_findings
    
    def check_https_redirect(self) -> List[TLSFinding]:
        redirect_findings: List[TLSFinding] = []
        http_url = f"http://{self.hostname}"
        
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
                response = client.get(http_url)
                
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location", "")
                    
                    if location.startswith("https://"):
                        if response.status_code not in (301, 308):
                            redirect_findings.append(TLSFinding(
                                title="HTTPS Redirect Not Permanent",
                                severity=Severity.LOW.value,
                                description=f"HTTP to HTTPS redirect uses status {response.status_code} instead of 301/308",
                                remediation="Use HTTP 301 (Moved Permanently) or 308 (Permanent Redirect) for HTTPS redirects to improve SEO and browser caching.",
                                confidence=85,
                                path=http_url,
                                metadata={"redirect_status": response.status_code, "location": location},
                            ))
                    else:
                        redirect_findings.append(TLSFinding(
                            title="HTTP Does Not Redirect to HTTPS",
                            severity=Severity.MEDIUM.value,
                            description=f"HTTP redirects to {location} instead of HTTPS",
                            remediation="Configure web server to redirect all HTTP traffic to HTTPS URLs.",
                            confidence=90,
                            path=http_url,
                            metadata={"redirect_location": location},
                        ))
                else:
                    redirect_findings.append(TLSFinding(
                        title="No HTTPS Redirect Configured",
                        severity=Severity.MEDIUM.value,
                        description=f"HTTP requests are served directly (status {response.status_code}) without redirecting to HTTPS",
                        remediation="Configure web server to redirect all HTTP (port 80) traffic to HTTPS (port 443). This prevents users from accidentally using unencrypted connections.",
                        confidence=95,
                        path=http_url,
                        metadata={"http_status": response.status_code},
                    ))
                    
        except httpx.ConnectError:
            pass
        except httpx.TimeoutException:
            pass
        except Exception as e:
            logger.error(f"Error checking HTTPS redirect: {e}")
        
        self.findings.extend(redirect_findings)
        return redirect_findings
    
    def check_protocol_versions(self) -> List[TLSFinding]:
        protocol_findings: List[TLSFinding] = []
        old_protocols = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1, Severity.MEDIUM.value),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, Severity.MEDIUM.value),
        ]
        
        for proto_name, proto_version, severity in old_protocols:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = proto_version
                context.maximum_version = proto_version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        protocol_findings.append(TLSFinding(
                            title=f"Deprecated Protocol {proto_name} Supported",
                            severity=severity,
                            description=f"Server accepts connections using {proto_name}, which is deprecated and has known vulnerabilities",
                            remediation=f"Disable {proto_name} on the server. Configure minimum TLS version to TLSv1.2 or TLSv1.3.",
                            confidence=95,
                            path=f"{self.hostname}:{self.port}",
                            metadata={"protocol": proto_name},
                        ))
                        
            except ssl.SSLError:
                pass
            except Exception as e:
                logger.debug(f"Could not check {proto_name}: {e}")
        
        self.findings.extend(protocol_findings)
        return protocol_findings
    
    def _get_certificate_info(self, verify: bool = True) -> CertificateInfo:
        if verify:
            context = ssl.create_default_context()
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                cert = ssock.getpeercert()
                
                if not cert:
                    raise ssl.SSLError("Could not retrieve certificate")
                
                subject = {}
                for item in cert.get("subject", ()):
                    for key, value in item:
                        subject[key] = value
                
                issuer = {}
                for item in cert.get("issuer", ()):
                    for key, value in item:
                        issuer[key] = value
                
                not_before = datetime.strptime(
                    cert.get("notBefore", ""),
                    "%b %d %H:%M:%S %Y %Z"
                )
                not_after = datetime.strptime(
                    cert.get("notAfter", ""),
                    "%b %d %H:%M:%S %Y %Z"
                )
                
                sans = []
                for san_type, san_value in cert.get("subjectAltName", ()):
                    if san_type == "DNS":
                        sans.append(san_value)
                
                return CertificateInfo(
                    subject=subject,
                    issuer=issuer,
                    version=cert.get("version", 0),
                    serial_number=cert.get("serialNumber", ""),
                    not_before=not_before,
                    not_after=not_after,
                    subject_alt_names=sans,
                    is_valid=verify,
                )
    
    def _check_expiration(self, cert_info: CertificateInfo) -> List[TLSFinding]:
        findings = []
        now = datetime.utcnow()
        days_until_expiry = (cert_info.not_after - now).days
        
        if days_until_expiry < 0:
            findings.append(TLSFinding(
                title="SSL Certificate Expired",
                severity=Severity.CRITICAL.value,
                description=f"Certificate expired {abs(days_until_expiry)} days ago on {cert_info.not_after.strftime('%Y-%m-%d')}",
                remediation="Renew the SSL certificate immediately. Expired certificates cause browser security warnings and prevent secure connections.",
                confidence=100,
                path=self.hostname,
                metadata={
                    "expiry_date": cert_info.not_after.isoformat(),
                    "days_expired": abs(days_until_expiry),
                },
            ))
            
        elif days_until_expiry <= CERT_EXPIRY_CRITICAL_DAYS:
            findings.append(TLSFinding(
                title="SSL Certificate Expiring Very Soon",
                severity=Severity.HIGH.value,
                description=f"Certificate expires in {days_until_expiry} days on {cert_info.not_after.strftime('%Y-%m-%d')}",
                remediation="Renew the SSL certificate immediately to prevent service disruption.",
                confidence=100,
                path=self.hostname,
                metadata={
                    "expiry_date": cert_info.not_after.isoformat(),
                    "days_remaining": days_until_expiry,
                },
            ))
            
        elif days_until_expiry <= CERT_EXPIRY_WARNING_DAYS:
            findings.append(TLSFinding(
                title="SSL Certificate Expiring Soon",
                severity=Severity.MEDIUM.value,
                description=f"Certificate expires in {days_until_expiry} days on {cert_info.not_after.strftime('%Y-%m-%d')}",
                remediation="Plan to renew the SSL certificate before expiration to avoid service disruption.",
                confidence=95,
                path=self.hostname,
                metadata={
                    "expiry_date": cert_info.not_after.isoformat(),
                    "days_remaining": days_until_expiry,
                },
            ))
        
        return findings
    
    def _handle_verification_error(self, error: ssl.SSLCertVerificationError) -> TLSFinding:
        error_msg = str(error)
        verify_message = getattr(error, 'verify_message', error_msg)
        
        if "hostname" in error_msg.lower() or "match" in error_msg.lower():
            return TLSFinding(
                title="SSL Certificate Hostname Mismatch",
                severity=Severity.HIGH.value,
                description=f"Certificate does not match hostname '{self.hostname}': {verify_message}",
                remediation="Obtain a certificate that includes the correct hostname in the Common Name (CN) or Subject Alternative Names (SAN).",
                confidence=95,
                path=self.hostname,
                metadata={"error": verify_message},
            )
            
        elif "self" in error_msg.lower() or "self-signed" in error_msg.lower():
            return TLSFinding(
                title="Self-Signed SSL Certificate",
                severity=Severity.HIGH.value,
                description="Server uses a self-signed certificate that is not trusted by browsers",
                remediation="Replace with a certificate from a trusted Certificate Authority (CA). Consider using Let's Encrypt for free trusted certificates.",
                confidence=95,
                path=self.hostname,
                metadata={"error": verify_message},
            )
            
        elif "expired" in error_msg.lower():
            return TLSFinding(
                title="SSL Certificate Expired",
                severity=Severity.CRITICAL.value,
                description=f"Certificate has expired: {verify_message}",
                remediation="Renew the SSL certificate immediately.",
                confidence=100,
                path=self.hostname,
                metadata={"error": verify_message},
            )
            
        elif "chain" in error_msg.lower() or "intermediate" in error_msg.lower():
            return TLSFinding(
                title="Incomplete Certificate Chain",
                severity=Severity.HIGH.value,
                description=f"Certificate chain is incomplete or invalid: {verify_message}",
                remediation="Ensure all intermediate certificates are properly configured on the server. Use a certificate chain checker tool to verify.",
                confidence=90,
                path=self.hostname,
                metadata={"error": verify_message},
            )
            
        else:
            return TLSFinding(
                title="SSL Certificate Validation Failed",
                severity=Severity.HIGH.value,
                description=f"Certificate validation failed: {verify_message}",
                remediation="Review and fix the SSL certificate configuration. Common issues include hostname mismatch, expired certificates, or incomplete certificate chains.",
                confidence=85,
                path=self.hostname,
                metadata={"error": verify_message},
            )


def check_tls(target: str, port: int = 443) -> List[Dict[str, Any]]:
    checker = TLSChecker(target, port)
    return checker.run_all_checks()


def check_certificate_expiry(target: str, port: int = 443) -> Dict[str, Any]:
    checker = TLSChecker(target, port)
    
    try:
        cert_info = checker._get_certificate_info(verify=False)
        now = datetime.utcnow()
        days_left = (cert_info.not_after - now).days
        
        return {
            "ok": days_left > CERT_EXPIRY_WARNING_DAYS,
            "days_left": days_left,
            "expiry_date": cert_info.not_after.isoformat(),
            "message": f"Certificate expires in {days_left} days" if days_left > 0 else f"Certificate expired {abs(days_left)} days ago",
        }
    except Exception as e:
        return {
            "ok": False,
            "days_left": None,
            "expiry_date": None,
            "message": f"Could not check certificate: {str(e)}",
        }


__all__ = [
    "TLSChecker",
    "TLSFinding",
    "CertificateInfo",
    "Severity",
    "check_tls",
    "check_certificate_expiry",
]
