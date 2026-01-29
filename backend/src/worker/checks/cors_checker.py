import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, field

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

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]

SENSITIVE_METHODS = {"PUT", "DELETE", "PATCH"}

SENSITIVE_HEADERS = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
}


@dataclass
class CORSFinding:
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
class CORSResponse:
    allow_origin: Optional[str] = None
    allow_credentials: bool = False
    allow_methods: List[str] = field(default_factory=list)
    allow_headers: List[str] = field(default_factory=list)
    expose_headers: List[str] = field(default_factory=list)
    max_age: Optional[int] = None
    vary_origin: bool = False


class CORSChecker:
    def __init__(self, target: str, timeout: int = DEFAULT_TIMEOUT):
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        self.target = target
        self.timeout = timeout
        self.findings: List[CORSFinding] = []
        
        parsed = urlparse(target)
        self.hostname = parsed.hostname or ""
        self.scheme = parsed.scheme
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        
        for evil_origin in EVIL_ORIGINS:
            self._check_origin(evil_origin)
        
        self._check_preflight()
        
        logger.info(f"CORS checks for {self.target}: {len(self.findings)} issues found")
        return [f.to_dict() for f in self.findings]
    
    def _parse_cors_headers(self, headers: httpx.Headers) -> CORSResponse:
        cors = CORSResponse()
        
        cors.allow_origin = headers.get("access-control-allow-origin")
        
        creds = headers.get("access-control-allow-credentials", "").lower()
        cors.allow_credentials = creds == "true"
        
        methods = headers.get("access-control-allow-methods", "")
        if methods:
            cors.allow_methods = [m.strip().upper() for m in methods.split(",")]
        
        allow_headers = headers.get("access-control-allow-headers", "")
        if allow_headers:
            cors.allow_headers = [h.strip().lower() for h in allow_headers.split(",")]
        
        expose = headers.get("access-control-expose-headers", "")
        if expose:
            cors.expose_headers = [h.strip().lower() for h in expose.split(",")]
        
        max_age = headers.get("access-control-max-age")
        if max_age:
            try:
                cors.max_age = int(max_age)
            except ValueError:
                pass
        
        vary = headers.get("vary", "").lower()
        cors.vary_origin = "origin" in vary
        
        return cors
    
    def _check_origin(self, evil_origin: str) -> None:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    self.target,
                    headers={"Origin": evil_origin},
                )
                
                cors = self._parse_cors_headers(response.headers)
                
                if not cors.allow_origin:
                    return
                
                if cors.allow_origin == "*":
                    self._add_wildcard_finding(cors, evil_origin)
                    return
                
                if cors.allow_origin == evil_origin:
                    self._add_reflection_finding(cors, evil_origin)
                    return
                
                if cors.allow_origin == "null" and evil_origin == "null":
                    self._add_null_origin_finding(cors)
                    return
                    
        except httpx.ConnectError:
            logger.debug(f"Could not connect to {self.target}")
        except httpx.TimeoutException:
            logger.debug(f"Timeout connecting to {self.target}")
        except Exception as e:
            logger.debug(f"Error checking CORS with origin {evil_origin}: {e}")
    
    def _check_preflight(self) -> None:
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.options(
                    self.target,
                    headers={
                        "Origin": "https://evil.com",
                        "Access-Control-Request-Method": "DELETE",
                        "Access-Control-Request-Headers": "Authorization, X-Custom-Header",
                    },
                )
                
                cors = self._parse_cors_headers(response.headers)
                
                if not cors.allow_origin:
                    return
                
                if cors.allow_methods:
                    dangerous_methods = set(cors.allow_methods) & SENSITIVE_METHODS
                    
                    if dangerous_methods and cors.allow_origin in ("*", "https://evil.com"):
                        self.findings.append(CORSFinding(
                            title="CORS Allows Dangerous HTTP Methods",
                            severity="medium",
                            description=f"CORS policy allows dangerous methods ({', '.join(dangerous_methods)}) from untrusted origins",
                            remediation="Restrict Access-Control-Allow-Methods to only necessary HTTP methods. Avoid allowing PUT, DELETE, PATCH from untrusted origins.",
                            confidence=85,
                            path=self.target,
                            metadata={
                                "allowed_methods": cors.allow_methods,
                                "dangerous_methods": list(dangerous_methods),
                            },
                        ))
                

                if "*" in cors.allow_headers:
                    self.findings.append(CORSFinding(
                        title="CORS Allows All Headers (Wildcard)",
                        severity="medium",
                        description="Access-Control-Allow-Headers is set to wildcard (*), allowing any custom header",
                        remediation="Explicitly list only the required headers instead of using wildcard. This reduces attack surface.",
                        confidence=90,
                        path=self.target,
                        metadata={"allow_headers": cors.allow_headers},
                    ))
                    
        except Exception as e:
            logger.debug(f"Error checking preflight: {e}")
    
    def _add_wildcard_finding(self, cors: CORSResponse, origin: str) -> None:
        if any(f.title == "Insecure CORS Configuration: Wildcard Origin" for f in self.findings):
            return
        
        if cors.allow_credentials:
            self.findings.append(CORSFinding(
                title="CORS Misconfiguration: Wildcard with Credentials",
                severity="medium",
                description="Server returns Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. While browsers block this combination, it indicates a misconfigured CORS policy.",
                remediation="Never use wildcard (*) origin with credentials. Specify exact trusted origins and set Vary: Origin header.",
                confidence=95,
                path=self.target,
                metadata={
                    "allow_origin": cors.allow_origin,
                    "allow_credentials": cors.allow_credentials,
                },
            ))
        else:
            self.findings.append(CORSFinding(
                title="Insecure CORS Configuration: Wildcard Origin",
                severity="medium",
                description="Access-Control-Allow-Origin is set to wildcard (*), allowing any website to make cross-origin requests",
                remediation="Replace wildcard (*) with a specific list of trusted origins. Use environment-specific configuration for allowed origins.",
                confidence=95,
                path=self.target,
                metadata={
                    "allow_origin": cors.allow_origin,
                    "allow_credentials": cors.allow_credentials,
                },
            ))
    
    def _add_reflection_finding(self, cors: CORSResponse, origin: str) -> None:
        severity = "high" if cors.allow_credentials else "medium"
        
        if any("Origin Reflection" in f.title for f in self.findings):
            return
        
        if cors.allow_credentials:
            self.findings.append(CORSFinding(
                title="Critical CORS Vulnerability: Origin Reflection with Credentials",
                severity="high",
                description=f"Server reflects the Origin header ({origin}) in Access-Control-Allow-Origin AND allows credentials. This allows any website to make authenticated cross-origin requests, potentially stealing sensitive data.",
                remediation="NEVER reflect arbitrary origins when credentials are allowed. Maintain a whitelist of trusted origins and validate against it. Always set Vary: Origin header.",
                confidence=98,
                path=self.target,
                metadata={
                    "reflected_origin": origin,
                    "allow_credentials": cors.allow_credentials,
                    "vary_origin": cors.vary_origin,
                },
            ))
        else:
            self.findings.append(CORSFinding(
                title="Insecure CORS Configuration: Origin Reflection",
                severity="medium", 
                description=f"Server reflects the Origin header ({origin}) in Access-Control-Allow-Origin. While credentials are not allowed, this is still a security anti-pattern.",
                remediation="Do not reflect arbitrary origins. Maintain a whitelist of trusted origins and validate against it. Set Vary: Origin header for proper caching.",
                confidence=90,
                path=self.target,
                metadata={
                    "reflected_origin": origin,
                    "allow_credentials": cors.allow_credentials,
                    "vary_origin": cors.vary_origin,
                },
            ))
        
        if not cors.vary_origin:
            self.findings.append(CORSFinding(
                title="CORS Missing Vary: Origin Header",
                severity="low",
                description="When reflecting origins or using dynamic CORS, the Vary: Origin header should be set to prevent cache poisoning",
                remediation="Add 'Vary: Origin' header to responses that include Access-Control-Allow-Origin to ensure proper caching behavior.",
                confidence=85,
                path=self.target,
                metadata={"vary_origin": cors.vary_origin},
            ))
    
    def _add_null_origin_finding(self, cors: CORSResponse) -> None:
        severity = "high" if cors.allow_credentials else "medium"
        
        self.findings.append(CORSFinding(
            title="Insecure CORS Configuration: Null Origin Allowed",
            severity=severity,
            description="Server allows 'null' origin which can be exploited via sandboxed iframes, data: URLs, or file:// URLs to bypass CORS restrictions",
            remediation="Never whitelist 'null' as an allowed origin. The null origin can be forged in various attack scenarios.",
            confidence=95,
            path=self.target,
            metadata={
                "allow_origin": cors.allow_origin,
                "allow_credentials": cors.allow_credentials,
            },
        ))


def check_cors(target: str, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    """Run all CORS security checks on target URL."""
    checker = CORSChecker(target, timeout)
    return checker.run_all_checks()


def quick_cors_check(target: str) -> Dict[str, Any]:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    try:
        with httpx.Client(timeout=10) as client:
            response = client.get(
                target,
                headers={"Origin": "https://evil.com"},
            )
            
            acao = response.headers.get("access-control-allow-origin")
            acac = response.headers.get("access-control-allow-credentials", "").lower() == "true"
            
            if not acao:
                return {
                    "cors_enabled": False,
                    "message": "No CORS headers present",
                    "secure": True,
                }
            
            is_secure = acao not in ("*", "https://evil.com", "null") and not acac
            
            return {
                "cors_enabled": True,
                "allow_origin": acao,
                "allow_credentials": acac,
                "reflects_origin": acao == "https://evil.com",
                "wildcard": acao == "*",
                "secure": is_secure,
                "message": "CORS appears secure" if is_secure else "Potential CORS misconfiguration detected",
            }
            
    except Exception as e:
        return {
            "cors_enabled": None,
            "error": str(e),
            "message": f"Could not check CORS: {e}",
        }



__all__ = [
    "CORSChecker",
    "CORSFinding",
    "CORSResponse",
    "check_cors",
    "quick_cors_check",
]
