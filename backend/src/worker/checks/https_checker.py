import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlunparse
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
MAX_REDIRECTS = 10


@dataclass
class HTTPSFinding:
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
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "path": self.path,
        }


@dataclass
class RedirectInfo:
    original_url: str
    final_url: str
    redirect_chain: List[Dict[str, Any]]
    redirects_to_https: bool
    uses_permanent_redirect: bool
    has_hsts: bool
    hsts_value: Optional[str] = None


class HTTPSChecker:
    def __init__(self, target: str, timeout: int = DEFAULT_TIMEOUT):
        self.original_target = target
        self.timeout = timeout
        self.findings: List[HTTPSFinding] = []
        self.http_url = self._get_http_url(target)
        self.https_url = self._get_https_url(target)
    
    def _get_http_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            return f"http://{url}"
        parsed = urlparse(url)
        return urlunparse(parsed._replace(scheme="http"))
    
    def _get_https_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        parsed = urlparse(url)
        return urlunparse(parsed._replace(scheme="https"))
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        redirect_info = self._check_http_redirect()
        
        if redirect_info:
            self._analyze_redirect(redirect_info)
        
        self._check_hsts_header()
        return [f.to_dict() for f in self.findings]
    
    def _check_http_redirect(self) -> Optional[RedirectInfo]:
        try:
            redirect_chain = []
            current_url = self.http_url
            redirects_to_https = False
            uses_permanent = True
            final_url = current_url
            has_hsts = False
            hsts_value = None
            
            with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
                for i in range(MAX_REDIRECTS):
                    response = client.get(
                        current_url,
                        headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
                    )
                    
                    hsts = response.headers.get("strict-transport-security")
                    if hsts:
                        has_hsts = True
                        hsts_value = hsts
                    
                    redirect_chain.append({
                        "url": current_url,
                        "status_code": response.status_code,
                        "location": response.headers.get("location"),
                    })
                    
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location:
                            break
                        
                        if response.status_code not in (301, 308):
                            uses_permanent = False
                        
                        if location.startswith("/"):
                            parsed = urlparse(current_url)
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"
                        
                        if location.startswith("https://"):
                            redirects_to_https = True
                        
                        current_url = location
                        final_url = location
                    else:
                        final_url = current_url
                        break
            
            return RedirectInfo(
                original_url=self.http_url,
                final_url=final_url,
                redirect_chain=redirect_chain,
                redirects_to_https=redirects_to_https,
                uses_permanent_redirect=uses_permanent,
                has_hsts=has_hsts,
                hsts_value=hsts_value,
            )
            
        except httpx.ConnectError as e:
            logger.debug(f"Connection error: {e}")
            return None
        except httpx.TimeoutException:
            logger.debug("Timeout checking HTTP redirect")
            return None
        except Exception as e:
            logger.warning(f"Error checking HTTP redirect: {e}")
            return None
    
    def _analyze_redirect(self, info: RedirectInfo) -> None:
        if not info.redirects_to_https:
            if info.final_url.startswith("http://"):
                self.findings.append(HTTPSFinding(
                    title="Missing HTTP to HTTPS Redirect",
                    severity="high",
                    description=(
                        f"The HTTP version of the site ({info.original_url}) does not redirect to HTTPS. "
                        f"Final URL after following redirects: {info.final_url}. "
                        "This allows attackers to intercept traffic via man-in-the-middle attacks, "
                        "steal session cookies, inject malicious content, and capture credentials."
                    ),
                    remediation=(
                        "Configure your web server to redirect all HTTP traffic to HTTPS:\n\n"
                        "**Apache (.htaccess or httpd.conf):**\n"
                        "```\n"
                        "RewriteEngine On\n"
                        "RewriteCond %{HTTPS} off\n"
                        "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"
                        "```\n\n"
                        "**nginx:**\n"
                        "```\n"
                        "server {\n"
                        "    listen 80;\n"
                        "    server_name example.com;\n"
                        "    return 301 https://$server_name$request_uri;\n"
                        "}\n"
                        "```\n\n"
                        "**IIS (web.config):**\n"
                        "```xml\n"
                        "<rule name=\"HTTP to HTTPS\" stopProcessing=\"true\">\n"
                        "  <match url=\"(.*)\" />\n"
                        "  <conditions>\n"
                        "    <add input=\"{HTTPS}\" pattern=\"off\" />\n"
                        "  </conditions>\n"
                        "  <action type=\"Redirect\" url=\"https://{HTTP_HOST}/{R:1}\" redirectType=\"Permanent\" />\n"
                        "</rule>\n"
                        "```"
                    ),
                    confidence=95,
                    path=info.original_url,
                    metadata={
                        "http_url": info.original_url,
                        "final_url": info.final_url,
                        "redirect_chain": info.redirect_chain,
                    },
                ))
                return
        
        if info.redirects_to_https and not info.uses_permanent_redirect:
            temp_redirects = [
                r for r in info.redirect_chain 
                if r["status_code"] in (302, 303, 307)
            ]
            
            self.findings.append(HTTPSFinding(
                title="Temporary HTTPS Redirect (Should Be Permanent)",
                severity="low",
                description=(
                    f"The HTTP to HTTPS redirect uses a temporary redirect (302/303/307) "
                    f"instead of a permanent redirect (301/308). "
                    f"Temporary redirects are followed every time, while permanent redirects "
                    f"can be cached by browsers, improving security and performance."
                ),
                remediation=(
                    "Change the redirect status code from 302 to 301 (Moved Permanently) "
                    "or from 307 to 308 (Permanent Redirect).\n\n"
                    "For Apache, use `[R=301]` instead of `[R=302]`.\n"
                    "For nginx, use `return 301` instead of `return 302`."
                ),
                confidence=90,
                path=info.original_url,
                metadata={
                    "redirect_chain": info.redirect_chain,
                    "temporary_redirects": temp_redirects,
                },
            ))
        
        if len(info.redirect_chain) > 2:
            self.findings.append(HTTPSFinding(
                title="Excessive Redirect Chain",
                severity="info",
                description=(
                    f"The HTTP to HTTPS redirect involves {len(info.redirect_chain)} hops. "
                    f"Long redirect chains increase latency and may confuse some clients. "
                    f"Chain: {' → '.join(r['url'] for r in info.redirect_chain)}"
                ),
                remediation=(
                    "Simplify the redirect chain to go directly from HTTP to the final HTTPS URL. "
                    "Avoid intermediate redirects through different hostnames or paths."
                ),
                confidence=80,
                path=info.original_url,
                metadata={
                    "chain_length": len(info.redirect_chain),
                    "redirect_chain": info.redirect_chain,
                },
            ))
    
    def _check_hsts_header(self) -> None:
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(
                    self.https_url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
                )
                
                hsts = response.headers.get("strict-transport-security")
                
                if not hsts:
                    self.findings.append(HTTPSFinding(
                        title="Missing HSTS Header",
                        severity="medium",
                        description=(
                            "The site does not send a Strict-Transport-Security (HSTS) header. "
                            "HSTS tells browsers to always use HTTPS, even if the user types 'http://'. "
                            "Without HSTS, users are vulnerable to SSL stripping attacks on their first visit."
                        ),
                        remediation=(
                            "Add the Strict-Transport-Security header to all HTTPS responses:\n\n"
                            "```\n"
                            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
                            "```\n\n"
                            "**Apache:**\n"
                            "```\n"
                            "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
                            "```\n\n"
                            "**nginx:**\n"
                            "```\n"
                            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                            "```\n\n"
                            "Start with a short max-age (e.g., 300) and increase after testing."
                        ),
                        confidence=95,
                        path=self.https_url,
                        metadata={
                            "https_url": self.https_url,
                        },
                    ))
                else:
                    self._analyze_hsts(hsts)
                    
        except Exception as e:
            logger.debug(f"Error checking HSTS: {e}")
    
    def _analyze_hsts(self, hsts_value: str) -> None:
        hsts_lower = hsts_value.lower()
        max_age = 0
        if "max-age=" in hsts_lower:
            try:
                max_age_str = hsts_lower.split("max-age=")[1].split(";")[0].strip()
                max_age = int(max_age_str)
            except (ValueError, IndexError):
                pass
        
        if max_age < 15768000:
            self.findings.append(HTTPSFinding(
                title="Weak HSTS Max-Age",
                severity="low",
                description=(
                    f"The HSTS max-age is set to {max_age} seconds ({max_age // 86400} days). "
                    "A max-age of at least 6 months (15768000 seconds) is recommended. "
                    "Short max-age values reduce the protection window."
                ),
                remediation=(
                    "Increase the HSTS max-age to at least 1 year (31536000 seconds):\n"
                    "```\n"
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                    "```"
                ),
                confidence=85,
                path=self.https_url,
                metadata={
                    "hsts_value": hsts_value,
                    "max_age_seconds": max_age,
                    "max_age_days": max_age // 86400,
                },
            ))
        
        if "includesubdomains" not in hsts_lower:
            self.findings.append(HTTPSFinding(
                title="HSTS Missing includeSubDomains",
                severity="info",
                description=(
                    "The HSTS header does not include the 'includeSubDomains' directive. "
                    "This means subdomains are not protected by HSTS and could be vulnerable "
                    "to SSL stripping attacks."
                ),
                remediation=(
                    "Add includeSubDomains to the HSTS header (ensure all subdomains support HTTPS first):\n"
                    "```\n"
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                    "```"
                ),
                confidence=80,
                path=self.https_url,
                metadata={
                    "hsts_value": hsts_value,
                },
            ))


def check_https_redirect(target: str, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    checker = HTTPSChecker(target, timeout)
    return checker.run_all_checks()


def quick_https_check(target: str) -> Dict[str, Any]:
    if not target.startswith(("http://", "https://")):
        http_url = f"http://{target}"
    else:
        parsed = urlparse(target)
        http_url = urlunparse(parsed._replace(scheme="http"))
    
    result = {
        "http_url": http_url,
        "redirects_to_https": False,
        "final_url": None,
        "redirect_count": 0,
        "has_hsts": False,
        "error": None,
    }
    
    try:
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            response = client.get(http_url)
            
            result["final_url"] = str(response.url)
            result["redirects_to_https"] = str(response.url).startswith("https://")
            result["redirect_count"] = len(response.history)
            result["has_hsts"] = "strict-transport-security" in response.headers
            
    except Exception as e:
        result["error"] = str(e)
    
    return result


__all__ = [
    "HTTPSChecker",
    "HTTPSFinding",
    "RedirectInfo",
    "check_https_redirect",
    "quick_https_check",
]
