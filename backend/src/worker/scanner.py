import logging
import time
import re
import ssl
import socket
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
import httpx

logger = logging.getLogger(__name__)

try:
    from src.worker.playwright_scanner import render_page, is_playwright_available
    PLAYWRIGHT_AVAILABLE = is_playwright_available()
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from src.worker.wordlist_probe import probe_endpoints
    WORDLIST_PROBE_AVAILABLE = True
except ImportError:
    WORDLIST_PROBE_AVAILABLE = False

try:
    from src.worker.reflection_check import check_reflections, generate_findings as generate_reflection_findings
    REFLECTION_CHECK_AVAILABLE = True
except ImportError:
    REFLECTION_CHECK_AVAILABLE = False

try:
    from src.worker.library_detector import detect_libraries
    LIBRARY_DETECTOR_AVAILABLE = True
except ImportError:
    LIBRARY_DETECTOR_AVAILABLE = False


USER_AGENT = "VibeSecure/1.0 (Security Scanner; +https://github.com/thebuildguild-dev/vibesecure)"

# Wordlist profiles for path probing
WORDLIST_PROFILES = {
    "minimal": ["admin", "backup", ".git", ".env"],
    "default": ["admin", "backup", ".git", ".env", "config", "test", "api", "docs", ".svn", ".htaccess"],
    "deep": ["admin", "backup", ".git", ".env", "config", "test", "api", "docs", ".svn", ".htaccess", 
             "phpmyadmin", "wp-admin", "uploads", "temp", "tmp", "log", "logs", "private", ".ssh", ".aws"]
}

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "title": "HSTS (HTTP Strict Transport Security) not configured",
        "severity": "high",
        "remediation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "title": "Content Security Policy (CSP) not configured",
        "severity": "medium",
        "remediation": "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
    },
    "X-Frame-Options": {
        "title": "Clickjacking protection (X-Frame-Options) missing",
        "severity": "medium",
        "remediation": "X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "title": "MIME-sniffing protection missing",
        "severity": "medium",
        "remediation": "X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "title": "Referrer-Policy header missing",
        "severity": "low",
        "remediation": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "title": "Permissions-Policy header missing",
        "severity": "low",
        "remediation": "Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
    },
    "X-XSS-Protection": {
        "title": "X-XSS-Protection header missing (legacy browsers)",
        "severity": "info",
        "remediation": "X-XSS-Protection: 1; mode=block",
    },
}


class ScannerError(Exception):
    """Base exception for scanner errors."""
    pass


class ConnectionError(ScannerError):
    """Failed to connect to target URL."""
    pass


class TimeoutError(ScannerError):
    """Scan timed out."""
    pass


class RobotsTxtError(ScannerError):
    """Error parsing or fetching robots.txt."""
    pass


@dataclass
class ScanResult:
    """Result from a scan operation."""
    success: bool
    findings: List[Dict[str, Any]]
    error: Optional[str] = None
    duration_seconds: float = 0.0
    metadata: Optional[Dict[str, Any]] = None
    pages_scanned: int = 0


@dataclass
class PageData:
    """Data captured from a single page."""
    url: str
    status_code: int
    headers: Dict[str, str]
    cookies: List[Dict[str, Any]]
    body: str
    links: Set[str] = field(default_factory=set)


class LinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.resources: List[Dict[str, str]] = []
        
    def handle_starttag(self, tag: str, attrs: List[tuple]):
        attrs_dict = dict(attrs)
        
        if tag == "a" and "href" in attrs_dict:
            href = attrs_dict["href"]
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                full_url = urljoin(self.base_url, href)
                self.links.add(full_url)
        
        resource_attrs = {
            "img": "src",
            "script": "src",
            "link": "href",
            "iframe": "src",
            "video": "src",
            "audio": "src",
            "source": "src",
            "object": "data",
            "embed": "src",
        }
        
        if tag in resource_attrs:
            attr_name = resource_attrs[tag]
            if attr_name in attrs_dict:
                resource_url = attrs_dict[attr_name]
                if resource_url:
                    full_url = urljoin(self.base_url, resource_url)
                    self.resources.append({
                        "tag": tag,
                        "url": full_url,
                        "attribute": attr_name,
                    })


class RobotsChecker:
    def __init__(self, base_url: str, user_agent: str = USER_AGENT):
        self.base_url = base_url
        self.user_agent = user_agent
        self.parser = RobotFileParser()
        self.loaded = False
        
    def load(self, timeout: int = 10) -> bool:
        parsed = urlparse(self.base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                response = client.get(robots_url, headers={"User-Agent": self.user_agent})
                
                if response.status_code == 200:
                    self.parser.parse(response.text.splitlines())
                    self.loaded = True
                else:
                    self.loaded = True
                    
        except Exception:
            self.loaded = True
            
        return self.loaded
    
    def is_allowed(self, url: str) -> bool:
        if not self.loaded:
            self.load()
        
        try:
            return self.parser.can_fetch(self.user_agent, url)
        except Exception:
            return True


def check_ssl_certificate(hostname: str, port: int = 443) -> List[Dict[str, Any]]:
    findings = []
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                if not cert:
                    findings.append({
                        "title": "Could not retrieve SSL certificate",
                        "severity": "high",
                        "remediation": "Ensure a valid SSL certificate is configured",
                        "confidence": 100,
                        "url": f"https://{hostname}",
                    })
                    return findings
                
                not_after = cert.get("notAfter")
                if not_after:
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days
                    
                    if days_until_expiry < 0:
                        findings.append({
                            "title": f"SSL certificate has EXPIRED ({abs(days_until_expiry)} days ago)",
                            "severity": "critical",
                            "remediation": "Renew the SSL certificate immediately",
                            "confidence": 100,
                            "url": f"https://{hostname}",
                        })
                    elif days_until_expiry < 7:
                        findings.append({
                            "title": f"SSL certificate expires in {days_until_expiry} days",
                            "severity": "high",
                            "remediation": "Renew the SSL certificate before expiry",
                            "confidence": 100,
                            "url": f"https://{hostname}",
                        })
                    elif days_until_expiry < 30:
                        findings.append({
                            "title": f"SSL certificate expires in {days_until_expiry} days",
                            "severity": "medium",
                            "remediation": "Plan to renew the SSL certificate soon",
                            "confidence": 100,
                            "url": f"https://{hostname}",
                        })
                
                protocol_version = ssock.version()
                if protocol_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    findings.append({
                        "title": f"Outdated TLS version in use: {protocol_version}",
                        "severity": "high",
                        "remediation": "Upgrade to TLS 1.2 or TLS 1.3",
                        "confidence": 100,
                        "url": f"https://{hostname}",
                    })
                    
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "title": f"SSL certificate verification failed: {e.verify_message}",
            "severity": "critical",
            "remediation": "Fix the SSL certificate configuration or use a valid certificate",
            "confidence": 100,
            "url": f"https://{hostname}",
        })
    except ssl.SSLError as e:
        findings.append({
            "title": f"SSL error: {str(e)}",
            "severity": "high",
            "remediation": "Review SSL/TLS configuration",
            "confidence": 90,
            "url": f"https://{hostname}",
        })
    except socket.timeout:
        findings.append({
            "title": "SSL connection timed out",
            "severity": "medium",
            "remediation": "Check if HTTPS is properly configured on port 443",
            "confidence": 80,
            "url": f"https://{hostname}",
        })
    except Exception as e:
        logger.warning(f"Could not check SSL certificate for {hostname}: {e}")
        
    return findings


def check_security_headers(headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            findings.append({
                "title": info["title"],
                "severity": info["severity"],
                "remediation": info["remediation"],
                "confidence": 90,
                "url": url,
            })
    
    if "strict-transport-security" in headers_lower:
        hsts_value = headers_lower["strict-transport-security"]
        
        max_age_match = re.search(r"max-age=(\d+)", hsts_value, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                findings.append({
                    "title": f"HSTS max-age is too short ({max_age} seconds)",
                    "severity": "low",
                    "remediation": "Set HSTS max-age to at least 31536000 (1 year)",
                    "confidence": 90,
                    "url": url,
                })
        
        if "includesubdomains" not in hsts_value.lower():
            findings.append({
                "title": "HSTS does not include subdomains",
                "severity": "low",
                "remediation": "Add 'includeSubDomains' to HSTS header for complete protection",
                "confidence": 85,
                "url": url,
            })
    
    return findings


def check_cookies(cookies: List[Dict[str, Any]], url: str, is_https: bool) -> List[Dict[str, Any]]:
    findings = []
    
    for cookie in cookies:
        name = cookie.get("name", "unknown")
        
        if is_https and not cookie.get("secure", False):
            findings.append({
                "title": f"Cookie '{name}' missing Secure flag",
                "severity": "medium",
                "remediation": f"Set the Secure flag on cookie '{name}' to prevent transmission over HTTP",
                "confidence": 95,
                "url": url,
            })
        
        if not cookie.get("httponly", False):
            session_patterns = ["session", "sess", "auth", "token", "jwt", "sid", "csrf"]
            if any(pattern in name.lower() for pattern in session_patterns):
                findings.append({
                    "title": f"Session cookie '{name}' missing HttpOnly flag",
                    "severity": "high",
                    "remediation": f"Set the HttpOnly flag on cookie '{name}' to prevent JavaScript access",
                    "confidence": 90,
                    "url": url,
                })
            else:
                findings.append({
                    "title": f"Cookie '{name}' missing HttpOnly flag",
                    "severity": "low",
                    "remediation": f"Consider setting the HttpOnly flag on cookie '{name}'",
                    "confidence": 80,
                    "url": url,
                })
        
        samesite = cookie.get("samesite", "").lower()
        if not samesite or samesite == "none":
            findings.append({
                "title": f"Cookie '{name}' has weak or missing SameSite attribute",
                "severity": "medium",
                "remediation": f"Set 'SameSite=Strict' or 'SameSite=Lax' on cookie '{name}'",
                "confidence": 85,
                "url": url,
            })
    
    return findings


def check_mixed_content(resources: List[Dict[str, str]], page_url: str) -> List[Dict[str, Any]]:
    findings = []
    
    if not page_url.startswith("https://"):
        return findings
    
    for resource in resources:
        resource_url = resource.get("url", "")
        if resource_url.startswith("http://"):
            findings.append({
                "title": f"Mixed content: HTTP {resource['tag']} loaded on HTTPS page",
                "severity": "medium",
                "remediation": f"Change the {resource['tag']} src to HTTPS: {resource_url}",
                "confidence": 100,
                "url": page_url,
            })
    
    return findings


def check_server_disclosure(headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    if "server" in headers_lower:
        server = headers_lower["server"]
        if re.search(r"[\d.]+", server):
            findings.append({
                "title": f"Server version disclosed: {server}",
                "severity": "info",
                "remediation": "Remove version information from Server header",
                "confidence": 100,
                "url": url,
            })
    
    if "x-powered-by" in headers_lower:
        powered_by = headers_lower["x-powered-by"]
        findings.append({
            "title": f"Technology stack disclosed: {powered_by}",
            "severity": "low",
            "remediation": "Remove the X-Powered-By header to avoid disclosing technology stack",
            "confidence": 100,
            "url": url,
        })
    
    if "x-aspnet-version" in headers_lower:
        findings.append({
            "title": f"ASP.NET version disclosed: {headers_lower['x-aspnet-version']}",
            "severity": "low",
            "remediation": "Remove the X-AspNet-Version header",
            "confidence": 100,
            "url": url,
        })
    
    return findings


def parse_cookies_from_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    cookies = []
    
    set_cookie_headers = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            set_cookie_headers.append(value)
    
    for cookie_str in set_cookie_headers:
        cookie_data = {"raw": cookie_str}
        parts = cookie_str.split(";")
        
        if parts:
            name_value = parts[0].strip()
            if "=" in name_value:
                name, value = name_value.split("=", 1)
                cookie_data["name"] = name.strip()
                cookie_data["value"] = value.strip()
            
            for part in parts[1:]:
                part = part.strip().lower()
                match part:
                    case "secure":
                        cookie_data["secure"] = True
                    case "httponly":
                        cookie_data["httponly"] = True
                    case s if s.startswith("samesite="):
                        cookie_data["samesite"] = s.split("=", 1)[1]
                    case s if s.startswith("path="):
                        cookie_data["path"] = s.split("=", 1)[1]
                    case s if s.startswith("domain="):
                        cookie_data["domain"] = s.split("=", 1)[1]
        
        if "name" in cookie_data:
            cookies.append(cookie_data)
    
    return cookies


def is_same_domain(url: str, base_url: str) -> bool:
    try:
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_url)
        
        return parsed_url.netloc == parsed_base.netloc
    except Exception:
        return False


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized


def run_passive_scan(
    url: str,
    depth: int = 2,
    rate_limit: float = 1.0,
    timeout: int = 30,
    max_pages: int = 50,
    options: Optional[Dict[str, Any]] = None,
    verification: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    assert verification is not None, "Domain verification is required for scanning"
    assert verification.verified is True, f"Domain {verification.domain} is not verified"
    
    logger.info(f"Starting scan of {url} (verification_id={verification.id})")
    
    options = options or {}
    ignore_robots = options.get("ignore_robots", False)
    auth_config = options.get("auth")
    render_js = options.get("render_js", False)
    wordlist_profile = options.get("wordlist_profile", "default")
    check_reflections_enabled = options.get("check_reflections", False)
    
    findings: List[Dict[str, Any]] = []
    visited: Set[str] = set()
    to_visit: List[tuple] = [(url, 0)]
    
    parsed_base = urlparse(url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
    is_https = url.startswith("https://")
    
    robots = None
    if not ignore_robots:
        robots = RobotsChecker(url)
        robots.load(timeout=timeout)
    
    if is_https:
        ssl_findings = check_ssl_certificate(parsed_base.netloc)
        findings.extend(ssl_findings)
    else:
        findings.append({
            "title": "Site not using HTTPS",
            "severity": "high",
            "remediation": "Enable HTTPS with a valid SSL certificate",
            "confidence": 100,
            "url": url,
        })
    
    playwright_result = None
    if render_js:
        if PLAYWRIGHT_AVAILABLE:
            try:
                playwright_result = render_page(
                    url=url,
                    verification_id=verification.id,
                    timeout=timeout * 1000,
                    screenshot_enabled=True,
                    max_retries=1,
                )
                
                if playwright_result['xhr_endpoints']:
                    findings.append({
                        "title": f"JavaScript XHR/Fetch endpoints detected ({len(playwright_result['xhr_endpoints'])})",
                        "severity": "info",
                        "remediation": "Review XHR/fetch endpoints for sensitive data exposure",
                        "confidence": 100,
                        "url": url,
                        "details": {
                            "xhr_endpoints": playwright_result['xhr_endpoints'][:50],
                            "total_count": len(playwright_result['xhr_endpoints']),
                        },
                    })
                
                inline_scripts = [s for s in playwright_result['scripts'] if s['type'] == 'inline']
                if inline_scripts:
                    findings.append({
                        "title": f"Inline JavaScript detected ({len(inline_scripts)} scripts)",
                        "severity": "low",
                        "remediation": "Consider moving inline scripts to external files and using CSP nonce/hash",
                        "confidence": 80,
                        "url": url,
                        "details": {
                            "inline_script_count": len(inline_scripts),
                            "total_script_count": len(playwright_result['scripts']),
                        },
                    })
                
                if LIBRARY_DETECTOR_AVAILABLE and playwright_result.get('html'):
                    try:
                        library_findings = detect_libraries(
                            html_content=playwright_result['html'],
                            url=url,
                            verification_id=verification.id,
                        )
                        if library_findings:
                            findings.extend(library_findings)
                    except Exception:
                        pass
                
            except Exception as e:
                findings.append({
                    "title": "JavaScript rendering failed",
                    "severity": "info",
                    "remediation": f"Could not render page with Playwright: {str(e)}",
                    "confidence": 100,
                    "url": url,
                })
        else:
            findings.append({
                "title": "JavaScript rendering unavailable",
                "severity": "info",
                "remediation": "Playwright not installed. Install with: pip install playwright && playwright install --with-deps chromium",
                "confidence": 100,
                "url": url,
            })
    
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    
    if auth_config:
        auth_type = auth_config.get("type", "").lower()
        match auth_type:
            case "basic":
                import base64
                username = auth_config.get("username", "")
                password = auth_config.get("password", "")
                credentials = f"{username}:{password}".encode()
                b64_credentials = base64.b64encode(credentials).decode()
                headers["Authorization"] = f"Basic {b64_credentials}"
            case "bearer":
                token = auth_config.get("token", "")
                headers["Authorization"] = f"Bearer {token}"
            case "cookie":
                cookie_string = auth_config.get("cookie_string", "")
                headers["Cookie"] = cookie_string
    
    pages_scanned = 0
    
    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers) as client:
        while to_visit and pages_scanned < max_pages:
            current_url, current_depth = to_visit.pop(0)
            
            normalized_url = normalize_url(current_url)
            if normalized_url in visited:
                continue
            
            if robots and not ignore_robots:
                if not robots.is_allowed(current_url):
                    continue
            
            if not is_same_domain(current_url, url):
                continue
            
            visited.add(normalized_url)
            
            try:
                if pages_scanned > 0:
                    time.sleep(rate_limit)
                
                response = client.get(current_url)
                pages_scanned += 1
                
                response_headers = dict(response.headers)
                cookies = parse_cookies_from_headers(response_headers)
                
                for cookie in response.cookies.jar:
                    cookie_dict = {
                        "name": cookie.name,
                        "value": cookie.value,
                        "secure": cookie.secure,
                        "path": cookie.path,
                    }
                    if not any(c.get("name") == cookie.name for c in cookies):
                        cookies.append(cookie_dict)
                
                header_findings = check_security_headers(response_headers, current_url)
                findings.extend(header_findings)
                
                cookie_findings = check_cookies(cookies, current_url, is_https)
                findings.extend(cookie_findings)
                
                disclosure_findings = check_server_disclosure(response_headers, current_url)
                findings.extend(disclosure_findings)
                
                if "text/html" in response.headers.get("content-type", ""):
                    try:
                        extractor = LinkExtractor(current_url)
                        extractor.feed(response.text)
                        
                        mixed_findings = check_mixed_content(extractor.resources, current_url)
                        findings.extend(mixed_findings)
                        
                        if LIBRARY_DETECTOR_AVAILABLE and current_depth == 0:
                            try:
                                library_findings = detect_libraries(
                                    html_content=response.text,
                                    url=current_url,
                                    verification_id=verification.id,
                                )
                                if library_findings:
                                    findings.extend(library_findings)
                            except Exception:
                                pass
                        
                        if current_depth < depth:
                            for link in extractor.links:
                                if is_same_domain(link, url):
                                    normalized_link = normalize_url(link)
                                    if normalized_link not in visited:
                                        to_visit.append((link, current_depth + 1))
                                        
                    except Exception:
                        pass
                
            except httpx.HTTPStatusError:
                pass
            except httpx.ConnectError:
                pass
            except httpx.TimeoutException:
                pass
            except Exception:
                pass
    
    if wordlist_profile != "minimal" and WORDLIST_PROBE_AVAILABLE:
        wordlist_paths = WORDLIST_PROFILES.get(wordlist_profile, WORDLIST_PROFILES["default"])
        
        try:
            discovered_endpoints = probe_endpoints(
                base_url=base_domain,
                wordlist=wordlist_paths,
                rate_limit=rate_limit,
                max_concurrency=3,
                timeout=timeout,
                verification_id=verification.id,
            )
            for endpoint in discovered_endpoints:
                severity = "medium"
                if endpoint.status_code == 200:
                    severity = "medium"  
                elif endpoint.status_code in [401, 403]:
                    severity = "low" 
                elif endpoint.path in [".git", ".env", ".aws", ".ssh"]:
                    severity = "high"
                
                finding = {
                    "title": f"Endpoint discovered: {endpoint.path}",
                    "severity": severity,
                    "remediation": f"Review access controls for {endpoint.path}. Consider removing if not needed.",
                    "confidence": 90,
                    "url": endpoint.full_url,
                    "details": {
                        "status_code": endpoint.status_code,
                        "content_type": endpoint.content_type,
                        "method": endpoint.method_used,
                        "wordlist_profile": wordlist_profile,
                    }
                }
                
                if endpoint.evidence_snippet:
                    finding["details"]["evidence"] = endpoint.evidence_snippet[:200]
                
                if endpoint.path in [".git", ".env"]:
                    finding["title"] = f"Sensitive file exposed: {endpoint.path}"
                    finding["severity"] = "critical"
                    finding["remediation"] = f"CRITICAL: Remove {endpoint.path} from public access immediately!"
                
                findings.append(finding)
                
        except Exception as e:
            findings.append({
                "title": "Wordlist probing failed",
                "severity": "info",
                "remediation": f"Could not complete endpoint discovery: {str(e)}",
                "confidence": 100,
                "url": base_domain,
            })
    
    check_reflections_enabled = options.get("check_reflections", False)
    
    if check_reflections_enabled and REFLECTION_CHECK_AVAILABLE:
        try:
            reflection_results = check_reflections(
                base_url=base_domain,
                timeout=timeout,
                verification_id=verification.id,
            )
            
            reflection_findings = generate_reflection_findings(
                reflection_results,
                verification_id=verification.id,
            )
            
            findings.extend(reflection_findings)
            
        except Exception as e:
            findings.append({
                "title": "Reflection checking failed",
                "severity": "info",
                "remediation": f"Could not complete reflection detection: {str(e)}",
                "confidence": 100,
                "url": base_domain,
            })
    
    seen_findings: Set[tuple] = set()
    unique_findings = []
    for finding in findings:
        key = (finding["title"], finding["url"])
        if key not in seen_findings:
            seen_findings.add(key)
            finding["verification_id"] = verification.id
            finding["verification_domain"] = verification.domain
            unique_findings.append(finding)
    
    logger.info(f"Scan complete: {pages_scanned} pages, {len(unique_findings)} findings")
    
    return unique_findings


def scan_url(
    url: str,
    timeout: int = 30,
    depth: int = 2,
    rate_limit: float = 1.0,
    options: Optional[Dict[str, Any]] = None,
    verification: Optional[Any] = None,
) -> ScanResult:
    start_time = time.time()
    
    try:
        findings = run_passive_scan(
            url=url,
            depth=depth,
            rate_limit=rate_limit,
            timeout=timeout,
            max_pages=50,
            options=options,
            verification=verification,
        )
        
        duration = time.time() - start_time
        
        for finding in findings:
            if "url" in finding and "path" not in finding:
                finding["path"] = finding["url"]
        
        logger.info(f"Scan completed in {duration:.2f}s with {len(findings)} findings")
        
        return ScanResult(
            success=True,
            findings=findings,
            duration_seconds=duration,
            metadata={
                "scanner_version": "2.0",
                "scan_type": "passive",
                "depth": depth,
                "rate_limit": rate_limit,
                "verification_id": verification.id if verification else None,
                "verification_domain": verification.domain if verification else None,
                "scan_options": options or {},
            },
            pages_scanned=len(set(f.get("url", "") for f in findings)),
        )
        
    except Exception as e:
        duration = time.time() - start_time
        logger.exception(f"Unexpected error scanning {url}: {e}")
        return ScanResult(
            success=False,
            findings=[],
            error=str(e),
            duration_seconds=duration,
        )
