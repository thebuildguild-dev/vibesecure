import re
import logging
from typing import List, Dict, Any, Optional, Tuple
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

VERSION_HEADERS: List[Tuple[str, str, str]] = [
    ("Server", "Web server software and version", "low"),
    ("X-Powered-By", "Backend technology and version", "medium"),
    ("X-AspNet-Version", "ASP.NET framework version", "medium"),
    ("X-AspNetMvc-Version", "ASP.NET MVC version", "medium"),
    ("X-Generator", "CMS or site generator", "low"),
    ("X-Drupal-Cache", "Drupal CMS indicator", "low"),
    ("X-Varnish", "Varnish cache server", "low"),
    ("X-Rack-Cache", "Ruby Rack cache", "low"),
    ("X-Runtime", "Application runtime (may leak timing info)", "info"),
    ("X-Version", "Application version", "medium"),
    ("X-App-Version", "Application version", "medium"),
    ("X-API-Version", "API version", "info"),
    ("X-CF-Powered-By", "ColdFusion indicator", "medium"),
    ("X-OWA-Version", "Outlook Web Access version", "medium"),
    ("X-Confluence-Request-Time", "Atlassian Confluence indicator", "low"),
    ("X-JIRA-Request-ID", "Atlassian JIRA indicator", "low"),
    ("X-Jenkins", "Jenkins CI server", "medium"),
    ("X-Shopify-Stage", "Shopify platform indicator", "info"),
    ("X-Magento-Cache-Debug", "Magento ecommerce indicator", "low"),
    ("X-WP-Nonce", "WordPress indicator", "low"),
    ("X-Litespeed-Cache", "LiteSpeed server", "low"),
    ("X-Turbo-Charged-By", "LiteSpeed indicator", "low"),
]

VERSION_PATTERNS = [
    r'/(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',
    r'\s+(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',
    r'^(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',
    r'-(\d+\.\d+(?:\.\d+)?)',
    r'v(\d+\.\d+(?:\.\d+)?)',
    r'version[:\s]+(\d+\.\d+(?:\.\d+)?)',
    r'\((\d+\.\d+(?:\.\d+)?)\)',
]

SOFTWARE_PATTERNS = [
    (r'Apache(?:/(\d+\.\d+(?:\.\d+)?))?', 'Apache', 'Web Server'),
    (r'nginx(?:/(\d+\.\d+(?:\.\d+)?))?', 'nginx', 'Web Server'),
    (r'Microsoft-IIS(?:/(\d+\.\d+))?', 'Microsoft IIS', 'Web Server'),
    (r'LiteSpeed', 'LiteSpeed', 'Web Server'),
    (r'Caddy', 'Caddy', 'Web Server'),
    (r'openresty(?:/(\d+\.\d+(?:\.\d+)?))?', 'OpenResty', 'Web Server'),
    (r'Tengine(?:/(\d+\.\d+(?:\.\d+)?))?', 'Tengine', 'Web Server'),
    (r'PHP(?:/(\d+\.\d+(?:\.\d+)?))?', 'PHP', 'Programming Language'),
    (r'ASP\.NET', 'ASP.NET', 'Framework'),
    (r'Express', 'Express.js', 'Framework'),
    (r'Ruby', 'Ruby', 'Programming Language'),
    (r'Python(?:/(\d+\.\d+(?:\.\d+)?))?', 'Python', 'Programming Language'),
    (r'Servlet(?:/(\d+\.\d+))?', 'Java Servlet', 'Framework'),
    (r'JSP(?:/(\d+\.\d+))?', 'JSP', 'Framework'),
    (r'ColdFusion', 'ColdFusion', 'Framework'),
    (r'Phusion Passenger', 'Phusion Passenger', 'Application Server'),
    (r'WordPress', 'WordPress', 'CMS'),
    (r'Drupal', 'Drupal', 'CMS'),
    (r'Joomla', 'Joomla', 'CMS'),
    (r'cloudflare', 'Cloudflare', 'CDN'),
    (r'AmazonS3', 'Amazon S3', 'Cloud Storage'),
    (r'AkamaiGHost', 'Akamai', 'CDN'),
    (r'Fastly', 'Fastly', 'CDN'),
]


@dataclass
class HeaderFinding:
    title: str
    severity: str
    description: str
    remediation: str
    confidence: int = 85
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
class VersionInfo:
    header_name: str
    header_value: str
    software: Optional[str] = None
    version: Optional[str] = None
    category: Optional[str] = None


class HeaderChecker:
    def __init__(
        self,
        target: str,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        self.target = target
        self.timeout = timeout
        self.findings: List[HeaderFinding] = []
        self.headers: Dict[str, str] = {}
        self.detected_tech: List[VersionInfo] = []
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting header analysis for {self.target}")
        
        self.findings = []
        self.detected_tech = []
        
        if not self._fetch_headers():
            return []
        
        self._check_version_headers()
        self._analyze_all_headers()
        self._create_summary_finding()
        
        logger.info(f"Header analysis complete. Found {len(self.findings)} issues.")
        
        return [f.to_dict() for f in self.findings]
    
    def _fetch_headers(self) -> bool:
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = client.head(
                    self.target,
                    headers={
                        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                    }
                )
                
                self.headers = dict(response.headers)
                return True
                
        except httpx.ConnectError as e:
            logger.warning(f"Connection error fetching headers: {e}")
        except httpx.TimeoutException:
            logger.warning(f"Timeout fetching headers from {self.target}")
        except Exception as e:
            logger.warning(f"Error fetching headers: {e}")
        
        return False
    
    def _check_version_headers(self) -> None:
        for header_name, description, base_severity in VERSION_HEADERS:
            header_value = None
            for h, v in self.headers.items():
                if h.lower() == header_name.lower():
                    header_value = v
                    break
            
            if not header_value:
                continue
            
            version_info = self._extract_version(header_name, header_value)
            
            if version_info.version:
                self.detected_tech.append(version_info)
                severity = "medium" if version_info.version else base_severity
                
                self.findings.append(HeaderFinding(
                    title=f"Version Disclosure: {header_name}",
                    severity=severity,
                    description=(
                        f"The {header_name} header discloses version information: `{header_value}`. "
                        f"Detected: {version_info.software or 'Unknown'} version {version_info.version}. "
                        "This information helps attackers identify known vulnerabilities."
                    ),
                    remediation=self._get_remediation(header_name, version_info),
                    confidence=90,
                    path=self.target,
                    metadata={
                        "header": header_name,
                        "value": header_value,
                        "software": version_info.software,
                        "version": version_info.version,
                    },
                ))
            elif header_value and header_name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
                self.findings.append(HeaderFinding(
                    title=f"Technology Disclosure: {header_name}",
                    severity="low",
                    description=(
                        f"The {header_name} header reveals technology information: `{header_value}`. "
                        "Even without version numbers, this helps attackers fingerprint the application."
                    ),
                    remediation=f"Remove the {header_name} header from responses.",
                    confidence=80,
                    path=self.target,
                    metadata={
                        "header": header_name,
                        "value": header_value,
                    },
                ))
    
    def _extract_version(self, header_name: str, header_value: str) -> VersionInfo:
        version_info = VersionInfo(
            header_name=header_name,
            header_value=header_value,
        )
        
        for pattern, software_name, category in SOFTWARE_PATTERNS:
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                version_info.software = software_name
                version_info.category = category
                if match.groups() and match.group(1):
                    version_info.version = match.group(1)
                break
        
        if not version_info.version:
            for pattern in VERSION_PATTERNS:
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    version_info.version = match.group(1)
                    break
        
        return version_info
    
    def _analyze_all_headers(self) -> None:
        dangerous_headers = {
            "X-Debug-Token": "Debug token that may reveal internal state",
            "X-Debug-Token-Link": "Debug link that may expose sensitive data",
            "X-Request-Id": "Request ID (minor info disclosure)",
            "X-Correlation-Id": "Correlation ID (minor info disclosure)",
        }
        
        for header_name, description in dangerous_headers.items():
            for h, v in self.headers.items():
                if h.lower() == header_name.lower():
                    self.findings.append(HeaderFinding(
                        title=f"Debug Header Exposed: {header_name}",
                        severity="info",
                        description=f"{description}. Value: `{v[:50]}...`" if len(v) > 50 else f"{description}. Value: `{v}`",
                        remediation=f"Remove the {header_name} header in production environments.",
                        confidence=70,
                        path=self.target,
                        metadata={"header": header_name, "value": v},
                    ))
                    break
        
        server_header = self.headers.get("Server", self.headers.get("server", ""))
        if server_header:
            detail_indicators = ["(", "mod_", "OpenSSL", "Ubuntu", "Debian", "CentOS", "Win"]
            if any(indicator in server_header for indicator in detail_indicators):
                if not any(f.metadata.get("header") == "Server" for f in self.findings):
                    self.findings.append(HeaderFinding(
                        title="Verbose Server Header",
                        severity="low",
                        description=(
                            f"The Server header contains detailed information: `{server_header}`. "
                            "This reveals OS, modules, and potentially exploitable details."
                        ),
                        remediation=(
                            "Configure the web server to return a minimal Server header. "
                            "For Apache: `ServerTokens Prod`. For nginx: `server_tokens off`."
                        ),
                        confidence=85,
                        path=self.target,
                        metadata={"header": "Server", "value": server_header},
                    ))
    
    def _get_remediation(self, header_name: str, version_info: VersionInfo) -> str:
        base_advice = f"Remove or minimize the {header_name} header to prevent version disclosure."
        
        specific_advice = {
            "Apache": (
                "For Apache, add to httpd.conf or .htaccess:\n"
                "```\n"
                "ServerTokens Prod\n"
                "ServerSignature Off\n"
                "```"
            ),
            "nginx": (
                "For nginx, add to nginx.conf:\n"
                "```\n"
                "server_tokens off;\n"
                "```"
            ),
            "PHP": (
                "For PHP, set in php.ini:\n"
                "```\n"
                "expose_php = Off\n"
                "```\n"
                "Or use header_remove('X-Powered-By') in code."
            ),
            "ASP.NET": (
                "For ASP.NET, add to web.config:\n"
                "```xml\n"
                "<system.web>\n"
                "  <httpRuntime enableVersionHeader=\"false\" />\n"
                "</system.web>\n"
                "<system.webServer>\n"
                "  <httpProtocol>\n"
                "    <customHeaders>\n"
                "      <remove name=\"X-Powered-By\" />\n"
                "    </customHeaders>\n"
                "  </httpProtocol>\n"
                "</system.webServer>\n"
                "```"
            ),
            "Express.js": (
                "For Express.js, disable the header:\n"
                "```javascript\n"
                "app.disable('x-powered-by');\n"
                "```\n"
                "Or use helmet middleware."
            ),
            "Microsoft IIS": (
                "For IIS, install URL Rewrite and add:\n"
                "```xml\n"
                "<rewrite>\n"
                "  <outboundRules>\n"
                "    <rule name=\"Remove Server header\">\n"
                "      <match serverVariable=\"RESPONSE_Server\" pattern=\".+\" />\n"
                "      <action type=\"Rewrite\" value=\"\" />\n"
                "    </rule>\n"
                "  </outboundRules>\n"
                "</rewrite>\n"
                "```"
            ),
        }
        
        if version_info.software in specific_advice:
            return f"{base_advice}\n\n{specific_advice[version_info.software]}"
        
        return base_advice
    
    def _create_summary_finding(self) -> None:
        if len(self.detected_tech) >= 3:
            tech_list = ", ".join([
                f"{t.software or 'Unknown'} {t.version or ''}"
                for t in self.detected_tech
            ])
            
            self.findings.append(HeaderFinding(
                title="Multiple Technology Versions Disclosed",
                severity="medium",
                description=(
                    f"Multiple technologies with version information are exposed: {tech_list}. "
                    "This comprehensive fingerprint significantly aids attackers in identifying vulnerabilities."
                ),
                remediation=(
                    "Implement a defense-in-depth approach to minimize information disclosure:\n"
                    "1. Configure all server software to hide version information\n"
                    "2. Use a reverse proxy or WAF to strip sensitive headers\n"
                    "3. Regularly audit response headers for information leakage"
                ),
                confidence=95,
                path=self.target,
                metadata={
                    "technologies": [
                        {"software": t.software, "version": t.version}
                        for t in self.detected_tech
                    ]
                },
            ))


def check_headers(target: str, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    checker = HeaderChecker(target, timeout)
    return checker.run_all_checks()


def quick_header_check(target: str) -> Dict[str, Any]:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    result = {
        "url": target,
        "headers": {},
        "version_disclosures": [],
        "technologies": [],
    }
    
    try:
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            response = client.head(target)
            result["headers"] = dict(response.headers)
            
            for header_name, _, _ in VERSION_HEADERS:
                for h, v in response.headers.items():
                    if h.lower() == header_name.lower():
                        result["version_disclosures"].append({
                            "header": header_name,
                            "value": v,
                        })
                        break
            
            server = response.headers.get("server", "")
            if server:
                for pattern, software_name, category in SOFTWARE_PATTERNS:
                    if re.search(pattern, server, re.IGNORECASE):
                        result["technologies"].append({
                            "name": software_name,
                            "category": category,
                            "source": "Server header",
                        })
                        break
            
            powered_by = response.headers.get("x-powered-by", "")
            if powered_by:
                result["technologies"].append({
                    "name": powered_by,
                    "category": "Framework/Language",
                    "source": "X-Powered-By header",
                })
                
    except Exception as e:
        result["error"] = str(e)
    
    return result


__all__ = [
    "HeaderChecker",
    "HeaderFinding",
    "VersionInfo",
    "check_headers",
    "quick_header_check",
    "VERSION_HEADERS",
    "SOFTWARE_PATTERNS",
]
