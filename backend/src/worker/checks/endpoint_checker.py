import logging
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
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
MAX_CONCURRENT_CHECKS = settings.security_check_max_concurrent


class EndpointCategory(str, Enum):
    CONFIG = "configuration"
    BACKUP = "backup"
    ADMIN = "admin"
    VCS = "version_control"
    DEBUG = "debug"
    DATABASE = "database"
    DISCLOSURE = "information_disclosure"
    API = "api"


SENSITIVE_PATHS: List[Tuple[str, EndpointCategory, str, str]] = [
    # Configuration files
    ("/.env", EndpointCategory.CONFIG, "Environment configuration file with secrets", "high"),
    ("/.env.local", EndpointCategory.CONFIG, "Local environment configuration", "high"),
    ("/.env.production", EndpointCategory.CONFIG, "Production environment secrets", "critical"),
    ("/.env.backup", EndpointCategory.CONFIG, "Backup of environment file", "high"),
    ("/config.php", EndpointCategory.CONFIG, "PHP configuration file", "high"),
    ("/config.yml", EndpointCategory.CONFIG, "YAML configuration file", "high"),
    ("/config.json", EndpointCategory.CONFIG, "JSON configuration file", "high"),
    ("/settings.py", EndpointCategory.CONFIG, "Python/Django settings file", "high"),
    ("/web.config", EndpointCategory.CONFIG, "IIS web configuration", "medium"),
    ("/wp-config.php", EndpointCategory.CONFIG, "WordPress configuration with DB credentials", "critical"),
    ("/configuration.php", EndpointCategory.CONFIG, "Joomla configuration file", "high"),
    ("/.htaccess", EndpointCategory.CONFIG, "Apache configuration file", "medium"),
    ("/.htpasswd", EndpointCategory.CONFIG, "Apache password file", "critical"),
    ("/app/config/parameters.yml", EndpointCategory.CONFIG, "Symfony parameters", "high"),
    
    # Backup files
    ("/backup.zip", EndpointCategory.BACKUP, "Backup archive", "high"),
    ("/backup.tar.gz", EndpointCategory.BACKUP, "Backup archive", "high"),
    ("/backup.sql", EndpointCategory.BACKUP, "Database backup", "critical"),
    ("/db.sql", EndpointCategory.BACKUP, "Database dump", "critical"),
    ("/database.sql", EndpointCategory.BACKUP, "Database dump", "critical"),
    ("/dump.sql", EndpointCategory.BACKUP, "Database dump", "critical"),
    ("/site.zip", EndpointCategory.BACKUP, "Site backup", "high"),
    ("/www.zip", EndpointCategory.BACKUP, "Web root backup", "high"),
    ("/backup.tar", EndpointCategory.BACKUP, "Backup archive", "high"),
    ("/.backup", EndpointCategory.BACKUP, "Backup directory", "high"),
    ("/old/", EndpointCategory.BACKUP, "Old files directory", "medium"),
    ("/bak/", EndpointCategory.BACKUP, "Backup directory", "medium"),
    
    # Admin panels
    ("/admin", EndpointCategory.ADMIN, "Admin panel", "medium"),
    ("/admin/", EndpointCategory.ADMIN, "Admin panel", "medium"),
    ("/administrator", EndpointCategory.ADMIN, "Admin panel", "medium"),
    ("/admin.php", EndpointCategory.ADMIN, "Admin script", "medium"),
    ("/wp-admin/", EndpointCategory.ADMIN, "WordPress admin", "low"),
    ("/phpmyadmin/", EndpointCategory.ADMIN, "phpMyAdmin database manager", "high"),
    ("/pma/", EndpointCategory.ADMIN, "phpMyAdmin (alternate path)", "high"),
    ("/adminer.php", EndpointCategory.ADMIN, "Adminer database manager", "high"),
    ("/manager/html", EndpointCategory.ADMIN, "Tomcat Manager", "high"),
    ("/cpanel", EndpointCategory.ADMIN, "cPanel access", "medium"),
    ("/webmail", EndpointCategory.ADMIN, "Webmail access", "low"),
    
    # Version control
    ("/.git/config", EndpointCategory.VCS, "Git repository configuration", "high"),
    ("/.git/HEAD", EndpointCategory.VCS, "Git repository HEAD reference", "high"),
    ("/.gitignore", EndpointCategory.VCS, "Git ignore file (info disclosure)", "low"),
    ("/.svn/entries", EndpointCategory.VCS, "SVN repository entries", "high"),
    ("/.svn/wc.db", EndpointCategory.VCS, "SVN working copy database", "high"),
    ("/.hg/", EndpointCategory.VCS, "Mercurial repository", "high"),
    ("/.bzr/", EndpointCategory.VCS, "Bazaar repository", "high"),
    ("/CVS/Root", EndpointCategory.VCS, "CVS repository", "high"),
    
    # Debug and development
    ("/phpinfo.php", EndpointCategory.DEBUG, "PHP information page", "high"),
    ("/info.php", EndpointCategory.DEBUG, "PHP info page", "high"),
    ("/test.php", EndpointCategory.DEBUG, "Test script", "medium"),
    ("/debug", EndpointCategory.DEBUG, "Debug endpoint", "medium"),
    ("/debug/", EndpointCategory.DEBUG, "Debug endpoint", "medium"),
    ("/_debug/", EndpointCategory.DEBUG, "Debug endpoint", "medium"),
    ("/trace", EndpointCategory.DEBUG, "Trace endpoint", "medium"),
    ("/console", EndpointCategory.DEBUG, "Console endpoint", "high"),
    ("/server-status", EndpointCategory.DEBUG, "Apache server status", "medium"),
    ("/server-info", EndpointCategory.DEBUG, "Apache server info", "medium"),
    ("/.DS_Store", EndpointCategory.DEBUG, "macOS directory metadata", "low"),
    ("/Thumbs.db", EndpointCategory.DEBUG, "Windows thumbnail cache", "low"),
    ("/elmah.axd", EndpointCategory.DEBUG, "ELMAH error log (.NET)", "high"),
    ("/error_log", EndpointCategory.DEBUG, "Error log file", "medium"),
    ("/errors.log", EndpointCategory.DEBUG, "Error log file", "medium"),
    ("/debug.log", EndpointCategory.DEBUG, "Debug log file", "medium"),
    
    # Database files
    ("/db.sqlite", EndpointCategory.DATABASE, "SQLite database", "critical"),
    ("/database.sqlite", EndpointCategory.DATABASE, "SQLite database", "critical"),
    ("/data.db", EndpointCategory.DATABASE, "Database file", "critical"),
    ("/users.db", EndpointCategory.DATABASE, "User database", "critical"),
    ("/.sqlite", EndpointCategory.DATABASE, "SQLite database", "critical"),
    
    # Information disclosure
    ("/robots.txt", EndpointCategory.DISCLOSURE, "Robots exclusion file", "info"),
    ("/sitemap.xml", EndpointCategory.DISCLOSURE, "Sitemap file", "info"),
    ("/crossdomain.xml", EndpointCategory.DISCLOSURE, "Flash cross-domain policy", "low"),
    ("/clientaccesspolicy.xml", EndpointCategory.DISCLOSURE, "Silverlight policy", "low"),
    ("/humans.txt", EndpointCategory.DISCLOSURE, "Humans.txt file", "info"),
    ("/security.txt", EndpointCategory.DISCLOSURE, "Security contact info", "info"),
    ("/.well-known/security.txt", EndpointCategory.DISCLOSURE, "Security contact info", "info"),
    ("/readme.html", EndpointCategory.DISCLOSURE, "Readme file (version disclosure)", "low"),
    ("/README.md", EndpointCategory.DISCLOSURE, "Readme file", "low"),
    ("/CHANGELOG.md", EndpointCategory.DISCLOSURE, "Changelog (version disclosure)", "low"),
    ("/VERSION", EndpointCategory.DISCLOSURE, "Version file", "low"),
    ("/composer.json", EndpointCategory.DISCLOSURE, "PHP dependencies", "low"),
    ("/package.json", EndpointCategory.DISCLOSURE, "Node.js dependencies", "low"),
    ("/composer.lock", EndpointCategory.DISCLOSURE, "PHP locked dependencies", "low"),
    ("/package-lock.json", EndpointCategory.DISCLOSURE, "Node.js locked dependencies", "low"),
    ("/Gemfile", EndpointCategory.DISCLOSURE, "Ruby dependencies", "low"),
    ("/requirements.txt", EndpointCategory.DISCLOSURE, "Python dependencies", "low"),
    
    # API documentation
    ("/swagger.json", EndpointCategory.API, "Swagger/OpenAPI spec", "low"),
    ("/openapi.json", EndpointCategory.API, "OpenAPI spec", "low"),
    ("/api-docs", EndpointCategory.API, "API documentation", "low"),
    ("/swagger-ui.html", EndpointCategory.API, "Swagger UI", "low"),
    ("/graphql", EndpointCategory.API, "GraphQL endpoint", "low"),
    ("/graphiql", EndpointCategory.API, "GraphQL interactive interface", "medium"),
    ("/.api/", EndpointCategory.API, "API directory", "low"),
]


@dataclass
class EndpointFinding:
    title: str
    severity: str
    description: str
    remediation: str
    confidence: int = 95
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
class EndpointResult:
    path: str
    status_code: int
    accessible: bool
    content_length: int = 0
    content_type: Optional[str] = None
    redirect_url: Optional[str] = None


class EndpointChecker:
    
    def __init__(
        self,
        target: str,
        timeout: int = DEFAULT_TIMEOUT,
        check_robots: bool = True,
    ):
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        parsed = urlparse(target)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.target = target
        self.timeout = timeout
        self.check_robots = check_robots
        self.findings: List[EndpointFinding] = []
        self.checked_paths: set = set()
        self.robots_disallowed: List[str] = []
        self._base_response_signature: Optional[Dict[str, Any]] = None
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting endpoint scan for {self.base_url}")
        
        self.findings = []
        self.checked_paths = set()
        
        self._get_base_signature()
        
        if self.check_robots:
            self._parse_robots_txt()
        
        for path, category, description, severity in SENSITIVE_PATHS:
            self._check_path(path, category, description, severity)
        
        for path in self.robots_disallowed:
            if path not in self.checked_paths:
                self._check_path(
                    path, 
                    EndpointCategory.DISCLOSURE, 
                    f"Path disallowed in robots.txt: {path}",
                    "medium"
                )
        
        logger.info(f"Endpoint scan complete. Found {len(self.findings)} exposed endpoints.")
        
        return [f.to_dict() for f in self.findings]
    
    def _check_path(
        self, 
        path: str, 
        category: EndpointCategory, 
        description: str, 
        severity: str
    ) -> Optional[EndpointResult]:
        if path in self.checked_paths:
            return None
        
        self.checked_paths.add(path)
        full_url = urljoin(self.base_url, path)
        
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
            ) as client:
                response = client.get(
                    full_url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                    }
                )
                
                result = EndpointResult(
                    path=path,
                    status_code=response.status_code,
                    accessible=response.status_code == 200,
                    content_length=len(response.content),
                    content_type=response.headers.get("content-type"),
                    redirect_url=response.headers.get("location") if response.status_code in (301, 302, 303, 307, 308) else None,
                )
                
                if result.accessible:
                    if self._is_false_positive(response):
                        return result
                    
                    self._create_finding(path, category, description, severity, result)
                
                elif result.redirect_url and any(x in result.redirect_url.lower() for x in ["login", "auth", "signin"]):
                    if severity in ("critical", "high"):
                        self.findings.append(EndpointFinding(
                            title=f"Protected Endpoint Found: {path}",
                            severity="info",
                            description=f"{description}. Endpoint exists but requires authentication (redirects to login).",
                            remediation="Ensure authentication is properly enforced. Consider if this endpoint should be publicly discoverable.",
                            confidence=70,
                            path=full_url,
                            metadata={
                                "status_code": result.status_code,
                                "redirect_url": result.redirect_url,
                                "category": category.value,
                            },
                        ))
                
                return result
                
        except (httpx.ConnectError, httpx.TimeoutException, Exception):
            pass
        
        return None
    
    def _get_base_signature(self) -> None:
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(
                    self.base_url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
                )
                
                if response.status_code == 200:
                    self._base_response_signature = {
                        "content_length": len(response.content),
                        "content_hash": hash(response.content[:1000]),
                        "title": self._extract_title(response.text),
                        "content_type": response.headers.get("content-type", ""),
                    }
        except Exception:
            pass
            self._base_response_signature = None
    
    def _extract_title(self, html: str) -> Optional[str]:
        try:
            import re
            match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()[:100]
        except Exception:
            pass
        return None
    
    def _is_false_positive(self, response) -> bool:
        if not self._base_response_signature:
            return False
        
        current_length = len(response.content)
        base_length = self._base_response_signature["content_length"]
        
        if current_length == base_length:
            current_hash = hash(response.content[:1000])
            if current_hash == self._base_response_signature["content_hash"]:
                return True
        
        if base_length > 0:
            length_ratio = current_length / base_length
            if 0.95 <= length_ratio <= 1.05:
                current_type = response.headers.get("content-type", "")
                if current_type == self._base_response_signature["content_type"]:
                    if "text/html" in current_type:
                        current_title = self._extract_title(response.text)
                        if current_title and current_title == self._base_response_signature["title"]:
                            return True
        
        return False
    
    def _create_finding(
        self,
        path: str,
        category: EndpointCategory,
        description: str,
        severity: str,
        result: EndpointResult,
    ) -> None:
        full_url = urljoin(self.base_url, path)
        
        remediation_map = {
            EndpointCategory.CONFIG: "Remove or restrict access to configuration files. Never expose .env, config files, or credentials publicly. Use server configuration to block access to sensitive file extensions.",
            EndpointCategory.BACKUP: "Remove backup files from web-accessible directories. Store backups in a secure, non-public location. Implement proper backup procedures that don't leave files in webroot.",
            EndpointCategory.ADMIN: "Restrict admin panel access by IP address, VPN, or additional authentication. Consider moving admin interfaces to non-standard paths or separate domains.",
            EndpointCategory.VCS: "Remove version control directories from production. Add rules to block access to .git, .svn, .hg directories in web server configuration.",
            EndpointCategory.DEBUG: "Remove debug scripts and endpoints from production. Disable debug modes and remove phpinfo(), test scripts, and development tools.",
            EndpointCategory.DATABASE: "CRITICAL: Remove database files from web-accessible directories immediately. Database files should never be in the webroot.",
            EndpointCategory.DISCLOSURE: "Review if this information should be publicly accessible. Consider the sensitivity of exposed data.",
            EndpointCategory.API: "Review API documentation exposure. Consider if public API docs are intentional and if they expose sensitive endpoints.",
        }
        
        remediation = remediation_map.get(category, "Restrict access to this endpoint or remove it from the web-accessible directory.")
        
        match severity:
            case "critical":
                title = f"Critical Exposure: {path}"
            case "high":
                title = f"Sensitive Endpoint Exposed: {path}"
            case "medium":
                title = f"Potentially Sensitive Endpoint: {path}"
            case _:
                title = f"Endpoint Accessible: {path}"
        
        if severity == "info" and path in ("/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt"):
            return
        
        self.findings.append(EndpointFinding(
            title=title,
            severity=severity,
            description=f"{description}. This endpoint returned HTTP 200 and appears accessible.",
            remediation=remediation,
            confidence=95 if result.content_length > 0 else 80,
            path=full_url,
            metadata={
                "status_code": result.status_code,
                "content_length": result.content_length,
                "content_type": result.content_type,
                "category": category.value,
            },
        ))
    
    def _parse_robots_txt(self) -> None:
        robots_url = urljoin(self.base_url, "/robots.txt")
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(robots_url)
                
                if response.status_code != 200:
                    return
                
                for line in response.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/" and not path.startswith("#"):
                            if "*" not in path:
                                self.robots_disallowed.append(path)
                
                if self.robots_disallowed:
                    logger.info(f"Found {len(self.robots_disallowed)} disallowed paths in robots.txt")
                    
        except Exception:
            pass


def check_endpoints(target: str, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    checker = EndpointChecker(target, timeout)
    return checker.run_all_checks()


def quick_endpoint_check(target: str, paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    if paths is None:
        paths = ["/.env", "/.git/config", "/backup.zip", "/phpinfo.php", "/admin"]
    
    results = []
    
    try:
        with httpx.Client(timeout=10, follow_redirects=False) as client:
            for path in paths:
                full_url = urljoin(target, path)
                try:
                    response = client.get(full_url)
                    results.append({
                        "path": path,
                        "url": full_url,
                        "status": response.status_code,
                        "accessible": response.status_code == 200,
                        "size": len(response.content),
                    })
                except Exception:
                    results.append({
                        "path": path,
                        "url": full_url,
                        "status": None,
                        "accessible": False,
                        "error": True,
                    })
    except Exception as e:
        return [{"error": str(e)}]
    
    return results


__all__ = [
    "EndpointChecker",
    "EndpointFinding",
    "EndpointResult",
    "EndpointCategory",
    "check_endpoints",
    "quick_endpoint_check",
    "SENSITIVE_PATHS",
]
