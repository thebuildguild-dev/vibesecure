import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
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

# Common directories to check for listing
COMMON_DIRECTORIES: List[Tuple[str, str]] = [
    # Upload directories
    ("/uploads/", "User uploads directory"),
    ("/upload/", "Upload directory"),
    ("/files/", "Files directory"),
    ("/documents/", "Documents directory"),
    ("/docs/", "Documentation directory"),
    ("/attachments/", "Attachments directory"),
    ("/media/", "Media files directory"),
    
    # Static asset directories
    ("/static/", "Static assets directory"),
    ("/assets/", "Assets directory"),
    ("/public/", "Public files directory"),
    ("/resources/", "Resources directory"),
    ("/content/", "Content directory"),
    
    # Image directories
    ("/images/", "Images directory"),
    ("/img/", "Images directory"),
    ("/imgs/", "Images directory"),
    ("/photos/", "Photos directory"),
    ("/pictures/", "Pictures directory"),
    ("/thumbnails/", "Thumbnails directory"),
    ("/gallery/", "Gallery directory"),
    
    # Script/style directories
    ("/js/", "JavaScript directory"),
    ("/javascript/", "JavaScript directory"),
    ("/scripts/", "Scripts directory"),
    ("/css/", "CSS directory"),
    ("/styles/", "Styles directory"),
    ("/fonts/", "Fonts directory"),
    
    # Data directories
    ("/data/", "Data directory"),
    ("/tmp/", "Temporary files directory"),
    ("/temp/", "Temporary files directory"),
    ("/cache/", "Cache directory"),
    ("/logs/", "Logs directory"),
    ("/log/", "Log directory"),
    
    # Backup directories
    ("/backup/", "Backup directory"),
    ("/backups/", "Backups directory"),
    ("/bak/", "Backup directory"),
    ("/old/", "Old files directory"),
    ("/archive/", "Archive directory"),
    
    # CMS specific
    ("/wp-content/uploads/", "WordPress uploads"),
    ("/wp-includes/", "WordPress includes"),
    ("/sites/default/files/", "Drupal files"),
    ("/storage/", "Laravel storage"),
    
    # Development
    ("/test/", "Test directory"),
    ("/tests/", "Tests directory"),
    ("/demo/", "Demo directory"),
    ("/examples/", "Examples directory"),
    ("/samples/", "Samples directory"),
    
    # Include directories
    ("/includes/", "Includes directory"),
    ("/inc/", "Includes directory"),
    ("/lib/", "Library directory"),
    ("/libs/", "Libraries directory"),
    ("/vendor/", "Vendor directory"),
    ("/node_modules/", "Node modules directory"),
    
    # Admin areas
    ("/admin/", "Admin directory"),
    ("/administrator/", "Administrator directory"),
    ("/private/", "Private directory"),
    ("/internal/", "Internal directory"),
]

# Patterns that indicate directory listing is enabled
DIRECTORY_LISTING_PATTERNS: List[Tuple[str, str]] = [
    # Apache patterns
    (r'Index of /', "Apache directory index"),
    (r'<title>Index of', "Apache directory index title"),
    (r'Parent Directory</a>', "Apache parent directory link"),
    (r'\[DIR\]', "Apache directory marker"),
    (r'\[TXT\]', "Apache text file marker"),
    (r'\[IMG\]', "Apache image marker"),
    (r'Apache/[\d.]+ Server at', "Apache server signature"),
    (r'<address>Apache/', "Apache address tag"),
    
    # nginx patterns
    (r'<title>Index of', "nginx directory index"),
    (r'<h1>Index of', "nginx directory heading"),
    (r'nginx/[\d.]+</center>', "nginx server signature"),
    (r'autoindex', "nginx autoindex"),
    
    # IIS patterns
    (r'\[To Parent Directory\]', "IIS parent directory"),
    (r'<H1>.*Directory Listing', "IIS directory listing header"),
    (r'Microsoft-IIS/', "IIS server signature"),
    
    # LiteSpeed patterns
    (r'LiteSpeed', "LiteSpeed server"),
    
    # Generic patterns
    (r'Directory Listing', "Generic directory listing"),
    (r'Directory listing for', "Generic directory listing"),
    (r'directory of', "Directory listing indicator"),
    (r'<a href="\.\./?">', "Parent directory link"),
    (r'<a href="\?C=[NMSD];O=[AD]">', "Sortable column links"),
    (r'Last modified</a>', "Last modified column"),
    (r'<pre>.*<a href="', "Preformatted directory listing"),
    
    # File listing indicators (multiple file links)
    (r'\.zip">', "ZIP file link in listing"),
    (r'\.sql">', "SQL file link in listing"),
    (r'\.bak">', "Backup file link in listing"),
    (r'\.conf">', "Config file link in listing"),
    (r'\.log">', "Log file link in listing"),
]

# High-value files that indicate serious exposure if found in listings
SENSITIVE_FILE_PATTERNS: List[Tuple[str, str]] = [
    (r'\.sql"', "Database dump file"),
    (r'\.bak"', "Backup file"),
    (r'\.backup"', "Backup file"),
    (r'\.zip"', "Archive file"),
    (r'\.tar"', "Archive file"),
    (r'\.gz"', "Compressed file"),
    (r'\.rar"', "Archive file"),
    (r'\.7z"', "Archive file"),
    (r'\.env"', "Environment file"),
    (r'\.config"', "Configuration file"),
    (r'\.conf"', "Configuration file"),
    (r'\.ini"', "Configuration file"),
    (r'\.log"', "Log file"),
    (r'\.key"', "Key file"),
    (r'\.pem"', "Certificate/key file"),
    (r'\.crt"', "Certificate file"),
    (r'password', "Password-related file"),
    (r'secret', "Secret-related file"),
    (r'credential', "Credentials file"),
    (r'\.git"', "Git directory"),
    (r'\.svn"', "SVN directory"),
    (r'\.htaccess"', "Apache config"),
    (r'\.htpasswd"', "Apache password file"),
    (r'web\.config"', "IIS config"),
]


@dataclass
class DirectoryFinding:
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
class DirectoryResult:
    path: str
    url: str
    has_listing: bool
    status_code: int
    patterns_matched: List[str]
    sensitive_files: List[str]
    server_type: Optional[str] = None


class DirectoryChecker:
    def __init__(
        self,
        target: str,
        timeout: int = DEFAULT_TIMEOUT,
        check_sensitive_files: bool = True,
    ):
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        parsed = urlparse(target)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.target = target
        self.timeout = timeout
        self.check_sensitive_files = check_sensitive_files
        self.findings: List[DirectoryFinding] = []
        self.exposed_directories: List[DirectoryResult] = []
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting directory listing scan for {self.base_url}")
        
        self.findings = []
        self.exposed_directories = []
        
        for path, description in COMMON_DIRECTORIES:
            result = self._check_directory(path, description)
            if result and result.has_listing:
                self.exposed_directories.append(result)
                self._create_finding(result, description)
        
        if len(self.exposed_directories) >= 3:
            self._create_summary_finding()
        
        logger.info(f"Directory scan complete. Found {len(self.exposed_directories)} exposed directories.")
        
        return [f.to_dict() for f in self.findings]
    
    def _check_directory(self, path: str, description: str) -> Optional[DirectoryResult]:
        url = urljoin(self.base_url, path)
        
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = client.get(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                    }
                )
                
                if response.status_code != 200:
                    return DirectoryResult(
                        path=path,
                        url=url,
                        has_listing=False,
                        status_code=response.status_code,
                        patterns_matched=[],
                        sensitive_files=[],
                    )
                
                content = response.text
                patterns_matched = []
                sensitive_files = []
                server_type = None
                
                for pattern, pattern_name in DIRECTORY_LISTING_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        patterns_matched.append(pattern_name)
                        
                        if "Apache" in pattern_name:
                            server_type = "Apache"
                        elif "nginx" in pattern_name:
                            server_type = "nginx"
                        elif "IIS" in pattern_name:
                            server_type = "IIS"
                
                if self.check_sensitive_files and patterns_matched:
                    for file_pattern, file_desc in SENSITIVE_FILE_PATTERNS:
                        if re.search(file_pattern, content, re.IGNORECASE):
                            sensitive_files.append(file_desc)
                
                if not server_type:
                    server_header = response.headers.get("server", "")
                    if "Apache" in server_header:
                        server_type = "Apache"
                    elif "nginx" in server_header:
                        server_type = "nginx"
                    elif "IIS" in server_header or "Microsoft" in server_header:
                        server_type = "IIS"
                
                has_listing = len(patterns_matched) > 0
                
                return DirectoryResult(
                    path=path,
                    url=url,
                    has_listing=has_listing,
                    status_code=response.status_code,
                    patterns_matched=patterns_matched,
                    sensitive_files=sensitive_files,
                    server_type=server_type,
                )
                
        except httpx.ConnectError:
            pass
        except httpx.TimeoutException:
            pass
        except Exception as e:
            logger.warning(f"Error checking {url}: {e}")
        
        return None
    
    def _create_finding(self, result: DirectoryResult, description: str) -> None:
        if result.sensitive_files:
            severity = "high"
            title = f"Directory Listing with Sensitive Files: {result.path}"
        else:
            severity = "medium"
            title = f"Directory Listing Enabled: {result.path}"
        
        desc_parts = [
            f"Directory listing is enabled for {result.path} ({description}).",
            f"The server exposes the contents of this directory to anyone who requests it.",
        ]
        
        if result.patterns_matched:
            patterns_str = ", ".join(result.patterns_matched[:3])
            desc_parts.append(f"Detected patterns: {patterns_str}.")
        
        if result.sensitive_files:
            files_str = ", ".join(set(result.sensitive_files)[:5])
            desc_parts.append(f"SENSITIVE FILES DETECTED: {files_str}.")
        
        desc_parts.append(
            "Directory listings can expose file structure, backup files, "
            "configuration files, and other sensitive information."
        )
        
        remediation = self._get_remediation(result.server_type)
        
        self.findings.append(DirectoryFinding(
            title=title,
            severity=severity,
            description=" ".join(desc_parts),
            remediation=remediation,
            confidence=90 if len(result.patterns_matched) >= 2 else 80,
            path=result.url,
            metadata={
                "directory": result.path,
                "patterns_matched": result.patterns_matched,
                "sensitive_files": result.sensitive_files,
                "server_type": result.server_type,
            },
        ))
    
    def _get_remediation(self, server_type: Optional[str]) -> str:
        base_advice = "Disable directory listing on your web server."
        
        apache_advice = """
**Apache:**
Add to `.htaccess` or `httpd.conf`:
```
Options -Indexes
```

Or for specific directories in `<Directory>` blocks:
```
<Directory /var/www/html/uploads>
    Options -Indexes
</Directory>
```
"""
        
        nginx_advice = """
**nginx:**
Remove or set to off the `autoindex` directive:
```
location /uploads/ {
    autoindex off;
}
```

Or globally in the server block:
```
server {
    autoindex off;
    ...
}
```
"""
        
        iis_advice = """
**IIS:**
1. Open IIS Manager
2. Select the site or directory
3. Double-click "Directory Browsing"
4. Click "Disable" in the Actions pane

Or via web.config:
```xml
<system.webServer>
    <directoryBrowse enabled="false" />
</system.webServer>
```
"""
        
        if server_type == "Apache":
            return f"{base_advice}\n{apache_advice}"
        elif server_type == "nginx":
            return f"{base_advice}\n{nginx_advice}"
        elif server_type == "IIS":
            return f"{base_advice}\n{iis_advice}"
        else:
            return f"{base_advice}\n{apache_advice}\n{nginx_advice}\n{iis_advice}"
    
    def _create_summary_finding(self) -> None:
        dir_list = ", ".join([d.path for d in self.exposed_directories[:5]])
        if len(self.exposed_directories) > 5:
            dir_list += f", and {len(self.exposed_directories) - 5} more"
        
        has_sensitive = any(d.sensitive_files for d in self.exposed_directories)
        
        self.findings.append(DirectoryFinding(
            title="Multiple Directory Listings Enabled",
            severity="high" if has_sensitive else "medium",
            description=(
                f"Directory listing is enabled on {len(self.exposed_directories)} directories: {dir_list}. "
                "This widespread exposure suggests directory listing may be enabled server-wide, "
                "significantly increasing the attack surface and potential for information disclosure."
            ),
            remediation=(
                "Disable directory listing globally on the web server rather than per-directory.\n\n"
                "**Apache:** Add `Options -Indexes` to the main configuration.\n"
                "**nginx:** Set `autoindex off;` in the http or server block.\n"
                "**IIS:** Disable directory browsing at the site level."
            ),
            confidence=95,
            path=self.base_url,
            metadata={
                "exposed_count": len(self.exposed_directories),
                "directories": [d.path for d in self.exposed_directories],
                "has_sensitive_files": has_sensitive,
            },
        ))


def check_directory_listing(target: str, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    checker = DirectoryChecker(target, timeout)
    return checker.run_all_checks()


def quick_directory_check(
    target: str, 
    paths: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    if paths is None:
        paths = ["/uploads/", "/static/", "/images/", "/files/", "/backup/"]
    
    results = []
    
    try:
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            for path in paths:
                url = urljoin(target, path)
                try:
                    response = client.get(url)
                    
                    has_listing = False
                    if response.status_code == 200:
                        content = response.text
                        if re.search(r'Index of|Directory listing|Parent Directory', content, re.IGNORECASE):
                            has_listing = True
                    
                    results.append({
                        "path": path,
                        "url": url,
                        "status": response.status_code,
                        "has_listing": has_listing,
                    })
                except Exception:
                    results.append({
                        "path": path,
                        "url": url,
                        "status": None,
                        "error": True,
                    })
    except Exception as e:
        return [{"error": str(e)}]
    
    return results


__all__ = [
    "DirectoryChecker",
    "DirectoryFinding",
    "DirectoryResult",
    "check_directory_listing",
    "quick_directory_check",
    "COMMON_DIRECTORIES",
    "DIRECTORY_LISTING_PATTERNS",
]
