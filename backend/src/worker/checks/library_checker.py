import re
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from packaging import version as pkg_version

import httpx

try:
    from src.core.config import settings
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
    from src.core.config import settings

logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT = settings.security_check_library_timeout

KNOWN_LIBRARIES: List[Dict[str, Any]] = [
    # jQuery
    {
        "name": "jQuery",
        "patterns": [
            r'jquery[.-]?(\d+\.\d+\.\d+)',
            r'jquery\.min\.js',
            r'jquery\.js',
            r'/jquery/',
        ],
        "version_regex": r'jquery[.-]?(\d+\.\d+\.\d+)',
        "global_check": r'jQuery\.fn\.jquery\s*[=:]\s*["\'](\d+\.\d+\.\d+)',
        "min_safe": "3.5.0",
        "eol": "1.12.4",
        "vulnerabilities": {
            "3.4.1": "CVE-2020-11022, CVE-2020-11023 - XSS vulnerabilities",
            "3.4.0": "CVE-2020-11022, CVE-2020-11023 - XSS vulnerabilities",
            "2.2.4": "Multiple XSS vulnerabilities",
            "1.12.4": "Multiple XSS and prototype pollution vulnerabilities",
        },
    },
    # jQuery UI
    {
        "name": "jQuery UI",
        "patterns": [
            r'jquery-ui[.-]?(\d+\.\d+\.\d+)',
            r'jquery\.ui',
            r'jqueryui',
        ],
        "version_regex": r'jquery-ui[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "1.13.0",
        "eol": "1.11.4",
        "vulnerabilities": {
            "1.12.1": "CVE-2021-41182, CVE-2021-41183, CVE-2021-41184 - XSS vulnerabilities",
        },
    },
    # Bootstrap
    {
        "name": "Bootstrap",
        "patterns": [
            r'bootstrap[.-]?(\d+\.\d+\.\d+)',
            r'bootstrap\.min\.js',
            r'bootstrap\.min\.css',
            r'bootstrap\.bundle',
            r'/bootstrap/',
        ],
        "version_regex": r'bootstrap[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "5.2.0",
        "eol": "3.4.1",
        "vulnerabilities": {
            "4.3.1": "CVE-2019-8331 - XSS in tooltip/popover",
            "3.4.0": "CVE-2019-8331 - XSS vulnerability",
            "3.3.7": "Multiple XSS vulnerabilities",
        },
    },
    # Angular (AngularJS 1.x)
    {
        "name": "AngularJS",
        "patterns": [
            r'angular[.-]?(\d+\.\d+\.\d+)',
            r'angular\.min\.js',
            r'angular\.js',
        ],
        "version_regex": r'angular[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "1.8.3",
        "eol": "1.2.32",
        "vulnerabilities": {
            "1.6.9": "Sandbox escape vulnerabilities",
            "1.5.11": "Multiple security issues",
            "1.4.14": "Sandbox escape, XSS vulnerabilities",
        },
    },
    # Vue.js
    {
        "name": "Vue.js",
        "patterns": [
            r'vue[.-]?(\d+\.\d+\.\d+)',
            r'vue\.min\.js',
            r'vue\.js',
            r'vue\.global',
            r'vue\.runtime',
        ],
        "version_regex": r'vue[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "3.2.0",
        "eol": "2.6.14",
        "vulnerabilities": {},
    },
    # React
    {
        "name": "React",
        "patterns": [
            r'react[.-]?(\d+\.\d+\.\d+)',
            r'react\.production\.min\.js',
            r'react\.development\.js',
            r'react-dom',
        ],
        "version_regex": r'react[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "18.0.0",
        "eol": "16.14.0",
        "vulnerabilities": {
            "16.0.0": "CVE-2018-6341 - XSS vulnerability",
        },
    },
    # Lodash
    {
        "name": "Lodash",
        "patterns": [
            r'lodash[.-]?(\d+\.\d+\.\d+)',
            r'lodash\.min\.js',
            r'lodash\.js',
        ],
        "version_regex": r'lodash[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "4.17.21",
        "eol": "3.10.1",
        "vulnerabilities": {
            "4.17.20": "CVE-2021-23337 - Command injection",
            "4.17.15": "CVE-2020-8203 - Prototype pollution",
            "4.17.11": "CVE-2019-10744 - Prototype pollution",
        },
    },
    # Moment.js
    {
        "name": "Moment.js",
        "patterns": [
            r'moment[.-]?(\d+\.\d+\.\d+)',
            r'moment\.min\.js',
            r'moment\.js',
            r'moment-with-locales',
        ],
        "version_regex": r'moment[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "2.29.4",
        "eol": "2.24.0",
        "vulnerabilities": {
            "2.29.1": "CVE-2022-24785 - Path traversal",
            "2.19.2": "ReDoS vulnerability",
        },
    },
    # Handlebars
    {
        "name": "Handlebars",
        "patterns": [
            r'handlebars[.-]?(\d+\.\d+\.\d+)',
            r'handlebars\.min\.js',
            r'handlebars\.js',
        ],
        "version_regex": r'handlebars[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "4.7.7",
        "eol": "3.0.8",
        "vulnerabilities": {
            "4.7.6": "CVE-2021-23369 - Remote code execution",
            "4.5.3": "CVE-2019-19919 - Prototype pollution",
        },
    },
    # Font Awesome
    {
        "name": "Font Awesome",
        "patterns": [
            r'font-?awesome[.-]?(\d+\.\d+\.\d+)',
            r'fontawesome[.-]?(\d+\.\d+\.\d+)',
            r'font-awesome\.min\.css',
            r'all\.min\.css.*fontawesome',
        ],
        "version_regex": r'font-?awesome[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "6.0.0",
        "eol": "4.7.0",
        "vulnerabilities": {},
    },
    # Axios
    {
        "name": "Axios",
        "patterns": [
            r'axios[.-]?(\d+\.\d+\.\d+)',
            r'axios\.min\.js',
        ],
        "version_regex": r'axios[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "1.6.0",
        "eol": "0.21.4",
        "vulnerabilities": {
            "1.5.1": "CVE-2023-45857 - CSRF vulnerability",
            "0.21.1": "CVE-2021-3749 - ReDoS vulnerability",
        },
    },
    # Underscore.js
    {
        "name": "Underscore.js",
        "patterns": [
            r'underscore[.-]?(\d+\.\d+\.\d+)',
            r'underscore\.min\.js',
        ],
        "version_regex": r'underscore[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "1.13.6",
        "eol": "1.8.3",
        "vulnerabilities": {
            "1.12.0": "CVE-2021-23358 - Arbitrary code execution",
        },
    },
    # D3.js
    {
        "name": "D3.js",
        "patterns": [
            r'd3[.-]?(\d+\.\d+\.\d+)',
            r'd3\.min\.js',
            r'd3\.v\d+',
        ],
        "version_regex": r'd3[.-]?v?(\d+\.\d+\.\d+)',
        "min_safe": "7.0.0",
        "eol": "3.5.17",
        "vulnerabilities": {},
    },
    # TinyMCE
    {
        "name": "TinyMCE",
        "patterns": [
            r'tinymce[.-]?(\d+\.\d+\.\d+)',
            r'tinymce\.min\.js',
            r'tinymce/tinymce',
        ],
        "version_regex": r'tinymce[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "6.0.0",
        "eol": "4.9.11",
        "vulnerabilities": {
            "5.10.2": "CVE-2022-23494 - XSS vulnerability",
        },
    },
    # CKEditor
    {
        "name": "CKEditor",
        "patterns": [
            r'ckeditor[.-]?(\d+\.\d+\.\d+)',
            r'ckeditor\.js',
            r'ckeditor4?5?',
        ],
        "version_regex": r'ckeditor[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "41.0.0",
        "eol": "4.16.2",
        "vulnerabilities": {
            "4.16.1": "CVE-2021-41165 - XSS vulnerability",
        },
    },
    # Select2
    {
        "name": "Select2",
        "patterns": [
            r'select2[.-]?(\d+\.\d+\.\d+)',
            r'select2\.min\.js',
            r'select2\.min\.css',
        ],
        "version_regex": r'select2[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "4.1.0",
        "eol": "3.5.4",
        "vulnerabilities": {},
    },
    # Popper.js
    {
        "name": "Popper.js",
        "patterns": [
            r'popper[.-]?(\d+\.\d+\.\d+)',
            r'popper\.min\.js',
            r'@popperjs',
        ],
        "version_regex": r'popper[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "2.11.0",
        "eol": "1.16.1",
        "vulnerabilities": {},
    },
    # Chart.js
    {
        "name": "Chart.js",
        "patterns": [
            r'chart[.-]?(\d+\.\d+\.\d+)',
            r'chart\.min\.js',
            r'chart\.js',
        ],
        "version_regex": r'chart[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "4.0.0",
        "eol": "2.9.4",
        "vulnerabilities": {},
    },
    # Modernizr
    {
        "name": "Modernizr",
        "patterns": [
            r'modernizr[.-]?(\d+\.\d+\.\d+)',
            r'modernizr\.min\.js',
        ],
        "version_regex": r'modernizr[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "3.12.0",
        "eol": "2.8.3",
        "vulnerabilities": {},
    },
    # Backbone.js
    {
        "name": "Backbone.js",
        "patterns": [
            r'backbone[.-]?(\d+\.\d+\.\d+)',
            r'backbone\.min\.js',
        ],
        "version_regex": r'backbone[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "1.4.1",
        "eol": "1.1.2",
        "vulnerabilities": {},
    },
    # Knockout.js
    {
        "name": "Knockout.js",
        "patterns": [
            r'knockout[.-]?(\d+\.\d+\.\d+)',
            r'knockout\.min\.js',
        ],
        "version_regex": r'knockout[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "3.5.1",
        "eol": "3.4.2",
        "vulnerabilities": {},
    },
    # Ember.js
    {
        "name": "Ember.js",
        "patterns": [
            r'ember[.-]?(\d+\.\d+\.\d+)',
            r'ember\.min\.js',
            r'ember\.prod',
        ],
        "version_regex": r'ember[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "4.0.0",
        "eol": "3.28.11",
        "vulnerabilities": {},
    },
    # DOMPurify
    {
        "name": "DOMPurify",
        "patterns": [
            r'dompurify[.-]?(\d+\.\d+\.\d+)',
            r'purify\.min\.js',
        ],
        "version_regex": r'dompurify[.-]?(\d+\.\d+\.\d+)',
        "min_safe": "3.0.0",
        "eol": "2.3.0",
        "vulnerabilities": {
            "2.3.3": "CVE-2022-25927 - Mutation XSS bypass",
        },
    },
]


@dataclass
class LibraryFinding:
    title: str
    severity: str
    description: str
    remediation: str
    confidence: int = 80
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
class DetectedLibrary:
    name: str
    version: Optional[str]
    source_url: str
    source_type: str
    min_safe_version: Optional[str] = None
    eol_version: Optional[str] = None
    vulnerability: Optional[str] = None
    is_outdated: bool = False
    is_eol: bool = False


class LibraryChecker:
    
    def __init__(
        self,
        target: str,
        timeout: int = DEFAULT_TIMEOUT,
        check_linked_files: bool = True,
    ):
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        self.target = target
        self.timeout = timeout
        self.check_linked_files = check_linked_files
        self.findings: List[LibraryFinding] = []
        self.detected_libraries: List[DetectedLibrary] = []
        self.html_content: str = ""
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting library scan for {self.target}")
        
        self.findings = []
        self.detected_libraries = []
        
        if not self._fetch_page():
            return []
        
        self._extract_script_tags()
        self._extract_link_tags()
        self._check_inline_scripts()
        
        for lib in self.detected_libraries:
            if lib.is_outdated or lib.is_eol or lib.vulnerability:
                self._create_finding(lib)
        
        outdated_count = sum(1 for lib in self.detected_libraries if lib.is_outdated)
        if outdated_count >= 3:
            self._create_summary_finding()
        
        logger.info(f"Found {len(self.findings)} issues in {len(self.detected_libraries)} libraries")
        
        return [f.to_dict() for f in self.findings]
    
    def _fetch_page(self) -> bool:
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = client.get(
                    self.target,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    }
                )
                
                if response.status_code == 200:
                    self.html_content = response.text
                    return True
                else:
                    logger.warning(f"Failed to fetch page: HTTP {response.status_code}")
                    return False
                    
        except Exception as e:
            logger.warning(f"Error fetching page: {e}")
            return False
    
    def _extract_script_tags(self) -> None:
        script_pattern = r'<script[^>]*\ssrc=["\']([^"\']+)["\'][^>]*>'
        
        for match in re.finditer(script_pattern, self.html_content, re.IGNORECASE):
            src = match.group(1)
            self._analyze_resource_url(src, "script")
    
    def _extract_link_tags(self) -> None:
        link_pattern = r'<link[^>]*\shref=["\']([^"\']+)["\'][^>]*>'
        
        for match in re.finditer(link_pattern, self.html_content, re.IGNORECASE):
            href = match.group(1)
            if 'rel=' in match.group(0).lower() and 'stylesheet' not in match.group(0).lower():
                continue
            self._analyze_resource_url(href, "link")
    
    def _check_inline_scripts(self) -> None:
        comment_pattern = r'/\*[^*]*(?:jQuery|Bootstrap|Angular|Vue|React|Lodash)[^*]*v?(\d+\.\d+\.\d+)[^*]*\*/'
        
        for match in re.finditer(comment_pattern, self.html_content, re.IGNORECASE):
            version = match.group(1)
            full_match = match.group(0)
            
            for lib_info in KNOWN_LIBRARIES:
                if lib_info["name"].lower() in full_match.lower():
                    self._check_version(lib_info, version, "inline comment", "inline")
                    break
        
        for lib_info in KNOWN_LIBRARIES:
            if "global_check" in lib_info:
                global_match = re.search(lib_info["global_check"], self.html_content)
                if global_match:
                    version = global_match.group(1)
                    self._check_version(lib_info, version, "inline detection", "inline")
    
    def _analyze_resource_url(self, url: str, source_type: str) -> None:
        if url.startswith("//"):
            url = f"https:{url}"
        elif url.startswith("/"):
            url = urljoin(self.target, url)
        elif not url.startswith(("http://", "https://")):
            url = urljoin(self.target, url)
        
        url_lower = url.lower()
        
        for lib_info in KNOWN_LIBRARIES:
            matched = False
            version = None
            
            for pattern in lib_info["patterns"]:
                if re.search(pattern, url_lower):
                    matched = True
                    version_match = re.search(lib_info["version_regex"], url_lower)
                    if version_match:
                        version = version_match.group(1)
                    break
            
            if matched:
                self._check_version(lib_info, version, url, source_type)
                break
    
    def _check_version(
        self, 
        lib_info: Dict[str, Any], 
        version: Optional[str], 
        source: str, 
        source_type: str
    ) -> None:
        existing = [l for l in self.detected_libraries if l.name == lib_info["name"]]
        if existing:
            if version and not existing[0].version:
                existing[0].version = version
            return
        
        is_outdated = False
        is_eol = False
        vulnerability = None
        
        if version:
            try:
                current = pkg_version.parse(version)
                min_safe = pkg_version.parse(lib_info["min_safe"])
                eol = pkg_version.parse(lib_info["eol"])
                
                if current < min_safe:
                    is_outdated = True
                
                if current <= eol:
                    is_eol = True
                
                if version in lib_info.get("vulnerabilities", {}):
                    vulnerability = lib_info["vulnerabilities"][version]
                    
            except Exception as e:
                logger.debug(f"Version parsing error for {lib_info['name']} {version}: {e}")
        
        detected = DetectedLibrary(
            name=lib_info["name"],
            version=version,
            source_url=source,
            source_type=source_type,
            min_safe_version=lib_info["min_safe"],
            eol_version=lib_info["eol"],
            vulnerability=vulnerability,
            is_outdated=is_outdated,
            is_eol=is_eol,
        )
        
        self.detected_libraries.append(detected)
    
    def _create_finding(self, lib: DetectedLibrary) -> None:
        if lib.vulnerability:
            severity = "high"
            title = f"Vulnerable Library: {lib.name} {lib.version or ''}"
        elif lib.is_eol:
            severity = "medium"
            title = f"End-of-Life Library: {lib.name} {lib.version or ''}"
        elif lib.is_outdated:
            severity = "low"
            title = f"Outdated Frontend Library: {lib.name} {lib.version or ''}"
        else:
            severity = "info"
            title = f"Detected Library: {lib.name}"
        
        desc_parts = []
        
        if lib.version:
            desc_parts.append(f"Detected {lib.name} version {lib.version}.")
        else:
            desc_parts.append(f"Detected {lib.name} (version could not be determined).")
        
        if lib.vulnerability:
            desc_parts.append(f"KNOWN VULNERABILITY: {lib.vulnerability}")
        
        if lib.is_eol:
            desc_parts.append(
                f"This version is end-of-life and no longer receives security updates. "
                f"EOL version: {lib.eol_version}."
            )
        elif lib.is_outdated:
            desc_parts.append(
                f"This version is outdated. Minimum recommended version: {lib.min_safe_version}."
            )
        
        desc_parts.append(f"Source: {lib.source_url[:100]}{'...' if len(lib.source_url) > 100 else ''}")
        
        remediation = f"Update {lib.name} to at least version {lib.min_safe_version}."
        
        match lib.name:
            case "jQuery":
                remediation += "\n\nMigrate to jQuery 3.x using the jQuery Migrate plugin for compatibility."
            case "AngularJS":
                remediation += "\n\nNote: AngularJS (1.x) reached end-of-life. Consider migrating to Angular (2+)."
            case "Moment.js":
                remediation += "\n\nNote: Moment.js is in maintenance mode. Consider migrating to Day.js or Luxon."
        
        if lib.vulnerability:
            remediation += f"\n\nAddress vulnerability: {lib.vulnerability}"
        
        self.findings.append(LibraryFinding(
            title=title,
            severity=severity,
            description=" ".join(desc_parts),
            remediation=remediation,
            confidence=90 if lib.version else 60,
            path=self.target,
            metadata={
                "library": lib.name,
                "version": lib.version,
                "min_safe_version": lib.min_safe_version,
                "is_eol": lib.is_eol,
                "vulnerability": lib.vulnerability,
                "source_url": lib.source_url,
                "source_type": lib.source_type,
            },
        ))
    
    def _create_summary_finding(self) -> None:
        outdated = [lib for lib in self.detected_libraries if lib.is_outdated or lib.is_eol]
        vulnerable = [lib for lib in self.detected_libraries if lib.vulnerability]
        
        lib_list = ", ".join([f"{lib.name} {lib.version or ''}" for lib in outdated[:5]])
        
        self.findings.append(LibraryFinding(
            title="Multiple Outdated Frontend Libraries",
            severity="high" if vulnerable else "medium",
            description=(
                f"Detected {len(outdated)} outdated frontend libraries: {lib_list}. "
                f"{len(vulnerable)} have known vulnerabilities. "
                "Outdated libraries may contain security vulnerabilities and should be updated."
            ),
            remediation=(
                "Implement a dependency management strategy:\n"
                "1. Audit all frontend dependencies regularly\n"
                "2. Use tools like npm audit, Snyk, or Retire.js\n"
                "3. Set up automated alerts for security advisories\n"
                "4. Establish a process for timely updates"
            ),
            confidence=95,
            path=self.target,
            metadata={
                "outdated_count": len(outdated),
                "vulnerable_count": len(vulnerable),
                "libraries": [
                    {"name": lib.name, "version": lib.version, "vulnerability": lib.vulnerability}
                    for lib in outdated
                ],
            },
        ))


def check_libraries(target: str, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    checker = LibraryChecker(target, timeout)
    return checker.run_all_checks()


def quick_library_check(target: str) -> Dict[str, Any]:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    result = {
        "url": target,
        "libraries": [],
        "error": None,
    }
    
    try:
        checker = LibraryChecker(target, timeout=10)
        if checker._fetch_page():
            checker._extract_script_tags()
            checker._extract_link_tags()
            checker._check_inline_scripts()
            
            result["libraries"] = [
                {
                    "name": lib.name,
                    "version": lib.version,
                    "is_outdated": lib.is_outdated,
                    "source": lib.source_type,
                }
                for lib in checker.detected_libraries
            ]
    except Exception as e:
        result["error"] = str(e)
    
    return result


__all__ = [
    "LibraryChecker",
    "LibraryFinding",
    "DetectedLibrary",
    "check_libraries",
    "quick_library_check",
    "KNOWN_LIBRARIES",
]
