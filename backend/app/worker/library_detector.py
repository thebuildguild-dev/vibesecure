import re
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from urllib.parse import urlparse, unquote

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False
    logger.warning("BeautifulSoup not available. Will use regex-only parsing.")


@dataclass
class LibraryDetection:
    name: str
    version: Optional[str] = None
    evidence_url: Optional[str] = None
    evidence_type: str = "cdn"
    confidence: int = 80
    details: Optional[str] = None


CDN_PATTERNS = [
    {"name": "jsdelivr_npm", "pattern": r"cdn\.jsdelivr\.net/npm/([^/@]+)@([^/]+)", "library_group": 1, "version_group": 2},
    {"name": "unpkg", "pattern": r"unpkg\.com/([^/@]+)@([^/]+)", "library_group": 1, "version_group": 2},
    {"name": "cdnjs", "pattern": r"cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)", "library_group": 1, "version_group": 2},
    {"name": "google_cdn", "pattern": r"ajax\.googleapis\.com/ajax/libs/([^/]+)/([^/]+)", "library_group": 1, "version_group": 2},
    {"name": "jsdelivr_gh", "pattern": r"cdn\.jsdelivr\.net/gh/[^/]+/([^/@]+)@([^/]+)", "library_group": 1, "version_group": 2},
]

LIBRARY_PATTERNS = [
    {"name": "react", "pattern": r"react(?:\.min)?\.js", "type": "framework"},
    {"name": "vue", "pattern": r"vue(?:\.min)?\.js", "type": "framework"},
    {"name": "angular", "pattern": r"angular(?:\.min)?\.js", "type": "framework"},
    {"name": "svelte", "pattern": r"svelte(?:\.min)?\.js", "type": "framework"},
    {"name": "jquery", "pattern": r"jquery(?:\.min)?\.js", "type": "library"},
    {"name": "lodash", "pattern": r"lodash(?:\.min)?\.js", "type": "library"},
    {"name": "axios", "pattern": r"axios(?:\.min)?\.js", "type": "library"},
    {"name": "moment", "pattern": r"moment(?:\.min)?\.js", "type": "library"},
    {"name": "google-analytics", "pattern": r"google-analytics\.com/analytics\.js", "type": "analytics"},
    {"name": "gtag", "pattern": r"googletagmanager\.com/gtag/js", "type": "analytics"},
    {"name": "gtm", "pattern": r"googletagmanager\.com/gtm\.js", "type": "analytics"},
    {"name": "facebook-pixel", "pattern": r"connect\.facebook\.net/.*?/fbevents\.js", "type": "analytics"},
    {"name": "hotjar", "pattern": r"static\.hotjar\.com/", "type": "analytics"},
    {"name": "mixpanel", "pattern": r"cdn\.mxpnl\.com/", "type": "analytics"},
    {"name": "bootstrap", "pattern": r"bootstrap(?:\.min)?\.js", "type": "ui"},
    {"name": "tailwind", "pattern": r"tailwindcss", "type": "ui"},
    {"name": "material-ui", "pattern": r"material-ui", "type": "ui"},
    {"name": "webpack", "pattern": r"webpack", "type": "build"},
    {"name": "vite", "pattern": r"@vite/client", "type": "build"},
]

INLINE_INDICATORS = [
    {"name": "React", "pattern": r"React\.createElement|ReactDOM\.render", "type": "framework"},
    {"name": "Vue", "pattern": r"new Vue\(|Vue\.createApp", "type": "framework"},
    {"name": "Angular", "pattern": r"angular\.module|ng-app", "type": "framework"},
    {"name": "jQuery", "pattern": r"\$\(|jQuery\(", "type": "library"},
    {"name": "Google Analytics", "pattern": r"ga\(|gtag\(", "type": "analytics"},
    {"name": "Facebook Pixel", "pattern": r"fbq\(", "type": "analytics"},
]

KNOWN_OLD_VERSIONS = {
    "jquery": ["1.x", "2.x"],
    "react": ["16.x", "15.x"],
    "angular": ["1.x"],
    "vue": ["2.x"],
}


class LibraryDetector:
    def __init__(self, html: str, verification_id: Optional[int] = None):
        self.html = html
        self.verification_id = verification_id
        self.detections: List[LibraryDetection] = []
    
    def detect_all(self) -> List[LibraryDetection]:
        script_urls = self._extract_script_urls()
        
        for url in script_urls:
            detections = self._detect_from_cdn_url(url)
            self.detections.extend(detections)
        
        if BEAUTIFULSOUP_AVAILABLE:
            inline_scripts = self._extract_inline_scripts()
            for script_content in inline_scripts:
                detections = self._detect_from_inline(script_content)
                self.detections.extend(detections)
        
        return self._deduplicate_detections()
    
    def _extract_script_urls(self) -> List[str]:
        urls = []
        
        if BEAUTIFULSOUP_AVAILABLE:
            soup = BeautifulSoup(self.html, 'html.parser')
            script_tags = soup.find_all('script', src=True)
            urls = [tag['src'] for tag in script_tags if tag.get('src')]
        else:
            pattern = r'<script[^>]+src=["\'](.*?)["\']'
            matches = re.findall(pattern, self.html, re.IGNORECASE)
            urls = matches
        
        return urls
    
    def _extract_inline_scripts(self) -> List[str]:
        if not BEAUTIFULSOUP_AVAILABLE:
            return []
        
        scripts = []
        soup = BeautifulSoup(self.html, 'html.parser')
        
        script_tags = soup.find_all('script', src=False)
        
        for tag in script_tags:
            content = tag.string
            if content and len(content.strip()) > 0:
                scripts.append(content[:10000])
        
        return scripts
    
    def _detect_from_cdn_url(self, url: str) -> List[LibraryDetection]:
        detections = []
        
        for cdn_config in CDN_PATTERNS:
            pattern = cdn_config["pattern"]
            match = re.search(pattern, url, re.IGNORECASE)
            
            if match:
                library_name = match.group(cdn_config["library_group"]).lower().strip()
                version = match.group(cdn_config["version_group"]).strip()
                
                detection = LibraryDetection(
                    name=library_name,
                    version=version,
                    evidence_url=url,
                    evidence_type="cdn",
                    confidence=95,
                    details=f"Detected from {cdn_config['name']} CDN pattern"
                )
                
                detections.append(detection)
                return detections
        
        for lib_config in LIBRARY_PATTERNS:
            pattern = lib_config["pattern"]
            if re.search(pattern, url, re.IGNORECASE):
                library_name = lib_config["name"]
                
                detection = LibraryDetection(
                    name=library_name,
                    version=None,
                    evidence_url=url,
                    evidence_type="cdn",
                    confidence=80,
                    details=f"Detected from URL pattern ({lib_config['type']})"
                )
                
                detections.append(detection)
                return detections
        
        return detections
    
    def _detect_from_inline(self, script_content: str) -> List[LibraryDetection]:
        detections = []
        
        for indicator in INLINE_INDICATORS:
            if re.search(indicator["pattern"], script_content, re.IGNORECASE):
                detection = LibraryDetection(
                    name=indicator["name"],
                    version=None,
                    evidence_url=None,
                    evidence_type="inline",
                    confidence=70,
                    details=f"Detected from inline script pattern ({indicator['type']})"
                )
                detections.append(detection)
        
        return detections
    
    def _deduplicate_detections(self) -> List[LibraryDetection]:
        by_name: Dict[str, List[LibraryDetection]] = {}
        
        for detection in self.detections:
            name_lower = detection.name.lower()
            if name_lower not in by_name:
                by_name[name_lower] = []
            by_name[name_lower].append(detection)
        
        unique = []
        for name, detections_list in by_name.items():
            sorted_detections = sorted(
                detections_list,
                key=lambda d: (d.version is not None, d.confidence),
                reverse=True
            )
            unique.append(sorted_detections[0])
        
        return unique
    
    def check_outdated(self, detection: LibraryDetection) -> bool:
        if not detection.version:
            return False
        
        library_lower = detection.name.lower()
        
        if library_lower in KNOWN_OLD_VERSIONS:
            for old_pattern in KNOWN_OLD_VERSIONS[library_lower]:
                if old_pattern.endswith('.x'):
                    major = old_pattern.split('.')[0]
                    if detection.version.startswith(major + '.'):
                        return True
        
        return False


def detect_libraries(
    html: str,
    verification_id: Optional[int] = None,
) -> List[LibraryDetection]:
    detector = LibraryDetector(html, verification_id)
    return detector.detect_all()


def generate_findings(
    detections: List[LibraryDetection],
    url: str,
    verification_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    findings = []
    
    for detection in detections:
        detector = LibraryDetector("", verification_id)
        is_outdated = detector.check_outdated(detection)
        severity = "low" if is_outdated else "info"
        
        title = f"JavaScript library detected: {detection.name}"
        if detection.version:
            title += f" {detection.version}"
        
        if is_outdated:
            title += " (possibly outdated)"
        
        remediation = f"Library '{detection.name}' detected on the page."
        if detection.version:
            remediation += f" Version: {detection.version}."
        
        if is_outdated:
            remediation += " This version may be outdated. Review for known vulnerabilities and consider updating."
        else:
            remediation += " Review for known vulnerabilities if this is a critical library."
        
        finding = {
            "title": title,
            "severity": severity,
            "remediation": remediation,
            "confidence": detection.confidence,
            "url": url,
            "details": {
                "library": detection.name,
                "version": detection.version,
                "evidence_url": detection.evidence_url,
                "evidence_type": detection.evidence_type,
                "possibly_outdated": is_outdated,
                "verification_id": verification_id,
            }
        }
        
        findings.append(finding)
    
    return findings
