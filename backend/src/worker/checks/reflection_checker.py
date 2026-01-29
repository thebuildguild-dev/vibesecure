import re
import uuid
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from html import escape as html_escape

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
MARKER_PREFIX = "SCANTEST"

COMMON_PARAMS = [
    "q", "query", "search", "s", "keyword", "keywords",
    "id", "page", "name", "user", "username",
    "url", "redirect", "return", "next", "goto", "dest",
    "file", "path", "dir", "document",
    "action", "cmd", "command",
    "message", "msg", "text", "content", "body",
    "title", "subject", "description",
    "email", "mail",
    "callback", "cb", "jsonp",
    "template", "tpl", "view",
    "lang", "language", "locale",
    "sort", "order", "filter",
    "debug", "test", "dev",
]

DANGEROUS_CONTEXTS = [
    (r'<script[^>]*>[^<]*{marker}[^<]*</script>', "script_block", "high"),
    (r'on\w+\s*=\s*["\'][^"\']*{marker}', "event_handler", "high"),
    (r'(?:href|src)\s*=\s*["\']javascript:[^"\']*{marker}', "javascript_uri", "high"),
    (r'<[^>]+\s+\w+\s*=\s*{marker}', "unquoted_attribute", "high"),
    (r'<[^>]+\s+\w+\s*=\s*["\'][^"\']*{marker}[^"\']*["\']', "quoted_attribute", "medium"),
    (r'<!--[^>]*{marker}[^>]*-->', "html_comment", "low"),
    (r'style\s*=\s*["\'][^"\']*{marker}', "style_attribute", "medium"),
    (r'<style[^>]*>[^<]*{marker}[^<]*</style>', "style_block", "medium"),
    (r'data-\w+\s*=\s*["\'][^"\']*{marker}', "data_attribute", "low"),
    (r'<body[^>]*>.*{marker}', "html_body", "medium"),
    (r'<textarea[^>]*>[^<]*{marker}', "textarea", "low"),
    (r'<title[^>]*>[^<]*{marker}', "title_tag", "low"),
]


@dataclass
class ReflectionFinding:
    title: str
    severity: str
    description: str
    remediation: str
    confidence: int = 75
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
class ReflectionResult:
    parameter: str
    marker: str
    reflected: bool
    reflection_count: int
    contexts: List[Tuple[str, str]]
    encoded_reflected: bool = False
    url_tested: str = ""


class ReflectionChecker:
    
    def __init__(
        self,
        target: str,
        timeout: int = DEFAULT_TIMEOUT,
        test_common_params: bool = True,
        max_params_to_test: int = 20,
    ):
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        
        self.target = target
        self.timeout = timeout
        self.test_common_params = test_common_params
        self.max_params_to_test = max_params_to_test
        self.findings: List[ReflectionFinding] = []
        self.reflections: List[ReflectionResult] = []
        
        self.parsed = urlparse(target)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}{self.parsed.path}"
        self.existing_params = parse_qs(self.parsed.query)
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting reflection scan for {self.target}")
        
        self.findings = []
        self.reflections = []
        
        params_to_test = self._get_params_to_test()
        
        if not params_to_test:
            return []
        
        for param in params_to_test[:self.max_params_to_test]:
            result = self._test_parameter(param)
            if result and result.reflected:
                self.reflections.append(result)
                self._create_finding(result)
        
        if len(self.reflections) >= 3:
            self._create_summary_finding()
        
        logger.info(f"Reflection scan complete. Found {len(self.reflections)} reflected parameters.")
        
        return [f.to_dict() for f in self.findings]
    
    def _get_params_to_test(self) -> List[str]:
        params = set()
        params.update(self.existing_params.keys())
        
        if self.test_common_params:
            params.update(COMMON_PARAMS)
        
        return list(params)
    
    def _generate_marker(self) -> str:
        unique_id = uuid.uuid4().hex[:8].upper()
        return f"{MARKER_PREFIX}{unique_id}"
    
    def _test_parameter(self, param: str) -> Optional[ReflectionResult]:
        marker = self._generate_marker()
        
        test_params = dict(self.existing_params)
        test_params[param] = [marker]
        
        flat_params = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
        query_string = urlencode(flat_params)
        
        test_url = urlunparse((
            self.parsed.scheme,
            self.parsed.netloc,
            self.parsed.path,
            "",
            query_string,
            ""
        ))
        
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = client.get(
                    test_url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    }
                )
                
                if response.status_code != 200:
                    return ReflectionResult(
                        parameter=param,
                        marker=marker,
                        reflected=False,
                        reflection_count=0,
                        contexts=[],
                        url_tested=test_url,
                    )
                
                content = response.text
                
                reflected = marker in content
                reflection_count = content.count(marker) if reflected else 0
                
                encoded_marker = html_escape(marker)
                encoded_reflected = encoded_marker in content and encoded_marker != marker
                
                contexts = []
                if reflected:
                    contexts = self._analyze_contexts(content, marker)
                
                return ReflectionResult(
                    parameter=param,
                    marker=marker,
                    reflected=reflected,
                    reflection_count=reflection_count,
                    contexts=contexts,
                    encoded_reflected=encoded_reflected,
                    url_tested=test_url,
                )
                
        except httpx.ConnectError:
            logger.debug(f"Connection error testing {param}")
        except httpx.TimeoutException:
            logger.debug(f"Timeout testing {param}")
        except Exception as e:
            logger.debug(f"Error testing {param}: {e}")
        
        return None
    
    def _analyze_contexts(self, content: str, marker: str) -> List[Tuple[str, str]]:
        contexts = []
        
        for pattern, context_name, severity in DANGEROUS_CONTEXTS:
            regex = pattern.replace("{marker}", re.escape(marker))
            
            if re.search(regex, content, re.IGNORECASE | re.DOTALL):
                contexts.append((context_name, severity))
        
        return contexts
    
    def _create_finding(self, result: ReflectionResult) -> None:
        max_severity = "info"
        dangerous_contexts = []
        
        for context_name, severity in result.contexts:
            dangerous_contexts.append(context_name)
            if severity == "high":
                max_severity = "medium"
            elif severity == "medium" and max_severity not in ("medium",):
                max_severity = "low"
        
        if dangerous_contexts:
            title = f"Reflected Parameter in Dangerous Context: {result.parameter}"
        else:
            title = f"Reflected Parameter Detected: {result.parameter}"
        
        desc_parts = [
            f"The parameter `{result.parameter}` is reflected in the response.",
            f"A test marker was injected and appeared {result.reflection_count} time(s) in the HTML."
        ]
        
        if dangerous_contexts:
            contexts_str = ", ".join(dangerous_contexts[:3])
            desc_parts.append(f"The reflection appears in potentially dangerous contexts: {contexts_str}.")
            desc_parts.append("This may indicate a Cross-Site Scripting (XSS) vulnerability.")
        else:
            desc_parts.append("While the reflection is in a relatively safe context, it should still be reviewed.")
        
        if result.encoded_reflected:
            desc_parts.append("Note: The value is HTML-encoded, which provides some protection.")
            max_severity = "info"
        
        remediation = (
            "To prevent XSS vulnerabilities:\n\n"
            "1. **Output Encoding**: Always encode user input based on context:\n"
            "   - HTML context: HTML entity encoding\n"
            "   - JavaScript: JavaScript encoding\n"
            "   - URL: URL encoding\n"
            "   - CSS: CSS encoding\n\n"
            "2. **Input Validation**: Validate and sanitize user input\n\n"
            "3. **Content Security Policy**: Implement CSP headers to mitigate XSS impact\n\n"
            "4. **Use Safe APIs**: Use textContent instead of innerHTML, parameterized queries\n\n"
            "5. **Framework Protection**: Use framework auto-escaping features"
        )
        
        if dangerous_contexts:
            if "script_block" in dangerous_contexts or "event_handler" in dangerous_contexts:
                remediation += (
                    "\n\n**HIGH RISK**: Reflection in script context is especially dangerous. "
                    "Never insert untrusted data directly into JavaScript code."
                )
        
        self.findings.append(ReflectionFinding(
            title=title,
            severity=max_severity,
            description=" ".join(desc_parts),
            remediation=remediation,
            confidence=85 if dangerous_contexts else 70,
            path=result.url_tested,
            metadata={
                "parameter": result.parameter,
                "reflection_count": result.reflection_count,
                "contexts": [c[0] for c in result.contexts],
                "context_severities": {c[0]: c[1] for c in result.contexts},
                "encoded": result.encoded_reflected,
                "marker_used": result.marker,
            },
        ))
    
    def _create_summary_finding(self) -> None:
        params_list = ", ".join([r.parameter for r in self.reflections[:5]])
        
        has_dangerous = any(
            any(ctx[1] == "high" for ctx in r.contexts)
            for r in self.reflections
        )
        
        self.findings.append(ReflectionFinding(
            title="Multiple Reflected Parameters Detected",
            severity="low" if has_dangerous else "info",
            description=(
                f"Detected {len(self.reflections)} parameters that are reflected in responses: "
                f"{params_list}. Multiple reflection points increase the likelihood of "
                "exploitable XSS vulnerabilities. Each should be reviewed for proper encoding."
            ),
            remediation=(
                "Implement a consistent output encoding strategy across the application:\n"
                "1. Use a templating engine with auto-escaping enabled by default\n"
                "2. Conduct a security review of all reflected parameters\n"
                "3. Implement Content Security Policy (CSP)\n"
                "4. Consider using a Web Application Firewall (WAF)"
            ),
            confidence=80,
            path=self.target,
            metadata={
                "reflected_count": len(self.reflections),
                "parameters": [r.parameter for r in self.reflections],
                "has_dangerous_contexts": has_dangerous,
            },
        ))


def check_reflections(target: str, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    checker = ReflectionChecker(target, timeout)
    return checker.run_all_checks()


def quick_reflection_check(target: str, params: Optional[List[str]] = None) -> Dict[str, Any]:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    result = {
        "url": target,
        "reflected_params": [],
        "safe_params": [],
        "error": None,
    }
    
    try:
        checker = ReflectionChecker(target, timeout=10, test_common_params=False)
        
        if params:
            params_to_test = params
        else:
            params_to_test = list(checker.existing_params.keys())
        
        for param in params_to_test[:10]:
            test_result = checker._test_parameter(param)
            if test_result:
                if test_result.reflected:
                    result["reflected_params"].append({
                        "name": param,
                        "count": test_result.reflection_count,
                        "contexts": [c[0] for c in test_result.contexts],
                    })
                else:
                    result["safe_params"].append(param)
                    
    except Exception as e:
        result["error"] = str(e)
    
    return result


def test_single_param(url: str, param: str, value: str = None) -> Dict[str, Any]:
    checker = ReflectionChecker(url, timeout=10, test_common_params=False)
    
    if value:
        marker = value
    else:
        marker = checker._generate_marker()
    
    result = checker._test_parameter(param)
    
    if result:
        return {
            "parameter": param,
            "marker": marker,
            "reflected": result.reflected,
            "count": result.reflection_count,
            "contexts": [c[0] for c in result.contexts],
            "url_tested": result.url_tested,
        }
    
    return {"error": "Test failed"}


__all__ = [
    "ReflectionChecker",
    "ReflectionFinding",
    "ReflectionResult",
    "check_reflections",
    "quick_reflection_check",
    "test_single_param",
    "COMMON_PARAMS",
    "DANGEROUS_CONTEXTS",
]
