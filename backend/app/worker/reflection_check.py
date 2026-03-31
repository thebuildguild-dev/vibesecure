import asyncio
import secrets
import logging
import time
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

COMMON_PARAM_NAMES = [
    "q", "search", "query", "keyword", "term",
    "name", "id", "value", "data", "input", "text",
    "msg", "message", "comment", "content",
    "url", "redirect", "return", "callback",
]

TOKEN_PREFIX = "VIBESECURE"
MAX_RESPONSE_SIZE = 1024 * 1024
EVIDENCE_SNIPPET_SIZE = 200


@dataclass
class ReflectionResult:
    url: str
    param_name: str
    token: str
    reflected: bool
    evidence_snippet: Optional[str] = None
    evidence_position: Optional[int] = None
    response_size: int = 0
    reflection_count: int = 0
    error: Optional[str] = None


@dataclass
class ReflectionCheckStats:
    total_params_tested: int = 0
    reflections_found: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


class ReflectionChecker:
    def __init__(
        self,
        base_url: str,
        param_names: Optional[List[str]] = None,
        timeout: int = 10,
        user_agent: str = "VibeSecure/1.0 (Security Scanner; +https://github.com/thebuildguild-dev/vibesecure)",
        verification_id: Optional[int] = None,
    ):
        self.base_url = base_url.rstrip('/')
        self.param_names = param_names or COMMON_PARAM_NAMES
        self.timeout = timeout
        self.user_agent = user_agent
        self.verification_id = verification_id
        
        parsed = urlparse(base_url)
        self.domain = parsed.netloc
        
        self.stats = ReflectionCheckStats(total_params_tested=len(self.param_names))
    
    def _generate_token(self) -> str:
        random_suffix = secrets.token_hex(3)
        return f"{TOKEN_PREFIX}-RAND-{random_suffix}"
    
    async def check_all(self) -> List[ReflectionResult]:
        start_time = time.time()
        logger.info(f"[ReflectionChecker] Checking {self.base_url} ({len(self.param_names)} params)")
        
        results: List[ReflectionResult] = []
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": self.user_agent},
        ) as client:
            for param_name in self.param_names:
                try:
                    result = await self._check_param(client, param_name)
                    if result and result.reflected:
                        results.append(result)
                        self.stats.reflections_found += 1
                        logger.info(f"[ReflectionChecker] Reflection: {param_name} ({result.reflection_count}x)")
                except Exception as e:
                    self.stats.errors += 1
        
        self.stats.duration_seconds = time.time() - start_time
        
        logger.info(f"[ReflectionChecker] Found {self.stats.reflections_found} reflections in {self.stats.duration_seconds:.1f}s")
        
        return results
    
    async def _check_param(
        self,
        client: httpx.AsyncClient,
        param_name: str,
    ) -> Optional[ReflectionResult]:
        token = self._generate_token()
        test_url = f"{self.base_url}?{param_name}={token}"
        
        try:
            response = await client.get(test_url)
            
            response_size = len(response.content)
            if response_size > MAX_RESPONSE_SIZE:
                return None
            
            response_text = response.text
            token_lower = token.lower()
            response_lower = response_text.lower()
            
            if token_lower not in response_lower:
                return None
            
            reflection_count = response_lower.count(token_lower)
            first_position = response_lower.find(token_lower)
            
            evidence_start = max(0, first_position - 50)
            evidence_end = min(len(response_text), first_position + len(token) + 150)
            evidence_snippet = response_text[evidence_start:evidence_end]
            evidence_snippet = ' '.join(evidence_snippet.split())
            
            result = ReflectionResult(
                url=test_url,
                param_name=param_name,
                token=token,
                reflected=True,
                evidence_snippet=evidence_snippet[:EVIDENCE_SNIPPET_SIZE],
                evidence_position=first_position,
                response_size=response_size,
                reflection_count=reflection_count,
            )
            
            return result
            
        except httpx.TimeoutException:
            return None
        except Exception:
            return None


def check_reflections(
    base_url: str,
    param_names: Optional[List[str]] = None,
    timeout: int = 10,
    verification_id: Optional[int] = None,
) -> List[ReflectionResult]:
    checker = ReflectionChecker(
        base_url=base_url,
        param_names=param_names,
        timeout=timeout,
        verification_id=verification_id,
    )
    
    return asyncio.run(checker.check_all())


async def check_reflections_async(
    base_url: str,
    param_names: Optional[List[str]] = None,
    timeout: int = 10,
    verification_id: Optional[int] = None,
) -> List[ReflectionResult]:
    checker = ReflectionChecker(
        base_url=base_url,
        param_names=param_names,
        timeout=timeout,
        verification_id=verification_id,
    )
    
    return await checker.check_all()


def generate_findings(
    results: List[ReflectionResult],
    verification_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    findings = []
    
    for result in results:
        severity = "low"
        if result.reflection_count > 3:
            severity = "medium"
        
        remediation = (
            f"Parameter '{result.param_name}' reflects user input in the response. "
            "Ensure proper output encoding and Content-Security-Policy headers are in place. "
            "Consider implementing input validation and output sanitization."
        )
        
        finding = {
            "title": f"Parameter reflection detected: {result.param_name}",
            "severity": severity,
            "remediation": remediation,
            "confidence": 95,
            "url": result.url,
            "details": {
                "param_name": result.param_name,
                "token": result.token,
                "reflection_count": result.reflection_count,
                "evidence": result.evidence_snippet,
                "response_size": result.response_size,
                "verification_id": verification_id,
            }
        }
        
        findings.append(finding)
    
    return findings
