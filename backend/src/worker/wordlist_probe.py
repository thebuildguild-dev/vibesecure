import asyncio
import logging
import time
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

MAX_EVIDENCE_SIZE = 1024
MAX_CONTENT_LENGTH = 10 * 1024 * 1024

PROBE_METHOD_HEAD = "HEAD"
PROBE_METHOD_GET = "GET"

INTERESTING_STATUS_CODES = {
    200, 201, 204, 301, 302, 307, 308, 401, 403, 405,
}

BACKOFF_INITIAL_DELAY = 2
BACKOFF_MAX_DELAY = 60
BACKOFF_MULTIPLIER = 2


@dataclass
class EndpointProbeResult:
    path: str
    full_url: str
    status_code: int
    method_used: str
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    evidence_snippet: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    redirect_location: Optional[str] = None
    interesting: bool = False
    error: Optional[str] = None


@dataclass
class ProbeStats:
    total_paths: int = 0
    paths_probed: int = 0
    endpoints_found: int = 0
    status_code_distribution: Dict[int, int] = field(default_factory=dict)
    rate_limit_hits: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


class WordlistProber:
    def __init__(
        self,
        base_url: str,
        wordlist: List[str],
        rate_limit: float = 1.0,
        max_concurrency: int = 5,
        timeout: int = 10,
        user_agent: str = "VibeSecure/1.0 (Security Scanner; +https://github.com/thebuildguild-dev/vibesecure)",
        verification_id: Optional[int] = None,
    ):
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist
        self.rate_limit = rate_limit
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.user_agent = user_agent
        self.verification_id = verification_id
        
        parsed = urlparse(base_url)
        self.domain = parsed.netloc
        
        self.stats = ProbeStats(total_paths=len(wordlist))
        
        self._last_request_time = 0.0
        self._rate_limit_backoff = BACKOFF_INITIAL_DELAY
    
    async def probe_all(self) -> List[EndpointProbeResult]:
        start_time = time.time()
        logger.info(f"[WordlistProber] Probing {self.base_url} ({len(self.wordlist)} paths)")
        
        results: List[EndpointProbeResult] = []
        
        semaphore = asyncio.Semaphore(self.max_concurrency)
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            headers={"User-Agent": self.user_agent},
        ) as client:
            tasks = [
                self._probe_path_with_semaphore(client, path, semaphore)
                for path in self.wordlist
            ]
            
            probe_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in probe_results:
                if isinstance(result, Exception):
                    self.stats.errors += 1
                elif result is not None and result.interesting:
                    results.append(result)
        
        self.stats.duration_seconds = time.time() - start_time
        self.stats.endpoints_found = len(results)
        
        logger.info(
            f"[WordlistProber] Found {self.stats.endpoints_found} endpoints "
            f"({self.stats.paths_probed}/{self.stats.total_paths} probed, {self.stats.duration_seconds:.1f}s)"
        )
        
        return results
    
    async def _probe_path_with_semaphore(
        self,
        client: httpx.AsyncClient,
        path: str,
        semaphore: asyncio.Semaphore,
    ) -> Optional[EndpointProbeResult]:
        async with semaphore:
            return await self._probe_path(client, path)
    
    async def _probe_path(
        self,
        client: httpx.AsyncClient,
        path: str,
    ) -> Optional[EndpointProbeResult]:
        if not path.startswith('/'):
            path = '/' + path
        
        full_url = urljoin(self.base_url, path)
        
        await self._apply_rate_limit()
        
        try:
            result = await self._send_head_request(client, full_url, path)
            
            if result is None:
                return None
            
            self.stats.paths_probed += 1
            self.stats.status_code_distribution[result.status_code] = \
                self.stats.status_code_distribution.get(result.status_code, 0) + 1
            
            if result.interesting and result.status_code in [200, 401]:
                await self._fetch_evidence(client, result)
            
            return result if result.interesting else None
            
        except httpx.HTTPStatusError as e:
            self.stats.paths_probed += 1
            self.stats.status_code_distribution[e.response.status_code] = \
                self.stats.status_code_distribution.get(e.response.status_code, 0) + 1
            return None
            
        except httpx.TimeoutException:
            self.stats.errors += 1
            return None
            
        except Exception:
            self.stats.errors += 1
            return None
    
    async def _send_head_request(
        self,
        client: httpx.AsyncClient,
        full_url: str,
        path: str,
    ) -> Optional[EndpointProbeResult]:
        try:
            response = await client.head(full_url)
            
            if response.status_code == 429:
                self.stats.rate_limit_hits += 1
                await self._handle_rate_limit()
                return None
            
            if response.status_code not in INTERESTING_STATUS_CODES:
                return None
            
            headers = dict(response.headers)
            content_type = headers.get('content-type', '').split(';')[0].strip()
            content_length_str = headers.get('content-length')
            content_length = int(content_length_str) if content_length_str else None
            
            if content_length and content_length > MAX_CONTENT_LENGTH:
                return None
            
            result = EndpointProbeResult(
                path=path,
                full_url=full_url,
                status_code=response.status_code,
                method_used=PROBE_METHOD_HEAD,
                content_type=content_type if content_type else None,
                content_length=content_length,
                headers={
                    'content-type': content_type,
                    'server': headers.get('server', 'unknown'),
                },
                redirect_location=headers.get('location'),
                interesting=True,
            )
            
            logger.info(f"[WordlistProber] Found: {path} ({response.status_code})")
            
            return result
            
        except httpx.HTTPStatusError:
            raise
    
    async def _fetch_evidence(
        self,
        client: httpx.AsyncClient,
        result: EndpointProbeResult,
    ) -> None:
        await self._apply_rate_limit()
        
        try:
            async with client.stream('GET', result.full_url) as response:
                if response.status_code == 429:
                    self.stats.rate_limit_hits += 1
                    await self._handle_rate_limit()
                    return
                
                content_bytes = b""
                async for chunk in response.aiter_bytes():
                    content_bytes += chunk
                    if len(content_bytes) >= MAX_EVIDENCE_SIZE:
                        break
                
                try:
                    evidence = content_bytes.decode('utf-8', errors='replace')[:MAX_EVIDENCE_SIZE]
                    result.evidence_snippet = evidence
                    result.method_used = PROBE_METHOD_GET
                except Exception:
                    pass
                    
        except Exception:
            pass
    
    async def _apply_rate_limit(self) -> None:
        if self._last_request_time > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit:
                sleep_time = self.rate_limit - elapsed
                await asyncio.sleep(sleep_time)
        
        self._last_request_time = time.time()
    
    async def _handle_rate_limit(self) -> None:
        await asyncio.sleep(self._rate_limit_backoff)
        
        self._rate_limit_backoff = min(
            self._rate_limit_backoff * BACKOFF_MULTIPLIER,
            BACKOFF_MAX_DELAY
        )


def probe_endpoints(
    base_url: str,
    wordlist: List[str],
    rate_limit: float = 1.0,
    max_concurrency: int = 5,
    timeout: int = 10,
    verification_id: Optional[int] = None,
) -> List[EndpointProbeResult]:
    prober = WordlistProber(
        base_url=base_url,
        wordlist=wordlist,
        rate_limit=rate_limit,
        max_concurrency=max_concurrency,
        timeout=timeout,
        verification_id=verification_id,
    )
    
    return asyncio.run(prober.probe_all())


async def probe_endpoints_async(
    base_url: str,
    wordlist: List[str],
    rate_limit: float = 1.0,
    max_concurrency: int = 5,
    timeout: int = 10,
    verification_id: Optional[int] = None,
) -> List[EndpointProbeResult]:
    prober = WordlistProber(
        base_url=base_url,
        wordlist=wordlist,
        rate_limit=rate_limit,
        max_concurrency=max_concurrency,
        timeout=timeout,
        verification_id=verification_id,
    )
    
    return await prober.probe_all()
