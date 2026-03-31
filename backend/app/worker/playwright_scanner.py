import asyncio
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright, Browser, Page, Error as PlaywrightError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not available. Install: pip install playwright && playwright install --with-deps chromium")


class PlaywrightScanner:
    def __init__(
        self,
        timeout: int = 30000,
        wait_for_networkidle: bool = True,
        screenshot_enabled: bool = False,
        screenshot_dir: Optional[Path] = None,
    ):
        self.timeout = timeout
        self.wait_for_networkidle = wait_for_networkidle
        self.screenshot_enabled = screenshot_enabled
        self.screenshot_dir = screenshot_dir or Path("./uploads/screenshots")
        
        if self.screenshot_enabled:
            self.screenshot_dir.mkdir(parents=True, exist_ok=True)
    
    async def scan(
        self,
        url: str,
        verification_id: Optional[int] = None,
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright not installed. Install with: "
                "pip install playwright && playwright install --with-deps chromium"
            )
        
        if not url or not url.startswith(('http://', 'https://')):
            raise ValueError(f"Invalid URL: {url}")
        
        last_error = None
        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    await asyncio.sleep(2 ** attempt)
                
                result = await self._scan_with_playwright(url, verification_id)
                return result
                
            except Exception as e:
                last_error = e
                if attempt == max_retries:
                    raise RuntimeError(f"Failed to scan {url} after {max_retries + 1} attempts: {last_error}")
        
        raise RuntimeError(f"Unexpected error during scan: {last_error}")
    
    async def _scan_with_playwright(
        self,
        url: str,
        verification_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        logger.info(f"[Playwright] Starting rendering scan for {url}")
        start_time = datetime.now(timezone.utc)
        xhr_endpoints: List[str] = []
        
        async def handle_request(request):
            if request.resource_type in ['xhr', 'fetch']:
                xhr_endpoints.append(request.url)
        
        async with async_playwright() as playwright:
            browser: Browser = await playwright.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                ]
            )
            
            try:
                context = await browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='VibeSecure/1.0 (Security Scanner; Headless; +https://github.com/thebuildguild-dev/vibesecure)',
                )
                
                page: Page = await context.new_page()
                page.on('request', handle_request)
                
                wait_until = 'networkidle' if self.wait_for_networkidle else 'domcontentloaded'
                await page.goto(url, timeout=self.timeout, wait_until=wait_until)
                
                html = await page.content()
                scripts = await self._extract_scripts(page)
                
                screenshot_path = None
                if self.screenshot_enabled:
                    screenshot_path = await self._capture_screenshot(page, url, verification_id)
                
                end_time = datetime.now(timezone.utc)
                duration_ms = (end_time - start_time).total_seconds() * 1000
                unique_xhr_endpoints = list(set(xhr_endpoints))
                
                logger.info(f"[Playwright] Scan complete for {url} in {duration_ms:.2f}ms. Found {len(unique_xhr_endpoints)} XHR endpoints.")
                
                result = {
                    'html': html,
                    'scripts': scripts,
                    'xhr_endpoints': unique_xhr_endpoints,
                    'screenshot_path': str(screenshot_path) if screenshot_path else None,
                    'metadata': {
                        'url': url,
                        'verification_id': verification_id,
                        'duration_ms': duration_ms,
                        'wait_strategy': wait_until,
                        'timeout_ms': self.timeout,
                        'timestamp': start_time.isoformat(),
                    }
                }
                
                return result
                
            finally:
                await browser.close()
    
    async def _extract_scripts(self, page: Page) -> List[Dict[str, Any]]:
        scripts = []
        
        external_scripts = await page.eval_on_selector_all(
            'script[src]',
            'elements => elements.map(el => el.src)'
        )
        for src in external_scripts:
            scripts.append({
                'type': 'external',
                'src': src,
                'content': None,
            })
        
        inline_scripts = await page.eval_on_selector_all(
            'script:not([src])',
            'elements => elements.map(el => el.textContent)'
        )
        for i, content in enumerate(inline_scripts):
            truncated = content[:5000] if len(content) > 5000 else content
            scripts.append({
                'type': 'inline',
                'src': None,
                'content': truncated,
                'length': len(content),
                'truncated': len(content) > 5000,
                'index': i,
            })
        
        return scripts
    
    async def _capture_screenshot(
        self,
        page: Page,
        url: str,
        verification_id: Optional[int] = None,
    ) -> Path:
        parsed = urlparse(url)
        domain = parsed.netloc.replace(':', '_')
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        
        filename = f"{domain}_{timestamp}"
        if verification_id:
            filename += f"_v{verification_id}"
        filename += ".png"
        
        screenshot_path = self.screenshot_dir / filename
        await page.screenshot(path=str(screenshot_path), full_page=True)
        return screenshot_path


async def render_page_async(
    url: str,
    verification_id: Optional[int] = None,
    timeout: int = 30000,
    screenshot_enabled: bool = False,
    screenshot_dir: Optional[Path] = None,
    max_retries: int = 2,
) -> Dict[str, Any]:
    scanner = PlaywrightScanner(
        timeout=timeout,
        wait_for_networkidle=True,
        screenshot_enabled=screenshot_enabled,
        screenshot_dir=screenshot_dir,
    )
    
    return await scanner.scan(url, verification_id, max_retries)


def render_page(
    url: str,
    verification_id: Optional[int] = None,
    timeout: int = 30000,
    screenshot_enabled: bool = False,
    screenshot_dir: Optional[Path] = None,
    max_retries: int = 2,
) -> Dict[str, Any]:
    return asyncio.run(render_page_async(
        url=url,
        verification_id=verification_id,
        timeout=timeout,
        screenshot_enabled=screenshot_enabled,
        screenshot_dir=screenshot_dir,
        max_retries=max_retries,
    ))


def is_playwright_available() -> bool:
    return PLAYWRIGHT_AVAILABLE


def get_installation_instructions() -> str:
    return (
        "Playwright not installed.\n"
        "1. pip install playwright\n"
        "2. playwright install --with-deps chromium\n"
    )

