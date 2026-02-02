import logging
from typing import Optional, List
from contextlib import contextmanager

import httpx


logger = logging.getLogger(__name__)


class HTTPClientFactory:
    DEFAULT_USER_AGENT = "VibeSecure/1.0"
    DEFAULT_TIMEOUT = 10.0
    
    @staticmethod
    def create_client(
        timeout: float = DEFAULT_TIMEOUT,
        follow_redirects: bool = True,
        verify: bool = False,
        headers: Optional[dict] = None,
        user_agent: Optional[str] = None
    ) -> httpx.Client:
        client_headers = headers or {}
        
        if user_agent or "User-Agent" not in client_headers:
            client_headers["User-Agent"] = user_agent or HTTPClientFactory.DEFAULT_USER_AGENT
        
        return httpx.Client(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=verify,
            headers=client_headers
        )
    
    @staticmethod
    @contextmanager
    def get_client(*args, **kwargs):
        client = HTTPClientFactory.create_client(*args, **kwargs)
        try:
            yield client
        finally:
            client.close()


def try_multiple_urls(
    urls: List[str],
    timeout: float = 5.0,
    verify: bool = False,
    user_agent: Optional[str] = None
) -> Optional[httpx.Response]:
    with HTTPClientFactory.get_client(
        timeout=timeout,
        verify=verify,
        user_agent=user_agent
    ) as client:
        for url in urls:
            try:
                response = client.get(url)
                if response.status_code == 200:
                    return response
            except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError) as e:
                logger.debug(f"Failed to fetch {url}: {e}")
                continue
    
    return None
