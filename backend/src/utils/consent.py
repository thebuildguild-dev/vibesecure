import httpx
from datetime import datetime, timezone
from urllib.parse import urlparse

from src.utils.domain import handle_localhost, domain_to_urls
from src.utils.http_client import HTTPClientFactory


def generate_consent_file_content(domain: str, user_email: str) -> str:
    return f"""vibesecure-active-consent=YES
domain={domain}
requested_by={user_email}
consent_date={datetime.now(timezone.utc).strftime('%Y-%m-%d')}

# This file authorizes VibeSecure to perform active security scanning
# Active scanning generates potentially malicious payloads (SQL injection, XSS, etc.)
# Only authorize if you have legal permission and understand the risks
"""


def consent_file_url(domain: str) -> str:
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc

    domain = domain.rstrip("/")
    return f"https://{domain}/.well-known/vibesecure-consent.txt"


def check_active_consent(domain: str, user_email: str) -> bool:
    candidates = handle_localhost(domain)
    
    urls_to_try = []
    for d in candidates:
        urls_to_try.extend(domain_to_urls(d))
    
    consent_urls = [f"{base_url}/.well-known/vibesecure-consent.txt" for base_url in urls_to_try]

    with HTTPClientFactory.get_client(timeout=5.0, user_agent="VibeSecure/1.0") as client:
        for url in consent_urls:
            try:
                response = client.get(url)

                if response.status_code != 200:
                    continue

                lines = [
                    line.strip()
                    for line in response.text.splitlines()
                    if line.strip() and not line.startswith("#")
                ]

                if "vibesecure-active-consent=YES" not in lines:
                    continue

                requested_by = None
                for line in lines:
                    if line.startswith("requested_by="):
                        requested_by = line.split("=", 1)[1].strip()
                        break

                if requested_by and requested_by != user_email:
                    continue

                return True
                
            except (httpx.ConnectError, httpx.TimeoutException):
                continue
        
        return False


def extract_domain(url: str) -> str:
    return urlparse(url).netloc
