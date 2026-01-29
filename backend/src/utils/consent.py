import httpx
from urllib.parse import urlparse


def consent_file_url(domain: str) -> str:
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc

    domain = domain.rstrip("/")
    return f"https://{domain}/.well-known/vibesecure-consent.txt"


def check_active_consent(domain: str, user_email: str) -> bool:
    candidates = [domain]
    if "localhost" in domain or "127.0.0.1" in domain:
        candidates.append(domain.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal"))
    
    urls_to_try = []
    for d in candidates:
        urls_to_try.append(f"https://{d}/.well-known/vibesecure-consent.txt")
        urls_to_try.append(f"http://{d}/.well-known/vibesecure-consent.txt")

    client = httpx.Client(timeout=5.0, follow_redirects=True, headers={"User-Agent": "VibeSecure/1.0"}, verify=False)

    try:
        for url in urls_to_try:
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

                # If we passed all checks, return True
                client.close()
                return True
                
            except (httpx.ConnectError, httpx.TimeoutException):
                continue
                
        client.close()
        return False

    except Exception:
        client.close()
        return False


def extract_domain(url: str) -> str:
    return urlparse(url).netloc
