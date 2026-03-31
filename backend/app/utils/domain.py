from urllib.parse import urlparse


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc or domain.replace("http://", "").replace("https://", "")
    
    domain = domain.split("/")[0].split("?")[0]
    
    domain = domain.rstrip(".")
    
    return domain


def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or url


def domain_to_urls(domain: str, include_http: bool = True) -> list[str]:
    urls = [f"https://{domain}"]
    if include_http:
        urls.append(f"http://{domain}")
    return urls


def handle_localhost(domain: str) -> list[str]:
    candidates = [domain]
    
    if "localhost" in domain or "127.0.0.1" in domain:
        docker_domain = domain.replace("localhost", "host.docker.internal").replace(
            "127.0.0.1", "host.docker.internal"
        )
        candidates.append(docker_domain)
    
    return candidates
