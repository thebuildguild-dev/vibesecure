from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional, List
from datetime import datetime, timezone


def now_utc() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class Settings(BaseSettings):
    debug: bool = False
    database_url: str
    redis_url: str
    firebase_service_account_path: Optional[str] = None
    firebase_credentials_json: Optional[str] = None
    firebase_project_id: str
    resend_api_key: str
    email_from: str
    gemini_api_key: Optional[str] = None
    frontend_url: str = "http://localhost:3000"
    backend_url: str = "http://api:8000"
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    cors_allow_credentials: bool = True
    cors_allow_methods: str = "*"
    cors_allow_headers: str = "*"
    rate_limit_max_requests: int = 100
    domain_verification_token_ttl_days: int = 7
    domain_verification_max_requests_per_domain_per_day: int = 3
    domain_verification_max_requests_per_user_per_day: int = 5
    domain_verification_token_length: int = 36
    domain_verification_allow_header: bool = True
    scan_default_depth: int = 2
    scan_default_rate_limit_secs: float = 1.0
    scan_allow_ignore_robots: bool = True
    scan_allow_authenticated: bool = True
    scan_playwright_timeout_sec: int = 10
    security_check_default_timeout: int = 10
    security_check_library_timeout: int = 15
    security_check_max_concurrent: int = 5
    tls_cert_expiry_warning_days: int = 30
    tls_cert_expiry_critical_days: int = 7
    zap_base_url: str = "http://zap:8090"
    zap_timeout: int = 120
    zap_spider_poll_interval: int = 2
    zap_active_scan_poll_interval: int = 5
    zap_rate_limit_delay: float = 0.5
    celery_task_time_limit: int = 600
    celery_task_soft_time_limit: int = 540
    celery_worker_prefetch_multiplier: int = 1
    celery_worker_concurrency: int = 4
    celery_result_expires: int = 86400
    
    class Config:
        env_file = ".env"
        extra = "ignore"
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Parse comma-separated CORS origins into a list."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
    
    def model_post_init(self, __context) -> None:
        if not self.database_url:
            raise RuntimeError("DATABASE_URL environment variable is required")
        if not self.redis_url:
            raise RuntimeError("REDIS_URL environment variable is required")
        if not self.firebase_service_account_path and not self.firebase_credentials_json:
            raise RuntimeError("Either FIREBASE_SERVICE_ACCOUNT_PATH or FIREBASE_CREDENTIALS_JSON environment variable is required")
        if not self.firebase_project_id:
            raise RuntimeError("FIREBASE_PROJECT_ID environment variable is required")
        if not self.resend_api_key:
            raise RuntimeError("RESEND_API_KEY environment variable is required")
        if not self.email_from:
            raise RuntimeError("EMAIL_FROM environment variable is required")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
