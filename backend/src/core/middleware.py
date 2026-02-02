from datetime import datetime, timedelta, timezone
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import redis
from firebase_admin import auth
from src.core.config import settings

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int, redis_url: str):
        super().__init__(app)
        self.max_requests = max_requests
        self.redis_client = redis.from_url(redis_url, decode_responses=True)

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    
    def _extract_user_from_token(self, request: Request) -> str:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return "anonymous"
        
        token = auth_header.replace("Bearer ", "")
        try:
            decoded_token = auth.verify_id_token(token)
            return decoded_token.get("uid", "anonymous")
        except:
            return "anonymous"

    def _get_rate_limit_key(self, client_ip: str, user_id: str) -> str:
        today = datetime.now(timezone.utc).date().isoformat()
        return f"ratelimit:{user_id}:{client_ip}:{today}"

    def _get_ttl_seconds(self) -> int:
        now = datetime.now(timezone.utc)
        end_of_day = datetime.combine(now.date() + timedelta(days=1), datetime.min.time())
        return int((end_of_day - now).total_seconds())

    async def dispatch(self, request: Request, call_next):
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        user_id = self._extract_user_from_token(request)
        rate_limit_key = self._get_rate_limit_key(client_ip, user_id)

        try:
            current_count = self.redis_client.incr(rate_limit_key)
            
            if current_count == 1:
                self.redis_client.expire(rate_limit_key, self._get_ttl_seconds())

            if current_count > self.max_requests:
                return JSONResponse(
                    status_code=429,
                    content={"detail": f"Rate limit exceeded. Max {self.max_requests} requests per day."},
                    headers={"Retry-After": "86400"},
                )

            response = await call_next(request)
            
            remaining = max(0, self.max_requests - current_count)
            response.headers["X-RateLimit-Limit"] = str(self.max_requests)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            
            ttl = self.redis_client.ttl(rate_limit_key)
            if ttl > 0:
                reset_timestamp = int((datetime.now(timezone.utc) + timedelta(seconds=ttl)).timestamp())
                response.headers["X-RateLimit-Reset"] = str(reset_timestamp)

            return response
            
        except redis.RedisError as e:
            print(f"Redis error in rate limiter: {e}")
            return await call_next(request)
