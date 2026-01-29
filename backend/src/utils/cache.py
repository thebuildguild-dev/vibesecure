import json
import hashlib
from typing import Optional, Any, Callable
from functools import wraps
import redis

from src.core.config import settings


class RedisCache:
    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or settings.redis_url
        self.client = redis.from_url(self.redis_url, decode_responses=True)
        self.binary_client = redis.from_url(self.redis_url, decode_responses=False)
    
    def get(self, key: str) -> Optional[str]:
        try:
            return self.client.get(key)
        except redis.RedisError as e:
            print(f"Redis GET error for key {key}: {e}")
            return None

    def get_binary(self, key: str) -> Optional[bytes]:
        try:
            return self.binary_client.get(key)
        except redis.RedisError as e:
            print(f"Redis GET BINARY error for key {key}: {e}")
            return None
    
    def set(self, key: str, value: str, ttl: int = 3600) -> bool:
        try:
            return self.client.setex(key, ttl, value)
        except redis.RedisError as e:
            print(f"Redis SET error for key {key}: {e}")
            return False

    def set_binary(self, key: str, value: bytes, ttl: int = 3600) -> bool:
        try:
            return self.binary_client.setex(key, ttl, value)
        except redis.RedisError as e:
            print(f"Redis SET BINARY error for key {key}: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        try:
            return bool(self.client.delete(key))
        except redis.RedisError as e:
            print(f"Redis DELETE error for key {key}: {e}")
            return False
    
    def delete_pattern(self, pattern: str) -> int:
        try:
            keys = self.client.keys(pattern)
            if keys:
                return self.client.delete(*keys)
            return 0
        except redis.RedisError as e:
            print(f"Redis DELETE pattern error for {pattern}: {e}")
            return 0
    
    def get_json(self, key: str) -> Optional[Any]:
        value = self.get(key)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return None
        return None
    
    def set_json(self, key: str, value: Any, ttl: int = 3600) -> bool:
        try:
            json_str = json.dumps(value)
            return self.set(key, json_str, ttl)
        except (TypeError, ValueError) as e:
            print(f"JSON serialization error for key {key}: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        try:
            return bool(self.client.exists(key))
        except redis.RedisError:
            return False


cache = RedisCache()


def cache_key(*args, prefix: str = "cache") -> str:
    key_data = ":".join(str(arg) for arg in args)
    key_hash = hashlib.md5(key_data.encode()).hexdigest()[:12]
    return f"{prefix}:{key_hash}:{key_data}"


def cached(ttl: int = 3600, key_prefix: str = "cache"):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_key_parts = [func.__name__] + [str(a) for a in args]
            if kwargs:
                cache_key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
            
            key = cache_key(*cache_key_parts, prefix=key_prefix)
            
            cached_result = cache.get_json(key)
            if cached_result is not None:
                return cached_result
            
            result = func(*args, **kwargs)
            cache.set_json(key, result, ttl)
            return result
        
        return wrapper
    return decorator


class CacheKeys:
    SCAN = "scan:{scan_id}"
    SCAN_DETAIL = "scan:detail:{scan_id}"
    SCAN_FINDINGS = "scan:findings:{scan_id}"
    SCAN_LIST = "scan:list:*"
    SCAN_REPORT_JSON = "report:json:{scan_id}"
    SCAN_REPORT_PDF = "report:pdf:{scan_id}"
    SCAN_AI_SUMMARY = "ai:summary:{scan_id}"
    
    @staticmethod
    def invalidate_scan(scan_id: str):
        """Invalidate all cached data for a scan."""
        patterns = [
            f"scan:{scan_id}*",
            f"scan:detail:{scan_id}*",
            f"scan:findings:{scan_id}*",
            f"report:*:{scan_id}*",
            f"ai:summary:{scan_id}*",
            "scan:list:*",
        ]
        for pattern in patterns:
            cache.delete_pattern(pattern)


__all__ = ["cache", "cached", "cache_key", "RedisCache", "CacheKeys"]
