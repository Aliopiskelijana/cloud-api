import logging
import redis

logger = logging.getLogger(__name__)
_client: redis.Redis | None = None


def get_redis() -> redis.Redis | None:
    global _client
    if _client is None:
        from app.config import settings
        try:
            _client = redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=3,
                retry_on_timeout=False,
            )
            _client.ping()
        except Exception as e:
            logger.warning("Redis unavailable: %s — rate limiting disabled", e)
            return None
    return _client
