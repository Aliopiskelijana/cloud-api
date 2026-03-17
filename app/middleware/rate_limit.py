import time

from fastapi import HTTPException, Request, status

from app.redis_client import get_redis

RATE_LIMIT_REQUESTS = 60   # per window
RATE_LIMIT_WINDOW = 60     # seconds


def get_identifier(request: Request) -> str:
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return f"key:{api_key}"
    ip = request.client.host if request.client else "unknown"
    return f"ip:{ip}"


def check_rate_limit(request: Request) -> None:
    r = get_redis()
    identifier = get_identifier(request)
    redis_key = f"ratelimit:{identifier}"

    pipe = r.pipeline()
    pipe.incr(redis_key)
    pipe.ttl(redis_key)
    count, ttl = pipe.execute()

    if ttl == -1:
        r.expire(redis_key, RATE_LIMIT_WINDOW)

    if count > RATE_LIMIT_REQUESTS:
        retry_after = ttl if ttl > 0 else RATE_LIMIT_WINDOW
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )
