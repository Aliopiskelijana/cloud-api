import time

from fastapi import Request
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.database import SessionLocal
from app import models


EXCLUDED_PATHS = {"/docs", "/redoc", "/openapi.json", "/health"}


class UsageTrackerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)

        start = time.monotonic()
        response = await call_next(request)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        api_key_header = request.headers.get("X-API-Key")
        if api_key_header:
            self._log_usage(
                api_key=api_key_header,
                endpoint=request.url.path,
                method=request.method,
                status_code=response.status_code,
                response_time_ms=elapsed_ms,
                ip_address=request.client.host if request.client else "unknown",
            )

        return response

    def _log_usage(self, api_key: str, endpoint: str, method: str,
                   status_code: int, response_time_ms: int, ip_address: str) -> None:
        db: Session = SessionLocal()
        try:
            key_record = db.query(models.APIKey).filter(
                models.APIKey.key == api_key,
                models.APIKey.is_active == True,
            ).first()
            if not key_record:
                return
            log = models.UsageLog(
                api_key_id=key_record.id,
                endpoint=endpoint,
                method=method,
                status_code=status_code,
                response_time_ms=response_time_ms,
                ip_address=ip_address,
            )
            db.add(log)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
