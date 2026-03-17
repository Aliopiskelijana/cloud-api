from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.middleware.rate_limit import check_rate_limit

router = APIRouter(prefix="/api/v1", tags=["protected"])


def require_api_key(request: Request, db: Session = Depends(get_db)) -> models.APIKey:
    key = request.headers.get("X-API-Key")
    if not key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="X-API-Key header missing")
    record = db.query(models.APIKey).filter(
        models.APIKey.key == key,
        models.APIKey.is_active == True,
    ).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key")
    check_rate_limit(request)
    return record


@router.get("/data")
def get_data(api_key: models.APIKey = Depends(require_api_key)):
    return {
        "message": "Access granted",
        "key_name": api_key.name,
        "data": [{"id": 1, "value": "sample"}, {"id": 2, "value": "data"}],
    }


@router.get("/status")
def get_status(api_key: models.APIKey = Depends(require_api_key)):
    return {"status": "ok", "key_name": api_key.name}
