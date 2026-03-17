from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.routes.auth import get_current_user

router = APIRouter(prefix="/usage", tags=["usage"])


@router.get("/{key_id}", response_model=schemas.UsageSummary)
def get_usage(
    key_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    key = db.query(models.APIKey).filter(
        models.APIKey.id == key_id,
        models.APIKey.user_id == current_user.id,
    ).first()
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    logs = db.query(models.UsageLog).filter(models.UsageLog.api_key_id == key_id)
    total = logs.count()
    successful = logs.filter(models.UsageLog.status_code < 400).count()

    avg_time = db.query(func.avg(models.UsageLog.response_time_ms)).filter(
        models.UsageLog.api_key_id == key_id
    ).scalar() or 0.0

    top_endpoints = (
        db.query(models.UsageLog.endpoint, func.count(models.UsageLog.id).label("count"))
        .filter(models.UsageLog.api_key_id == key_id)
        .group_by(models.UsageLog.endpoint)
        .order_by(func.count(models.UsageLog.id).desc())
        .limit(5)
        .all()
    )

    return schemas.UsageSummary(
        total_requests=total,
        successful_requests=successful,
        failed_requests=total - successful,
        avg_response_time_ms=round(avg_time, 2),
        top_endpoints=[{"endpoint": e, "count": c} for e, c in top_endpoints],
    )


@router.get("/{key_id}/logs", response_model=list[schemas.UsageLogOut])
def get_logs(
    key_id: int,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    key = db.query(models.APIKey).filter(
        models.APIKey.id == key_id,
        models.APIKey.user_id == current_user.id,
    ).first()
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    return (
        db.query(models.UsageLog)
        .filter(models.UsageLog.api_key_id == key_id)
        .order_by(models.UsageLog.timestamp.desc())
        .limit(limit)
        .all()
    )
