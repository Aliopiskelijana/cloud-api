from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.routes.auth import get_current_user

router = APIRouter(prefix="/keys", tags=["api-keys"])


@router.post("/", response_model=schemas.APIKeyOut, status_code=status.HTTP_201_CREATED)
def create_key(
    payload: schemas.APIKeyCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    key = models.APIKey(name=payload.name, user_id=current_user.id)
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


@router.get("/", response_model=list[schemas.APIKeyPublic])
def list_keys(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return db.query(models.APIKey).filter(models.APIKey.user_id == current_user.id).all()


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_key(
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
    key.is_active = False
    db.commit()
