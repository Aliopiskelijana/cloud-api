"""
Cloud API Monitor — minimal single-entry-point for Render
All heavy imports (bcrypt, jose, psycopg2) are deferred to function call time
so uvicorn binds the port and passes the /health check within < 2 seconds.
"""
import logging
import os
import threading
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker
from sqlalchemy.pool import NullPool

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ── Config ──────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
SECRET_KEY   = os.environ["SECRET_KEY"]
ALGORITHM    = os.environ.get("ALGORITHM", "HS256")
TOKEN_EXPIRE = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# ── DB ───────────────────────────────────────────────────────────────────────
Base = declarative_base()

connect_args = {}
if "postgresql" in DATABASE_URL:
    connect_args = {"connect_timeout": 10}

engine = create_engine(DATABASE_URL, poolclass=NullPool, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Models ────────────────────────────────────────────────────────────────────
import secrets as _secrets


class User(Base):
    __tablename__ = "users"
    id             = Column(Integer, primary_key=True, index=True)
    email          = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    api_keys       = relationship("APIKey", back_populates="user")


class APIKey(Base):
    __tablename__ = "api_keys"
    id         = Column(Integer, primary_key=True, index=True)
    key        = Column(String, unique=True, index=True, default=lambda: f"sk_{_secrets.token_urlsafe(32)}")
    name       = Column(String, nullable=False)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active  = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    user       = relationship("User", back_populates="api_keys")
    usage_logs = relationship("UsageLog", back_populates="api_key")


class UsageLog(Base):
    __tablename__ = "usage_logs"
    id              = Column(Integer, primary_key=True, index=True)
    api_key_id      = Column(Integer, ForeignKey("api_keys.id"), nullable=False)
    endpoint        = Column(String, nullable=False)
    method          = Column(String, nullable=False)
    status_code     = Column(Integer, nullable=False)
    response_time_ms = Column(Integer, nullable=False)
    ip_address      = Column(String, nullable=False)
    timestamp       = Column(DateTime, default=datetime.utcnow, index=True)
    api_key         = relationship("APIKey", back_populates="usage_logs")


# ── Schemas ───────────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    email: str
    is_active: bool
    created_at: datetime
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class APIKeyCreate(BaseModel):
    name: str

class APIKeyOut(BaseModel):
    id: int
    key: str
    name: str
    is_active: bool
    created_at: datetime
    class Config:
        from_attributes = True

class UsageSummary(BaseModel):
    total_requests: int
    endpoints: dict

# ── Auth helpers (heavy imports deferred) ────────────────────────────────────
def hash_password(password: str) -> str:
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    import bcrypt
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    from jose import jwt
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=TOKEN_EXPIRE))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    from jose import JWTError, jwt
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Cloud API Monitor",
    description="API key management with usage tracking and rate limiting",
    version="1.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.query(User).filter(User.email == payload.get("sub", "")).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


# ── DB init (background thread — does not block /health) ─────────────────────
def _setup_db():
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables ready")
    except Exception as e:
        logger.error("DB setup failed: %s", e)


threading.Thread(target=_setup_db, daemon=True).start()


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/", tags=["health"])
def root():
    return {"status": "ok", "service": "Cloud API Monitor"}


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}


# ── Auth routes ───────────────────────────────────────────────────────────────
@app.post("/auth/signup", response_model=UserOut, status_code=201, tags=["auth"])
def signup(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(400, "Email already registered")
    user = User(email=payload.email, hashed_password=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=Token, tags=["auth"])
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    return {"access_token": create_access_token({"sub": user.email}), "token_type": "bearer"}


# ── API Key routes ────────────────────────────────────────────────────────────
@app.post("/api-keys", response_model=APIKeyOut, status_code=201, tags=["api-keys"])
def create_key(payload: APIKeyCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    key = APIKey(name=payload.name, user_id=current_user.id)
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


@app.get("/api-keys", response_model=list[APIKeyOut], tags=["api-keys"])
def list_keys(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(APIKey).filter(APIKey.user_id == current_user.id).all()


@app.delete("/api-keys/{key_id}", status_code=204, tags=["api-keys"])
def revoke_key(key_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == current_user.id).first()
    if not key:
        raise HTTPException(404, "Key not found")
    key.is_active = False
    db.commit()


# ── Usage routes ──────────────────────────────────────────────────────────────
@app.get("/usage", tags=["usage"])
def usage_summary(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    keys = db.query(APIKey).filter(APIKey.user_id == current_user.id).all()
    key_ids = [k.id for k in keys]
    logs = db.query(UsageLog).filter(UsageLog.api_key_id.in_(key_ids)).all() if key_ids else []
    endpoints: dict = {}
    for log in logs:
        endpoints[log.endpoint] = endpoints.get(log.endpoint, 0) + 1
    return {"total_requests": len(logs), "endpoints": endpoints}


# ── Protected route (demonstrates API key auth) ───────────────────────────────
@app.get("/protected", tags=["protected"])
def protected(request: Request, db: Session = Depends(get_db)):
    import time
    start = time.monotonic()
    api_key_header = request.headers.get("X-API-Key")
    if not api_key_header:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "X-API-Key header required")
    key_record = db.query(APIKey).filter(APIKey.key == api_key_header, APIKey.is_active == True).first()
    if not key_record:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or inactive API key")

    elapsed_ms = int((time.monotonic() - start) * 1000)
    log = UsageLog(
        api_key_id=key_record.id,
        endpoint="/protected",
        method="GET",
        status_code=200,
        response_time_ms=elapsed_ms,
        ip_address=request.client.host if request.client else "unknown",
    )
    db.add(log)
    db.commit()
    return {"message": "Access granted", "key_name": key_record.name}
