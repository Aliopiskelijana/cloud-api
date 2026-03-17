from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


# Auth
class UserCreate(BaseModel):
    email: EmailStr
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


# API Keys
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


class APIKeyPublic(BaseModel):
    id: int
    name: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Usage
class UsageLogOut(BaseModel):
    id: int
    endpoint: str
    method: str
    status_code: int
    response_time_ms: int
    ip_address: str
    timestamp: datetime

    class Config:
        from_attributes = True


class UsageSummary(BaseModel):
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time_ms: float
    top_endpoints: list[dict]
