from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, HttpUrl, field_serializer


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class VerifyOTPRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=4, max_length=12)


class ResendOTPRequest(BaseModel):
    email: EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: str
    is_admin: bool
    is_verified: bool
    created_at: datetime


class MessageOut(BaseModel):
    message: str


class JobCreateRequest(BaseModel):
    start_url: str
    title: str = ""
    mode: str = "full_audit"
    speed: str = "balanced"
    authorized_confirmed: bool = False
    # Full CrawlConfig overlay (bools/ints/strings). Unknown keys ignored by worker.
    settings: Dict[str, Any] = Field(default_factory=dict)
    target_urls: List[str] = Field(default_factory=list)


class JobSettingsPatch(BaseModel):
    settings: Dict[str, Any] = Field(default_factory=dict)


def _utc_iso(value: Optional[datetime]) -> Optional[str]:
    """Serialize naive UTC datetimes with a Z so browsers do not treat them as local time."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.isoformat() + "Z"
    return value.isoformat()


class JobOut(BaseModel):
    id: str
    title: str
    start_url: str
    mode: str
    speed: str
    status: str
    authorized_confirmed: bool
    config_json: Dict[str, Any]
    progress_json: Dict[str, Any]
    log_tail: str
    error_message: str
    report_html_path: str
    report_txt_path: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    updated_at: datetime

    @field_serializer("created_at", "started_at", "finished_at", "updated_at")
    def serialize_datetimes(self, value: Optional[datetime]) -> Optional[str]:
        return _utc_iso(value)


class JobListOut(BaseModel):
    jobs: List[JobOut]


class MetaOut(BaseModel):
    modes: Dict[str, Any]
    speeds: Dict[str, Any]
    default_settings: Dict[str, Any]
    setting_groups: List[Dict[str, Any]]
    setting_fields: Dict[str, Any] = Field(default_factory=dict)
    wordlists: List[Dict[str, str]] = Field(default_factory=list)
