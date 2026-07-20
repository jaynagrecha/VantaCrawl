from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import uuid4

from sqlalchemy import Column, JSON, Text
from sqlmodel import Field, SQLModel


def _uuid() -> str:
    return str(uuid4())


class User(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    email: str = Field(index=True, unique=True)
    password_hash: str
    is_admin: bool = False
    is_verified: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login_at: Optional[datetime] = None


class EmailOTP(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    email: str = Field(index=True)
    code_hash: str
    purpose: str = "verify"  # verify | login_reset (future)
    attempts: int = 0
    expires_at: datetime
    consumed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanJob(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    user_id: str = Field(index=True)
    title: str = ""
    start_url: str
    mode: str = "full_audit"
    speed: str = "balanced"
    status: str = Field(default="queued", index=True)
    # queued | running | paused | stopping | completed | failed | cancelled
    authorized_confirmed: bool = False
    config_json: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    progress_json: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    log_tail: str = Field(default="", sa_column=Column(Text))
    error_message: str = ""
    report_html_path: str = ""
    report_txt_path: str = ""
    report_dir: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)
