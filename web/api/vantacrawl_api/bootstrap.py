from __future__ import annotations

import logging
import os
from pathlib import Path

from sqlmodel import Session, select

from .config import get_settings
from .database import engine, init_db
from .models import User
from .security import hash_password

log = logging.getLogger("vantacrawl.bootstrap")

_DEFAULT_SECRET = "change-me-in-production-use-long-random-string"


def ensure_production_secrets() -> None:
    settings = get_settings()
    on_render = bool(os.environ.get("RENDER") or os.environ.get("RENDER_SERVICE_ID"))
    is_prod = (settings.app_env or "").lower() in {"production", "prod"} or on_render
    if not is_prod:
        return
    secret = (settings.secret_key or "").strip()
    if not secret or secret == _DEFAULT_SECRET or len(secret) < 32:
        raise RuntimeError(
            "Refusing to start: set SECRET_KEY to a long random string "
            "(Render generateValue or a 32+ char secret)."
        )
    admin_pw = settings.admin_password or ""
    if admin_pw in {"", "ChangeMeAdmin123!"}:
        log.warning(
            "ADMIN_PASSWORD is still the default — set a strong password in the Dashboard."
        )


def ensure_dirs() -> None:
    settings = get_settings()
    for path in (settings.data_dir, settings.reports_dir, settings.jobs_dir):
        Path(path).mkdir(parents=True, exist_ok=True)


def ensure_admin_user() -> None:
    settings = get_settings()
    email = (settings.admin_email or "").strip().lower()
    password = settings.admin_password or ""
    if not email or not password:
        log.warning("ADMIN_EMAIL / ADMIN_PASSWORD not set — skipping admin bootstrap")
        return
    with Session(engine) as session:
        existing = session.exec(select(User).where(User.email == email)).first()
        if existing:
            if not existing.is_admin or not existing.is_verified:
                existing.is_admin = True
                existing.is_verified = True
                session.add(existing)
                session.commit()
            return
        user = User(
            email=email,
            password_hash=hash_password(password),
            is_admin=True,
            is_verified=True,
        )
        session.add(user)
        session.commit()
        log.info("Admin user ready: %s", email)


def startup() -> None:
    ensure_production_secrets()
    ensure_dirs()
    init_db()
    ensure_admin_user()
