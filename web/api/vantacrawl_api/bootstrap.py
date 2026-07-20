from __future__ import annotations

import logging
from pathlib import Path

from sqlmodel import Session, select

from .config import get_settings
from .database import engine, init_db
from .models import User
from .security import hash_password

log = logging.getLogger("vantacrawl.bootstrap")


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
    ensure_dirs()
    init_db()
    ensure_admin_user()
