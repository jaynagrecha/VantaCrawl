from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from passlib.context import CryptContext

from .config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(subject: str, *, extra: Optional[Dict[str, Any]] = None) -> str:
    settings = get_settings()
    payload: Dict[str, Any] = {
        "sub": subject,
        "exp": datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes),
        "iat": datetime.utcnow(),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    settings = get_settings()
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])


def generate_otp_code(length: int = 6) -> str:
    upper = 10**length
    return f"{secrets.randbelow(upper):0{length}d}"


def hash_otp(code: str) -> str:
    settings = get_settings()
    raw = f"{settings.secret_key}:{code}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
