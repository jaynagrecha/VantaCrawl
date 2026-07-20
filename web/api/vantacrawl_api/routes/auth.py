from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, status
from sqlmodel import select

from ..config import get_settings
from ..deps import CurrentUser, SessionDep
from ..email_smtp import send_otp_email
from ..models import EmailOTP, User
from ..schemas import (
    LoginRequest,
    MessageOut,
    RegisterRequest,
    ResendOTPRequest,
    TokenResponse,
    UserOut,
    VerifyOTPRequest,
)
from ..security import (
    create_access_token,
    generate_otp_code,
    hash_otp,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


async def _issue_otp(session: SessionDep, email: str) -> None:
    settings = get_settings()
    code = generate_otp_code(settings.otp_length)
    otp = EmailOTP(
        email=email,
        code_hash=hash_otp(code),
        purpose="verify",
        expires_at=datetime.utcnow() + timedelta(minutes=settings.otp_ttl_minutes),
    )
    session.add(otp)
    session.commit()
    await send_otp_email(email, code)


@router.post("/register", response_model=MessageOut)
async def register(body: RegisterRequest, session: SessionDep):
    email = body.email.strip().lower()
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        if existing.is_verified:
            raise HTTPException(status_code=400, detail="Email already registered")
        # Allow re-register attempt to resend OTP for unverified
        existing.password_hash = hash_password(body.password)
        session.add(existing)
        session.commit()
        await _issue_otp(session, email)
        return MessageOut(message="Account exists but unverified. OTP sent.")
    user = User(email=email, password_hash=hash_password(body.password), is_verified=False)
    session.add(user)
    session.commit()
    await _issue_otp(session, email)
    return MessageOut(message="Registered. Check your email for the OTP.")


@router.post("/verify-otp", response_model=TokenResponse)
async def verify_otp(body: VerifyOTPRequest, session: SessionDep):
    settings = get_settings()
    email = body.email.strip().lower()
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    otp = session.exec(
        select(EmailOTP)
        .where(EmailOTP.email == email, EmailOTP.purpose == "verify")
        .order_by(EmailOTP.created_at.desc())
    ).first()
    if otp and otp.consumed_at is not None:
        otp = None
    if not otp:
        raise HTTPException(status_code=400, detail="No active OTP. Request a new code.")
    if otp.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="OTP expired")
    if otp.attempts >= settings.otp_max_attempts:
        raise HTTPException(status_code=400, detail="Too many attempts. Request a new code.")
    otp.attempts += 1
    session.add(otp)
    session.commit()
    if otp.code_hash != hash_otp(body.code.strip()):
        raise HTTPException(status_code=400, detail="Invalid OTP")
    otp.consumed_at = datetime.utcnow()
    user.is_verified = True
    user.last_login_at = datetime.utcnow()
    session.add(otp)
    session.add(user)
    session.commit()
    token = create_access_token(user.id, extra={"email": user.email, "admin": user.is_admin})
    return TokenResponse(access_token=token)


@router.post("/resend-otp", response_model=MessageOut)
async def resend_otp(body: ResendOTPRequest, session: SessionDep):
    email = body.email.strip().lower()
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        # Don't leak existence
        return MessageOut(message="If the account exists, an OTP was sent.")
    if user.is_verified:
        return MessageOut(message="Account already verified. You can log in.")
    await _issue_otp(session, email)
    return MessageOut(message="OTP sent.")


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, session: SessionDep):
    email = body.email.strip().lower()
    user = session.exec(select(User).where(User.email == email)).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Check your inbox for the OTP.",
        )
    user.last_login_at = datetime.utcnow()
    session.add(user)
    session.commit()
    token = create_access_token(user.id, extra={"email": user.email, "admin": user.is_admin})
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser):
    return UserOut(
        id=user.id,
        email=user.email,
        is_admin=user.is_admin,
        is_verified=user.is_verified,
        created_at=user.created_at,
    )
