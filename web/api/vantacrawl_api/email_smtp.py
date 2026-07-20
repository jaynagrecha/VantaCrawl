"""Gmail SMTP delivery for OTP emails."""

from __future__ import annotations

import asyncio
import logging
from email.message import EmailMessage

import aiosmtplib

from .config import get_settings

log = logging.getLogger("vantacrawl.email")


async def send_email(*, to: str, subject: str, text: str, html: str | None = None) -> None:
    settings = get_settings()
    if not settings.smtp_user or not settings.smtp_password:
        # Dev fallback: log OTP path without sending
        log.warning("SMTP not configured — email to %s not sent. Subject=%s\n%s", to, subject, text)
        return

    message = EmailMessage()
    message["From"] = settings.smtp_sender
    message["To"] = to
    message["Subject"] = subject
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")

    await aiosmtplib.send(
        message,
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_user,
        password=settings.smtp_password,
        start_tls=settings.smtp_use_tls,
    )


async def send_otp_email(to: str, code: str) -> None:
    settings = get_settings()
    minutes = settings.otp_ttl_minutes
    text = (
        f"Your {settings.app_name} verification code is: {code}\n\n"
        f"It expires in {minutes} minutes. If you did not register, ignore this email."
    )
    html = f"""
    <div style="font-family:Manrope,Segoe UI,sans-serif;background:#0b1220;color:#e8eefc;padding:24px">
      <div style="max-width:480px;margin:0 auto;background:#121a2b;border:1px solid #2a364d;border-radius:14px;padding:24px">
        <h1 style="margin:0 0 8px;font-size:20px">Vanta<span style="color:#3dd6c6">Crawl</span></h1>
        <p style="color:#93a0b8">Confirm your email to activate your account.</p>
        <p style="font-size:32px;letter-spacing:8px;font-weight:800;color:#3dd6c6;margin:24px 0">{code}</p>
        <p style="color:#93a0b8;font-size:13px">Expires in {minutes} minutes.</p>
      </div>
    </div>
    """
    await send_email(to=to, subject=f"{settings.app_name} verification code", text=text, html=html)


def send_otp_email_sync(to: str, code: str) -> None:
    asyncio.run(send_otp_email(to, code))
