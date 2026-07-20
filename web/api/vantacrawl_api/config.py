"""Runtime settings for VantaCrawl web API (Render / local)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[3]  # repo root
WEB_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "VantaCrawl"
    app_env: str = "development"
    secret_key: str = "change-me-in-production-use-long-random-string"
    access_token_expire_minutes: int = 60 * 24 * 7

    database_url: str = f"sqlite:///{(WEB_ROOT / 'data' / 'vantacrawl.db').as_posix()}"
    redis_url: str = "redis://localhost:6379/0"

    admin_email: str = "admin@localhost"
    admin_password: str = "ChangeMeAdmin123!"

    # Gmail SMTP (use an App Password)
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True

    otp_ttl_minutes: int = 10
    otp_max_attempts: int = 5
    otp_length: int = 6

    data_dir: str = str(WEB_ROOT / "data")
    reports_dir: str = str(WEB_ROOT / "data" / "reports")
    jobs_dir: str = str(WEB_ROOT / "data" / "jobs")
    ui_dist_dir: str = str(WEB_ROOT / "ui" / "dist")

    cors_origins: str = "*"
    public_base_url: str = "http://localhost:8000"

    job_queue_key: str = "vantacrawl:jobs"
    progress_channel_prefix: str = "vantacrawl:progress:"

    # Free Render has no Background Workers — run the queue consumer in-process.
    embed_worker: bool = True

    @property
    def smtp_sender(self) -> str:
        return self.smtp_from or self.smtp_user

    @property
    def sqlalchemy_url(self) -> str:
        url = self.database_url
        # Render often provides postgres://
        if url.startswith("postgres://"):
            return "postgresql://" + url[len("postgres://") :]
        return url


@lru_cache
def get_settings() -> Settings:
    return Settings()
