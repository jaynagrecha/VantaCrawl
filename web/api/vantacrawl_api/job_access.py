"""Strict per-user job ownership.

Jobs are visible/accessible only to the owning user. Admin status does not
grant cross-tenant access to another user's scan jobs, reports, or logs.
"""

from __future__ import annotations

from typing import Optional

from fastapi import HTTPException
from sqlmodel import Session, select

from .models import ScanJob, User


def assert_job_owner(job: Optional[ScanJob], user: User) -> ScanJob:
    """Return job if ``user`` owns it; otherwise 404 (no existence leak)."""
    if not job or not user or not getattr(user, "id", None):
        raise HTTPException(status_code=404, detail="Job not found")
    owner = (job.user_id or "").strip()
    if not owner or owner != str(user.id):
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def select_jobs_for_user(user: User):
    """SQLModel select for jobs owned by ``user`` only (newest first)."""
    return select(ScanJob).where(ScanJob.user_id == user.id).order_by(ScanJob.created_at.desc())


def get_owned_job(session: Session, job_id: str, user: User) -> ScanJob:
    return assert_job_owner(session.get(ScanJob, job_id), user)
