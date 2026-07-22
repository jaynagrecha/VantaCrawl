"""Job access control: owner-only for regular users; admins see all.

Non-admin users can only list/open jobs they created. Admin users retain
full visibility and access across all tenants.
"""

from __future__ import annotations

from typing import Optional

from fastapi import HTTPException
from sqlmodel import Session, select

from .models import ScanJob, User

# Active / in-flight — must stop or finish before delete
ACTIVE_JOB_STATUSES = frozenset({"queued", "running", "paused", "stopping", "scheduled"})


def job_is_deletable(status: str) -> bool:
    return (status or "").strip().lower() not in ACTIVE_JOB_STATUSES


def assert_job_owner(job: Optional[ScanJob], user: User) -> ScanJob:
    """Return job if ``user`` owns it, or if ``user`` is admin; else 404."""
    if not job or not user or not getattr(user, "id", None):
        raise HTTPException(status_code=404, detail="Job not found")
    if getattr(user, "is_admin", False):
        return job
    owner = (job.user_id or "").strip()
    if not owner or owner != str(user.id):
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def select_jobs_for_user(user: User):
    """Jobs for the dashboard: own jobs only, or all jobs when admin."""
    if getattr(user, "is_admin", False):
        return select(ScanJob).order_by(ScanJob.created_at.desc())
    return select(ScanJob).where(ScanJob.user_id == user.id).order_by(ScanJob.created_at.desc())


def get_owned_job(session: Session, job_id: str, user: User) -> ScanJob:
    return assert_job_owner(session.get(ScanJob, job_id), user)
