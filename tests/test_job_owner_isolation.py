"""Per-user job isolation — no cross-tenant list/get (admins included)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "web" / "api"
if str(API) not in sys.path:
    sys.path.insert(0, str(API))

from vantacrawl_api.job_access import assert_job_owner, select_jobs_for_user  # noqa: E402
from vantacrawl_api.models import ScanJob, User  # noqa: E402


def _user(uid: str, *, admin: bool = False) -> User:
    return User(
        id=uid,
        email=f"{uid}@example.com",
        password_hash="x",
        is_admin=admin,
        is_verified=True,
    )


def _job(jid: str, owner: str) -> ScanJob:
    return ScanJob(
        id=jid,
        user_id=owner,
        title="t",
        start_url="https://example.com",
        status="completed",
    )


def test_owner_can_access_own_job():
    user = _user("u1")
    job = _job("j1", "u1")
    assert assert_job_owner(job, user).id == "j1"


def test_other_user_cannot_access_job():
    user = _user("u2")
    job = _job("j1", "u1")
    with pytest.raises(HTTPException) as exc:
        assert_job_owner(job, user)
    assert exc.value.status_code == 404


def test_admin_cannot_access_other_users_job():
    """Admin badge must not bypass tenant isolation for scan jobs."""
    admin = _user("admin1", admin=True)
    job = _job("j1", "u1")
    with pytest.raises(HTTPException) as exc:
        assert_job_owner(job, admin)
    assert exc.value.status_code == 404


def test_missing_job_is_404():
    with pytest.raises(HTTPException) as exc:
        assert_job_owner(None, _user("u1"))
    assert exc.value.status_code == 404


def test_empty_owner_id_denied():
    user = _user("u1")
    job = _job("j1", "")
    with pytest.raises(HTTPException):
        assert_job_owner(job, user)


def test_list_helper_scopes_to_user():
    user = _user("u1", admin=True)
    stmt = select_jobs_for_user(user)
    # Walk SQLAlchemy where criteria for the bound user id
    found = False
    for clause in getattr(stmt, "_where_criteria", ()) or ():
        text = str(clause)
        if "user_id" in text.lower() and "u1" in text:
            found = True
            break
        for element in getattr(clause, "get_children", lambda: ())():
            if getattr(element, "value", None) == "u1":
                found = True
    assert found, f"expected user_id == u1 filter in {stmt!r}"


def test_source_has_no_admin_job_bypass():
    """Regression: list/get/reports must not reintroduce admin OR ownership bypass."""
    jobs_src = (API / "vantacrawl_api" / "routes" / "jobs.py").read_text(encoding="utf-8")
    reports_src = (API / "vantacrawl_api" / "routes" / "reports.py").read_text(encoding="utf-8")
    access_src = (API / "vantacrawl_api" / "job_access.py").read_text(encoding="utf-8")
    # Former bypass patterns (job.user_id != user.id and not user.is_admin)
    assert "job.user_id != user.id" not in jobs_src
    assert "job.user_id != user.id" not in reports_src
    assert 'payload.get("admin")' not in jobs_src
    assert "is_admin" not in access_src
    assert "select_jobs_for_user" in jobs_src
    assert "assert_job_owner" in jobs_src
    assert "assert_job_owner" in reports_src
    # Admin must not get an unfiltered job list
    assert "if user.is_admin" not in jobs_src
