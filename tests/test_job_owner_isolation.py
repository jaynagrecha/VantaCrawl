"""Job isolation: regular users see only their jobs; admins see all."""

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
    assert assert_job_owner(_job("j1", "u1"), _user("u1")).id == "j1"


def test_other_user_cannot_access_job():
    with pytest.raises(HTTPException) as exc:
        assert_job_owner(_job("j1", "u1"), _user("u2"))
    assert exc.value.status_code == 404


def test_admin_can_access_other_users_job():
    admin = _user("admin1", admin=True)
    assert assert_job_owner(_job("j1", "u1"), admin).id == "j1"


def test_missing_job_is_404():
    with pytest.raises(HTTPException) as exc:
        assert_job_owner(None, _user("u1"))
    assert exc.value.status_code == 404


def test_empty_owner_id_denied_for_user():
    with pytest.raises(HTTPException):
        assert_job_owner(_job("j1", ""), _user("u1"))


def test_empty_owner_id_allowed_for_admin():
    assert assert_job_owner(_job("j1", ""), _user("admin1", admin=True)).id == "j1"


def test_list_helper_scopes_users_but_not_admins():
    user_stmt = select_jobs_for_user(_user("u1"))
    admin_stmt = select_jobs_for_user(_user("admin1", admin=True))
    user_blob = repr(user_stmt)
    admin_blob = repr(admin_stmt)
    assert "user_id" in user_blob.lower() or any(
        getattr(el, "value", None) == "u1"
        for clause in (getattr(user_stmt, "_where_criteria", ()) or ())
        for el in (getattr(clause, "get_children", lambda: ())() or (clause,))
    )
    # Admin list has no user_id equality filter
    admin_where = getattr(admin_stmt, "_where_criteria", ()) or ()
    assert not admin_where or "user_id" not in repr(admin_where).lower()


def test_source_keeps_admin_bypass_in_job_access():
    access_src = (API / "vantacrawl_api" / "job_access.py").read_text(encoding="utf-8")
    assert "is_admin" in access_src
    jobs_src = (API / "vantacrawl_api" / "routes" / "jobs.py").read_text(encoding="utf-8")
    assert "assert_job_owner" in jobs_src
    assert "select_jobs_for_user" in jobs_src
