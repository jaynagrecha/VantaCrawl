from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session

from ..database import get_session
from ..models import ScanJob, User
from ..security import decode_access_token

router = APIRouter(prefix="/reports", tags=["reports"])
optional_bearer = HTTPBearer(auto_error=False)
SessionDep = Annotated[Session, Depends(get_session)]


def resolve_user(
    session: SessionDep,
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(optional_bearer)],
    token: Optional[str] = Query(None, description="JWT for iframe / download links"),
) -> User:
    raw = token or (credentials.credentials if credentials else None)
    if not raw:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_access_token(raw)
        user_id = payload.get("sub")
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.is_verified and not user.is_admin:
        raise HTTPException(status_code=403, detail="Email not verified")
    return user


UserAuth = Annotated[User, Depends(resolve_user)]


def _owned_job(session: Session, job_id: str, user: User) -> ScanJob:
    job = session.get(ScanJob, job_id)
    if not job or (job.user_id != user.id and not user.is_admin):
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _html_path(job: ScanJob) -> Path:
    path = Path(job.report_html_path or "")
    if path.is_file():
        return path
    report_dir = Path(job.report_dir or "")
    matches = sorted(report_dir.glob("*_SEARCH_REPORT.html")) if report_dir.is_dir() else []
    if not matches:
        raise HTTPException(status_code=404, detail="HTML report not ready")
    return matches[-1]


def _txt_path(job: ScanJob) -> Path:
    path = Path(job.report_txt_path or "")
    if path.is_file():
        return path
    report_dir = Path(job.report_dir or "")
    matches = sorted(report_dir.glob("*_SEARCH_REPORT.txt")) if report_dir.is_dir() else []
    if not matches:
        raise HTTPException(status_code=404, detail="Text report not ready")
    return matches[-1]


@router.get("/{job_id}/html")
def report_html(job_id: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    return FileResponse(_html_path(job), media_type="text/html")


@router.get("/{job_id}/txt")
def report_txt(job_id: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    return FileResponse(_txt_path(job), media_type="text/plain")


@router.get("/{job_id}/embed", response_class=HTMLResponse)
def report_embed(job_id: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    return HTMLResponse(_html_path(job).read_text(encoding="utf-8", errors="replace"))
