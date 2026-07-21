from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlmodel import Session

from ..database import get_session
from ..models import ScanJob, User
from ..security import decode_access_token
from ..services.report_paths import find_report_file, heal_job_report_paths, job_report_roots

router = APIRouter(prefix="/reports", tags=["reports"])
optional_bearer = HTTPBearer(auto_error=False)
SessionDep = Annotated[Session, Depends(get_session)]
REPO_ROOT = Path(__file__).resolve().parents[4]
WEB_DATA = Path(__file__).resolve().parents[2] / "data"


class ArtifactInfo(BaseModel):
    name: str
    path: str
    size: int
    kind: str


class CompareResponse(BaseModel):
    summary: dict
    html_path: str


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
    return heal_job_report_paths(session, job)


def _html_path(job: ScanJob) -> Path:
    path = find_report_file(
        job,
        ("*_ASSESSMENT_REPORT.html", "*_SEARCH_REPORT.html"),
        preferred=job.report_html_path or "",
    )
    if path is not None:
        return path
    raise HTTPException(status_code=404, detail="HTML report not ready")


def _txt_path(job: ScanJob) -> Path:
    path = find_report_file(
        job,
        ("*_ASSESSMENT_REPORT.txt", "*_SEARCH_REPORT.txt"),
        preferred=job.report_txt_path or "",
    )
    if path is not None:
        return path
    raise HTTPException(status_code=404, detail="Text report not ready")


def _technical_html_path(job: ScanJob) -> Path:
    path = find_report_file(
        job,
        ("*_SEARCH_REPORT.html",),
        preferred="",
    )
    if path is not None:
        return path
    raise HTTPException(status_code=404, detail="Technical HTML report not ready")


def _safe_under(root: Path, candidate: Path) -> Path:
    root = root.resolve()
    cand = candidate.resolve()
    if root not in cand.parents and cand != root:
        raise HTTPException(status_code=400, detail="Invalid path")
    return cand


# Static compare routes MUST be declared before /{job_id}/...
@router.post("/compare", response_model=CompareResponse)
async def compare_reports(
    session: SessionDep,
    user: UserAuth,
    report_a: UploadFile = File(...),
    report_b: UploadFile = File(...),
):
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from feature_exports import compare_crawl_reports

    settings_dir = WEB_DATA / "comparisons"
    settings_dir.mkdir(parents=True, exist_ok=True)
    a_path = settings_dir / f"{user.id}_a.json"
    b_path = settings_dir / f"{user.id}_b.json"
    out_path = settings_dir / f"{user.id}_comparison.html"
    a_path.write_bytes(await report_a.read())
    b_path.write_bytes(await report_b.read())
    summary = compare_crawl_reports(str(a_path), str(b_path), str(out_path))
    return CompareResponse(summary=summary, html_path=str(out_path))


@router.get("/compare/html", response_class=HTMLResponse)
def compare_html(session: SessionDep, user: UserAuth):
    out_path = WEB_DATA / "comparisons" / f"{user.id}_comparison.html"
    if not out_path.is_file():
        raise HTTPException(status_code=404, detail="No comparison yet — upload two JSON reports first")
    return HTMLResponse(out_path.read_text(encoding="utf-8", errors="replace"))


@router.get("/{job_id}/html")
def report_html(job_id: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    return FileResponse(_html_path(job), media_type="text/html")


@router.get("/{job_id}/technical.html")
def report_technical_html(job_id: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    return FileResponse(_technical_html_path(job), media_type="text/html")


@router.get("/{job_id}/txt")
def report_txt(job_id: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    return FileResponse(_txt_path(job), media_type="text/plain")


@router.get("/{job_id}/embed", response_class=HTMLResponse)
def report_embed(job_id: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    return HTMLResponse(_html_path(job).read_text(encoding="utf-8", errors="replace"))


@router.get("/{job_id}/log", response_class=PlainTextResponse)
def report_log(job_id: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    return PlainTextResponse(job.log_tail or "", media_type="text/plain")


@router.get("/{job_id}/artifacts", response_model=List[ArtifactInfo])
def list_artifacts(job_id: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    items: List[ArtifactInfo] = []
    seen = set()
    for report_dir in job_report_roots(job):
        if not report_dir.is_dir():
            continue
        for path in sorted(report_dir.rglob("*")):
            if not path.is_file():
                continue
            try:
                rel = str(path.relative_to(report_dir)).replace("\\", "/")
            except ValueError:
                rel = path.name
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            kind = path.suffix.lower().lstrip(".") or "file"
            items.append(ArtifactInfo(name=rel, path=rel, size=path.stat().st_size, kind=kind))
    return items


@router.get("/{job_id}/artifacts/{artifact_path:path}")
def download_artifact(job_id: str, artifact_path: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    for report_dir in job_report_roots(job):
        if not report_dir.is_dir():
            continue
        try:
            target = _safe_under(report_dir, report_dir / artifact_path)
        except HTTPException:
            continue
        if target.is_file():
            return FileResponse(target, filename=target.name)
    raise HTTPException(status_code=404, detail="Artifact not found")


@router.get("/{job_id}/bundle.zip")
def download_bundle(job_id: str, session: SessionDep, user: UserAuth):
    job = _owned_job(session, job_id, user)
    roots = [r for r in job_report_roots(job) if r.is_dir()]
    if not roots:
        raise HTTPException(status_code=404, detail="No artifacts")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        seen = set()
        for report_dir in roots:
            for path in report_dir.rglob("*"):
                if not path.is_file():
                    continue
                key = str(path.resolve())
                if key in seen:
                    continue
                seen.add(key)
                try:
                    arc = str(path.relative_to(report_dir))
                except ValueError:
                    arc = path.name
                zf.write(path, arcname=arc)
        if job.log_tail:
            zf.writestr("live_logs.txt", job.log_tail)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{job_id}_artifacts.zip"'},
    )
