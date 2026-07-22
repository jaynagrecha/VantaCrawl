from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from sqlmodel import select

from ..config import get_settings
from ..deps import CurrentUser, SessionDep
from ..job_access import assert_job_owner, job_is_deletable, select_jobs_for_user
from ..models import ScanJob, User
from ..schemas import JobCreateRequest, JobListOut, JobOut, JobSettingsPatch, MessageOut
from ..security import decode_access_token
from ..services.queue import (
    clear_job_command,
    enqueue_job,
    publish_progress,
    purge_job_queue_state,
    redis_client,
    set_job_command,
)
from ..scan_settings import MODE_PRESETS, available_wordlists, concurrency_for_speed
from target_url_safety import validate_public_http_url, validate_public_http_urls

router = APIRouter(prefix="/jobs", tags=["jobs"])


def _purge_job_files(job: ScanJob) -> None:
    """Best-effort delete of on-disk job/report directories for this job id only."""
    settings = get_settings()
    candidates: List[Path] = [
        Path(settings.jobs_dir) / job.id,
        Path(settings.reports_dir) / job.id,
    ]
    if (job.report_dir or "").strip():
        candidates.append(Path(job.report_dir))

    for raw in candidates:
        try:
            resolved = raw.resolve()
        except Exception:
            continue
        if job.id not in resolved.parts:
            continue
        if resolved.is_dir():
            shutil.rmtree(resolved, ignore_errors=True)
        elif resolved.is_file():
            try:
                resolved.unlink()
            except OSError:
                pass


def _require_safe_targets(start: str, extras: Optional[List[str]] = None) -> tuple[str, List[str]]:
    try:
        safe_start = validate_public_http_url(start)
        safe_extras = validate_public_http_urls(extras or [])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return safe_start, safe_extras


def _to_out(job: ScanJob) -> JobOut:
    return JobOut(
        id=job.id,
        title=job.title,
        start_url=job.start_url,
        mode=job.mode,
        speed=job.speed,
        status=job.status,
        authorized_confirmed=job.authorized_confirmed,
        config_json=job.config_json or {},
        progress_json=job.progress_json or {},
        log_tail=job.log_tail or "",
        error_message=job.error_message or "",
        report_html_path=job.report_html_path or "",
        report_txt_path=job.report_txt_path or "",
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        updated_at=job.updated_at,
    )


def _owned(job: Optional[ScanJob], user) -> ScanJob:
    """Owner-only for regular users; admins may access any job."""
    return assert_job_owner(job, user)


def _build_config_json(body: JobCreateRequest) -> dict:
    preset = dict(MODE_PRESETS.get(body.mode, {}))
    speed = body.speed or preset.pop("speed", "balanced")
    crawl, enum, download = concurrency_for_speed(speed)
    merged = {
        "profile": preset.get("profile", "full"),
        "crawl_concurrency": crawl,
        "enum_concurrency": enum,
        "download_concurrency": download,
        **{k: v for k, v in preset.items() if k != "speed"},
        **(body.settings or {}),
        "mode": body.mode,
        "speed": speed,
    }
    if body.target_urls:
        merged["target_urls"] = [u.strip() for u in body.target_urls if u and str(u).strip()]
    return merged


def _persist_and_enqueue(session, user, start: str, title: str, mode: str, speed: str, config: dict) -> ScanJob:
    settings = get_settings()
    host = urlparse(start).netloc
    job = ScanJob(
        user_id=user.id,
        title=(title or "").strip() or host,
        start_url=start,
        mode=mode,
        speed=speed,
        status="queued",
        authorized_confirmed=True,
        config_json=config,
        progress_json={"phase": "queued", "message": "Waiting for worker"},
        report_dir=str(Path(settings.reports_dir) / "pending"),
    )
    session.add(job)
    session.commit()
    session.refresh(job)

    job_dir = Path(settings.jobs_dir) / job.id
    report_dir = Path(settings.reports_dir) / job.id
    job_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "uploads").mkdir(parents=True, exist_ok=True)
    job.report_dir = str(report_dir)
    job.updated_at = datetime.utcnow()
    session.add(job)
    session.commit()
    session.refresh(job)

    try:
        enqueue_job(job.id)
    except Exception as exc:
        job.status = "failed"
        job.error_message = f"Queue unavailable: {exc}"
        session.add(job)
        session.commit()
        raise HTTPException(status_code=503, detail="Job queue unavailable (is Redis running?)") from exc

    publish_progress(job.id, {"status": "queued", "message": "Job enqueued"})
    return job


@router.post("", response_model=JobOut)
def create_job(body: JobCreateRequest, session: SessionDep, user: CurrentUser):
    if not body.authorized_confirmed:
        raise HTTPException(
            status_code=400,
            detail="You must confirm this is an authorized target before starting a scan.",
        )
    start = (body.start_url or "").strip()
    if not start.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="start_url must be http(s)")
    if not urlparse(start).netloc:
        raise HTTPException(status_code=400, detail="Invalid start_url")
    start, safe_targets = _require_safe_targets(start, body.target_urls or [])
    config = _build_config_json(body)
    if safe_targets:
        config["target_urls"] = safe_targets
    job = _persist_and_enqueue(session, user, start, body.title, body.mode, body.speed, config)
    return _to_out(job)


@router.post("/with-files", response_model=JobOut)
async def create_job_with_files(
    session: SessionDep,
    user: CurrentUser,
    start_url: str = Form(...),
    title: str = Form(""),
    mode: str = Form("full_audit"),
    speed: str = Form("balanced"),
    authorized_confirmed: bool = Form(False),
    settings_json: str = Form("{}"),
    targets_text: str = Form(""),
    targets_file: Optional[UploadFile] = File(None),
    wordlist_file: Optional[UploadFile] = File(None),
    extra_wordlist_file: Optional[UploadFile] = File(None),
    postman_file: Optional[UploadFile] = File(None),
    har_file: Optional[UploadFile] = File(None),
    wordlist_id: str = Form(""),
):
    if not authorized_confirmed:
        raise HTTPException(status_code=400, detail="You must confirm this is an authorized target before starting a scan.")
    start = start_url.strip()
    if not start.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="start_url must be http(s)")

    urls: List[str] = []
    if targets_text.strip():
        for line in targets_text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line.startswith(("http://", "https://")):
                urls.append(line)
    if targets_file is not None and targets_file.filename:
        raw = (await targets_file.read()).decode("utf-8", errors="ignore")
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line.startswith(("http://", "https://")):
                urls.append(line)
    if not urls:
        urls = [start]
    start, urls = _require_safe_targets(urls[0], urls)

    try:
        settings_obj = json.loads(settings_json or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="settings_json must be JSON") from exc

    req = JobCreateRequest(
        start_url=start,
        title=title,
        mode=mode,
        speed=speed,
        authorized_confirmed=True,
        settings=settings_obj,
        target_urls=urls,
    )
    config = _build_config_json(req)
    config["target_urls"] = urls
    job = _persist_and_enqueue(session, user, start, title, mode, speed, config)

    settings = get_settings()
    uploads = Path(settings.jobs_dir) / job.id / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    cfg = dict(job.config_json or {})

    chosen_id = (wordlist_id or "").strip()
    if chosen_id and chosen_id != "__upload__":
        match = next((w for w in available_wordlists() if w["id"] == chosen_id), None)
        if not match:
            raise HTTPException(status_code=400, detail=f"Unknown wordlist: {chosen_id}")
        src = Path(match["path"])
        if not src.is_file():
            raise HTTPException(status_code=400, detail=f"Wordlist file missing on server: {chosen_id}")
        # Stable bundled path — do not copy into ephemeral job uploads/ (Render wipe → queued fail)
        cfg["wordlist_file"] = str(src.resolve())
        cfg["use_wordlist"] = True
        cfg["wordlist_id"] = chosen_id

    if wordlist_file is not None and wordlist_file.filename:
        dest = uploads / Path(wordlist_file.filename).name
        dest.write_bytes(await wordlist_file.read())
        cfg["wordlist_file"] = str(dest)
        cfg["use_wordlist"] = True
        cfg["wordlist_id"] = "upload"
    if extra_wordlist_file is not None and extra_wordlist_file.filename:
        dest = uploads / ("extra_" + Path(extra_wordlist_file.filename).name)
        dest.write_bytes(await extra_wordlist_file.read())
        extras = list(cfg.get("extra_wordlists") or [])
        extras.append(str(dest))
        cfg["extra_wordlists"] = extras
    if postman_file is not None and postman_file.filename:
        dest = uploads / ("postman_" + Path(postman_file.filename).name)
        dest.write_bytes(await postman_file.read())
        cfg["api_postman_file"] = str(dest)
        cfg["api_recon"] = True
    if har_file is not None and har_file.filename:
        dest = uploads / ("har_" + Path(har_file.filename).name)
        dest.write_bytes(await har_file.read())
        cfg["api_har_file"] = str(dest)
        cfg["api_recon"] = True
    job.config_json = cfg
    job.updated_at = datetime.utcnow()
    session.add(job)
    session.commit()
    session.refresh(job)
    return _to_out(job)


@router.get("", response_model=JobListOut)
def list_jobs(session: SessionDep, user: CurrentUser):
    jobs = session.exec(select_jobs_for_user(user)).all()
    return JobListOut(jobs=[_to_out(j) for j in jobs])


@router.get("/{job_id}", response_model=JobOut)
def get_job(job_id: str, session: SessionDep, user: CurrentUser):
    from ..services.report_paths import heal_job_report_paths

    job = heal_job_report_paths(session, _owned(session.get(ScanJob, job_id), user))
    return _to_out(job)


@router.delete("/{job_id}", response_model=MessageOut)
def delete_job(job_id: str, session: SessionDep, user: CurrentUser):
    """Delete a finished job and its reports. Active/running jobs cannot be deleted."""
    job = _owned(session.get(ScanJob, job_id), user)
    if not job_is_deletable(job.status):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Cannot delete a job while status is '{job.status}'. "
                "Stop or wait until it finishes, then delete."
            ),
        )

    _purge_job_files(job)
    try:
        purge_job_queue_state(job.id)
    except Exception:
        pass

    session.delete(job)
    session.commit()
    return MessageOut(message="Job deleted")


@router.patch("/{job_id}/settings", response_model=MessageOut)
def patch_settings(job_id: str, body: JobSettingsPatch, session: SessionDep, user: CurrentUser):
    job = _owned(session.get(ScanJob, job_id), user)
    if job.status not in ("paused", "running", "queued"):
        raise HTTPException(status_code=400, detail=f"Cannot edit settings in status {job.status}")
    cfg = dict(job.config_json or {})
    pending = dict(cfg.get("pending_live_settings") or {})
    pending.update(body.settings or {})
    cfg["pending_live_settings"] = pending
    cfg.update(body.settings or {})
    cfg["_live_dirty"] = True
    job.config_json = cfg
    job.updated_at = datetime.utcnow()
    session.add(job)
    session.commit()
    return MessageOut(message="Settings saved — applied on Resume")


@router.post("/{job_id}/pause", response_model=MessageOut)
def pause_job(job_id: str, session: SessionDep, user: CurrentUser):
    job = _owned(session.get(ScanJob, job_id), user)
    if job.status == "queued":
        job.status = "paused"
        job.updated_at = datetime.utcnow()
        session.add(job)
        session.commit()
        set_job_command(job_id, "pause")
        publish_progress(job_id, {"status": "paused", "message": "Paused before start"})
        return MessageOut(message="Paused before start")
    if job.status != "running":
        raise HTTPException(status_code=400, detail=f"Cannot pause from status {job.status}")
    set_job_command(job_id, "pause")
    job.status = "paused"
    job.updated_at = datetime.utcnow()
    session.add(job)
    session.commit()
    publish_progress(job_id, {"status": "paused", "message": "Pause requested"})
    return MessageOut(message="Pause requested")


@router.post("/{job_id}/resume", response_model=MessageOut)
def resume_job(job_id: str, session: SessionDep, user: CurrentUser):
    job = _owned(session.get(ScanJob, job_id), user)
    if job.status not in ("paused", "scheduled"):
        raise HTTPException(status_code=400, detail=f"Cannot resume from status {job.status}")

    if not job.started_at:
        job.status = "queued"
        job.updated_at = datetime.utcnow()
        session.add(job)
        session.commit()
        clear_job_command(job_id)
        enqueue_job(job.id)
        publish_progress(job_id, {"status": "queued", "message": "Re-queued after pause"})
        return MessageOut(message="Re-queued")

    set_job_command(job_id, "resume")
    job.status = "running"
    job.updated_at = datetime.utcnow()
    session.add(job)
    session.commit()
    publish_progress(job_id, {"status": "running", "message": "Resume requested"})
    return MessageOut(message="Resume requested")


def _force_cancel(job: ScanJob, session, *, note: str) -> MessageOut:
    from reporting import write_partial_full_reports
    from ..services.summary_report import write_summary_report

    set_job_command(job.id, "stop")
    job.status = "cancelled"
    job.finished_at = datetime.utcnow()
    job.updated_at = datetime.utcnow()
    job.error_message = job.error_message or note

    report_dir = Path(job.report_dir or "")
    if not report_dir:
        settings = get_settings()
        report_dir = Path(settings.jobs_dir) / job.id / "reports"
        job.report_dir = str(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    html_path = ""
    txt_path = ""
    existing = (job.report_html_path or "").strip()
    if existing and Path(existing).is_file() and "ASSESSMENT_REPORT" in Path(existing).name.upper():
        html_path = existing
        txt_path = (job.report_txt_path or "").strip()

    # Prefer full assessment/search reports from findings collected so far
    if not html_path:
        try:
            written = write_partial_full_reports(
                report_dir=report_dir,
                start_url=job.start_url or "",
                title=job.title or "Scan",
                progress=job.progress_json or {},
                config=None,
            )
            if written:
                from ..services.report_paths import find_report_file

                html = find_report_file(
                    job,
                    ("*_ASSESSMENT_REPORT.html", "*_SEARCH_REPORT.html"),
                )
                txt = find_report_file(
                    job,
                    ("*_ASSESSMENT_REPORT.txt", "*_SEARCH_REPORT.txt"),
                )
                if html:
                    html_path = str(html)
                if txt:
                    txt_path = str(txt)
                elif written.get("assessment_report_html"):
                    html_path = written["assessment_report_html"]
                    txt_path = written.get("assessment_report_txt") or written.get("search_report_txt") or ""
                elif written.get("search_report_html"):
                    html_path = written["search_report_html"]
                    txt_path = written.get("search_report_txt") or ""
        except Exception:
            html_path = ""
            txt_path = ""

    if html_path and "ASSESSMENT_REPORT" in Path(html_path).name.upper():
        # Full report with explanations is ready — don't leave a scary stub note
        if job.error_message and "Full crawl report was never produced" in (job.error_message or ""):
            job.error_message = note
        elif not job.error_message:
            job.error_message = note

    if not html_path:
        html_path, txt_path = write_summary_report(
            report_dir,
            job_id=job.id,
            title=job.title or "Scan",
            start_url=job.start_url or "",
            status="cancelled",
            progress=job.progress_json or {},
            log_tail=job.log_tail or "",
            note=note
            + " Built a summary from live progress; full assessment report was unavailable.",
        )

    job.report_html_path = html_path
    job.report_txt_path = txt_path
    session.add(job)
    session.commit()
    publish_progress(
        job.id,
        {
            "status": "cancelled",
            "message": "Force-cancelled",
            "progress": job.progress_json or {},
        },
    )
    return MessageOut(message="Force-cancelled")


@router.post("/{job_id}/stop", response_model=MessageOut)
def stop_job(job_id: str, session: SessionDep, user: CurrentUser):
    job = _owned(session.get(ScanJob, job_id), user)
    if job.status in ("completed", "cancelled", "failed"):
        raise HTTPException(status_code=400, detail=f"Already finished ({job.status})")

    # Second Stop click while stuck in stopping → force cancel
    if job.status == "stopping":
        return _force_cancel(job, session, note="Force-cancelled (stop was stuck)")

    if job.status in ("queued", "scheduled") or (job.status == "paused" and not job.started_at):
        job.status = "cancelled"
        job.finished_at = datetime.utcnow()
        job.updated_at = datetime.utcnow()
        session.add(job)
        session.commit()
        set_job_command(job_id, "stop")
        publish_progress(job_id, {"status": "cancelled", "message": "Cancelled"})
        return MessageOut(message="Cancelled")

    set_job_command(job_id, "stop")
    job.status = "stopping"
    job.updated_at = datetime.utcnow()
    session.add(job)
    session.commit()
    publish_progress(job_id, {"status": "stopping", "message": "Stop requested"})
    return MessageOut(message="Stop requested")


@router.post("/{job_id}/force-cancel", response_model=MessageOut)
def force_cancel_job(job_id: str, session: SessionDep, user: CurrentUser):
    """Immediately mark cancelled when a stop hangs (e.g. Cloudflare-blocked requests)."""
    job = _owned(session.get(ScanJob, job_id), user)
    if job.status in ("completed", "cancelled", "failed"):
        return MessageOut(message=f"Already {job.status}")
    return _force_cancel(job, session, note="Force-cancelled by user")


@router.post("/{job_id}/summary-report", response_model=MessageOut)
def build_summary_report(job_id: str, session: SessionDep, user: CurrentUser):
    """Rebuild the full assessment report from findings collected so far.

    Falls back to a thin summary only when no findings/snapshot are available.
    """
    from reporting import write_partial_full_reports
    from ..services.report_paths import find_report_file, heal_job_report_paths
    from ..services.summary_report import write_summary_report

    job = _owned(session.get(ScanJob, job_id), user)
    report_dir = Path(job.report_dir or "")
    if not report_dir:
        settings = get_settings()
        report_dir = Path(settings.jobs_dir) / job.id / "reports"
        job.report_dir = str(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    html_path = ""
    txt_path = ""
    try:
        written = write_partial_full_reports(
            report_dir=report_dir,
            start_url=job.start_url or "",
            title=job.title or "Scan",
            progress=job.progress_json or {},
            config=None,
        )
        if written:
            html = find_report_file(
                job,
                ("*_ASSESSMENT_REPORT.html", "*_SEARCH_REPORT.html"),
            )
            txt = find_report_file(
                job,
                ("*_ASSESSMENT_REPORT.txt", "*_SEARCH_REPORT.txt"),
            )
            if html:
                html_path = str(html)
            if txt:
                txt_path = str(txt)
            elif written.get("assessment_report_html"):
                html_path = written["assessment_report_html"]
                txt_path = written.get("assessment_report_txt") or ""
            elif written.get("search_report_html"):
                html_path = written["search_report_html"]
                txt_path = written.get("search_report_txt") or ""
    except Exception:
        html_path = ""
        txt_path = ""

    if not html_path:
        html_path, txt_path = write_summary_report(
            report_dir,
            job_id=job.id,
            title=job.title or "Scan",
            start_url=job.start_url or "",
            status=job.status,
            progress=job.progress_json or {},
            log_tail=job.log_tail or "",
            note="Summary only — no findings snapshot was available to build the full assessment.",
        )
        msg = "Summary report ready (no findings available for full assessment)"
    else:
        msg = "Full assessment report rebuilt from findings collected so far"
        # Clear the old stub note if we now have a real assessment
        if job.error_message and "Full crawl report was never produced" in (job.error_message or ""):
            job.error_message = (job.error_message or "").replace(
                " Full crawl report was never produced (often blocked by Cloudflare).",
                "",
            ).strip()

    job.report_html_path = html_path
    job.report_txt_path = txt_path
    job.updated_at = datetime.utcnow()
    session.add(job)
    session.commit()
    heal_job_report_paths(session, job)
    return MessageOut(message=msg)


@router.websocket("/{job_id}/ws")
async def job_ws(websocket: WebSocket, job_id: str):
    import asyncio

    await websocket.accept()
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4401)
        return
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
    except Exception:
        await websocket.close(code=4401)
        return

    from sqlmodel import Session

    from ..database import engine

    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        owner = session.get(User, user_id) if user_id else None
        try:
            job = assert_job_owner(job, owner) if owner else None
        except HTTPException:
            job = None
        if not job:
            await websocket.close(code=4404)
            return
        await websocket.send_json(
            {
                "status": job.status,
                "progress": job.progress_json,
                "log_tail": (job.log_tail or "")[-4000:],
                "started_at": job.started_at.isoformat() + "Z" if job.started_at else None,
                "finished_at": job.finished_at.isoformat() + "Z" if job.finished_at else None,
            }
        )

    settings = get_settings()
    client = redis_client()
    pubsub = client.pubsub()
    channel = settings.progress_channel_prefix + job_id
    pubsub.subscribe(channel)

    async def pump_redis():
        while True:
            message = await asyncio.to_thread(
                pubsub.get_message, ignore_subscribe_messages=True, timeout=1.0
            )
            if message and message.get("type") == "message":
                data = message.get("data")
                await websocket.send_text(data if isinstance(data, str) else json.dumps(data))

    task = asyncio.create_task(pump_redis())
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        task.cancel()
        pubsub.unsubscribe(channel)
        pubsub.close()
