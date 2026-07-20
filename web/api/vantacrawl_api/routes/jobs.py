from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from sqlmodel import select

from ..config import get_settings
from ..deps import CurrentUser, SessionDep
from ..models import ScanJob
from ..schemas import JobCreateRequest, JobListOut, JobOut, MessageOut
from ..security import decode_access_token
from ..services.queue import enqueue_job, publish_progress, redis_client, set_job_command
from ..scan_settings import MODE_PRESETS, concurrency_for_speed

router = APIRouter(prefix="/jobs", tags=["jobs"])


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
    return merged


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
    host = urlparse(start).netloc
    if not host:
        raise HTTPException(status_code=400, detail="Invalid start_url")

    settings = get_settings()
    job = ScanJob(
        user_id=user.id,
        title=body.title.strip() or host,
        start_url=start,
        mode=body.mode,
        speed=body.speed,
        status="queued",
        authorized_confirmed=True,
        config_json=_build_config_json(body),
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
    return _to_out(job)


@router.get("", response_model=JobListOut)
def list_jobs(session: SessionDep, user: CurrentUser):
    q = select(ScanJob).where(ScanJob.user_id == user.id).order_by(ScanJob.created_at.desc())
    if user.is_admin:
        q = select(ScanJob).order_by(ScanJob.created_at.desc())
    jobs = session.exec(q).all()
    return JobListOut(jobs=[_to_out(j) for j in jobs])


@router.get("/{job_id}", response_model=JobOut)
def get_job(job_id: str, session: SessionDep, user: CurrentUser):
    job = session.get(ScanJob, job_id)
    if not job or (job.user_id != user.id and not user.is_admin):
        raise HTTPException(status_code=404, detail="Job not found")
    return _to_out(job)


@router.post("/{job_id}/pause", response_model=MessageOut)
def pause_job(job_id: str, session: SessionDep, user: CurrentUser):
    job = session.get(ScanJob, job_id)
    if not job or (job.user_id != user.id and not user.is_admin):
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status not in ("running", "queued"):
        raise HTTPException(status_code=400, detail=f"Cannot pause from status {job.status}")
    set_job_command(job_id, "pause")
    job.status = "paused" if job.status == "running" else job.status
    job.updated_at = datetime.utcnow()
    session.add(job)
    session.commit()
    publish_progress(job_id, {"status": "paused", "message": "Pause requested"})
    return MessageOut(message="Pause requested")


@router.post("/{job_id}/resume", response_model=MessageOut)
def resume_job(job_id: str, session: SessionDep, user: CurrentUser):
    job = session.get(ScanJob, job_id)
    if not job or (job.user_id != user.id and not user.is_admin):
        raise HTTPException(status_code=404, detail="Job not found")
    set_job_command(job_id, "resume")
    if job.status == "paused":
        job.status = "running"
    job.updated_at = datetime.utcnow()
    session.add(job)
    session.commit()
    publish_progress(job_id, {"status": "running", "message": "Resume requested"})
    return MessageOut(message="Resume requested")


@router.post("/{job_id}/stop", response_model=MessageOut)
def stop_job(job_id: str, session: SessionDep, user: CurrentUser):
    job = session.get(ScanJob, job_id)
    if not job or (job.user_id != user.id and not user.is_admin):
        raise HTTPException(status_code=404, detail="Job not found")
    set_job_command(job_id, "stop")
    job.status = "stopping"
    job.updated_at = datetime.utcnow()
    session.add(job)
    session.commit()
    publish_progress(job_id, {"status": "stopping", "message": "Stop requested"})
    return MessageOut(message="Stop requested")


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
        if not job or (job.user_id != user_id and not payload.get("admin")):
            await websocket.close(code=4404)
            return
        await websocket.send_json(
            {
                "status": job.status,
                "progress": job.progress_json,
                "log_tail": (job.log_tail or "")[-4000:],
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
