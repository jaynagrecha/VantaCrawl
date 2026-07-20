"""In-process Redis job consumer for free-tier hosts without Background Workers."""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..config import get_settings
from .queue import claim_due_scheduled_jobs, enqueue_job, redis_client

log = logging.getLogger("vantacrawl.worker")

_ROOT = Path(__file__).resolve().parents[4]
_WORKER_DIR = _ROOT / "web" / "worker"
_stop: Optional[threading.Event] = None
_thread: Optional[threading.Thread] = None
_watchdog: Optional[threading.Thread] = None


def _ensure_paths() -> None:
    for path in (str(_ROOT), str(_WORKER_DIR)):
        if path not in sys.path:
            sys.path.insert(0, path)


def _reclaim_stuck_queued_jobs() -> None:
    """Re-enqueue DB jobs still queued after a worker crash (skip ids already in Redis)."""
    try:
        from sqlmodel import Session, select

        from vantacrawl_api.database import engine
        from vantacrawl_api.models import ScanJob

        settings = get_settings()
        client = redis_client()
        pending = set(client.lrange(settings.job_queue_key, 0, -1) or [])
        with Session(engine) as session:
            jobs = session.exec(select(ScanJob).where(ScanJob.status == "queued")).all()
            for job in jobs:
                if job.started_at is not None:
                    continue
                if job.id in pending:
                    continue
                enqueue_job(job.id)
                pending.add(job.id)
                log.info("Re-queued stuck job %s", job.id)
    except Exception as exc:
        log.error("Failed to reclaim queued jobs: %s", exc)


def worker_loop(stop: threading.Event) -> None:
    _ensure_paths()
    from runner import run_job  # noqa: WPS433

    settings = get_settings()
    client = redis_client()
    log.info(
        "Embedded worker online · queue=%s redis=%s",
        settings.job_queue_key,
        settings.redis_url,
    )
    _reclaim_stuck_queued_jobs()
    while not stop.is_set():
        try:
            due = claim_due_scheduled_jobs()
            for job_id in due:
                log.info("Promoted scheduled job %s", job_id)
                from sqlmodel import Session

                from vantacrawl_api.database import engine
                from vantacrawl_api.models import ScanJob

                with Session(engine) as session:
                    job = session.get(ScanJob, job_id)
                    if job and job.status == "scheduled":
                        job.status = "queued"
                        job.updated_at = datetime.utcnow()
                        session.add(job)
                        session.commit()
        except Exception as exc:
            log.error("Delayed queue error: %s", exc)

        try:
            item = client.brpop(settings.job_queue_key, timeout=2)
        except Exception as exc:
            log.error("Redis error: %s", exc)
            time.sleep(2)
            continue
        if not item:
            continue
        _, job_id = item
        log.info("Picked job %s", job_id)
        try:
            asyncio.run(run_job(job_id))
        except asyncio.CancelledError:
            # Stop/cancel must not kill the consumer thread (CancelledError is BaseException)
            log.info("Job %s cancelled — worker stays online", job_id)
        except Exception:
            log.exception("Unhandled job failure %s", job_id)


def _watchdog_loop(stop: threading.Event) -> None:
    """Restart the consumer if a BaseException escapes the worker thread."""
    while not stop.is_set():
        time.sleep(5)
        global _thread
        if stop.is_set():
            return
        if _thread is None or not _thread.is_alive():
            log.error("Embedded worker thread died — restarting")
            _thread = threading.Thread(
                target=worker_loop,
                args=(stop,),
                name="vantacrawl-embedded-worker",
                daemon=True,
            )
            _thread.start()


def start_embedded_worker() -> None:
    global _stop, _thread, _watchdog
    if _thread and _thread.is_alive():
        return
    _stop = threading.Event()
    _thread = threading.Thread(
        target=worker_loop,
        args=(_stop,),
        name="vantacrawl-embedded-worker",
        daemon=True,
    )
    _thread.start()
    if _watchdog is None or not _watchdog.is_alive():
        _watchdog = threading.Thread(
            target=_watchdog_loop,
            args=(_stop,),
            name="vantacrawl-worker-watchdog",
            daemon=True,
        )
        _watchdog.start()


def stop_embedded_worker() -> None:
    if _stop is not None:
        _stop.set()
