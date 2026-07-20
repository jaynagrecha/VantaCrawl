"""In-process Redis job consumer for free-tier hosts without Background Workers."""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from ..config import get_settings
from .queue import claim_due_scheduled_jobs, redis_client

log = logging.getLogger("vantacrawl.worker")

_ROOT = Path(__file__).resolve().parents[4]
_WORKER_DIR = _ROOT / "web" / "worker"
_stop: Optional[threading.Event] = None
_thread: Optional[threading.Thread] = None


def _ensure_paths() -> None:
    for path in (str(_ROOT), str(_WORKER_DIR)):
        if path not in sys.path:
            sys.path.insert(0, path)


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
    while not stop.is_set():
        try:
            due = claim_due_scheduled_jobs()
            for job_id in due:
                log.info("Promoted scheduled job %s", job_id)
                from vantacrawl_api.database import engine
                from vantacrawl_api.models import ScanJob
                from sqlmodel import Session
                from datetime import datetime

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
        except Exception:
            log.exception("Unhandled job failure %s", job_id)


def start_embedded_worker() -> None:
    global _stop, _thread
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


def stop_embedded_worker() -> None:
    if _stop is not None:
        _stop.set()
