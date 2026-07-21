"""Redis job consumer — concurrent scans for multi-user SaaS.

Runs in-process on free-tier hosts (EMBED_WORKER=true) or as a standalone
Background Worker process (web/worker/worker.py). Both share the same queue.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set

from ..config import get_settings
from .queue import claim_due_scheduled_jobs, enqueue_job, redis_client
from .worker_slots import can_start_job

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


def _decode_job_id(raw) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def lookup_job_user_id(job_id: str) -> str:
    """Return owning user_id for a job, or empty string if unknown."""
    try:
        from sqlmodel import Session

        from vantacrawl_api.database import engine
        from vantacrawl_api.models import ScanJob

        with Session(engine) as session:
            job = session.get(ScanJob, job_id)
            if job and job.user_id:
                return str(job.user_id)
    except Exception as exc:
        log.debug("lookup_job_user_id(%s) failed: %s", job_id, exc)
    return ""


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


def _promote_scheduled_jobs() -> None:
    try:
        due = claim_due_scheduled_jobs()
        if not due:
            return
        from sqlmodel import Session

        from vantacrawl_api.database import engine
        from vantacrawl_api.models import ScanJob

        for job_id in due:
            log.info("Promoted scheduled job %s", job_id)
            with Session(engine) as session:
                job = session.get(ScanJob, job_id)
                if job and job.status == "scheduled":
                    job.status = "queued"
                    job.updated_at = datetime.utcnow()
                    session.add(job)
                    session.commit()
    except Exception as exc:
        log.error("Delayed queue error: %s", exc)


def _run_job_sync(job_id: str) -> None:
    from runner import run_job  # noqa: WPS433

    try:
        asyncio.run(run_job(job_id))
    except asyncio.CancelledError:
        # Stop/cancel must not kill the consumer (CancelledError is BaseException)
        log.info("Job %s cancelled — worker stays online", job_id)
    except Exception:
        log.exception("Unhandled job failure %s", job_id)


def worker_loop(stop: threading.Event) -> None:
    _ensure_paths()
    settings = get_settings()
    client = redis_client()
    max_concurrent = max(1, int(getattr(settings, "max_concurrent_scans", 3) or 3))
    max_per_user = max(1, int(getattr(settings, "max_concurrent_scans_per_user", 1) or 1))

    log.info(
        "Worker online · queue=%s · max_concurrent=%s · max_per_user=%s · redis=%s",
        settings.job_queue_key,
        max_concurrent,
        max_per_user,
        settings.redis_url,
    )
    _reclaim_stuck_queued_jobs()

    active_lock = threading.Lock()
    active_jobs: Set[str] = set()
    active_by_user: Dict[str, int] = {}

    def _release(job_id: str, user_id: str, fut: Future) -> None:
        with active_lock:
            active_jobs.discard(job_id)
            if user_id:
                left = active_by_user.get(user_id, 1) - 1
                if left <= 0:
                    active_by_user.pop(user_id, None)
                else:
                    active_by_user[user_id] = left
        try:
            fut.result()
        except Exception:
            log.exception("Job future error %s", job_id)

    with ThreadPoolExecutor(max_workers=max_concurrent, thread_name_prefix="vc-scan") as pool:
        while not stop.is_set():
            _promote_scheduled_jobs()

            with active_lock:
                slots_free = max_concurrent - len(active_jobs)
            if slots_free <= 0:
                # Keep jobs in Redis until a slot frees — do not BRPOP into memory backlog.
                time.sleep(0.4)
                continue

            try:
                item = client.brpop(settings.job_queue_key, timeout=2)
            except Exception as exc:
                log.error("Redis error: %s", exc)
                time.sleep(2)
                continue
            if not item:
                continue

            _, raw_id = item
            job_id = _decode_job_id(raw_id)
            user_id = lookup_job_user_id(job_id)

            with active_lock:
                ok, reason = can_start_job(
                    user_id,
                    active_job_count=len(active_jobs),
                    active_by_user=active_by_user,
                    max_concurrent=max_concurrent,
                    max_per_user=max_per_user,
                )
                if not ok:
                    # Put back for later; other users' jobs behind it can still run after sleep.
                    client.lpush(settings.job_queue_key, job_id)
                    defer = True
                else:
                    active_jobs.add(job_id)
                    if user_id:
                        active_by_user[user_id] = active_by_user.get(user_id, 0) + 1
                    defer = False

            if defer:
                log.info(
                    "Deferred job %s (%s) — active=%s users=%s",
                    job_id,
                    reason,
                    len(active_jobs),
                    dict(active_by_user),
                )
                time.sleep(1.0)
                continue

            log.info(
                "Picked job %s · user=%s · active=%s/%s",
                job_id,
                user_id or "?",
                len(active_jobs),
                max_concurrent,
            )
            fut = pool.submit(_run_job_sync, job_id)
            fut.add_done_callback(lambda f, j=job_id, u=user_id: _release(j, u, f))

    log.info("Worker loop stopped")


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
