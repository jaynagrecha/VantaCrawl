"""Run a VantaCrawl scan job against the existing crawl orchestrator."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from sqlmodel import Session

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

WEB_API = Path(__file__).resolve().parents[1] / "api"
if str(WEB_API) not in sys.path:
    sys.path.insert(0, str(WEB_API))

from vantacrawl_api.config import get_settings  # noqa: E402
from vantacrawl_api.database import engine  # noqa: E402
from vantacrawl_api.models import ScanJob  # noqa: E402
from vantacrawl_api.services.queue import (  # noqa: E402
    clear_job_command,
    get_job_command,
    publish_progress,
)

from crawl_config import CrawlConfig  # noqa: E402
from crawl_orchestrator import PauseController, run_full_crawl_async  # noqa: E402
from crawl_stats import CrawlStats  # noqa: E402
from crawler_common import DownloadManager  # noqa: E402

log = logging.getLogger("vantacrawl.worker")


def _update_job(job_id: str, **fields: Any) -> None:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        if not job:
            return
        for key, value in fields.items():
            setattr(job, key, value)
        job.updated_at = datetime.utcnow()
        session.add(job)
        session.commit()


def _append_log(job_id: str, line: str, *, max_chars: int = 24000) -> str:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        if not job:
            return line
        tail = (job.log_tail or "") + line + "\n"
        if len(tail) > max_chars:
            tail = tail[-max_chars:]
        job.log_tail = tail
        job.updated_at = datetime.utcnow()
        session.add(job)
        session.commit()
        return tail


def _build_crawl_config(job: ScanJob) -> CrawlConfig:
    settings = get_settings()
    job_dir = Path(settings.jobs_dir) / job.id
    report_dir = Path(job.report_dir or (Path(settings.reports_dir) / job.id))
    job_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    overlay = dict(job.config_json or {})
    overlay.pop("mode", None)
    overlay.pop("speed", None)

    cfg = CrawlConfig(
        start_url=job.start_url,
        output_file_path=str(job_dir / "found_urls.txt"),
        download_dir=str(job_dir / "downloads"),
        checkpoint_file=str(job_dir / "crawl_checkpoint.json"),
        enum_checkpoint_file=str(job_dir / "enum_checkpoint.json"),
        false_positive_file=str(job_dir / "false_positives.json"),
    )
    # Point reports into per-job folder via monkeypatch of report_dir method if needed
    for key, value in overlay.items():
        if hasattr(cfg, key) and key not in {
            "start_url",
            "output_file_path",
            "download_dir",
            "checkpoint_file",
            "enum_checkpoint_file",
            "false_positive_file",
        }:
            try:
                setattr(cfg, key, value)
            except Exception:
                pass

    # Web UI sends extensions as a comma-separated string
    ext = getattr(cfg, "extensions", None)
    if isinstance(ext, str):
        parts = [p.strip() for p in ext.split(",") if p.strip()]
        cfg.extensions = parts or None

    # Override report_dir()
    cfg.report_dir = lambda: str(report_dir)  # type: ignore[method-assign]
    return cfg


async def run_job(job_id: str) -> None:
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        if not job:
            log.error("Job missing: %s", job_id)
            return
        if job.status in ("completed", "cancelled", "failed"):
            return
        start_url = job.start_url
        cfg_snapshot = dict(job.config_json or {})

    clear_job_command(job_id)
    _update_job(
        job_id,
        status="running",
        started_at=datetime.utcnow(),
        error_message="",
        progress_json={"phase": "starting", "message": "Worker picked up job"},
    )
    publish_progress(job_id, {"status": "running", "message": "Scan starting"})

    stop_flag = {"stop": False}
    pause = PauseController(lambda: not stop_flag["stop"])

    def output_callback(message: str):
        text = str(message)
        _append_log(job_id, text)
        publish_progress(job_id, {"status": pause.paused and "paused" or "running", "log": text})

    def update_progress(payload):
        if isinstance(payload, dict):
            _update_job(job_id, progress_json=payload)
            publish_progress(job_id, {"status": "running", "progress": payload})

    async def command_watcher():
        while not stop_flag["stop"]:
            cmd = get_job_command(job_id)
            if cmd == "pause":
                pause.pause()
                _update_job(job_id, status="paused")
                publish_progress(job_id, {"status": "paused", "message": "Paused"})
                clear_job_command(job_id)
            elif cmd == "resume":
                pause.resume()
                _update_job(job_id, status="running")
                publish_progress(job_id, {"status": "running", "message": "Resumed"})
                clear_job_command(job_id)
            elif cmd == "stop":
                stop_flag["stop"] = True
                pause.resume()
                _update_job(job_id, status="stopping")
                publish_progress(job_id, {"status": "stopping", "message": "Stopping"})
                clear_job_command(job_id)
                break
            await asyncio.sleep(0.4)

    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        assert job is not None
        config = _build_crawl_config(job)
        report_dir = Path(job.report_dir)

    stats = CrawlStats()
    watcher = asyncio.create_task(command_watcher())
    try:
        await run_full_crawl_async(
            config,
            output_callback,
            lambda: not stop_flag["stop"],
            manager=DownloadManager(),
            update_progress=update_progress,
            stats=stats,
            pause_controller=pause,
        )
        # Discover report paths
        html_matches = sorted(report_dir.glob("*_SEARCH_REPORT.html"))
        txt_matches = sorted(report_dir.glob("*_SEARCH_REPORT.txt"))
        status = "cancelled" if stop_flag["stop"] else "completed"
        _update_job(
            job_id,
            status=status,
            finished_at=datetime.utcnow(),
            report_html_path=str(html_matches[-1]) if html_matches else "",
            report_txt_path=str(txt_matches[-1]) if txt_matches else "",
            progress_json={
                "phase": status,
                "pages_crawled": stats.pages_crawled,
                "findings": len(stats.findings),
                "enum_hits": stats.enum_hits,
            },
        )
        publish_progress(
            job_id,
            {
                "status": status,
                "message": "Scan finished",
                "progress": {"pages_crawled": stats.pages_crawled, "findings": len(stats.findings)},
            },
        )
    except Exception as exc:
        log.exception("Job %s failed", job_id)
        _update_job(
            job_id,
            status="failed",
            finished_at=datetime.utcnow(),
            error_message=str(exc)[:2000],
        )
        publish_progress(job_id, {"status": "failed", "message": str(exc)})
    finally:
        stop_flag["stop"] = True
        watcher.cancel()
        try:
            await watcher
        except Exception:
            pass
