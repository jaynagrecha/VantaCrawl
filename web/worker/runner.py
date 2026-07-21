"""Run a VantaCrawl scan job against the existing crawl orchestrator."""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    enqueue_job,
    get_job_command,
    publish_progress,
)

from browser_fetch import apply_selenium_login, make_browser_fetcher, quit_selenium_driver  # noqa: E402
from crawl_config import CrawlConfig  # noqa: E402
from crawl_orchestrator import PauseController, run_full_crawl_async  # noqa: E402
from crawl_stats import CrawlStats  # noqa: E402
from crawler_common import DownloadManager  # noqa: E402

log = logging.getLogger("vantacrawl.worker")


def _absolute_report_paths(report_dir: Path, job_id: str = "") -> tuple[str, str]:
    """Pick newest assessment/search reports; copy into report_dir when found elsewhere."""
    report_dir = Path(report_dir).resolve()
    roots = [report_dir]
    try:
        from crawl_config import BASE_DIR

        roots.append(Path(BASE_DIR) / "Reports")
    except Exception:
        pass
    settings = get_settings()
    if job_id:
        roots.append(Path(settings.jobs_dir) / job_id)
        roots.append(Path(settings.reports_dir) / job_id)

    def _newest(patterns: tuple[str, ...]) -> Optional[Path]:
        found: list[Path] = []
        for root in roots:
            if not root.is_dir():
                continue
            for pattern in patterns:
                found.extend(p for p in root.glob(pattern) if p.is_file())
                found.extend(p for p in root.rglob(pattern) if p.is_file())
        if not found:
            return None
        uniq = {p.resolve() for p in found}
        return sorted(uniq, key=lambda p: p.stat().st_mtime)[-1]

    html = _newest(("*_ASSESSMENT_REPORT.html",)) or _newest(("*_SEARCH_REPORT.html",))
    txt = _newest(("*_ASSESSMENT_REPORT.txt",)) or _newest(("*_SEARCH_REPORT.txt",))

    if html is not None and html.parent.resolve() != report_dir:
        report_dir.mkdir(parents=True, exist_ok=True)
        dest = report_dir / html.name
        try:
            if not dest.is_file() or dest.stat().st_mtime < html.stat().st_mtime:
                dest.write_bytes(html.read_bytes())
            html = dest
        except Exception:
            log.exception("Failed to copy HTML report into %s", report_dir)
    if txt is not None and txt.parent.resolve() != report_dir:
        report_dir.mkdir(parents=True, exist_ok=True)
        dest = report_dir / txt.name
        try:
            if not dest.is_file() or dest.stat().st_mtime < txt.stat().st_mtime:
                dest.write_bytes(txt.read_bytes())
            txt = dest
        except Exception:
            log.exception("Failed to copy TXT report into %s", report_dir)

    return (str(html.resolve()) if html else "", str(txt.resolve()) if txt else "")


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


def _get_job(job_id: str) -> Optional[ScanJob]:
    with Session(engine) as session:
        return session.get(ScanJob, job_id)


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
    overlay.pop("target_urls", None)
    overlay.pop("pending_live_settings", None)

    wordlist = overlay.pop("wordlist_file", None)
    wordlist_id = overlay.pop("wordlist_id", None)
    extras = overlay.pop("extra_wordlists", None)
    postman = overlay.pop("api_postman_file", None)
    har = overlay.pop("api_har_file", None)
    api_wl = overlay.pop("api_recon_wordlist", None)

    from vantacrawl_api.scan_settings import ensure_wordlist_path

    resolved_wordlist = ensure_wordlist_path(
        {"wordlist_file": wordlist, "wordlist_id": wordlist_id}
    )

    cfg = CrawlConfig(
        start_url=job.start_url,
        output_file_path=str(job_dir / "found_urls.txt"),
        download_dir=str(job_dir / "downloads"),
        checkpoint_file=str(job_dir / "crawl_checkpoint.json"),
        enum_checkpoint_file=str(job_dir / "enum_checkpoint.json"),
        false_positive_file=str(job_dir / "false_positives.json"),
        wordlist_file=resolved_wordlist,
    )
    if isinstance(extras, list) and extras:
        cfg.extra_wordlists = [str(p) for p in extras if p]
    if postman:
        cfg.api_postman_file = str(postman)
    if har:
        cfg.api_har_file = str(har)
    if api_wl:
        cfg.api_recon_wordlist = str(api_wl)

    for key, value in overlay.items():
        if hasattr(cfg, key) and key not in {
            "start_url",
            "output_file_path",
            "download_dir",
            "checkpoint_file",
            "enum_checkpoint_file",
            "false_positive_file",
            "wordlist_file",
            "wordlist_id",
            "api_postman_file",
            "api_har_file",
            "api_recon_wordlist",
        }:
            try:
                setattr(cfg, key, value)
            except Exception:
                pass

    ext = getattr(cfg, "extensions", None)
    if isinstance(ext, str):
        parts = [p.strip() for p in ext.split(",") if p.strip()]
        cfg.extensions = parts or None

    cfg.report_dir = lambda: str(Path(report_dir).resolve())  # type: ignore[method-assign]
    cfg.report_title = (job.title or "").strip()
    return cfg


def cfg_default_wordlist() -> str:
    from crawl_config import DEFAULT_DIR_WORDLIST

    return DEFAULT_DIR_WORDLIST


def _target_urls(job: ScanJob) -> List[str]:
    raw = (job.config_json or {}).get("target_urls")
    urls: List[str] = []
    if isinstance(raw, list):
        urls = [str(u).strip() for u in raw if str(u).strip()]
    if not urls:
        urls = [job.start_url]
    return urls


def _schedule_followup(job: ScanJob) -> None:
    hours = float((job.config_json or {}).get("schedule_interval_hours") or 0)
    if hours <= 0:
        return
    run_at = datetime.utcnow() + timedelta(hours=hours)
    clone = ScanJob(
        user_id=job.user_id,
        title=f"{job.title} (scheduled)",
        start_url=job.start_url,
        mode=job.mode,
        speed=job.speed,
        status="scheduled",
        authorized_confirmed=True,
        config_json=dict(job.config_json or {}),
        progress_json={"phase": "scheduled", "run_at": run_at.isoformat() + "Z", "message": f"Next run at {run_at.isoformat()}Z"},
        report_dir=str(Path(get_settings().reports_dir) / "pending"),
    )
    with Session(engine) as session:
        session.add(clone)
        session.commit()
        session.refresh(clone)
        settings = get_settings()
        job_dir = Path(settings.jobs_dir) / clone.id
        report_dir = Path(settings.reports_dir) / clone.id
        job_dir.mkdir(parents=True, exist_ok=True)
        report_dir.mkdir(parents=True, exist_ok=True)
        clone.report_dir = str(report_dir)
        session.add(clone)
        session.commit()
        clone_id = clone.id
    # Store delayed enqueue marker
    from vantacrawl_api.services.queue import schedule_job

    schedule_job(clone_id, run_at.timestamp())
    log.info("Scheduled follow-up job %s at %s", clone_id, run_at.isoformat())


async def run_job(job_id: str) -> None:
    job = _get_job(job_id)
    if not job:
        log.error("Job missing: %s", job_id)
        return

    # Honour stop/cancel before any work (fixes queued stop + pause races)
    if job.status in ("completed", "cancelled", "failed"):
        clear_job_command(job_id)
        return
    if job.status == "stopping" or get_job_command(job_id) == "stop":
        clear_job_command(job_id)
        _update_job(job_id, status="cancelled", finished_at=datetime.utcnow(), error_message="")
        publish_progress(job_id, {"status": "cancelled", "message": "Cancelled before start"})
        return
    if job.status == "paused" and not job.started_at:
        # Paused while still queued — wait until resume re-enqueues
        clear_job_command(job_id)
        publish_progress(job_id, {"status": "paused", "message": "Paused before start"})
        return

    clear_job_command(job_id)
    _update_job(
        job_id,
        status="running",
        started_at=job.started_at or datetime.utcnow(),
        error_message="",
        progress_json={"phase": "starting", "message": "Worker picked up job"},
    )
    publish_progress(job_id, {"status": "running", "message": "Scan starting", "started_at": datetime.utcnow().isoformat() + "Z"})

    stop_flag = {"stop": False}
    pause = PauseController(lambda: not stop_flag["stop"])
    manager = DownloadManager()
    live_config_holder: Dict[str, CrawlConfig] = {}
    live_progress_state: Dict[str, Any] = {
        "phase": "starting",
        "progress_pct": 0,
        "pages_crawled": 0,
        "enum_hits": 0,
        "findings": 0,
    }
    last_progress_persist = {"t": 0.0}
    enum_only_hint = {"value": False}

    def _status_now() -> str:
        return "paused" if pause.paused else ("stopping" if stop_flag["stop"] else "running")

    def _publish_live(payload: Dict[str, Any], *, force_db: bool = False, message: str = "") -> None:
        from vantacrawl_api.services.live_progress import build_live_progress

        stats_obj = stats_holder.get("stats")
        payload = dict(payload)
        # Keep Progress: elapsed fresh even when the crawler stalls on WAF/security
        # and stops emitting new friendly stats lines.
        text = str(payload.get("progress_text") or live_progress_state.get("progress_text") or "")
        if stats_obj is not None and hasattr(stats_obj, "format_friendly_line"):
            if text.startswith("Progress:"):
                payload["progress_text"] = stats_obj.format_friendly_line()

        # Prefer in-memory merge; stats object is closed over below after creation
        merged = build_live_progress(
            stats_obj,
            progress_text=str(payload.get("progress_text") or ""),
            total=int(payload.get("bytes_total") or 0),
            done=int(payload.get("bytes_done") or 0),
            phase=payload.get("phase"),
            enum_only=enum_only_hint["value"],
            previous=live_progress_state,
        )
        live_progress_state.clear()
        live_progress_state.update(merged)
        now = time.time()
        if force_db or (now - last_progress_persist["t"]) >= 0.75:
            last_progress_persist["t"] = now
            _update_job(job_id, progress_json=dict(live_progress_state))
        publish_progress(
            job_id,
            {
                "status": _status_now(),
                "progress": dict(live_progress_state),
                "message": message or str(live_progress_state.get("progress_text") or ""),
            },
        )

    stats_holder: Dict[str, Any] = {"stats": CrawlStats()}

    def output_callback(message: str):
        text = str(message)
        _append_log(job_id, text)
        low = text.lower()
        phase = None
        if (
            "starting advanced folder" in low
            or "directory scan" in low
            or "brute force" in low
            or "preparing directory enum" in low
            or "building enum wordlist" in low
            or "pro enum:" in low
        ):
            phase = "enum"
            live_progress_state["progress_pct"] = 0
        elif "crawling:" in low or "page crawl" in low:
            phase = "crawl"
        elif any(
            k in low
            for k in (
                "api recon",
                "api passive",
                "api docs",
                "api active",
                "api import",
                "graphql introspection",
            )
        ):
            phase = "api_recon"
        elif "security" in low or "vuln" in low or "finding" in low:
            phase = "security"
        elif any(
            k in low
            for k in (
                "wayback",
                "common crawl",
                "historical",
                "request stealth",
                "protections spotted",
                "looking up old urls",
                "checking what protections",
                "subdomain enum",
                "enumerating subdomains",
                "searching for related subdomains",
            )
        ):
            phase = "recon"
        live_progress_state["progress_text"] = text[:240]
        if phase:
            live_progress_state["phase"] = phase
        if "cf-challenge" in low or "slowing down for a moment" in low:
            live_progress_state["challenge_events"] = int(live_progress_state.get("challenge_events") or 0) + 1
        if "protections spotted so far:" in low:
            names = text.split(":", 1)[-1].strip()
            if names:
                live_progress_state["protections"] = [n.strip() for n in names.split(",") if n.strip()]
        # Always refresh cockpit on log lines so tiles leave "Starting" during recon
        _publish_live(live_progress_state)
        publish_progress(job_id, {"status": _status_now(), "log": text})

    def update_progress(total_or_payload=0, downloaded_size=0, size_text=""):
        """Match desktop callback: (total, done, text). Also accept a single progress dict."""
        if isinstance(total_or_payload, dict):
            live_progress_state.update(total_or_payload)
            _publish_live(live_progress_state, force_db=True)
            return
        try:
            total_size = int(total_or_payload or 0)
            done = int(downloaded_size or 0)
        except (TypeError, ValueError):
            total_size, done = 0, 0
        _publish_live(
            {
                "bytes_total": total_size,
                "bytes_done": done,
                "progress_text": str(size_text or "")[:240],
            },
            message=str(size_text or "")[:240],
        )

    def apply_pending_live_settings():
        cfg = live_config_holder.get("cfg")
        if cfg is None:
            return
        fresh_job = _get_job(job_id)
        if not fresh_job:
            return
        pending = dict((fresh_job.config_json or {}).get("pending_live_settings") or {})
        if not pending:
            # Also allow full config_json overlay (minus frozen keys)
            pending = {k: v for k, v in (fresh_job.config_json or {}).items() if k not in ("mode", "speed", "target_urls", "pending_live_settings")}
            # Only apply if marked dirty
            if not (fresh_job.config_json or {}).get("_live_dirty"):
                return
        try:
            fresh = _build_crawl_config(fresh_job)
            changed = cfg.apply_live_settings(fresh)
            overlay = dict(fresh_job.config_json or {})
            overlay.pop("pending_live_settings", None)
            overlay["_live_dirty"] = False
            _update_job(job_id, config_json=overlay)
            if changed:
                preview = ", ".join(changed[:12])
                extra = f" (+{len(changed) - 12} more)" if len(changed) > 12 else ""
                output_callback(f"Resumed with updated settings: {preview}{extra}")
            else:
                output_callback("Resumed.")
        except Exception:
            log.exception("Live settings apply failed for %s", job_id)

    pause.on_resume(apply_pending_live_settings)

    async def command_watcher():
        while not stop_flag["stop"]:
            cmd = get_job_command(job_id)
            if cmd == "pause":
                pause.pause()
                _update_job(job_id, status="paused")
                publish_progress(job_id, {"status": "paused", "message": "Paused — edit settings then Resume"})
                clear_job_command(job_id)
            elif cmd == "resume":
                pause.resume()
                _update_job(job_id, status="running")
                publish_progress(job_id, {"status": "running", "message": "Resume requested"})
                clear_job_command(job_id)
            elif cmd == "stop":
                stop_flag["stop"] = True
                pause.resume()
                try:
                    manager.cancel_all()
                except Exception:
                    pass
                _update_job(job_id, status="stopping")
                publish_progress(job_id, {"status": "stopping", "message": "Stopping"})
                clear_job_command(job_id)
                break
            await asyncio.sleep(0.35)

    job = _get_job(job_id)
    assert job is not None
    report_dir = Path(job.report_dir)
    targets = _target_urls(job)
    stats = stats_holder["stats"]
    watcher = asyncio.create_task(command_watcher())

    async def stats_ticker():
        while not stop_flag["stop"]:
            try:
                st = stats_holder.get("stats")
                # Once the scan has real work (or a Progress: line exists), keep the
                # cockpit Progress: clock alive during WAF stalls / findings spam.
                if st is not None and hasattr(st, "format_friendly_line"):
                    prev = str(live_progress_state.get("progress_text") or "")
                    has_work = bool(
                        getattr(st, "pages_crawled", 0)
                        or getattr(st, "enum_words_tested", 0)
                        or getattr(st, "api_recon_probes_done", 0)
                        or getattr(st, "api_recon_probes_total", 0)
                        or getattr(st, "subdomain_probes_done", 0)
                        or getattr(st, "subdomain_probes_total", 0)
                        or len(getattr(st, "findings", []) or [])
                    )
                    if prev.startswith("Progress:") or has_work:
                        live_progress_state["progress_text"] = st.format_friendly_line()
                _publish_live(dict(live_progress_state))
            except Exception:
                log.exception("stats_ticker failed for %s", job_id)
            await asyncio.sleep(1.5)

    ticker = asyncio.create_task(stats_ticker())
    live_progress_state["phase"] = "recon"
    live_progress_state["progress_text"] = "Worker started — preparing scan…"
    live_progress_state["health"] = "Waiting"
    _publish_live(live_progress_state, force_db=True, message="Worker started")
    use_browser = False
    try:
        for index, url in enumerate(targets):
            if stop_flag["stop"]:
                break
            job = _get_job(job_id)
            assert job is not None
            # Refresh start_url for this target
            cfg_overlay = dict(job.config_json or {})
            cfg_overlay.pop("pending_live_settings", None)
            job.config_json = cfg_overlay
            config = _build_crawl_config(job)
            config.start_url = url
            enum_on = bool(
                getattr(config, "enum_only", False) or getattr(config, "directory_enum", False)
            )
            if (
                enum_on
                and bool(getattr(config, "use_wordlist", True))
                and not Path(config.wordlist_file).is_file()
            ):
                raise FileNotFoundError(
                    f"Directory wordlist not found: {config.wordlist_file}. "
                    "Choose a catalog wordlist again or re-upload (ephemeral upload copies are not used for catalog lists)."
                )
            live_config_holder["cfg"] = config
            enum_only_hint["value"] = bool(getattr(config, "enum_only", False))
            live_progress_state["phase"] = "enum" if enum_only_hint["value"] else "crawl"
            _publish_live(live_progress_state, force_db=True)

            output_callback(f"\n=== Target {index + 1}/{len(targets)}: {url} ===\n")
            if config.use_selenium_login:
                config = apply_selenium_login(config, output=output_callback)

            use_browser = bool(
                config.selenium_fallback
                or config.deep_mirror
                or config.screenshot_capture
                or getattr(config, "browser_primary", False)
                or getattr(config, "browser_on_challenge", False)
            )
            fetcher = None
            if use_browser:
                try:
                    fetcher = make_browser_fetcher(config)
                    output_callback(
                        "Real Chrome fetch path ready — "
                        + (
                            "primary HTML navigations"
                            if getattr(config, "browser_primary", False) or config.deep_mirror
                            else "challenge escalation"
                        )
                        + (
                            "; auto cookie sync on"
                            if getattr(config, "auto_sync_cookies", True)
                            else ""
                        )
                        + "."
                    )
                except Exception as exc:
                    output_callback(f"Chrome fetch path unavailable ({exc}); continuing with HTTP stealth only.")
                    fetcher = None
                    use_browser = False

            crawl_task = asyncio.create_task(
                run_full_crawl_async(
                    config,
                    output_callback,
                    lambda: not stop_flag["stop"],
                    manager=manager,
                    update_progress=update_progress,
                    page_html_fetcher=fetcher,
                    stats=stats,
                    pause_controller=pause,
                )
            )
            stop_requested_at: float | None = None
            stop_grace_s = 3.5
            while not crawl_task.done():
                # API force-cancel may mark cancelled while we are still winding down
                latest_cmd = _get_job(job_id)
                if latest_cmd and latest_cmd.status == "cancelled":
                    stop_flag["stop"] = True
                if stop_flag["stop"]:
                    if stop_requested_at is None:
                        stop_requested_at = time.time()
                        try:
                            manager.cancel_all()
                        except Exception:
                            pass
                        crawl_task.cancel()
                        output_callback("Stop requested — cancelling in-flight work…")
                    elif time.time() - stop_requested_at > stop_grace_s:
                        crawl_task.cancel()
                        output_callback(
                            "Stop grace ended — abandoning hung HTTP (WAF/timeouts). Finishing job."
                        )
                        break
                done, _pending = await asyncio.wait({crawl_task}, timeout=0.25)
                if done:
                    break

            if crawl_task.done():
                try:
                    await crawl_task
                except asyncio.CancelledError:
                    output_callback("Scan stop confirmed.")
                except Exception:
                    if stop_flag["stop"]:
                        output_callback("Scan stop confirmed.")
                    else:
                        raise
            else:
                # Critical: never await a cancelled task forever — httpx may ignore
                # CancelledError until the socket times out (looks like Stop hang).
                crawl_task.cancel()
                try:
                    await asyncio.wait({crawl_task}, timeout=1.0)
                except Exception:
                    pass
                if not crawl_task.done():

                    async def _drain_abandoned(task: asyncio.Task) -> None:
                        try:
                            await task
                        except Exception:
                            pass

                    asyncio.create_task(_drain_abandoned(crawl_task))
                    output_callback("Scan stop confirmed (abandoned hung requests).")
                else:
                    try:
                        await crawl_task
                    except (asyncio.CancelledError, Exception):
                        pass
                    output_callback("Scan stop confirmed.")
                break  # do not start next target after stop

        assessment_matches = (
            sorted(report_dir.glob("*_ASSESSMENT_REPORT.html")) if report_dir.is_dir() else []
        )
        html_matches = assessment_matches or (
            sorted(report_dir.glob("*_SEARCH_REPORT.html")) if report_dir.is_dir() else []
        )
        # Stop/cancel often skips orchestrator write_all — build full reports from in-memory stats.
        if not html_matches:
            cfg = live_config_holder.get("cfg")
            job_snap = _get_job(job_id)
            try:
                from reporting import write_stats_reports

                written = write_stats_reports(
                    stats,
                    report_dir=str(Path(report_dir).resolve()),
                    start_url=(getattr(cfg, "start_url", None) if cfg else None)
                    or (job_snap.start_url if job_snap else "")
                    or "",
                    title=(getattr(cfg, "report_title", None) if cfg else None)
                    or (job_snap.title if job_snap else "")
                    or "",
                    config=cfg,
                    output_callback=output_callback,
                )
                if written:
                    output_callback("Wrote full reports from results collected so far.")
            except Exception:
                log.exception("Failed to write partial full reports for %s", job_id)

        html_path, txt_path = _absolute_report_paths(Path(report_dir), job_id=job_id)

        # Honour force-cancel from API while we were winding down
        latest = _get_job(job_id)
        if latest and latest.status == "cancelled":
            status = "cancelled"
        else:
            status = "cancelled" if stop_flag["stop"] else "completed"
        findings_preview = []
        try:
            from security_scan import mask_secret_value

            for f in list(getattr(stats, "findings", []) or [])[:40]:
                if isinstance(f, dict):
                    evidence = str(f.get("evidence") or "")
                    findings_preview.append(
                        {
                            "severity": str(f.get("severity") or f.get("severity_label") or ""),
                            "title": str(f.get("title") or f.get("detail") or f.get("type") or "")[:160],
                            "url": str(f.get("url") or ""),
                            "category": str(f.get("category") or ""),
                            "evidence_masked": mask_secret_value(evidence) if evidence else "",
                            "evidence_full": evidence,
                        }
                    )
        except Exception:
            findings_preview = []

        progress = {
            **dict(live_progress_state),
            "phase": status,
            "progress_pct": 100 if status == "completed" else int(live_progress_state.get("progress_pct") or 0),
            "progress_text": "Scan finished" if status == "completed" else "Scan ended",
            "pages_crawled": stats.pages_crawled,
            "findings": len(stats.findings),
            "enum_hits": stats.enum_hits,
            "enum_words_tested": getattr(stats, "enum_words_tested", 0),
            "enum_words_total": getattr(stats, "enum_words_total", 0),
            "queue_size": getattr(stats, "queue_size", 0),
            "enum_hit_urls": list(getattr(stats, "enum_hit_urls", []) or [])[:80],
            "findings_preview": findings_preview,
            "elapsed_seconds": stats.elapsed_seconds() if hasattr(stats, "elapsed_seconds") else None,
            "eta_seconds": 0,
        }
        finished_job = _get_job(job_id)
        if not html_path:
            from vantacrawl_api.services.summary_report import write_summary_report

            note = ""
            if status == "cancelled":
                note = (
                    "Scan was stopped before structured reports could be written. "
                    "This summary uses the live progress snapshot only."
                )
            summary_html, summary_txt = write_summary_report(
                Path(report_dir).resolve(),
                job_id=job_id,
                title=(finished_job.title if finished_job else "") or "Scan",
                start_url=(finished_job.start_url if finished_job else "") or "",
                status=status,
                progress=progress,
                log_tail=(finished_job.log_tail if finished_job else "") or "",
                note=note,
            )
            output_callback("Wrote summary report (full HTML report was not produced).")
            html_path, txt_path = _absolute_report_paths(Path(report_dir), job_id=job_id)
            if not html_path:
                html_path, txt_path = summary_html, summary_txt
        _update_job(
            job_id,
            status=status,
            finished_at=datetime.utcnow(),
            report_html_path=html_path,
            report_txt_path=txt_path,
            report_dir=str(Path(report_dir).resolve()),
            progress_json=progress,
        )
        publish_progress(job_id, {"status": status, "message": "Scan finished", "progress": progress})
        if status == "completed" and finished_job:
            try:
                _schedule_followup(finished_job)
            except Exception:
                log.exception("Failed to schedule follow-up for %s", job_id)
    except Exception as exc:
        log.exception("Job %s failed", job_id)
        failed_job = _get_job(job_id)
        html_path = ""
        txt_path = ""
        try:
            cfg = live_config_holder.get("cfg")
            rdir = Path(failed_job.report_dir) if failed_job and failed_job.report_dir else report_dir
            from reporting import write_stats_reports

            written = write_stats_reports(
                stats,
                report_dir=str(Path(rdir).resolve()),
                start_url=(getattr(cfg, "start_url", None) if cfg else None)
                or (failed_job.start_url if failed_job else "")
                or "",
                title=(getattr(cfg, "report_title", None) if cfg else None)
                or (failed_job.title if failed_job else "")
                or "",
                config=cfg,
                output_callback=output_callback,
            )
            html_path, txt_path = _absolute_report_paths(Path(rdir), job_id=job_id)
            if written and html_path:
                output_callback("Wrote full reports from results collected before failure.")
        except Exception:
            log.exception("Failed to write partial full reports for failed job %s", job_id)
        if not html_path:
            try:
                from vantacrawl_api.services.summary_report import write_summary_report

                rdir = Path(failed_job.report_dir) if failed_job and failed_job.report_dir else report_dir
                html_path, txt_path = write_summary_report(
                    Path(rdir).resolve(),
                    job_id=job_id,
                    title=(failed_job.title if failed_job else "") or "Scan",
                    start_url=(failed_job.start_url if failed_job else "") or "",
                    status="failed",
                    progress=(failed_job.progress_json if failed_job else {}) or {},
                    log_tail=(failed_job.log_tail if failed_job else "") or "",
                    note=f"Scan failed: {exc}",
                )
                linked = _absolute_report_paths(Path(rdir), job_id=job_id)
                if linked[0]:
                    html_path, txt_path = linked
            except Exception:
                log.exception("Failed to write summary report for %s", job_id)
        _update_job(
            job_id,
            status="failed",
            finished_at=datetime.utcnow(),
            error_message=str(exc)[:2000],
            report_html_path=html_path,
            report_txt_path=txt_path,
            report_dir=str(Path(failed_job.report_dir if failed_job and failed_job.report_dir else report_dir).resolve()),
        )
        publish_progress(job_id, {"status": "failed", "message": str(exc)})
    finally:
        stop_flag["stop"] = True
        if use_browser:
            try:
                quit_selenium_driver()
            except Exception:
                pass
        for task in (watcher, ticker):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
