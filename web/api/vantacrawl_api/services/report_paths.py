"""Resolve scan report files on disk (handles path drift + legacy locations)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Tuple


def _settings():
    from ..config import get_settings

    return get_settings()


def job_report_roots(job: Any) -> List[Path]:
    """Candidate directories where report artifacts may live for a job."""
    settings = _settings()
    roots: List[Path] = []
    seen = set()

    def add(path: Optional[Path]) -> None:
        if path is None:
            return
        try:
            key = str(path)
        except Exception:
            return
        if key in seen:
            return
        seen.add(key)
        roots.append(path)

    report_dir = getattr(job, "report_dir", "") or ""
    job_id = getattr(job, "id", "") or ""
    if report_dir:
        add(Path(report_dir))
    if job_id:
        add(Path(settings.reports_dir) / job_id)
        add(Path(settings.jobs_dir) / job_id)
        add(Path(settings.jobs_dir) / job_id / "reports")
    # Desktop / misconfigured cloud fallback (default CrawlConfig.report_dir)
    add(Path(settings.data_dir).parent / "Reports")
    add(Path(settings.data_dir) / "Reports")
    try:
        from crawl_config import BASE_DIR

        add(Path(BASE_DIR) / "Reports")
    except Exception:
        pass
    return roots


def find_report_file(
    job: Any,
    patterns: Sequence[str],
    *,
    preferred: str = "",
) -> Optional[Path]:
    """Return the newest matching report file, or None."""
    if preferred:
        preferred_path = Path(preferred)
        if preferred_path.is_file():
            return preferred_path
        name = preferred_path.name
        if name:
            for root in job_report_roots(job):
                if not root.is_dir():
                    continue
                direct = root / name
                if direct.is_file():
                    return direct
                matches = sorted(root.rglob(name))
                if matches:
                    return matches[-1]

    found: List[Path] = []
    for root in job_report_roots(job):
        if not root.is_dir():
            continue
        for pattern in patterns:
            found.extend(root.glob(pattern))
            found.extend(root.rglob(pattern))
    if not found:
        return None

    def sort_key(path: Path) -> Tuple[int, float]:
        name = path.name.upper()
        rank = (
            0
            if "ASSESSMENT_REPORT" in name
            else (1 if "SEARCH_REPORT" in name else (2 if "SUMMARY_REPORT" in name else 3))
        )
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        return (rank, -mtime)

    found_unique = sorted({p.resolve() for p in found if p.is_file()}, key=sort_key)
    return found_unique[0] if found_unique else None


def heal_job_report_paths(session, job: Any) -> Any:
    """If DB paths are stale but files exist on disk, rewrite absolute paths onto the job row."""
    html = find_report_file(
        job,
        ("*_ASSESSMENT_REPORT.html", "*_SEARCH_REPORT.html", "*_SUMMARY_REPORT.html"),
        preferred=getattr(job, "report_html_path", "") or "",
    )
    txt = find_report_file(
        job,
        ("*_ASSESSMENT_REPORT.txt", "*_SEARCH_REPORT.txt", "*_SUMMARY_REPORT.txt"),
        preferred=getattr(job, "report_txt_path", "") or "",
    )
    changed = False
    if html and str(html) != (getattr(job, "report_html_path", "") or ""):
        job.report_html_path = str(html)
        if not getattr(job, "report_dir", ""):
            job.report_dir = str(html.parent)
        changed = True
    if txt and str(txt) != (getattr(job, "report_txt_path", "") or ""):
        job.report_txt_path = str(txt)
        changed = True
    if changed:
        session.add(job)
        session.commit()
        session.refresh(job)
    return job


def list_pattern_matches(roots: Iterable[Path], patterns: Sequence[str]) -> List[Path]:
    out: List[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for pattern in patterns:
            out.extend(p for p in root.glob(pattern) if p.is_file())
    return out
