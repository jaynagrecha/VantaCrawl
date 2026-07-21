"""Report path discovery / heal helpers."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "web" / "api"))


def test_find_report_file_prefers_assessment(tmp_path, monkeypatch):
    reports = tmp_path / "reports" / "job1"
    reports.mkdir(parents=True)
    (reports / "x_SEARCH_REPORT.html").write_text("<search/>", encoding="utf-8")
    (reports / "x_ASSESSMENT_REPORT.html").write_text("<assess/>", encoding="utf-8")

    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    from vantacrawl_api import config as cfg
    from vantacrawl_api.services.report_paths import find_report_file, job_report_roots

    cfg.get_settings.cache_clear()

    job = SimpleNamespace(
        id="job1",
        report_dir=str(reports),
        report_html_path="",
        report_txt_path="",
    )
    found = find_report_file(job, ("*_ASSESSMENT_REPORT.html", "*_SEARCH_REPORT.html"))
    assert found is not None
    assert found.name.endswith("_ASSESSMENT_REPORT.html")
    roots = job_report_roots(job)
    assert any(r == reports for r in roots)


def test_find_report_file_heals_basename_under_root(tmp_path, monkeypatch):
    reports = tmp_path / "reports" / "job2"
    reports.mkdir(parents=True)
    target = reports / "WU__host_ASSESSMENT_REPORT.html"
    target.write_text("<ok/>", encoding="utf-8")

    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    from vantacrawl_api import config as cfg
    from vantacrawl_api.services.report_paths import find_report_file

    cfg.get_settings.cache_clear()

    job = SimpleNamespace(
        id="job2",
        report_dir=str(reports),
        report_html_path="/old/missing/WU__host_ASSESSMENT_REPORT.html",
        report_txt_path="",
    )
    found = find_report_file(
        job,
        ("*_ASSESSMENT_REPORT.html",),
        preferred=job.report_html_path,
    )
    assert found == target
