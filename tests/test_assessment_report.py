from crawl_stats import CrawlStats
from assessment_report import build_assessment_document
from assessment_html import render_assessment_html
from reporting import ReportWriter, build_report_base_name


def test_assessment_document_dual_audience(tmp_path):
    stats = CrawlStats()
    stats.pages_crawled = 12
    stats.enum_hits = 2
    stats.enum_hit_urls = ["https://lab.example/admin", "https://lab.example/.env"]
    stats.findings = [
        {
            "severity": "high",
            "category": "header_audit",
            "detail": "missing HSTS",
            "url": "https://lab.example/",
            "evidence": "strict-transport-security absent",
        },
        {
            "severity": "medium",
            "category": "sensitive_path",
            "detail": "exposed admin path",
            "url": "https://lab.example/admin",
        },
    ]
    doc = build_assessment_document(
        stats,
        "https://lab.example/",
        config_meta={"profile": "full", "mode": "full_audit", "title": "Lab"},
        mode="full_audit",
        job_title="Lab",
    )
    assert doc["risk_level"] in ("High", "Critical", "Medium")
    assert doc["findings"]
    assert "executive" in doc["findings"][0]
    assert "what" in doc["findings"][0]
    html = render_assessment_html(doc, technical_report_name="tech.html")
    assert "Executive summary" in html
    assert "For decision makers" in html
    assert "For security engineers" in html
    assert "Remediation roadmap" in html

    writer = ReportWriter(str(tmp_path), "https://lab.example/", title="RepoTrace")
    paths = writer.write_all(
        stats,
        {
            "search_conclusion_report": True,
            "html_report": True,
            "json_report": False,
            "csv_export": False,
            "sqlite_export": False,
            "assessment_report": True,
        },
        config_meta={"profile": "full", "mode": "full_audit", "security_scan": True, "title": "RepoTrace"},
    )
    assert paths.get("assessment_report_html")
    assert paths.get("search_report_html")
    assert "RepoTrace__lab.example_" in paths["assessment_report_html"].replace("\\", "/")
    text = open(paths["assessment_report_html"], encoding="utf-8").read()
    assert "Security Assessment Report" in text


def test_report_base_name_title_and_host():
    name = build_report_base_name("https://westernunion.com/app", "Repo Trace!", timestamp="20260720_153000")
    assert name == "Repo-Trace__westernunion.com_20260720_153000"
    host_only = build_report_base_name("https://westernunion.com/", "", timestamp="20260720_153000")
    assert host_only == "westernunion.com_20260720_153000"
