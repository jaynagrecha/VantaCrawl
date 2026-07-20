"""
Web Crawler and Directory Brute Forcer — single entry point.

Run the GUI (default):
    python app.py

Run headless from the terminal:
    python app.py --cli --url https://example.com --wordlist Wordlist/small.txt --download
"""

import argparse
import asyncio
import os
import sys
import webbrowser

from PyQt5.QtCore import QThread, QTimer, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gui_presets import MODE_LABELS, SPEED_ORDER, SPEED_PROFILES, apply_mode_preset, apply_speed_profile, match_speed_profile
from defense_verify import format_defense_for_ui
from user_output import (
    format_comparison_summary,
    format_duration_friendly,
    format_friendly_findings,
    format_friendly_hits,
    simplify_log_line,
)

from browser_fetch import apply_selenium_login, make_browser_fetcher, quit_selenium_driver
from crawl_config import CrawlConfig, DEFAULT_DIR_WORDLIST
from crawl_orchestrator import PauseController, run_full_crawl_async
from crawl_stats import CrawlStats
from crawler_common import DownloadManager, get_project_paths, is_html_url, normalize_extensions

BASE_DIR, OUTPUT_FILE, DOWNLOAD_DIR = get_project_paths()


class CrawlerThread(QThread):
    update_output = pyqtSignal(str)
    update_progress = pyqtSignal(int, int, str)
    update_stats = pyqtSignal(str)
    finished_crawling = pyqtSignal()

    def __init__(self, config: CrawlConfig, target_urls=None):
        super().__init__()
        self.config = config
        self.target_urls = target_urls or [config.start_url]
        self._is_running = True
        self.manager = DownloadManager()
        self.pause_controller = PauseController(self.is_running)
        self.stats = CrawlStats()
        self.report_paths = {}
        self.conclusion = {}

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        use_browser = self.config.selenium_fallback or self.config.deep_mirror or self.config.screenshot_capture
        try:
            open(self.config.output_file_path, "w", encoding="utf-8").close()
            for index, url in enumerate(self.target_urls):
                if not self.is_running():
                    break
                self.config.start_url = url
                self.append(f"\n=== Target {index + 1}/{len(self.target_urls)}: {url} ===\n")
                result = loop.run_until_complete(
                    run_full_crawl_async(
                        self.config,
                        self.append,
                        self.pause_controller,
                        self.manager,
                        self.update_progress.emit,
                        make_browser_fetcher(self.config) if use_browser else None,
                        self.stats,
                        self.pause_controller,
                    )
                )
                if isinstance(result, tuple) and len(result) >= 3:
                    _, self.report_paths, self.conclusion = result[0], result[1], result[2] or {}
                elif isinstance(result, tuple) and len(result) == 2:
                    _, self.report_paths = result
        finally:
            if use_browser:
                quit_selenium_driver()
            loop.close()
            self.stats.mark_finished()
            self.update_stats.emit(self.stats.format_friendly_line())
            self.finished_crawling.emit()

    def stop(self):
        self._is_running = False
        self.manager.cancel_all()

    def pause(self):
        self.pause_controller.pause()
        self.stats.paused = True

    def resume(self):
        self.pause_controller.resume()
        self.stats.paused = False

    def is_running(self):
        return self._is_running

    def append(self, message):
        text = str(message)
        self.update_output.emit(text)
        if text.startswith("Progress:"):
            self.update_stats.emit(text)


class CrawlerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.crawler_thread = None
        self.wordlist_file = DEFAULT_DIR_WORDLIST
        self.extra_wordlists = []
        self.targets_file = None
        self.last_report_paths = {}
        self.schedule_timer = QTimer(self)
        self.schedule_timer.timeout.connect(self.start_crawling)
        self.stats_timer = QTimer(self)
        self.stats_timer.setInterval(1000)
        self.stats_timer.timeout.connect(self._refresh_live_stats)
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Web Crawler and Directory Brute Forcer")
        self.setGeometry(80, 60, 1020, 880)
        self._expert_groups = []

        root = QWidget(self)
        self.setCentralWidget(root)
        layout = QVBoxLayout()
        root.setLayout(layout)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        # ── Run tab ──────────────────────────────────────────────────────
        run = QWidget()
        run_layout = QVBoxLayout(run)

        run_layout.addWidget(QLabel("Target URL (or use multi-target file in Settings → Operations):"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        run_layout.addWidget(self.url_input)

        run_layout.addWidget(QLabel("Scan mode:"))
        self.mode_group = QButtonGroup(self)
        self.mode_fast_rb = QRadioButton(MODE_LABELS["fast_scan"])
        self.mode_site_rb = QRadioButton(MODE_LABELS["site_map"])
        self.mode_full_rb = QRadioButton(MODE_LABELS["full_audit"])
        self.mode_deep_rb = QRadioButton(MODE_LABELS["deep_audit"])
        self.mode_full_rb.setChecked(True)
        self.mode_deep_rb.setToolTip(
            "Opt-in heavy audit: large wordlist, auto-prefixes, recursive enum, historical seeds. "
            "Can run for hours on small sites — use Full Audit for everyday scans."
        )
        for idx, rb in enumerate(
            (self.mode_fast_rb, self.mode_site_rb, self.mode_full_rb, self.mode_deep_rb)
        ):
            self.mode_group.addButton(rb, idx)
            run_layout.addWidget(rb)
        self.mode_group.buttonClicked.connect(self.on_mode_changed)

        speed_row = QHBoxLayout()
        speed_row.addWidget(QLabel("Parallelism:"))
        self.speed_combo = QComboBox()
        for key in SPEED_ORDER:
            self.speed_combo.addItem(SPEED_PROFILES[key]["label"], key)
        self.speed_combo.addItem("Custom — manual workers below", "custom")
        self.speed_combo.setCurrentIndex(SPEED_ORDER.index("balanced"))
        self.speed_combo.setToolTip(
            "How many requests run at once (async workers on one scan thread).\n"
            "Balanced is the sweet spot for most lab targets.\n"
            "Gentle if the site rate-limits; Fast/Aggressive only on hosts that can take it."
        )
        self.speed_combo.currentIndexChanged.connect(self.on_speed_changed)
        speed_row.addWidget(self.speed_combo, stretch=1)
        run_layout.addLayout(speed_row)

        source_box = QGroupBox("Directory scan source")
        source_layout = QVBoxLayout(source_box)
        self.directory_enum_cb = QCheckBox(
            "Run directory enum (opt-in — usually the slowest phase)"
        )
        self.directory_enum_cb.setChecked(False)
        self.directory_enum_cb.setToolTip(
            "Probe folder/file names after crawl (or only, in Fast Scan). "
            "Full Audit leaves this off; Deep Audit turns it on."
        )
        source_layout.addWidget(self.directory_enum_cb)
        src_row = QHBoxLayout()
        self.use_wordlist_cb = QCheckBox("Use wordlist file")
        self.use_wordlist_cb.setChecked(True)
        self.mutation_enum_cb = QCheckBox("Mutation scan (adds paths on top of wordlist)")
        self.mutation_enum_cb.setChecked(True)
        src_row.addWidget(self.use_wordlist_cb)
        src_row.addWidget(self.mutation_enum_cb)
        source_layout.addLayout(src_row)
        wl_row = QHBoxLayout()
        self.wordlist_button = QPushButton("Directory wordlist…")
        self.wordlist_button.clicked.connect(self.select_wordlist)
        self.wordlist_label = QLabel(DEFAULT_DIR_WORDLIST)
        wl_row.addWidget(self.wordlist_button)
        wl_row.addWidget(self.wordlist_label, stretch=1)
        source_layout.addLayout(wl_row)
        run_layout.addWidget(source_box)

        btn_row = QHBoxLayout()
        self.start_button = QPushButton("Start")
        self.pause_button = QPushButton("Pause")
        self.resume_button = QPushButton("Resume")
        self.stop_button = QPushButton("Stop")
        self.export_log_button = QPushButton("Export log")
        self.view_report_button = QPushButton("View last search report")
        self.view_report_button.setEnabled(False)
        self.pause_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_crawling)
        self.pause_button.clicked.connect(self.pause_crawling)
        self.resume_button.clicked.connect(self.resume_crawling)
        self.stop_button.clicked.connect(self.stop_crawling)
        self.export_log_button.clicked.connect(self.export_log)
        self.view_report_button.clicked.connect(self.view_last_report)
        for btn in (
            self.start_button, self.pause_button, self.resume_button,
            self.stop_button, self.export_log_button, self.view_report_button,
        ):
            btn_row.addWidget(btn)
        run_layout.addLayout(btn_row)

        self.stats_label = QLabel("Ready to scan")
        run_layout.addWidget(self.stats_label)

        run_layout.addWidget(QLabel("What’s happening:"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        run_layout.addWidget(self.output_text)

        run_layout.addWidget(QLabel("Download progress:"))
        self.progress_bar = QProgressBar()
        run_layout.addWidget(self.progress_bar)
        self.size_label = QLabel("Size: N/A")
        run_layout.addWidget(self.size_label)

        tabs.addTab(run, "Run")

        # ── Settings tab ─────────────────────────────────────────────────
        settings_tab = QWidget()
        settings_outer = QVBoxLayout(settings_tab)
        self.expert_cb = QCheckBox("Expert mode (show connection, operations, automation, exports)")
        self.expert_cb.toggled.connect(self._set_expert_visible)
        settings_outer.addWidget(self.expert_cb)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        settings_inner = QWidget()
        settings_layout = QVBoxLayout(settings_inner)

        crawl_box = QGroupBox("Crawl & mirror")
        crawl_layout = QVBoxLayout(crawl_box)
        self.crawl_only_radio = QRadioButton("Crawl and brute force (no download)")
        self.crawl_only_radio.setChecked(True)
        self.download_radio = QRadioButton(
            "Crawl, brute force, and download (mirror mode — pages + CSS/JS/images)"
        )
        crawl_layout.addWidget(self.crawl_only_radio)
        crawl_layout.addWidget(self.download_radio)
        crawl_layout.addWidget(QLabel("Profile preset:"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["full", "quick", "stealth", "gobuster"])
        crawl_layout.addWidget(self.profile_combo)
        crawl_layout.addWidget(QLabel("Download only these file extensions (optional):"))
        self.extensions_input = QLineEdit()
        self.extensions_input.setPlaceholderText("Leave empty = all types · e.g. pdf,jpg,png,zip,html")
        self.extensions_input.setToolTip(
            "DOWNLOAD filter — which file types to save to disk when download/mirror is on.\n"
            "Example: pdf,docx,xlsx  ·  Leave empty = save all types.\n"
            "Different from Enum extensions (Directory brute force), which append suffixes "
            "while guessing paths (admin → admin.php).\n"
            "Note: if “also save page components” is checked, CSS/JS/images for HTML pages "
            "are still fetched so offline pages look correct.\n"
            "Tip: Pause → change this → Resume applies it to the running scan."
        )
        crawl_layout.addWidget(self.extensions_input)
        self.restrict_domain_checkbox = QCheckBox("Restrict to same domain")
        self.restrict_domain_checkbox.setChecked(True)
        self.ignore_robots_checkbox = QCheckBox("Disregard robots.txt")
        self.ignore_robots_checkbox.setChecked(True)
        self.bypass_forbidden_checkbox = QCheckBox(
            "Bypass Forbidden/Unauthorized pages (401/403 — crawl and save instead of skipping)"
        )
        self.bypass_forbidden_checkbox.setChecked(True)
        self.server_side_txt_checkbox = QCheckBox("Save PHP/ASP.NET as .txt")
        self.server_side_txt_checkbox.setChecked(True)
        self.structure_checkbox = QCheckBox("HTTrack-style folder structure")
        self.structure_checkbox.setChecked(True)
        self.rewrite_checkbox = QCheckBox("Rewrite links for offline browsing")
        self.rewrite_checkbox.setChecked(True)
        self.mirror_assets_cb = QCheckBox(
            "When downloading: also save page components (CSS, JS, images, fonts, CDNs)"
        )
        self.mirror_assets_cb.setChecked(True)
        self.mirror_assets_cb.setToolTip(
            "For every HTML page saved, fetch stylesheets, scripts, images, and fonts "
            "(same site and common CDNs) and rewrite links for offline viewing."
        )
        self.download_radio.toggled.connect(self._on_download_mode_toggled)
        self.selenium_fallback_checkbox = QCheckBox("Selenium fallback")
        self.deep_mirror_checkbox = QCheckBox("Deep mirror (render all HTML in Chrome)")
        depth_row = QHBoxLayout()
        depth_row.addWidget(QLabel("Brute-force depth:"))
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 5)
        self.depth_spin.setValue(3)
        depth_row.addWidget(self.depth_spin)
        depth_row.addWidget(QLabel("Link depth limit (0=unlimited):"))
        self.link_depth_spin = QSpinBox()
        self.link_depth_spin.setRange(0, 20)
        self.link_depth_spin.setValue(0)
        depth_row.addWidget(self.link_depth_spin)
        for w in (
            self.restrict_domain_checkbox,
            self.ignore_robots_checkbox,
            self.bypass_forbidden_checkbox,
            self.server_side_txt_checkbox,
            self.structure_checkbox,
            self.rewrite_checkbox,
            self.mirror_assets_cb,
            self.selenium_fallback_checkbox,
            self.deep_mirror_checkbox,
        ):
            crawl_layout.addWidget(w)
        crawl_layout.addLayout(depth_row)
        settings_layout.addWidget(crawl_box)

        enum_box = QGroupBox("Directory brute force")
        enum_layout = QVBoxLayout(enum_box)
        mut_row = QHBoxLayout()
        self.mutation_builtin_cb = QCheckBox("Built-in common paths")
        self.mutation_builtin_cb.setChecked(True)
        self.mutation_seeds_cb = QCheckBox("Mutate seed URL tokens")
        self.mutation_seeds_cb.setChecked(True)
        mut_row.addWidget(self.mutation_builtin_cb)
        mut_row.addWidget(self.mutation_seeds_cb)
        enum_layout.addLayout(mut_row)
        mut_max_row = QHBoxLayout()
        mut_max_row.addWidget(QLabel("Max mutation candidates:"))
        self.mutation_max_spin = QSpinBox()
        self.mutation_max_spin.setRange(1000, 500000)
        self.mutation_max_spin.setSingleStep(5000)
        self.mutation_max_spin.setValue(50000)
        mut_max_row.addWidget(self.mutation_max_spin)
        enum_layout.addLayout(mut_max_row)
        self.smart_fp_cb = QCheckBox("Smarter false-positive filter")
        self.smart_fp_cb.setChecked(True)
        self.ext_wordlist_cb = QCheckBox("Legacy: expand entire wordlist with extensions (slow)")
        self.gobuster_ext_cb = QCheckBox("Gobuster-style extensions per word (fast)")
        self.gobuster_ext_cb.setChecked(True)
        self.enum_only_cb = QCheckBox("Enum-only mode (skip crawl — Gobuster-beater)")
        self.enum_flat_cb = QCheckBox("Flat scan (no recursion into found dirs)")
        self.enum_flat_cb.setChecked(True)
        self.wildcard_cb = QCheckBox("Wildcard detection (multi-probe filter)")
        self.wildcard_cb.setChecked(True)
        self.enum_follow_redirects_cb = QCheckBox(
            "Follow same-host redirects and score final status (recommended)"
        )
        self.enum_follow_redirects_cb.setChecked(True)
        self.enum_follow_redirects_cb.setToolTip(
            "Resolves 301/302 chains on the same host before counting a hit. "
            "Stops HTTP→HTTPS→404 false positives (e.g. .well-known paths)."
        )
        self.smart_wl_cb = QCheckBox("Smart wordlist order (Wayback/crawl seeds first)")
        self.smart_wl_cb.setChecked(True)
        self.auto_prefix_cb = QCheckBox("Auto prefix-scoped enum from discovered paths")
        self.auto_prefix_cb.setChecked(True)
        self.fp_learn_cb = QCheckBox("False-positive learning (save to false_positives.json)")
        self.fp_learn_cb.setChecked(True)
        self.enum_auto_vuln_cb = QCheckBox("Auto vuln-scan each enum hit")
        self.enum_auto_vuln_cb.setChecked(True)
        self.vhost_cb = QCheckBox("Vhost enumeration (Host header fuzz)")
        self.s3_cb = QCheckBox("S3 bucket discovery")
        self.gcs_cb = QCheckBox("GCS bucket discovery")
        self.resume_enum_cb = QCheckBox("Resume enum checkpoint")
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Status whitelist (empty=default):"))
        self.status_whitelist_input = QLineEdit()
        self.status_whitelist_input.setPlaceholderText("200,204,401,403 (final status after redirects)")
        filter_row.addWidget(self.status_whitelist_input)
        filter_row.addWidget(QLabel("Blacklist:"))
        self.status_blacklist_input = QLineEdit("404")
        filter_row.addWidget(self.status_blacklist_input)
        ext_row = QHBoxLayout()
        enum_ext_label = QLabel("Enum extensions:")
        enum_ext_label.setToolTip(
            "BRUTE-FORCE suffixes — tried for each wordlist entry that has no extension yet.\n"
            "Example: word “admin” also probes admin.php, admin.bak, …\n"
            "This does NOT choose which files to download (that is Download extensions "
            "under Crawl & mirror)."
        )
        ext_row.addWidget(enum_ext_label)
        self.enum_ext_input = QLineEdit("php,asp,aspx,bak,old,txt,zip,sql,config,env")
        self.enum_ext_input.setToolTip(enum_ext_label.toolTip())
        ext_row.addWidget(self.enum_ext_input)
        exclude_row = QHBoxLayout()
        exclude_row.addWidget(QLabel("Exclude lengths:"))
        self.exclude_lengths_input = QLineEdit()
        self.exclude_lengths_input.setPlaceholderText("1234,5678")
        exclude_row.addWidget(self.exclude_lengths_input)
        exclude_row.addWidget(QLabel("Prefixes (comma):"))
        self.enum_prefix_input = QLineEdit()
        self.enum_prefix_input.setPlaceholderText("auto from crawl if empty")
        exclude_row.addWidget(self.enum_prefix_input)
        self.status_report_cb = QCheckBox("Status-code reporting on enum hits")
        self.status_report_cb.setChecked(True)
        self.queue_enum_cb = QCheckBox("Queue enum hits for link crawling")
        self.queue_enum_cb.setChecked(True)
        self.skip_enum_dl_cb = QCheckBox("Skip download during brute force (faster)")
        enum_limit_row = QHBoxLayout()
        enum_limit_row.addWidget(QLabel("Max enum words (0 = full wordlist):"))
        self.enum_word_limit_spin = QSpinBox()
        self.enum_word_limit_spin.setRange(0, 10_000_000)
        self.enum_word_limit_spin.setValue(15000)
        self.enum_word_limit_spin.setToolTip(
            "0 = entire wordlist (can take many hours on directory-list-2.3-big). "
            "15000 is a practical Full Audit default; raise it for deeper scans."
        )
        enum_limit_row.addWidget(self.enum_word_limit_spin)
        self.extra_wl_btn = QPushButton("Add CMS/extra wordlist")
        self.extra_wl_btn.clicked.connect(self.select_extra_wordlist)
        self.extra_wl_label = QLabel("No extra wordlists")
        for w in (
            self.smart_fp_cb, self.gobuster_ext_cb, self.ext_wordlist_cb, self.enum_only_cb,
            self.enum_flat_cb, self.wildcard_cb, self.enum_follow_redirects_cb,
            self.smart_wl_cb, self.auto_prefix_cb,
            self.fp_learn_cb, self.enum_auto_vuln_cb, self.vhost_cb, self.s3_cb, self.gcs_cb,
            self.resume_enum_cb,
        ):
            enum_layout.addWidget(w)
        enum_layout.addLayout(filter_row)
        enum_layout.addLayout(ext_row)
        enum_layout.addLayout(exclude_row)
        enum_layout.addWidget(self.status_report_cb)
        enum_layout.addWidget(self.queue_enum_cb)
        enum_layout.addWidget(self.skip_enum_dl_cb)
        enum_layout.addLayout(enum_limit_row)
        enum_layout.addWidget(self.extra_wl_btn)
        enum_layout.addWidget(self.extra_wl_label)
        settings_layout.addWidget(enum_box)

        discovery_box = QGroupBox("Discovery")
        disc_layout = QVBoxLayout(discovery_box)
        self.wayback_cb = QCheckBox("Wayback Machine historical URLs")
        self.wayback_cb.setChecked(True)
        self.cc_cb = QCheckBox("Common Crawl historical URLs")
        self.cc_cb.setChecked(True)
        self.subdomain_cb = QCheckBox("Subdomain enumeration")
        self.subdomain_cb.setChecked(True)
        self.openapi_cb = QCheckBox("OpenAPI / Swagger endpoint parsing")
        self.openapi_cb.setChecked(True)
        self.js_cb = QCheckBox("JavaScript bundle route extraction")
        self.js_cb.setChecked(True)
        self.form_cb = QCheckBox("HTML form discovery")
        self.form_cb.setChecked(True)
        self.form_probe_cb = QCheckBox("Form action probe (GET only, authorized targets)")
        self.rss_cb = QCheckBox("RSS/Atom feed following")
        self.rss_cb.setChecked(True)
        for w in (
            self.wayback_cb, self.cc_cb, self.subdomain_cb, self.openapi_cb, self.js_cb,
            self.form_cb, self.form_probe_cb, self.rss_cb,
        ):
            disc_layout.addWidget(w)
        settings_layout.addWidget(discovery_box)

        api_box = QGroupBox("API recon")
        api_layout = QVBoxLayout(api_box)
        self.api_recon_cb = QCheckBox("Enable API recon (passive + docs)")
        self.api_recon_cb.setChecked(True)
        self.api_recon_cb.setToolTip(
            "Mine API routes from crawl/JS, probe well-known OpenAPI/Swagger/GraphQL docs."
        )
        self.api_active_cb = QCheckBox("Light active API path enum (GET/HEAD, capped)")
        self.api_active_cb.setChecked(True)
        self.api_graphql_cb = QCheckBox("GraphQL introspection")
        self.api_graphql_cb.setChecked(True)
        self.api_word_limit_spin = QSpinBox()
        self.api_word_limit_spin.setRange(100, 50_000)
        self.api_word_limit_spin.setValue(3000)
        api_limit_row = QHBoxLayout()
        api_limit_row.addWidget(QLabel("API word limit:"))
        api_limit_row.addWidget(self.api_word_limit_spin)
        api_limit_row.addStretch(1)
        self.api_auth_name_input = QLineEdit("Authorization")
        self.api_auth_name_input.setPlaceholderText("Header name (e.g. Authorization)")
        self.api_auth_value_input = QLineEdit()
        self.api_auth_value_input.setPlaceholderText("Header value (e.g. Bearer …) — optional")
        self.api_auth_value_input.setEchoMode(QLineEdit.Password)
        self.api_postman_path = ""
        self.api_har_path = ""
        self.api_postman_label = QLabel("Postman: (none)")
        self.api_har_label = QLabel("HAR: (none)")
        api_import_row = QHBoxLayout()
        api_postman_btn = QPushButton("Postman…")
        api_postman_btn.clicked.connect(self._browse_postman)
        api_har_btn = QPushButton("HAR…")
        api_har_btn.clicked.connect(self._browse_har)
        api_import_row.addWidget(api_postman_btn)
        api_import_row.addWidget(api_har_btn)
        api_import_row.addStretch(1)
        for w in (self.api_recon_cb, self.api_active_cb, self.api_graphql_cb):
            api_layout.addWidget(w)
        api_layout.addLayout(api_limit_row)
        api_layout.addWidget(QLabel("Optional API auth header:"))
        api_layout.addWidget(self.api_auth_name_input)
        api_layout.addWidget(self.api_auth_value_input)
        api_layout.addLayout(api_import_row)
        api_layout.addWidget(self.api_postman_label)
        api_layout.addWidget(self.api_har_label)
        settings_layout.addWidget(api_box)

        security_box = QGroupBox("Security (authorized targets only)")
        sec_layout = QVBoxLayout(security_box)
        self.security_cb = QCheckBox("Enable security scanning")
        self.security_cb.setChecked(True)
        self.secrets_cb = QCheckBox("Secret / API key pattern scan")
        self.secrets_cb.setChecked(True)
        self.headers_cb = QCheckBox("Security header audit")
        self.headers_cb.setChecked(True)
        self.cors_cb = QCheckBox("CORS misconfiguration check")
        self.cors_cb.setChecked(True)
        self.params_cb = QCheckBox("Parameter discovery")
        self.params_cb.setChecked(True)
        self.sensitive_cb = QCheckBox("Sensitive path highlights (.env, backups, etc.)")
        self.sensitive_cb.setChecked(True)
        self.vuln_cb = QCheckBox(
            "Vulnerability checks (SQLi, XSS, RCE, SSRF, traversal, auth, API leaks, secrets)"
        )
        self.vuln_cb.setChecked(True)
        self.vuln_probe_cb = QCheckBox(
            "Active injection probes (SQLi, XSS, RCE, SSRF, traversal — authorized only)"
        )
        self.vuln_probe_cb.setChecked(True)
        self.vuln_probe_cb.setToolTip(
            "Sends small safe payloads and compares against a baseline response to reduce false positives."
        )
        for w in (
            self.security_cb, self.secrets_cb, self.headers_cb, self.cors_cb, self.params_cb,
            self.sensitive_cb, self.vuln_cb, self.vuln_probe_cb,
        ):
            sec_layout.addWidget(w)
        settings_layout.addWidget(security_box)

        reporting_box = QGroupBox("Reporting")
        rep_layout = QVBoxLayout(reporting_box)
        self.search_conclusion_cb = QCheckBox(
            "Generate individual search report with plain-language conclusion (recommended)"
        )
        self.search_conclusion_cb.setChecked(True)
        self.html_rep_cb = QCheckBox("Detailed HTML report")
        self.html_rep_cb.setChecked(True)
        self.json_rep_cb = QCheckBox("JSON report")
        self.json_rep_cb.setChecked(True)
        self.sqlite_cb = QCheckBox("SQLite export")
        self.sqlite_cb.setChecked(True)
        self.csv_cb = QCheckBox("CSV findings export")
        self.csv_cb.setChecked(True)
        self.tech_cb = QCheckBox("Technology fingerprinting")
        self.tech_cb.setChecked(True)
        self.broken_cb = QCheckBox("Broken link report")
        self.broken_cb.setChecked(True)
        self.screenshot_cb = QCheckBox("Screenshot capture (requires Chrome)")
        self.warc_cb = QCheckBox("WARC export")
        self.warc_cb.setChecked(True)
        self.dedup_cb = QCheckBox("Duplicate content detection")
        self.dedup_cb.setChecked(True)
        self.incremental_cb = QCheckBox("Incremental mirror (ETag cache)")
        self.incremental_cb.setChecked(True)
        self.priority_cb = QCheckBox("Priority queue (HTML pages first)")
        self.priority_cb.setChecked(True)
        for w in (
            self.search_conclusion_cb, self.html_rep_cb, self.json_rep_cb, self.sqlite_cb, self.csv_cb,
            self.tech_cb, self.broken_cb, self.screenshot_cb, self.warc_cb, self.dedup_cb,
            self.incremental_cb, self.priority_cb,
        ):
            rep_layout.addWidget(w)
        settings_layout.addWidget(reporting_box)

        stealth_box = QGroupBox("Stealth / lab request hardening (authorized targets only)")
        stealth_layout = QVBoxLayout(stealth_box)
        self.evasion_enabled_cb = QCheckBox("Enable request stealth layer")
        self.evasion_enabled_cb.setChecked(True)
        stealth_layout.addWidget(self.evasion_enabled_cb)
        level_row = QHBoxLayout()
        level_row.addWidget(QLabel("Stealth level:"))
        self.evasion_level_combo = QComboBox()
        self.evasion_level_combo.addItems(["off", "basic", "stealth", "aggressive"])
        self.evasion_level_combo.setCurrentText("basic")
        self.evasion_level_combo.setToolTip(
            "basic = browser look + tiny delay (fastest; recommended for day-to-day)\n"
            "stealth = full browser headers, referers, backoff\n"
            "aggressive = slow human-like pacing (lab only — makes big wordlists take forever)"
        )
        level_row.addWidget(self.evasion_level_combo)
        level_row.addWidget(QLabel("Browser look:"))
        self.evasion_browser_combo = QComboBox()
        self.evasion_browser_combo.addItems(["chrome", "firefox", "safari", "edge", "random"])
        level_row.addWidget(self.evasion_browser_combo)
        stealth_layout.addLayout(level_row)
        ua_row = QHBoxLayout()
        ua_row.addWidget(QLabel("User-Agent strategy:"))
        self.evasion_ua_combo = QComboBox()
        self.evasion_ua_combo.addItems(["sticky_host", "sticky_session", "rotate"])
        ua_row.addWidget(self.evasion_ua_combo)
        stealth_layout.addLayout(ua_row)
        jitter_row = QHBoxLayout()
        jitter_row.addWidget(QLabel("Delay between requests (ms):"))
        self.evasion_jitter_min_spin = QSpinBox()
        self.evasion_jitter_min_spin.setRange(0, 10000)
        self.evasion_jitter_min_spin.setValue(0)
        self.evasion_jitter_max_spin = QSpinBox()
        self.evasion_jitter_max_spin.setRange(0, 30000)
        self.evasion_jitter_max_spin.setValue(60)
        jitter_row.addWidget(self.evasion_jitter_min_spin)
        jitter_row.addWidget(QLabel("to"))
        jitter_row.addWidget(self.evasion_jitter_max_spin)
        stealth_layout.addLayout(jitter_row)
        self.evasion_referer_cb = QCheckBox("Send Referer chain (looks like clicking around the site)")
        self.evasion_referer_cb.setChecked(True)
        self.evasion_lang_cb = QCheckBox("Rotate Accept-Language")
        self.evasion_lang_cb.setChecked(True)
        self.evasion_backoff_cb = QCheckBox("Slow down when blocked / rate-limited (429/403)")
        self.evasion_backoff_cb.setChecked(True)
        self.evasion_challenge_cb = QCheckBox("Detect bot-protection / challenge signals and back off")
        self.evasion_challenge_cb.setChecked(True)
        self.evasion_decoy_cb = QCheckBox("Warm-up with ordinary paths (favicon, robots.txt) before scanning")
        self.evasion_decoy_cb.setChecked(False)
        self.evasion_http2_cb = QCheckBox("Prefer HTTP/2 (more browser-like)")
        self.evasion_http2_cb.setChecked(True)
        for w in (
            self.evasion_referer_cb, self.evasion_lang_cb, self.evasion_backoff_cb,
            self.evasion_challenge_cb, self.evasion_decoy_cb, self.evasion_http2_cb,
        ):
            stealth_layout.addWidget(w)
        self.defense_verify_cb = QCheckBox(
            "Defense verification: score how often protections catch the scanner vs unchallenged gaps"
        )
        self.defense_verify_cb.setChecked(True)
        self.defense_verify_cb.setToolTip(
            "Reports catch rate and gaps. Does not solve CAPTCHAs or bypass bot management."
        )
        stealth_layout.addWidget(self.defense_verify_cb)
        stealth_layout.addWidget(QLabel(
            "Note: stealth hardens request fingerprints for your own lab. "
            "Defense verification measures catch vs gaps — it does not solve CAPTCHAs or bypass bot walls."
        ))
        settings_layout.addWidget(stealth_box)

        connection_box = QGroupBox("Connection & authentication")
        auth_layout = QVBoxLayout(connection_box)
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("Proxy URL e.g. http://127.0.0.1:8080")
        self.auth_user_input = QLineEdit()
        self.auth_user_input.setPlaceholderText("Basic auth username")
        self.auth_pass_input = QLineEdit()
        self.auth_pass_input.setEchoMode(QLineEdit.Password)
        self.auth_pass_input.setPlaceholderText("Basic auth password")
        self.cookie_input = QLineEdit()
        self.cookie_input.setPlaceholderText("Cookie string: session=abc; token=xyz")
        auth_layout.addWidget(QLabel("Proxy:"))
        auth_layout.addWidget(self.proxy_input)
        auth_layout.addWidget(self.auth_user_input)
        auth_layout.addWidget(self.auth_pass_input)
        auth_layout.addWidget(QLabel("Cookies:"))
        auth_layout.addWidget(self.cookie_input)
        settings_layout.addWidget(connection_box)
        self._expert_groups.append(connection_box)

        operations_box = QGroupBox("Operations")
        ops_layout = QVBoxLayout(operations_box)
        self.resume_cb = QCheckBox("Resume from checkpoint")
        self.targets_btn = QPushButton("Select multi-target URL list file")
        self.targets_btn.clicked.connect(self.select_targets_file)
        self.targets_label = QLabel("Single URL mode")
        self.redis_input = QLineEdit()
        self.redis_input.setPlaceholderText("Optional Redis URL for distributed queue")
        self.disk_spin = QSpinBox()
        self.disk_spin.setRange(0, 100000)
        self.disk_spin.setValue(500)
        self.disk_spin.setSuffix(" MB min free disk")
        ops_layout.addWidget(self.resume_cb)
        ops_layout.addWidget(self.targets_btn)
        ops_layout.addWidget(self.targets_label)
        ops_layout.addWidget(QLabel("Distributed Redis:"))
        ops_layout.addWidget(self.redis_input)
        disk_row = QHBoxLayout()
        disk_row.addWidget(QLabel("Disk space guard:"))
        disk_row.addWidget(self.disk_spin)
        ops_layout.addLayout(disk_row)
        settings_layout.addWidget(operations_box)
        self._expert_groups.append(operations_box)

        tools_box = QGroupBox("Performance, exports & automation")
        tools_layout = QVBoxLayout(tools_box)
        self._applying_speed = False
        perf_row = QHBoxLayout()
        perf_row.addWidget(QLabel("Crawl workers:"))
        self.crawl_concurrency_spin = QSpinBox()
        self.crawl_concurrency_spin.setRange(1, 20)
        self.crawl_concurrency_spin.setValue(4)
        self.crawl_concurrency_spin.setToolTip("Pages crawled at the same time")
        perf_row.addWidget(self.crawl_concurrency_spin)
        perf_row.addWidget(QLabel("Enum workers:"))
        self.enum_concurrency_spin = QSpinBox()
        self.enum_concurrency_spin.setRange(1, 200)
        self.enum_concurrency_spin.setValue(35)
        self.enum_concurrency_spin.setToolTip("Directory probes in each batch")
        perf_row.addWidget(self.enum_concurrency_spin)
        perf_row.addWidget(QLabel("Download workers:"))
        self.download_concurrency_spin = QSpinBox()
        self.download_concurrency_spin.setRange(1, 40)
        self.download_concurrency_spin.setValue(6)
        self.download_concurrency_spin.setToolTip("Files saved at the same time")
        perf_row.addWidget(self.download_concurrency_spin)
        tools_layout.addLayout(perf_row)
        for spin in (
            self.crawl_concurrency_spin,
            self.enum_concurrency_spin,
            self.download_concurrency_spin,
        ):
            spin.valueChanged.connect(self._on_concurrency_spin_changed)
        sim_row = QHBoxLayout()
        sim_row.addWidget(QLabel("Enum similarity (bytes):"))
        self.similarity_spin = QSpinBox()
        self.similarity_spin.setRange(0, 5000)
        self.similarity_spin.setValue(50)
        sim_row.addWidget(self.similarity_spin)
        sim_row.addStretch(1)
        tools_layout.addLayout(sim_row)
        self.skip_tracking_cb = QCheckBox("Skip tracking-pixel downloads (GIF, 1x1, analytics URLs)")
        self.skip_tracking_cb.setChecked(True)
        self.site_graph_cb = QCheckBox("Export site map graph (HTML)")
        self.site_graph_cb.setChecked(True)
        self.burp_cb = QCheckBox("Export Burp-style XML findings")
        self.burp_cb.setChecked(True)
        self.zap_cb = QCheckBox("Export ZAP-style JSON findings")
        self.zap_cb.setChecked(True)
        self.nuclei_cb = QCheckBox("Run Nuclei template scan (requires nuclei on PATH)")
        for w in (self.skip_tracking_cb, self.site_graph_cb, self.burp_cb, self.zap_cb, self.nuclei_cb):
            tools_layout.addWidget(w)
        login_box = QGroupBox("Authenticated crawl (Selenium login — authorized targets only)")
        login_layout = QVBoxLayout(login_box)
        self.use_login_cb = QCheckBox("Capture cookies via browser login before crawl")
        self.login_url_input = QLineEdit()
        self.login_url_input.setPlaceholderText("Login page URL")
        self.login_user_input = QLineEdit()
        self.login_user_input.setPlaceholderText("Username")
        self.login_pass_input = QLineEdit()
        self.login_pass_input.setEchoMode(QLineEdit.Password)
        login_layout.addWidget(self.use_login_cb)
        login_layout.addWidget(self.login_url_input)
        login_layout.addWidget(self.login_user_input)
        login_layout.addWidget(self.login_pass_input)
        tools_layout.addWidget(login_box)
        sched_row = QHBoxLayout()
        self.schedule_cb = QCheckBox("Repeat scan every")
        self.schedule_hours_spin = QSpinBox()
        self.schedule_hours_spin.setRange(1, 168)
        self.schedule_hours_spin.setValue(24)
        self.schedule_hours_spin.setSuffix(" hours")
        sched_row.addWidget(self.schedule_cb)
        sched_row.addWidget(self.schedule_hours_spin)
        tools_layout.addLayout(sched_row)
        self.compare_btn = QPushButton("Compare two crawl JSON reports…")
        self.compare_btn.clicked.connect(self.compare_reports_dialog)
        tools_layout.addWidget(self.compare_btn)
        settings_layout.addWidget(tools_box)
        self._expert_groups.append(tools_box)

        settings_layout.addStretch(1)
        scroll.setWidget(settings_inner)
        settings_outer.addWidget(scroll)
        tabs.addTab(settings_tab, "Settings")

        # ── Results tab ──────────────────────────────────────────────────
        results_tab = QWidget()
        results_layout = QVBoxLayout(results_tab)
        results_layout.addWidget(QLabel("Hidden paths found (folders or files that responded):"))
        self.results_hits_text = QTextEdit()
        self.results_hits_text.setReadOnly(True)
        self.results_hits_text.setPlaceholderText("When the scan finishes, any discovered paths will be listed here in plain language.")
        results_layout.addWidget(self.results_hits_text)
        results_layout.addWidget(QLabel("Possible security issues:"))
        self.results_findings_text = QTextEdit()
        self.results_findings_text.setReadOnly(True)
        self.results_findings_text.setPlaceholderText("Security checks will summarize anything worth reviewing here.")
        results_layout.addWidget(self.results_findings_text)
        results_layout.addWidget(QLabel("Defense verification (did your bot wall catch the scanner?):"))
        self.results_defense_text = QTextEdit()
        self.results_defense_text.setReadOnly(True)
        self.results_defense_text.setPlaceholderText(
            "After a scan: protections detected, catch rate, and unchallenged gaps to harden."
        )
        results_layout.addWidget(self.results_defense_text)
        results_btn_row = QHBoxLayout()
        self.refresh_results_btn = QPushButton("Refresh from last run")
        self.refresh_results_btn.clicked.connect(self.refresh_results)
        self.results_view_report_btn = QPushButton("View last search report")
        self.results_view_report_btn.setEnabled(False)
        self.results_view_report_btn.clicked.connect(self.view_last_report)
        self.open_reports_btn = QPushButton("Open Reports folder")
        self.open_reports_btn.clicked.connect(lambda: self._open_path(os.path.join(BASE_DIR, "Reports")))
        results_btn_row.addWidget(self.refresh_results_btn)
        results_btn_row.addWidget(self.results_view_report_btn)
        results_btn_row.addWidget(self.open_reports_btn)
        results_layout.addLayout(results_btn_row)
        tabs.addTab(results_tab, "Results")

        self.directory_enum_cb.toggled.connect(self._on_directory_enum_toggled)
        self.use_wordlist_cb.toggled.connect(self._sync_wordlist_controls)
        self.mutation_enum_cb.toggled.connect(self._sync_wordlist_controls)
        self._set_expert_visible(False)
        self._sync_wordlist_controls()
        apply_mode_preset(self, "full_audit")

    def on_mode_changed(self, _button=None):
        modes = ("fast_scan", "site_map", "full_audit", "deep_audit")
        idx = self.mode_group.checkedId()
        mode = modes[idx] if 0 <= idx < len(modes) else "full_audit"
        apply_mode_preset(self, mode)

    def on_speed_changed(self, _index=None):
        if getattr(self, "_applying_speed", False):
            return
        key = self.speed_combo.currentData()
        if key and key != "custom":
            apply_speed_profile(self, key)

    def _on_concurrency_spin_changed(self, _value=None):
        if getattr(self, "_applying_speed", False):
            return
        self._sync_speed_combo_from_spins()

    def _sync_speed_combo_from_spins(self):
        if not hasattr(self, "speed_combo"):
            return
        matched = match_speed_profile(
            self.crawl_concurrency_spin.value(),
            self.enum_concurrency_spin.value(),
            self.download_concurrency_spin.value(),
        )
        self._applying_speed = True
        try:
            if matched:
                idx = self.speed_combo.findData(matched)
            else:
                idx = self.speed_combo.findData("custom")
            if idx >= 0:
                self.speed_combo.setCurrentIndex(idx)
        finally:
            self._applying_speed = False

    def _on_directory_enum_toggled(self, enabled: bool):
        if enabled and not self.use_wordlist_cb.isChecked() and not self.mutation_enum_cb.isChecked():
            self.use_wordlist_cb.setChecked(True)
        self._sync_wordlist_controls()

    def _sync_wordlist_controls(self):
        enum_on = self.directory_enum_cb.isChecked() or self.mode_fast_rb.isChecked()
        use_wordlist = self.use_wordlist_cb.isChecked() and enum_on
        self.use_wordlist_cb.setEnabled(enum_on or self.mode_fast_rb.isChecked())
        self.mutation_enum_cb.setEnabled(enum_on or self.mode_fast_rb.isChecked())
        self.wordlist_button.setEnabled(use_wordlist)
        self.wordlist_label.setEnabled(use_wordlist)
        if enum_on and not use_wordlist and not self.mutation_enum_cb.isChecked():
            self.mutation_enum_cb.setChecked(True)

    def _on_download_mode_toggled(self, enabled: bool):
        if enabled:
            self.mirror_assets_cb.setChecked(True)
            self.structure_checkbox.setChecked(True)
            self.rewrite_checkbox.setChecked(True)

    def _set_expert_visible(self, visible: bool):
        for box in self._expert_groups:
            box.setVisible(visible)

    def refresh_results(self):
        if not self.crawler_thread:
            return
        stats = getattr(self.crawler_thread, "stats", None)
        if not stats:
            return
        hits = getattr(stats, "enum_hit_urls", []) or []
        self.results_hits_text.setPlainText(format_friendly_hits(hits, stats))
        findings = getattr(stats, "findings", []) or []
        self.results_findings_text.setPlainText(format_friendly_findings(findings))
        self.results_defense_text.setPlainText(format_defense_for_ui(getattr(stats, "defense_tracker", None)))

    def select_wordlist(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", BASE_DIR, "Text Files (*.txt)")
        if file_name:
            self.wordlist_file = file_name
            self.wordlist_label.setText(file_name)

    def select_extra_wordlist(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Extra Wordlist", BASE_DIR, "Text Files (*.txt)")
        if file_name and file_name not in self.extra_wordlists:
            self.extra_wordlists.append(file_name)
            self.extra_wl_label.setText("; ".join(self.extra_wordlists))

    def select_targets_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select URL list", BASE_DIR, "Text Files (*.txt)")
        if file_name:
            self.targets_file = file_name
            self.targets_label.setText(file_name)

    def _browse_postman(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select Postman collection", BASE_DIR, "JSON (*.json);;All (*.*)"
        )
        if file_name:
            self.api_postman_path = file_name
            self.api_postman_label.setText(f"Postman: {file_name}")

    def _browse_har(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "Select HAR capture", BASE_DIR, "HAR (*.har);;JSON (*.json);;All (*.*)"
        )
        if file_name:
            self.api_har_path = file_name
            self.api_har_label.setText(f"HAR: {file_name}")

    def build_config(self, start_url):
        return CrawlConfig(
            start_url=start_url,
            wordlist_file=self.wordlist_file,
            output_file_path=OUTPUT_FILE,
            download_dir=DOWNLOAD_DIR,
            restrict_domain=self.restrict_domain_checkbox.isChecked(),
            download_files=self.download_radio.isChecked(),
            extensions=normalize_extensions(self.parse_extensions()),
            max_depth=self.depth_spin.value(),
            link_depth_limit=self.link_depth_spin.value(),
            preserve_structure=self.structure_checkbox.isChecked(),
            rewrite_local=self.rewrite_checkbox.isChecked(),
            mirror_page_assets=self.mirror_assets_cb.isChecked() if self.download_radio.isChecked() else False,
            ignore_robots=self.ignore_robots_checkbox.isChecked(),
            bypass_forbidden=self.bypass_forbidden_checkbox.isChecked(),
            save_server_side_as_txt=self.server_side_txt_checkbox.isChecked(),
            profile=self.profile_combo.currentText(),
            wayback_seeds=self.wayback_cb.isChecked(),
            common_crawl_seeds=self.cc_cb.isChecked(),
            subdomain_enum=self.subdomain_cb.isChecked(),
            openapi_parse=self.openapi_cb.isChecked(),
            api_recon=self.api_recon_cb.isChecked(),
            api_recon_active=self.api_active_cb.isChecked(),
            api_recon_graphql=self.api_graphql_cb.isChecked(),
            api_recon_word_limit=self.api_word_limit_spin.value(),
            api_auth_header_name=self.api_auth_name_input.text().strip() or "Authorization",
            api_auth_header_value=self.api_auth_value_input.text().strip(),
            api_postman_file=self.api_postman_path or "",
            api_har_file=self.api_har_path or "",
            js_bundle_analysis=self.js_cb.isChecked(),
            form_discovery=self.form_cb.isChecked(),
            form_submit_probe=self.form_probe_cb.isChecked(),
            rss_feeds=self.rss_cb.isChecked(),
            smart_false_positive=self.smart_fp_cb.isChecked(),
            extension_aware_wordlist=self.ext_wordlist_cb.isChecked(),
            gobuster_style_extensions=self.gobuster_ext_cb.isChecked(),
            legacy_wordlist_expansion=self.ext_wordlist_cb.isChecked(),
            enum_only=self.enum_only_cb.isChecked(),
            enum_flat_scan=self.enum_flat_cb.isChecked(),
            wildcard_detection=self.wildcard_cb.isChecked(),
            enum_follow_redirects=self.enum_follow_redirects_cb.isChecked(),
            smart_wordlist_order=self.smart_wl_cb.isChecked(),
            auto_prefix_enum=self.auto_prefix_cb.isChecked(),
            false_positive_learning=self.fp_learn_cb.isChecked(),
            enum_auto_vuln_scan=self.enum_auto_vuln_cb.isChecked(),
            enum_auto_crawl_hits=self.enum_auto_vuln_cb.isChecked(),
            vhost_enum=self.vhost_cb.isChecked(),
            s3_enum=self.s3_cb.isChecked(),
            gcs_enum=self.gcs_cb.isChecked(),
            resume_enum_checkpoint=self.resume_enum_cb.isChecked(),
            enum_status_whitelist=self.status_whitelist_input.text().strip(),
            enum_status_blacklist=self.status_blacklist_input.text().strip(),
            enum_extensions=self.enum_ext_input.text().strip(),
            exclude_lengths=self.exclude_lengths_input.text().strip(),
            enum_prefixes=self.enum_prefix_input.text().strip(),
            status_code_report=self.status_report_cb.isChecked(),
            queue_enum_for_crawl=self.queue_enum_cb.isChecked(),
            skip_enum_download=self.skip_enum_dl_cb.isChecked(),
            enum_word_limit=self.enum_word_limit_spin.value(),
            extra_wordlists=list(self.extra_wordlists),
            directory_enum=self.directory_enum_cb.isChecked() or self.mode_fast_rb.isChecked(),
            use_wordlist=self.use_wordlist_cb.isChecked(),
            mutation_enum=self.mutation_enum_cb.isChecked(),
            mutation_builtin=self.mutation_builtin_cb.isChecked(),
            mutation_from_seeds=self.mutation_seeds_cb.isChecked(),
            mutation_max_candidates=self.mutation_max_spin.value(),
            security_scan=self.security_cb.isChecked(),
            secret_scan=self.secrets_cb.isChecked(),
            vuln_scan=self.vuln_cb.isChecked(),
            vuln_active_probe=self.vuln_probe_cb.isChecked(),
            active_probe_max_params=5,
            active_probe_max_forms=2,
            header_audit=self.headers_cb.isChecked(),
            cors_check=self.cors_cb.isChecked(),
            param_discovery=self.params_cb.isChecked(),
            sensitive_file_highlights=self.sensitive_cb.isChecked(),
            search_conclusion_report=self.search_conclusion_cb.isChecked(),
            html_report=self.html_rep_cb.isChecked(),
            json_report=self.json_rep_cb.isChecked(),
            sqlite_export=self.sqlite_cb.isChecked(),
            csv_export=self.csv_cb.isChecked(),
            tech_fingerprint=self.tech_cb.isChecked(),
            broken_link_report=self.broken_cb.isChecked(),
            screenshot_capture=self.screenshot_cb.isChecked(),
            warc_export=self.warc_cb.isChecked(),
            duplicate_content_detection=self.dedup_cb.isChecked(),
            incremental_mirror=self.incremental_cb.isChecked(),
            priority_html_first=self.priority_cb.isChecked(),
            proxy_url=self.proxy_input.text().strip(),
            auth_username=self.auth_user_input.text().strip(),
            auth_password=self.auth_pass_input.text(),
            cookie_string=self.cookie_input.text().strip(),
            resume_checkpoint=self.resume_cb.isChecked(),
            distributed_redis_url=self.redis_input.text().strip(),
            disk_space_guard_mb=self.disk_spin.value(),
            selenium_fallback=self.selenium_fallback_checkbox.isChecked(),
            deep_mirror=self.deep_mirror_checkbox.isChecked(),
            crawl_concurrency=self.crawl_concurrency_spin.value(),
            enum_concurrency=self.enum_concurrency_spin.value(),
            download_concurrency=self.download_concurrency_spin.value(),
            enum_similarity_threshold=self.similarity_spin.value(),
            skip_tracking_downloads=self.skip_tracking_cb.isChecked(),
            site_graph_export=self.site_graph_cb.isChecked(),
            burp_export=self.burp_cb.isChecked(),
            zap_export=self.zap_cb.isChecked(),
            nuclei_scan=self.nuclei_cb.isChecked(),
            use_selenium_login=self.use_login_cb.isChecked(),
            login_url=self.login_url_input.text().strip(),
            login_username=self.login_user_input.text().strip(),
            login_password=self.login_pass_input.text(),
            schedule_interval_hours=float(self.schedule_hours_spin.value()) if self.schedule_cb.isChecked() else 0,
            evasion_enabled=self.evasion_enabled_cb.isChecked(),
            evasion_level=self.evasion_level_combo.currentText(),
            evasion_browser=self.evasion_browser_combo.currentText(),
            evasion_ua_strategy=self.evasion_ua_combo.currentText(),
            evasion_jitter_min_ms=self.evasion_jitter_min_spin.value(),
            evasion_jitter_max_ms=max(self.evasion_jitter_min_spin.value(), self.evasion_jitter_max_spin.value()),
            evasion_referer_chain=self.evasion_referer_cb.isChecked(),
            evasion_language_rotate=self.evasion_lang_cb.isChecked(),
            evasion_adaptive_backoff=self.evasion_backoff_cb.isChecked(),
            evasion_challenge_detect=self.evasion_challenge_cb.isChecked(),
            evasion_decoy_requests=self.evasion_decoy_cb.isChecked(),
            evasion_http2=self.evasion_http2_cb.isChecked(),
            defense_verify=self.defense_verify_cb.isChecked(),
        )

    def load_target_urls(self):
        if self.targets_file:
            urls = []
            with open(self.targets_file, encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append(line)
            return urls or [self.url_input.text().strip()]
        url = self.url_input.text().strip()
        return [url] if url else []

    def parse_extensions(self):
        return [item.strip() for item in self.extensions_input.text().lower().split(",") if item.strip()]

    def compare_reports_dialog(self):
        path_a, _ = QFileDialog.getOpenFileName(self, "Report A (JSON)", os.path.join(BASE_DIR, "Reports"), "JSON (*.json)")
        if not path_a:
            return
        path_b, _ = QFileDialog.getOpenFileName(self, "Report B (JSON)", os.path.join(BASE_DIR, "Reports"), "JSON (*.json)")
        if not path_b:
            return
        out_path = os.path.join(BASE_DIR, "Reports", "comparison.html")
        from feature_exports import compare_crawl_reports

        summary = compare_crawl_reports(path_a, path_b, out_path)
        summary["output_path"] = out_path
        self.output_text.append(format_comparison_summary(summary))
        self._open_path(out_path)

    def apply_selenium_login(self, config):
        return apply_selenium_login(config, output=self.output_text.append)

    def start_crawling(self):
        urls = self.load_target_urls()
        if not urls or not urls[0]:
            self.output_text.append("Please enter a website address, or choose a file with a list of addresses.")
            return

        preview = self.build_config(urls[0])
        needs_wordlist = preview.use_wordlist
        if needs_wordlist and not os.path.isfile(self.wordlist_file):
            self.output_text.append(f"Could not find the wordlist file: {self.wordlist_file}")
            return
        if not preview.mutation_enum and not preview.use_wordlist:
            self.output_text.append("Turn on mutation scan or select a wordlist file before starting.")
            return

        self.start_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.resume_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        if not self.crawler_thread or not self.crawler_thread.isRunning():
            self.output_text.clear()

        config = self.build_config(urls[0])
        if config.use_selenium_login:
            config = self.apply_selenium_login(config)

        self.crawler_thread = CrawlerThread(config, urls)
        self.crawler_thread.update_output.connect(self.output_text.append)
        self.crawler_thread.update_progress.connect(self.update_progress)
        self.crawler_thread.update_stats.connect(lambda s: self.stats_label.setText(s))
        self.crawler_thread.finished_crawling.connect(self.finished_crawling)
        self.crawler_thread.start()
        self.stats_timer.start()

    def _refresh_live_stats(self):
        thread = self.crawler_thread
        if not thread or not thread.isRunning():
            return
        self.stats_label.setText(thread.stats.format_friendly_line())

    def pause_crawling(self):
        if self.crawler_thread:
            self.crawler_thread.pause()
            self.output_text.append(
                "Paused. You can change Settings now — they apply when you click Resume."
            )
            self._refresh_live_stats()

    def resume_crawling(self):
        if not self.crawler_thread:
            return
        fresh = self.build_config(self.crawler_thread.config.start_url)
        changed = self.crawler_thread.config.apply_live_settings(fresh)
        self.crawler_thread.resume()
        if changed:
            preview = ", ".join(changed[:12])
            extra = f" (+{len(changed) - 12} more)" if len(changed) > 12 else ""
            self.output_text.append(f"Resumed with updated settings: {preview}{extra}")
        else:
            self.output_text.append("Resumed.")
        self._refresh_live_stats()

    def stop_crawling(self):
        if self.crawler_thread:
            self.crawler_thread.stop()
            duration = format_duration_friendly(self.crawler_thread.stats.elapsed_seconds())
            self.output_text.append(f"\nStopped by user. Scan duration so far: {duration}.")

    def export_log(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export log", BASE_DIR, "Text Files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.output_text.toPlainText())
            self.output_text.append(f"Log exported to {path}")

    def update_progress(self, total_size, downloaded_size, size_text):
        if size_text:
            self.size_label.setText(simplify_log_line(size_text))
        if total_size > 0:
            self.progress_bar.setRange(0, 100)
            percent = min(100, int((downloaded_size / total_size) * 100))
            self.progress_bar.setValue(percent)
        elif size_text:
            self.progress_bar.setRange(0, 0)
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)

    def finished_crawling(self):
        self.stats_timer.stop()
        report_dir = os.path.join(BASE_DIR, "Reports")
        duration = ""
        if self.crawler_thread:
            secs = self.crawler_thread.stats.mark_finished()
            duration = format_duration_friendly(secs)
            self.stats_label.setText(self.crawler_thread.stats.format_friendly_line())
        duration_line = f"• Scan duration: {duration}\n" if duration else ""
        self.output_text.append(
            f"\nScan finished.\n"
            f"{duration_line}"
            f"• URL list: {OUTPUT_FILE}\n"
            f"• Downloaded files: {DOWNLOAD_DIR}\n"
            f"• Reports: {report_dir}\n"
            f"Open the Results tab for a plain-language summary."
        )
        self.start_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setRange(0, 100)
        self.size_label.setText("Size: N/A")

        if self.crawler_thread:
            self.last_report_paths = getattr(self.crawler_thread, "report_paths", {}) or {}
            conclusion = getattr(self.crawler_thread, "conclusion", {}) or {}
            if self.last_report_paths.get("search_report_html"):
                self.view_report_button.setEnabled(True)
                self.results_view_report_btn.setEnabled(True)
            self.refresh_results()
            if conclusion:
                self.show_search_conclusion_dialog(conclusion, self.last_report_paths)

        if self.schedule_cb.isChecked() and self.schedule_hours_spin.value() > 0:
            interval_ms = int(self.schedule_hours_spin.value() * 3600 * 1000)
            self.schedule_timer.start(interval_ms)
            self.output_text.append(f"Next scan scheduled in {self.schedule_hours_spin.value()} hour(s).")
        else:
            self.schedule_timer.stop()

    def show_search_conclusion_dialog(self, conclusion, report_paths):
        dialog = QDialog(self)
        dialog.setWindowTitle("Search Complete")
        dialog.setMinimumSize(720, 520)
        layout = QVBoxLayout(dialog)

        verdict = QLabel(f"<h2>{conclusion.get('verdict_title', 'Scan complete')}</h2>")
        verdict.setWordWrap(True)
        layout.addWidget(verdict)

        summary = QLabel(conclusion.get("verdict_body", ""))
        summary.setWordWrap(True)
        layout.addWidget(summary)

        layout.addWidget(QLabel("Full search report:"))
        report_text = QTextEdit()
        report_text.setReadOnly(True)
        report_text.setPlainText(conclusion.get("text", ""))
        layout.addWidget(report_text)

        button_row = QHBoxLayout()
        open_assessment_btn = QPushButton("Open assessment report")
        open_tech_btn = QPushButton("Open technical report")
        open_txt_btn = QPushButton("Open assessment text")
        open_folder_btn = QPushButton("Open Reports folder")

        assessment_path = report_paths.get("assessment_report_html", "")
        html_path = report_paths.get("search_report_html", "")
        txt_path = report_paths.get("assessment_report_txt") or report_paths.get("search_report_txt", "")

        open_assessment_btn.setEnabled(bool(assessment_path and os.path.isfile(assessment_path)))
        open_tech_btn.setEnabled(bool(html_path and os.path.isfile(html_path)))
        open_txt_btn.setEnabled(bool(txt_path and os.path.isfile(txt_path)))

        open_assessment_btn.clicked.connect(lambda: self._open_path(assessment_path))
        open_tech_btn.clicked.connect(lambda: self._open_path(html_path))
        open_txt_btn.clicked.connect(lambda: self._open_path(txt_path))
        open_folder_btn.clicked.connect(lambda: self._open_path(os.path.join(BASE_DIR, "Reports")))

        button_row.addWidget(open_assessment_btn)
        button_row.addWidget(open_tech_btn)
        button_row.addWidget(open_txt_btn)
        button_row.addWidget(open_folder_btn)
        layout.addLayout(button_row)

        close_box = QDialogButtonBox(QDialogButtonBox.Close)
        close_box.rejected.connect(dialog.reject)
        layout.addWidget(close_box)
        dialog.exec_()

    def view_last_report(self):
        assessment = self.last_report_paths.get("assessment_report_html", "")
        technical = self.last_report_paths.get("search_report_html", "")
        html_path = assessment if assessment and os.path.isfile(assessment) else technical
        if html_path and os.path.isfile(html_path):
            self._open_path(html_path)
        else:
            self.output_text.append("No assessment/technical report available yet. Run a crawl first.")

    @staticmethod
    def _open_path(path):
        if not path or not os.path.exists(path):
            return
        if path.lower().endswith(".html"):
            webbrowser.open(f"file:///{os.path.abspath(path).replace(chr(92), '/')}")
        else:
            os.startfile(os.path.abspath(path))

    def closeEvent(self, event):
        if self.crawler_thread and self.crawler_thread.isRunning():
            self.crawler_thread.stop()
            self.crawler_thread.wait(5000)
        quit_selenium_driver()
        event.accept()


def run_cli(args):
    extensions = normalize_extensions([x.strip() for x in args.extensions.split(",") if x.strip()]) if args.extensions else None
    use_wordlist = not args.no_wordlist
    mutation_enum = not args.no_mutation_enum
    if use_wordlist and args.wordlist and not os.path.isfile(args.wordlist):
        print(f"Error: wordlist not found: {args.wordlist}")
        sys.exit(1)
    if not mutation_enum and not use_wordlist:
        print("Error: enable mutation scan or provide a wordlist")
        sys.exit(1)
    config = CrawlConfig(
        start_url=args.url,
        wordlist_file=args.wordlist,
        output_file_path=OUTPUT_FILE,
        download_dir=DOWNLOAD_DIR,
        restrict_domain=not args.no_domain_restrict,
        download_files=args.download,
        extensions=extensions,
        max_depth=args.depth,
        profile=args.profile,
        selenium_fallback=args.selenium,
        deep_mirror=args.deep_mirror,
        preserve_structure=not args.flat_downloads,
        rewrite_local=not args.no_rewrite,
        ignore_robots=not args.use_robots,
        bypass_forbidden=not args.no_bypass_forbidden,
        resume_checkpoint=args.resume,
        vuln_active_probe=args.active_probe,
        enum_only=args.enum_only,
        vhost_enum=args.vhost,
        s3_enum=args.s3,
        gcs_enum=args.gcs,
        resume_enum_checkpoint=args.resume_enum,
        use_wordlist=use_wordlist,
        mutation_enum=mutation_enum,
        mutation_builtin=not args.no_mutation_builtin,
        mutation_from_seeds=not args.no_mutation_seeds,
        mutation_max_candidates=args.mutation_max,
        evasion_enabled=not args.no_evasion,
        evasion_level=args.evasion_level,
        evasion_browser=args.evasion_browser,
        evasion_ua_strategy=args.evasion_ua,
        evasion_decoy_requests=args.evasion_decoy or args.evasion_level == "aggressive",
        defense_verify=not args.no_defense_verify,
    )

    try:
        from tqdm import tqdm
        pbar = tqdm(desc="Crawling", unit=" pages")
    except ImportError:
        pbar = None

    def output_callback(message):
        print(message)
        if pbar and str(message).startswith("Crawling:"):
            pbar.update(1)

    def is_running():
        return True

    use_browser = args.selenium or args.deep_mirror
    fetcher = make_browser_fetcher(config) if use_browser else None

    urls = [args.url]
    if args.targets_file:
        with open(args.targets_file, encoding="utf-8", errors="ignore") as handle:
            urls = [line.strip() for line in handle if line.strip() and not line.startswith("#")]

    for url in urls:
        config.start_url = url
        print(f"\n=== Target: {url} ===")
        result = asyncio.run(
            run_full_crawl_async(
                config,
                output_callback,
                is_running,
                DownloadManager(),
                None,
                fetcher,
            )
        )
        if isinstance(result, tuple) and len(result) >= 3 and result[2]:
            print("\n" + result[2].get("text", ""))

    if pbar:
        pbar.close()
    if use_browser:
        quit_selenium_driver()

    print(f"\nResults: {OUTPUT_FILE}")
    print(f"Downloads: {DOWNLOAD_DIR}")
    print(f"Reports: {os.path.join(BASE_DIR, 'Reports')}")


def parse_args():
    parser = argparse.ArgumentParser(description="Web Crawler and Directory Brute Forcer — Full Edition")
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--targets-file", help="File with one URL per line")
    parser.add_argument("--wordlist", default=DEFAULT_DIR_WORDLIST)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--extensions", help="Comma-separated extensions")
    parser.add_argument("--no-domain-restrict", action="store_true")
    parser.add_argument("--selenium", action="store_true")
    parser.add_argument("--deep-mirror", action="store_true")
    parser.add_argument("--use-robots", action="store_true")
    parser.add_argument("--flat-downloads", action="store_true")
    parser.add_argument("--no-rewrite", action="store_true")
    parser.add_argument("--depth", type=int, default=3, choices=range(1, 6))
    parser.add_argument("--profile", default="full", choices=["full", "quick", "stealth", "gobuster"])
    parser.add_argument("--no-bypass-forbidden", action="store_true", help="Stop on HTTP 401/403 instead of processing")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument(
        "--active-probe",
        action="store_true",
        help="Enable active injection probes on params/forms (authorized targets only)",
    )
    parser.add_argument("--enum-only", action="store_true", help="Skip crawl; run directory/cloud/vhost enum only")
    parser.add_argument("--vhost", action="store_true", help="Enable vhost (Host header) enumeration")
    parser.add_argument("--s3", action="store_true", help="Enable S3 bucket discovery")
    parser.add_argument("--gcs", action="store_true", help="Enable GCS bucket discovery")
    parser.add_argument("--resume-enum", action="store_true", help="Resume directory enum from checkpoint")
    parser.add_argument("--no-wordlist", action="store_true", help="Skip file wordlist (mutations still run if enabled)")
    parser.add_argument("--no-mutation-enum", action="store_true", help="Disable mutation paths added on top of wordlist")
    parser.add_argument("--no-mutation-builtin", action="store_true", help="Skip built-in common paths in mutation mode")
    parser.add_argument("--no-mutation-seeds", action="store_true", help="Skip seed URL token mutations")
    parser.add_argument("--mutation-max", type=int, default=50000, help="Max mutation candidates")
    parser.add_argument("--no-evasion", action="store_true", help="Disable request stealth layer")
    parser.add_argument(
        "--evasion-level",
        default="aggressive",
        choices=["off", "basic", "stealth", "aggressive"],
        help="Request stealth level for authorized lab testing",
    )
    parser.add_argument(
        "--evasion-browser",
        default="chrome",
        choices=["chrome", "firefox", "safari", "edge", "random"],
    )
    parser.add_argument(
        "--evasion-ua",
        default="sticky_host",
        choices=["sticky_session", "sticky_host", "rotate"],
        help="User-Agent reuse strategy",
    )
    parser.add_argument("--evasion-decoy", action="store_true", help="Warm up with ordinary paths before scan")
    parser.add_argument(
        "--no-defense-verify",
        action="store_true",
        help="Disable defense catch/gap scoring report",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.cli:
        if not args.url and not args.targets_file:
            print("Error: --url or --targets-file required with --cli")
            sys.exit(1)
        run_cli(args)
        return

    app = QApplication(sys.argv)
    window = CrawlerApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
