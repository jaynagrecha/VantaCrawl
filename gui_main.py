from gui_helpers import build_sync_app_window, run_sync_gui

if __name__ == "__main__":
    CrawlerApp = build_sync_app_window(
        "Web Crawler and Directory Brute Forcer",
        restrict_domain=False,
        download_files=True,
        max_depth=1,
        show_progress=False,
    )
    run_sync_gui(CrawlerApp)
