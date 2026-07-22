from gui_helpers import build_async_app_window, run_async_gui

if __name__ == "__main__":
    CrawlerApp = build_async_app_window(
        "Web Crawler and Directory Brute Forcer",
        include_download_mode=True,
        include_extensions=False,
        restrict_domain=True,
        max_depth=3,
    )
    run_async_gui(CrawlerApp)
