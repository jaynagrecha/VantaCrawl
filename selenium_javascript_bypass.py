import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor

import httpx
from gui_helpers import AsyncCrawlerThread, build_async_app_window, run_async_gui
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from crawler_common import get_random_user_agent

_executor = ThreadPoolExecutor(max_workers=1)
_driver = None


def _init_selenium_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument(f"user-agent={get_random_user_agent()}")
    return webdriver.Chrome(service=ChromeService(), options=chrome_options)


def _fetch_with_selenium(url):
    global _driver
    if _driver is None:
        _driver = _init_selenium_driver()
    _driver.get(url)
    try:
        WebDriverWait(_driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    except Exception:
        pass
    return _driver.page_source, _driver.get_cookies()


async def selenium_page_fetcher(client, url):
    try:
        response = await client.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except httpx.HTTPError:
        loop = asyncio.get_running_loop()
        page_html, cookies = await loop.run_in_executor(_executor, _fetch_with_selenium, url)
        for cookie in cookies:
            client.cookies.set(
                cookie["name"],
                cookie["value"],
                domain=cookie.get("domain"),
            )
        return page_html


class SeleniumCrawlerThread(AsyncCrawlerThread):
    def run(self):
        try:
            super().run()
        finally:
            global _driver
            if _driver is not None:
                _driver.quit()
                _driver = None


def build_selenium_app_window():
    base_app = build_async_app_window(
        "Web Crawler and Directory Brute Forcer",
        include_download_mode=True,
        include_extensions=False,
        restrict_domain=True,
        max_depth=3,
        page_html_fetcher=selenium_page_fetcher,
    )

    class CrawlerApp(base_app):
        def start_crawling(self):
            url = self.url_input.text().strip()
            if not url:
                self.output_text.append("Please enter a valid URL.")
                return
            if not self.wordlist_file:
                self.output_text.append("Please select a wordlist file.")
                return

            download_files = self.download_radio.isChecked()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)

            self.crawler_thread = SeleniumCrawlerThread(
                url,
                self.wordlist_file,
                download_files=download_files,
                restrict_domain=True,
                max_depth=3,
                page_html_fetcher=selenium_page_fetcher,
            )
            self.crawler_thread.update_output.connect(self.update_output_text)
            self.crawler_thread.update_progress.connect(self.update_progress)
            self.crawler_thread.finished_crawling.connect(self.finished_crawling)
            self.crawler_thread.start()

    return CrawlerApp


if __name__ == "__main__":
    run_async_gui(build_selenium_app_window())
