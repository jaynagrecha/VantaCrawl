import asyncio

import httpx

from crawler_common import (
    DownloadManager,
    crawl_page_async,
    enumerate_directories_async,
    get_project_paths,
    get_request_headers,
)
from crawl_orchestrator import run_full_crawl_async

_, DEFAULT_OUTPUT_FILE, DEFAULT_DOWNLOAD_DIR = get_project_paths()


async def crawl(
    url,
    base_domain,
    download_dir,
    visited=None,
    download_files=False,
    extensions=None,
    restrict_domain=True,
    client=None,
):
    visited = visited if visited is not None else set()
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(http2=True, headers=get_request_headers(), follow_redirects=True)
    try:
        links, _, _, _ = await crawl_page_async(client, url, visited, base_domain, restrict_domain)
        return links
    finally:
        if owns_client:
            await client.aclose()


async def enumerate_directories(
    base_url,
    wordlist,
    download_dir,
    download_files=False,
    extensions=None,
    max_depth=3,
    output_file_path=None,
):
    output_file_path = output_file_path or DEFAULT_OUTPUT_FILE

    def output_callback(message):
        print(message)

    def is_running():
        return True

    headers = get_request_headers()
    async with httpx.AsyncClient(http2=True, headers=headers, follow_redirects=True) as client:
        return await enumerate_directories_async(
            base_url,
            wordlist,
            output_callback,
            is_running,
            output_file_path,
            client,
            download_files=download_files,
            download_dir=download_dir,
            extensions=extensions,
            max_depth=max_depth,
        )


async def run_full_crawl(
    url,
    wordlist,
    download_dir=None,
    download_files=False,
    extensions=None,
    restrict_domain=True,
    max_depth=3,
    output_file_path=None,
    profile="full",
):
    from crawl_config import CrawlConfig

    download_dir = download_dir or DEFAULT_DOWNLOAD_DIR
    output_file_path = output_file_path or DEFAULT_OUTPUT_FILE
    config = CrawlConfig(
        start_url=url,
        wordlist_file=wordlist,
        output_file_path=output_file_path,
        download_dir=download_dir,
        download_files=download_files,
        extensions=extensions,
        restrict_domain=restrict_domain,
        max_depth=max_depth,
        profile=profile,
    )

    def output_callback(message):
        print(message)

    def is_running():
        return True

    await run_full_crawl_async(config, output_callback, is_running, DownloadManager())


def start_sync_crawl(url, wordlist, download_dir, download_files=False, extensions=None, restrict_domain=True):
    asyncio.run(
        run_full_crawl(
            url,
            wordlist,
            download_dir=download_dir,
            download_files=download_files,
            extensions=extensions,
            restrict_domain=restrict_domain,
        )
    )
