from crawler import start_sync_crawl


def start_crawling(url, wordlist, download_dir, download_files=False, extensions=None, restrict_domain=True):
    start_sync_crawl(
        url,
        wordlist,
        download_dir,
        download_files=download_files,
        extensions=extensions,
        restrict_domain=restrict_domain,
    )
