import os
import sys

from crawler_common import (
    get_project_paths,
    is_valid_url,
    run_bfs_crawl_sync,
)

_, output_file_path, download_dir = get_project_paths()


def main(base_url, wordlist_file):
    downloaded_files = []

    def output_callback(message):
        print(message)

    def is_running():
        return True

    def update_progress(total_size, downloaded_size, size_text):
        if size_text:
            print(size_text)
        elif total_size > 0:
            progress = int((downloaded_size / total_size) * 100)
            print(f"\rDownload progress: {progress}%", end="", flush=True)

    run_bfs_crawl_sync(
        base_url,
        wordlist_file,
        output_callback,
        is_running,
        output_file_path,
        restrict_domain=False,
        download_files=True,
        download_dir=download_dir,
        update_progress=update_progress,
        max_depth=1,
    )

    if os.path.exists(output_file_path):
        with open(output_file_path, "r", encoding="utf-8") as log_file:
            urls = [line.strip() for line in log_file if line.strip() and is_valid_url(line.strip())]
        for path in urls:
            filename = os.path.join(download_dir, os.path.basename(path.rstrip("/").split("/")[-1]))
            if os.path.exists(filename):
                downloaded_files.append(filename)

    with open("found_paths_log.txt", "w", encoding="utf-8") as log_file:
        if os.path.exists(output_file_path):
            with open(output_file_path, "r", encoding="utf-8") as source:
                log_file.write("Found Paths:\n")
                log_file.write(source.read())
        log_file.write("\nDownloaded Files:\n")
        for file_path in downloaded_files:
            log_file.write(file_path + "\n")

    print(f"\nCrawling and downloading complete. Results logged in '{output_file_path}' and 'found_paths_log.txt'.")


if __name__ == "__main__":
    default_wordlist = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "Wordlist",
        "directory-list-2.3-big.txt",
    )
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://filesearch.tools/"
    wordlist = sys.argv[2] if len(sys.argv) > 2 else default_wordlist
    main(target_url, wordlist)
