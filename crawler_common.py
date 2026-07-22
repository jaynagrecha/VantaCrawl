"""Shared crawler, directory enumeration, and download logic."""

import asyncio
import os
import random
import re
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from collections import deque
from urllib.parse import unquote, urljoin, urlparse

import httpx
import requests
from bs4 import BeautifulSoup

from async_runtime import is_running

# Kept for backward compatibility; prefer evasion_layer profiles for live scans.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

LINK_SOURCES = (
    ("a", "href"),
    ("link", "href"),
    ("script", "src"),
    ("img", "src"),
    ("img", "data-src"),
    ("img", "data-original"),
    ("img", "data-lazy-src"),
    ("source", "src"),
    ("video", "src"),
    ("video", "poster"),
    ("audio", "src"),
    ("iframe", "src"),
    ("embed", "src"),
    ("object", "data"),
    ("area", "href"),
    ("form", "action"),
    ("input", "src"),
    ("button", "formaction"),
    ("blockquote", "cite"),
    ("del", "cite"),
    ("ins", "cite"),
    ("q", "cite"),
)

LAZY_URL_ATTRS = ("data-href", "data-url", "data-background", "data-image", "data-poster")

CSS_URL_RE = re.compile(r"""url\(\s*(['"]?)([^'")]+)\1\s*\)""", re.IGNORECASE)
CSS_IMPORT_RE = re.compile(
    r"""@import\s+(?:url\(\s*(['"]?)([^'")]+)\1\s*\)|(['"])([^'"]+)\3)""",
    re.IGNORECASE,
)
INLINE_STYLE_URL_RE = re.compile(r"""url\(\s*(['"]?)([^'")]+)\1\s*\)""", re.IGNORECASE)
JS_URL_RE = re.compile(
    r"""["']((?:https?:)?//[^"'\\]+|/?[^"'\\]+\.(?:css|js|mjs|php\d?|phtml|asp|aspx|ascx|ashx|cshtml|vbhtml|config|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|mp4|webm|json|xml|html?))["']""",
    re.IGNORECASE,
)
META_REFRESH_RE = re.compile(r"""url=(.+)$""", re.IGNORECASE)
TEXT_CONTENT_TYPES = ("text/", "application/javascript", "application/json", "application/xml", "image/svg+xml")

# Server-side source files saved as .txt for local inspection
SERVER_SIDE_SOURCE_EXTENSIONS = frozenset({
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".asp", ".aspx", ".ascx", ".asax", ".asmx", ".ashx", ".cshtml", ".vbhtml", ".master",
    ".jsp", ".jspx", ".cgi", ".pl",
    ".config",  # e.g. web.config
})

POSITIVE_STATUS_CODES = {200, 301, 302, 401, 403}
BYPASS_HTTP_CODES = frozenset({401, 403})
DEFAULT_ENUM_CONCURRENCY = 50
DEFAULT_DOWNLOAD_CONCURRENCY = 5
DEFAULT_MAX_DOWNLOAD_BYTES = 500 * 1024 * 1024
MAX_ATTEMPTS = 3
CHUNK_SIZE = 16 * 1024 * 1024
WRITE_PROGRESS_CHUNK = 256 * 1024


from user_output import format_enum_progress


def emit_download_progress(update_progress, total_size, downloaded_size, size_text=None):
    if not update_progress:
        return
    if hasattr(update_progress, "emit"):
        update_progress.emit(total_size, downloaded_size, size_text or "")
    else:
        update_progress(total_size, downloaded_size, size_text or "")


def format_byte_size(num: int) -> str:
    if num < 1024:
        return f"{num} B"
    if num < 1024 * 1024:
        return f"{num / 1024:.1f} KB"
    return f"{num / (1024 * 1024):.1f} MB"


class DownloadManager:
    def __init__(self):
        self.download_tasks = {}
        self.task_progress = {}
        self.cancelled = False
        self.cache = set()

    def add_task(self, url, task):
        self.download_tasks[url] = task
        self.task_progress[url] = 0

    def update_task_progress(self, url, progress):
        if url in self.task_progress:
            self.task_progress[url] = progress

    def cancel_tasks_below_percentage(self, percentage):
        for url, task in list(self.download_tasks.items()):
            if task and self.task_progress.get(url, 0) < percentage:
                task.cancel()

    def cancel_all(self):
        self.cancelled = True
        self.cancel_tasks_below_percentage(55)
        for task in list(self.download_tasks.values()):
            if task:
                task.cancel()


def get_project_paths():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_file_path = os.path.join(base_dir, "found_urls.txt")
    download_dir = os.path.join(base_dir, "Downloaded Files")
    os.makedirs(download_dir, exist_ok=True)
    return base_dir, output_file_path, download_dir


def get_random_user_agent():
    try:
        from evasion_layer import pick_user_agent_for_selenium

        return pick_user_agent_for_selenium()
    except Exception:
        return random.choice(USER_AGENTS)


def get_request_headers():
    try:
        from evasion_layer import EvasionConfig, EvasionSession

        return EvasionSession(EvasionConfig(enabled=True, level="basic")).base_client_headers()
    except Exception:
        return {
            "User-Agent": get_random_user_agent(),
            "Accept-Encoding": "gzip, deflate",
        }


def safe_urlparse(url):
    """Parse URL safely; return None when malformed (e.g. invalid IPv6)."""
    if not url or not isinstance(url, str):
        return None
    try:
        return urlparse(url.strip())
    except ValueError:
        return None


def is_valid_url(url):
    parsed = safe_urlparse(url)
    if not parsed:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def netloc_in_scope(netloc, base_domain):
    if not base_domain:
        return True
    netloc = netloc.lower()
    base_domain = base_domain.lower()
    return netloc == base_domain or netloc.endswith("." + base_domain)


def should_follow_url(full_url, base_domain, restrict_domain):
    if not is_valid_url(full_url):
        return False
    if restrict_domain and not netloc_in_scope(urlparse(full_url).netloc, base_domain):
        return False
    return True


def build_enum_url(base_url, path_segments, word):
    word = word.strip().strip("/")
    if not word or word.startswith("#") or "#" in word or " " in word:
        return None
    base = base_url if base_url.endswith("/") else base_url + "/"
    segments = [segment.strip("/") for segment in path_segments if segment and segment.strip("/")]
    segments.append(word)
    return urljoin(base, "/".join(segments))


def url_file_extension(url):
    return os.path.splitext(urlparse(url).path)[1].lower()


def is_server_side_source_url(url):
    return url_file_extension(url) in SERVER_SIDE_SOURCE_EXTENSIONS


def apply_txt_extension_for_server_files(path, url, save_server_side_as_txt=True):
    if save_server_side_as_txt and is_server_side_source_url(url):
        base, _ = os.path.splitext(path)
        return base + ".txt"
    return path


def safe_filename_from_url(url, save_server_side_as_txt=True):
    parsed = urlparse(url)
    name = unquote(os.path.basename(parsed.path))
    if not name or name in (".", ".."):
        ext = os.path.splitext(parsed.path)[1]
        name = "index" + ext if ext else "index.html"
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    name = name[:200] or "index.html"
    if save_server_side_as_txt and is_server_side_source_url(url):
        base, _ = os.path.splitext(name)
        name = base + ".txt"
    return name


def is_html_url(url, content_type=None):
    content_type = (content_type or "").lower()
    if "html" in content_type:
        return True
    parsed = safe_urlparse(url)
    if not parsed:
        return False
    path = parsed.path.lower()
    if not path or path.endswith("/"):
        return True
    return path.endswith((".html", ".htm", ".xhtml", ".php", ".asp", ".aspx", ".jsp", ".cgi"))


def mirror_relative_path(url, save_server_side_as_txt=True):
    parsed = urlparse(url)
    host_dir = parsed.netloc.replace(":", "_")
    path = unquote(parsed.path or "/")
    if path.endswith("/") or path == "/":
        path = path.rstrip("/") + "/index.html"
    elif not os.path.splitext(path)[1]:
        path = path.rstrip("/") + "/index.html"
    path = apply_txt_extension_for_server_files(path, url, save_server_side_as_txt)
    if parsed.query:
        base, ext = os.path.splitext(path)
        safe_query = re.sub(r'[<>:"/\\|?*&=]', "_", parsed.query)[:80]
        path = f"{base}_{safe_query}{ext or '.html'}"
    return host_dir, path.lstrip("/").replace("/", os.sep)


def mirror_filepath(url, download_dir, preserve_structure=True, save_server_side_as_txt=True):
    if not preserve_structure:
        return unique_filepath(download_dir, safe_filename_from_url(url, save_server_side_as_txt))
    host_dir, relative_path = mirror_relative_path(url, save_server_side_as_txt)
    filepath = os.path.join(download_dir, host_dir, relative_path)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    return filepath


def relative_link(from_url, to_url):
    _, from_rel = mirror_relative_path(from_url)
    _, to_rel = mirror_relative_path(to_url)
    from_dir = os.path.dirname(from_rel.replace("/", os.sep))
    rel = os.path.relpath(to_rel.replace("/", os.sep), from_dir or ".")
    return rel.replace("\\", "/")


ASSET_PATH_RE = re.compile(
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|json|xml|txt|htc)(?:\?|$)",
    re.I,
)


def is_page_asset_url(url: str) -> bool:
    if not url or not is_valid_url(url):
        return False
    path = urlparse(url).path.lower()
    if ASSET_PATH_RE.search(path):
        return True
    # cPanel / WHM and similar revisioned static trees
    if "/unprotected/" in path or "/cpanel_magic_revision_" in path.lower():
        return True
    if any(token in path for token in ("/css/", "/js/", "/images/", "/img/", "/fonts/", "/static/", "/assets/", "/media/", "/dist/", "/build/")):
        return True
    if path.endswith(("/favicon.ico", "/robots.txt")):
        return True
    return False


def _same_site(host_a: str, host_b: str) -> bool:
    a = (host_a or "").lower().split(":")[0]
    b = (host_b or "").lower().split(":")[0]
    if not a or not b:
        return False
    if a == b:
        return True
    return a.endswith("." + b) or b.endswith("." + a)


def extract_page_assets(html_text: str, page_url: str, host: str = "", *, include_cdn: bool = True) -> list:
    """CSS/JS/image/font URLs needed for an offline copy of the page."""
    if not html_text:
        return []
    host = (host or urlparse(page_url).netloc).lower()
    soup = BeautifulSoup(html_text, "html.parser")
    candidates = set(extract_urls_from_html(soup, page_url))
    for style_tag in soup.find_all("style"):
        if style_tag.string:
            candidates.update(extract_urls_from_css(style_tag.string, page_url))

    # Explicit tags that are always components of the page
    for tag in soup.find_all("link", href=True):
        add_url_to_set(candidates, tag.get("href"), page_url)
    for tag in soup.find_all("script", src=True):
        add_url_to_set(candidates, tag.get("src"), page_url)
    for tag in soup.find_all(["img", "source", "video", "audio", "track"], src=True):
        add_url_to_set(candidates, tag.get("src"), page_url)
    for tag in soup.find_all("video", poster=True):
        add_url_to_set(candidates, tag.get("poster"), page_url)

    assets = []
    seen = set()
    for url in candidates:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            continue
        asset_host = parsed.netloc.lower()
        same = _same_site(asset_host, host)
        if not same and not include_cdn:
            continue
        if not same and not is_page_asset_url(url):
            continue
        if same and not is_page_asset_url(url):
            # Same-site: still take stylesheet/script/image-ish paths
            if not any(token in parsed.path.lower() for token in ("/css", "/js", "/img", "/image", "/font", "/static", "/asset", "/media", "/unprotected", "/dist", "/build")):
                continue
        if url in seen:
            continue
        seen.add(url)
        assets.append(url)
    return assets


def _rewrite_css_urls(css_text: str, file_url: str, host: str) -> str:
    if not css_text:
        return css_text
    host = host.lower()

    def repl(match):
        prefix, raw, suffix = match.group(1), match.group(2), match.group(3)
        cleaned = raw.strip().strip("'\"")
        if cleaned.startswith("data:"):
            return match.group(0)
        target = normalize_raw_url(cleaned, file_url)
        if not target or not _should_rewrite_mirror_target(target, host):
            return match.group(0)
        try:
            return f"{prefix}{relative_link(file_url, target)}{suffix}"
        except ValueError:
            return match.group(0)

    return re.sub(r"(url\(\s*)([^)]+?)(\s*\))", repl, css_text, flags=re.I)


def _should_rewrite_mirror_target(target: str, page_host: str) -> bool:
    """Rewrite local copies for same-site URLs and any static asset URL (incl. CDNs)."""
    if not target:
        return False
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return False
    if _same_site(parsed.netloc, page_host):
        return True
    return is_page_asset_url(target)


def rewrite_for_local_mirror(content, file_url, host, content_type):
    """Rewrite absolute, root-relative, and CDN asset links for offline viewing."""
    if not content or not host:
        return content

    host = host.lower()
    ctype = (content_type or "").lower()
    path = urlparse(file_url).path.lower()

    if "css" in ctype or path.endswith(".css"):
        return _rewrite_css_urls(content, file_url, host)

    # Prefer structured HTML rewrite so /path and CDN URLs become relative files
    if "html" in ctype or path.endswith((".html", ".htm")) or content.lstrip()[:20].lower().startswith(("<!doctype", "<html")):
        try:
            soup = BeautifulSoup(content, "html.parser")
        except Exception:
            soup = None
        if soup is not None:
            attrs = ("href", "src", "poster", "data-src", "data-href", "data-url", "data-original", "data-lazy-src")
            for tag in soup.find_all(True):
                for attr in attrs:
                    raw = tag.get(attr)
                    if not raw or isinstance(raw, list):
                        continue
                    raw = str(raw).strip()
                    if not raw or raw.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
                        continue
                    target = normalize_raw_url(raw, file_url)
                    if not target or not _should_rewrite_mirror_target(target, host):
                        continue
                    try:
                        tag[attr] = relative_link(file_url, target)
                    except ValueError:
                        pass
                if tag.has_attr("srcset"):
                    parts = []
                    for entry in str(tag.get("srcset")).split(","):
                        bits = entry.strip().split()
                        if not bits:
                            continue
                        target = normalize_raw_url(bits[0], file_url)
                        if target and _should_rewrite_mirror_target(target, host):
                            try:
                                bits[0] = relative_link(file_url, target)
                            except ValueError:
                                pass
                        parts.append(" ".join(bits))
                    if parts:
                        tag["srcset"] = ", ".join(parts)
                if tag.name == "style" and tag.string:
                    new_css = _rewrite_css_urls(str(tag.string), file_url, host)
                    tag.clear()
                    tag.append(new_css)
                style = tag.get("style")
                if style:
                    tag["style"] = _rewrite_css_urls(style, file_url, host)
            # Drop <base href> so relative links resolve against the file location
            for base in soup.find_all("base"):
                base.decompose()
            return str(soup)

    host_pattern = re.escape(host)

    def replace_absolute(match):
        absolute = match.group(0)
        target = normalize_raw_url(absolute, file_url)
        if not target or urlparse(target).netloc.lower() != host:
            return absolute
        try:
            return relative_link(file_url, target)
        except ValueError:
            return absolute

    absolute_pattern = re.compile(rf"https?://{host_pattern}[^\s\"'<>)\]]*", re.IGNORECASE)
    rewritten = absolute_pattern.sub(replace_absolute, content)

    def root_repl(match):
        q1, path, q2 = match.group(1), match.group(2), match.group(3)
        if q1 != q2:
            return match.group(0)
        target = normalize_raw_url(path, file_url)
        if not target or urlparse(target).netloc.lower() != host:
            return match.group(0)
        try:
            return f"{q1}{relative_link(file_url, target)}{q2}"
        except ValueError:
            return match.group(0)

    return re.sub(
        r"""(['"])(/(?:cPanel_magic_revision_[^'"\s]+|unprotected/[^'"\s]+|[^'"\s]+\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|woff2?|ttf|eot|ico|htc)(?:\?[^'"]*)?))(['"])""",
        root_repl,
        rewritten,
        flags=re.I,
    )


def get_effective_base_url(soup, page_url):
    base_tag = soup.find("base", href=True)
    if base_tag:
        return urljoin(page_url, base_tag["href"].strip())
    return page_url


def unique_filepath(download_dir, filename):
    filepath = os.path.join(download_dir, filename)
    base, ext = os.path.splitext(filepath)
    counter = 1
    while os.path.exists(filepath):
        filepath = f"{base}_{counter}{ext}"
        counter += 1
    return filepath


def is_plausible_href(href):
    if not href or "${" in href or "{{" in href or "}}" in href:
        return False
    if href.startswith(("{", "}", "%7B", "%7D")):
        return False
    if any(char in href for char in ("*", "{", "}", "<", ">", "|", "^", "\\", "`")):
        return False
    return True


_LOG_FILE_LOCK = threading.Lock()


def log_to_file(output_file_path, url):
    with _LOG_FILE_LOCK:
        with open(output_file_path, "a", encoding="utf-8") as file:
            file.write(url + "\n")


def load_wordlist(wordlist_file, max_words: int = 0):
    """Load wordlist lines. If max_words > 0, stop after that many usable entries."""
    words = []
    if not wordlist_file:
        return words
    with open(wordlist_file, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            if "#" in word or " " in word:
                continue
            words.append(word)
            if max_words and len(words) >= max_words:
                break
    return words


def normalize_extensions(extensions):
    if not extensions:
        return None
    normalized = []
    for ext in extensions:
        ext = ext.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = "." + ext
        normalized.append(ext)
    return normalized or None


def extension_allowed(url, extensions):
    if is_server_side_source_url(url):
        return True
    if not extensions:
        return True
    file_extension = url_file_extension(url)
    if not file_extension:
        return False
    return file_extension in extensions


def is_text_content(content_type, url):
    content_type = (content_type or "").lower()
    if any(token in content_type for token in TEXT_CONTENT_TYPES):
        return True
    path = urlparse(url).path.lower()
    return path.endswith(
        (
            ".html", ".htm", ".css", ".js", ".mjs", ".json", ".xml", ".svg", ".txt",
            ".php", ".php3", ".php4", ".php5", ".phtml",
            ".asp", ".aspx", ".ascx", ".asax", ".asmx", ".ashx", ".cshtml", ".vbhtml",
            ".jsp", ".jspx", ".cgi", ".config",
        )
    ) or path.endswith("robots.txt") or is_server_side_source_url(url)


def normalize_raw_url(raw, base_url):
    raw = raw.strip().strip("'\"")
    if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:", "blob:", "#")):
        return None
    if not is_plausible_href(raw):
        return None
    if raw.startswith("//"):
        parsed = urlparse(base_url)
        raw = f"{parsed.scheme}:{raw}"
    full_url = raw if raw.startswith(("http://", "https://")) else urljoin(base_url, raw)
    if "${" in full_url or not is_valid_url(full_url):
        return None
    return canonicalize_crawl_url(full_url, base_url=base_url)


def canonicalize_crawl_url(url: str, *, base_url: str = "") -> str:
    """Strip default ports and prefer HTTPS when the crawl base is HTTPS.

    Cleartext ``http://host:80/`` trips Akamai bot rules and is useless when the
    scan started on HTTPS — rewrite to ``https://host/``.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url
    if parsed.scheme not in ("http", "https"):
        return url
    host = parsed.hostname
    if not host:
        return url
    base_scheme = ""
    try:
        base_scheme = (urlparse(base_url).scheme or "").lower() if base_url else ""
    except Exception:
        base_scheme = ""
    scheme = parsed.scheme.lower()
    port = parsed.port
    # When the crawl origin is HTTPS, never follow cleartext http twin URLs
    if scheme == "http" and base_scheme == "https":
        scheme = "https"
        if port in (80, 443):
            port = None
    elif scheme == "http" and port == 80:
        port = None
    elif scheme == "https" and port == 443:
        port = None
    netloc = f"{host}:{port}" if port else host
    if parsed.username:
        user = parsed.username
        if parsed.password:
            user = f"{user}:{parsed.password}"
        netloc = f"{user}@{netloc}"
    path = parsed.path or "/"
    from urllib.parse import urlunparse

    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def filter_scoped_urls(urls, base_domain, restrict_domain):
    return {url for url in urls if should_follow_url(url, base_domain, restrict_domain)}


def add_url_to_set(target, raw, base_url):
    full_url = normalize_raw_url(raw, base_url)
    if full_url:
        target.add(full_url)


def parse_srcset(srcset_value, base_url, target):
    for entry in srcset_value.split(","):
        candidate = entry.strip().split()[0] if entry.strip() else ""
        add_url_to_set(target, candidate, base_url)


def extract_urls_from_css(text, base_url):
    urls = set()
    for match in CSS_URL_RE.finditer(text):
        add_url_to_set(urls, match.group(2), base_url)
    for match in CSS_IMPORT_RE.finditer(text):
        imported = match.group(2) or match.group(4)
        if imported:
            add_url_to_set(urls, imported, base_url)
    return urls


def extract_urls_from_js(text, base_url):
    urls = set()
    for match in JS_URL_RE.finditer(text):
        add_url_to_set(urls, match.group(1), base_url)
    return urls


def extract_urls_from_html(soup, page_url):
    links = set()
    effective_base = get_effective_base_url(soup, page_url)

    for tag, attr in LINK_SOURCES:
        for element in soup.find_all(tag):
            value = element.get(attr)
            if value:
                add_url_to_set(links, value, effective_base)

    for tag in ("img", "source"):
        for element in soup.find_all(tag):
            srcset = element.get("srcset")
            if srcset:
                parse_srcset(srcset, effective_base, links)

    for attr in LAZY_URL_ATTRS:
        for element in soup.find_all(attrs={attr: True}):
            add_url_to_set(links, element.get(attr), effective_base)

    for element in soup.find_all(style=True):
        for match in INLINE_STYLE_URL_RE.finditer(element.get("style", "")):
            add_url_to_set(links, match.group(2), effective_base)

    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}):
        content = meta.get("content", "")
        refresh = META_REFRESH_RE.search(content)
        if refresh:
            add_url_to_set(links, refresh.group(1).strip(), effective_base)

    for meta in soup.find_all("meta", attrs={"property": re.compile(r"^og:url$", re.I)}):
        add_url_to_set(links, meta.get("content"), effective_base)

    for link_tag in soup.find_all("link", href=True):
        rel_attr = link_tag.get("rel", [])
        if isinstance(rel_attr, str):
            rel = rel_attr.lower()
        else:
            rel = " ".join(rel_attr).lower()
        if any(token in rel for token in ("canonical", "alternate", "preload", "prefetch", "manifest", "stylesheet", "icon")):
            add_url_to_set(links, link_tag.get("href"), effective_base)

    return links


def is_xml_content(content_type, path, body_text):
    content_type = (content_type or "").lower()
    path = (path or "").lower()
    if "xml" in content_type or path.endswith(".xml"):
        return True
    stripped = (body_text or "").lstrip()
    return stripped.startswith("<?xml") or stripped.startswith("<urlset") or stripped.startswith("<sitemapindex")


def is_html_content(content_type, path, body_text):
    if is_xml_content(content_type, path, body_text):
        return False
    content_type = (content_type or "").lower()
    path = (path or "").lower()
    if "html" in content_type:
        return True
    if path.endswith((".html", ".htm", ".xhtml", ".php", ".asp", ".aspx", ".jsp", ".cgi")):
        return True
    stripped = (body_text or "").lstrip().lower()
    return stripped.startswith("<!doctype html") or stripped.startswith("<html")


def extract_urls_from_xml(body_text, base_url):
    urls = set()
    try:
        root = ET.fromstring(body_text)
        for element in root.iter():
            if element.tag.endswith("loc") and element.text:
                add_url_to_set(urls, element.text.strip(), base_url)
    except ET.ParseError:
        for match in re.finditer(r"<loc>\s*(.*?)\s*</loc>", body_text, re.IGNORECASE):
            add_url_to_set(urls, match.group(1), base_url)
    return urls


def extract_urls_from_robots(body_text, base_url):
    urls = set()
    for line in body_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("sitemap:"):
            add_url_to_set(urls, line.split(":", 1)[1].strip(), base_url)
    return urls


def extract_urls_from_content(url, content_type, body_text, base_domain, restrict_domain, extra_urls=None, ignore_robots=True):
    links = set()
    if body_text:
        path = urlparse(url).path.lower()
        if is_html_content(content_type, path, body_text):
            soup = BeautifulSoup(body_text, "html.parser")
            links.update(extract_urls_from_html(soup, url))
            for style_tag in soup.find_all("style"):
                if style_tag.string:
                    links.update(extract_urls_from_css(style_tag.string, url))
        if is_xml_content(content_type, path, body_text):
            links.update(extract_urls_from_xml(body_text, url))
        if "css" in (content_type or "").lower() or path.endswith(".css"):
            links.update(extract_urls_from_css(body_text, url))
        if "javascript" in (content_type or "").lower() or path.endswith((".js", ".mjs")):
            links.update(extract_urls_from_js(body_text, url))
        if not ignore_robots and path.endswith("robots.txt"):
            links.update(extract_urls_from_robots(body_text, url))

    if extra_urls:
        for raw in extra_urls:
            add_url_to_set(links, raw, url)

    return filter_scoped_urls(links, base_domain, restrict_domain)


def extract_links(soup, page_url):
    return extract_urls_from_html(soup, page_url)


def seed_urls(start_url, restrict_domain, ignore_robots=True):
    start_url = canonicalize_crawl_url(start_url, base_url=start_url)
    seeds = [start_url]
    if restrict_domain:
        base = start_url if start_url.endswith("/") else start_url + "/"
        extra_paths = ["sitemap.xml", "sitemap_index.xml"]
        if not ignore_robots:
            extra_paths.insert(0, "robots.txt")
        for path in extra_paths:
            seeds.append(canonicalize_crawl_url(urljoin(base, path), base_url=start_url))
    return seeds


def response_length(response):
    content_length = response.headers.get("content-length")
    if content_length and content_length.isdigit():
        return int(content_length)
    if hasattr(response, "content"):
        return len(response.content)
    return 0


def should_accept_http_status(status_code, bypass_forbidden=True):
    if status_code < 400:
        return True
    if bypass_forbidden and status_code in BYPASS_HTTP_CODES:
        return True
    return False


def raise_unless_acceptable(response, bypass_forbidden=True):
    if not should_accept_http_status(response.status_code, bypass_forbidden):
        response.raise_for_status()


def looks_like_existing_path(
    status_code,
    content_length,
    baseline_length,
    baseline_status,
    bypass_forbidden=True,
    similarity_threshold=50,
):
    if bypass_forbidden and status_code in BYPASS_HTTP_CODES:
        return True
    if status_code not in POSITIVE_STATUS_CODES:
        return False
    if baseline_length and content_length:
        if abs(content_length - baseline_length) < similarity_threshold and status_code == baseline_status:
            return False
    return True


def get_sync_baseline(session, base_url):
    probe_url = build_enum_url(base_url, [], f".crawler-baseline-{uuid.uuid4().hex}")
    try:
        response = session.get(probe_url, timeout=5, allow_redirects=False)
        return response_length(response), response.status_code
    except requests.RequestException:
        return 0, 404


def sync_path_exists(session, url, baseline_length, baseline_status, bypass_forbidden=True):
    try:
        response = session.head(url, timeout=5, allow_redirects=False)
        status = response.status_code
        if status in (405, 501) or (bypass_forbidden and status in BYPASS_HTTP_CODES):
            response = session.get(url, timeout=5, allow_redirects=False, stream=True)
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) >= 8192:
                    break
            response.close()
            content_length = len(content) or response_length(response)
            return looks_like_existing_path(
                response.status_code, content_length, baseline_length, baseline_status, bypass_forbidden
            )
        content_length = response_length(response)
        return looks_like_existing_path(status, content_length, baseline_length, baseline_status, bypass_forbidden)
    except requests.RequestException:
        return False


async def get_async_baseline(client, base_url):
    probe_url = build_enum_url(base_url, [], f".crawler-baseline-{uuid.uuid4().hex}")
    try:
        response = await client.get(probe_url, timeout=5, follow_redirects=False)
        return response_length(response), response.status_code
    except httpx.HTTPError:
        return 0, 404


async def async_path_exists(client, url, baseline_length, baseline_status, bypass_forbidden=True):
    """Existence probe via GET (browser-like; avoids Akamai 'HTTP HEAD Method Used')."""
    try:
        response = await client.get(url, timeout=5, follow_redirects=False)
        content_length = len(response.content) if response.content else response_length(response)
        return looks_like_existing_path(
            response.status_code, content_length, baseline_length, baseline_status, bypass_forbidden
        )
    except httpx.HTTPError:
        return False


def crawl_page_sync(
    session, url, visited, base_domain, restrict_domain, extra_urls=None, ignore_robots=True, bypass_forbidden=True
):
    response = session.get(url, timeout=15)
    raise_unless_acceptable(response, bypass_forbidden)
    content_type = response.headers.get("content-type", "")
    body_text = response.text if is_text_content(content_type, url) else ""
    links = extract_urls_from_content(
        url, content_type, body_text, base_domain, restrict_domain, extra_urls, ignore_robots
    )
    return links, response.content, content_type, dict(response.headers)


async def crawl_page_async(
    client,
    url,
    visited,
    base_domain,
    restrict_domain,
    page_html=None,
    extra_urls=None,
    ignore_robots=True,
    bypass_forbidden=True,
    conditional_headers=None,
):
    response = None
    if page_html is not None:
        content_type = "text/html"
        body = page_html.encode("utf-8")
        body_text = page_html
    else:
        headers = dict(conditional_headers or {})
        response = await client.get(url, timeout=15, headers=headers)
        if response.status_code == 304:
            hdrs = dict(response.headers)
            hdrs["_status_code"] = str(response.status_code)
            return set(), b"", response.headers.get("content-type", ""), hdrs
        raise_unless_acceptable(response, bypass_forbidden)
        content_type = response.headers.get("content-type", "")
        body = response.content
        body_text = body.decode("utf-8", errors="replace") if is_text_content(content_type, url) else ""
    links = extract_urls_from_content(
        url, content_type, body_text, base_domain, restrict_domain, extra_urls, ignore_robots
    )
    resp_headers = dict(response.headers) if response is not None else {}
    if response is not None:
        resp_headers["_status_code"] = str(response.status_code)
    return links, body, content_type, resp_headers


def _write_body_with_progress(filepath, body, update_progress=None):
    total_size = len(body)
    if update_progress and total_size > 0:
        emit_download_progress(
            update_progress,
            total_size,
            0,
            f"Saving {os.path.basename(filepath)} ({format_byte_size(total_size)})",
        )
    written = 0
    with open(filepath, "wb") as handle:
        for offset in range(0, total_size, WRITE_PROGRESS_CHUNK):
            chunk = body[offset : offset + WRITE_PROGRESS_CHUNK]
            handle.write(chunk)
            written += len(chunk)
            if update_progress and total_size > 0:
                emit_download_progress(update_progress, total_size, written, None)
    if update_progress and total_size > 0:
        emit_download_progress(
            update_progress,
            total_size,
            total_size,
            f"Saved {os.path.basename(filepath)} ({format_byte_size(total_size)})",
        )


def save_body_sync(
    url,
    body,
    download_dir,
    output_callback,
    extensions=None,
    preserve_structure=True,
    rewrite_local=True,
    content_type="",
    save_server_side_as_txt=True,
    update_progress=None,
):
    if not extension_allowed(url, extensions):
        output_callback(f"Skipped: {url} (extension filter)")
        return None
    if len(body) > DEFAULT_MAX_DOWNLOAD_BYTES:
        output_callback(f"Skipped: {url} (exceeds size limit)")
        return None

    host = urlparse(url).netloc
    if rewrite_local and preserve_structure and is_text_content(content_type, url):
        try:
            text = body.decode("utf-8", errors="replace")
            text = rewrite_for_local_mirror(text, url, host, content_type)
            body = text.encode("utf-8")
        except UnicodeError:
            pass

    filepath = mirror_filepath(url, download_dir, preserve_structure, save_server_side_as_txt)
    _write_body_with_progress(filepath, body, update_progress)
    if is_server_side_source_url(url) and save_server_side_as_txt:
        output_callback(f"Downloaded server file as text: {url} to {filepath}")
    else:
        output_callback(f"Downloaded: {url} to {filepath}")
    return filepath


async def save_body_async(
    url,
    body,
    download_dir,
    output_callback,
    extensions=None,
    manager=None,
    preserve_structure=True,
    rewrite_local=True,
    content_type="",
    save_server_side_as_txt=True,
    update_progress=None,
    return_asset_urls=False,
):
    if manager and url in manager.cache:
        output_callback(f"Skipped: {url} (already downloaded)")
        return ([], None) if return_asset_urls else None
    if not extension_allowed(url, extensions):
        output_callback(f"Skipped: {url} (extension filter)")
        return ([], None) if return_asset_urls else None
    if len(body) > DEFAULT_MAX_DOWNLOAD_BYTES:
        output_callback(f"Skipped: {url} (exceeds size limit)")
        return ([], None) if return_asset_urls else None

    host = urlparse(url).netloc
    asset_urls = []
    text = None
    if is_text_content(content_type, url):
        try:
            text = body.decode("utf-8", errors="replace")
        except UnicodeError:
            text = None
    if text is not None and (
        "html" in (content_type or "").lower()
        or urlparse(url).path.lower().endswith((".html", ".htm"))
        or text.lstrip()[:20].lower().startswith(("<!doctype", "<html"))
    ):
        asset_urls = extract_page_assets(text, url, host, include_cdn=True)
    if rewrite_local and preserve_structure and text is not None:
        try:
            text = rewrite_for_local_mirror(text, url, host, content_type)
            body = text.encode("utf-8")
        except UnicodeError:
            pass
    elif "css" in (content_type or "").lower() and text is not None and rewrite_local:
        body = _rewrite_css_urls(text, url, host).encode("utf-8")
        asset_urls.extend(extract_urls_from_css(text, url))

    filepath = mirror_filepath(url, download_dir, preserve_structure, save_server_side_as_txt)
    _write_body_with_progress(filepath, body, update_progress)
    if manager:
        manager.cache.add(url)
    if is_server_side_source_url(url) and save_server_side_as_txt:
        output_callback(f"Downloaded server file as text: {url} to {filepath}")
    else:
        output_callback(f"Downloaded: {url} to {filepath}")
    if return_asset_urls:
        return asset_urls, filepath
    return filepath


async def download_referenced_assets(
    client,
    page_url,
    asset_urls,
    download_dir,
    output_callback,
    *,
    manager=None,
    extensions=None,
    preserve_structure=True,
    rewrite_local=True,
    save_server_side_as_txt=True,
    download_semaphore=None,
    bypass_forbidden=True,
    update_progress=None,
    max_assets=200,
    running=None,
    on_body_callback=None,
):
    """Download CSS/JS/images/fonts (same site + CDNs) for a mirrored HTML page."""
    if not asset_urls:
        return 0
    saved = 0
    # Prefer stylesheets/scripts first so offline pages look right
    ordered = sorted(
        asset_urls,
        key=lambda u: (
            0 if ".css" in u.lower() else
            1 if ".js" in u.lower() or ".mjs" in u.lower() else
            2 if any(ext in u.lower() for ext in (".woff", ".ttf", ".eot", ".otf")) else
            3
        ),
    )[:max_assets]
    output_callback(f"Downloading {len(ordered)} supporting file(s) for offline view of {page_url}")

    async def fetch_one(asset_url, *, allow_nested=True):
        nonlocal saved
        if running and not await is_running(running):
            return
        if manager and asset_url in manager.cache:
            return
        if not is_valid_url(asset_url):
            return
        try:
            if download_semaphore is not None:
                async with download_semaphore:
                    response = await client.get(asset_url, timeout=15, follow_redirects=True)
            else:
                response = await client.get(asset_url, timeout=15, follow_redirects=True)
            raise_unless_acceptable(response, bypass_forbidden)
            content_type = response.headers.get("content-type", "")
            body_bytes = response.content or b""
            if on_body_callback:
                try:
                    on_body_callback(asset_url, body_bytes, content_type)
                except Exception:
                    pass
            # Never apply the page extension filter to components — CSS/fonts must always save
            nested, _path = await save_body_async(
                asset_url,
                body_bytes,
                download_dir,
                output_callback,
                None,
                manager,
                preserve_structure,
                rewrite_local,
                content_type,
                save_server_side_as_txt,
                update_progress,
                return_asset_urls=True,
            )
            saved += 1
            if allow_nested and nested and (".css" in asset_url.lower() or "css" in content_type.lower()):
                for nested_url in list(nested)[:40]:
                    await fetch_one(nested_url, allow_nested=False)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            output_callback(f"Could not save asset {asset_url}: {error}")

    for asset_url in ordered:
        await fetch_one(asset_url)
    if saved:
        output_callback(f"Saved {saved} supporting file(s) for {page_url}")
    return saved


def download_file_sync(session, url, download_dir, output_callback, update_progress=None, extensions=None):
    if not extension_allowed(url, extensions):
        output_callback(f"Skipped: {url} (extension filter)")
        return None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = session.get(url, stream=True, timeout=10)
            response.raise_for_status()
            total_size = int(response.headers.get("content-length", 0))
            if total_size > DEFAULT_MAX_DOWNLOAD_BYTES:
                output_callback(f"Skipped: {url} (exceeds size limit)")
                return None

            filepath = unique_filepath(download_dir, safe_filename_from_url(url))
            if update_progress and total_size > 0:
                emit_download_progress(
                    update_progress, total_size, 0, f"Size: {format_byte_size(total_size)}"
                )

            downloaded_size = 0
            with open(filepath, "wb") as handle:
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    downloaded_size += len(chunk)
                    if downloaded_size > DEFAULT_MAX_DOWNLOAD_BYTES:
                        handle.close()
                        os.remove(filepath)
                        output_callback(f"Skipped: {url} (exceeded size limit while downloading)")
                        return None
                    handle.write(chunk)
                    if update_progress and total_size > 0:
                        emit_download_progress(update_progress, total_size, downloaded_size, None)

            output_callback(f"Downloaded: {url} to {filepath}")
            return filepath
        except requests.RequestException as error:
            if attempt == MAX_ATTEMPTS:
                output_callback(f"Error downloading {url} after {MAX_ATTEMPTS} attempts: {error}")
            else:
                output_callback(f"Retrying download for {url} ({attempt}/{MAX_ATTEMPTS})...")
    return None


async def download_file_async(
    client,
    url,
    download_dir,
    output_callback,
    update_progress=None,
    manager=None,
    extensions=None,
    download_semaphore=None,
):
    if manager and url in manager.cache:
        output_callback(f"Skipped: {url} (already downloaded)")
        return None
    if not extension_allowed(url, extensions):
        output_callback(f"Skipped: {url} (extension filter)")
        return None

    async def _download():
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                async with client.stream("GET", url, timeout=10) as response:
                    response.raise_for_status()
                    total_size = int(response.headers.get("content-length", 0))
                    if total_size > DEFAULT_MAX_DOWNLOAD_BYTES:
                        output_callback(f"Skipped: {url} (exceeds size limit)")
                        return None

                    filepath = unique_filepath(download_dir, safe_filename_from_url(url))
                    if update_progress and total_size > 0:
                        emit_download_progress(
                            update_progress, total_size, 0, f"Size: {format_byte_size(total_size)}"
                        )

                    downloaded_size = 0
                    progress = 0
                    with open(filepath, "wb") as handle:
                        async for chunk in response.aiter_bytes(CHUNK_SIZE):
                            if manager and manager.cancelled:
                                raise asyncio.CancelledError()
                            if not chunk:
                                continue
                            downloaded_size += len(chunk)
                            if downloaded_size > DEFAULT_MAX_DOWNLOAD_BYTES:
                                handle.close()
                                os.remove(filepath)
                                output_callback(f"Skipped: {url} (exceeded size limit while downloading)")
                                return None
                            handle.write(chunk)
                            if total_size > 0:
                                progress = (downloaded_size / total_size) * 100
                                if update_progress:
                                    emit_download_progress(update_progress, total_size, downloaded_size, None)
                                if manager:
                                    manager.update_task_progress(url, progress)
                            elif manager and manager.cancelled:
                                raise asyncio.CancelledError()

                    output_callback(f"Downloaded: {url} to {filepath}")
                    if manager:
                        manager.cache.add(url)
                    return filepath
            except asyncio.CancelledError:
                output_callback(f"Cancelled: {url}")
                raise
            except Exception as error:
                if attempt == MAX_ATTEMPTS:
                    output_callback(f"Error downloading {url} after {MAX_ATTEMPTS} attempts: {error}")
                else:
                    output_callback(f"Retrying download for {url} ({attempt}/{MAX_ATTEMPTS})...")
        return None

    if download_semaphore is None:
        return await _download()
    async with download_semaphore:
        return await _download()


# Path segments that look like files — never recurse directory enum under these.
_ENUM_FILE_EXT_RE = re.compile(
    r"(?i)\.("
    r"svg|png|jpe?g|gif|webp|ico|avif|bmp|"
    r"js|mjs|cjs|css|map|wasm|"
    r"woff2?|ttf|eot|otf|"
    r"mp4|webm|mp3|wav|ogg|flac|"
    r"pdf|zip|rar|7z|gz|tgz|tar|bz2|"
    r"html?|xhtml|xml|json|txt|csv|md|"
    r"php\d?|phtml|asp|aspx|jspx?|cgi|pl|"
    r"exe|dll|bin|apk|dmg|iso|"
    r"yml|yaml|toml|ini|cfg|conf|env|bak|old|orig|swp|tmp|log"
    r")$"
)
_ENUM_VERSION_SEGMENT_RE = re.compile(r"(?i)^v?\d+(?:\.\d+)+$")


def looks_like_file_path_segment(segment: str) -> bool:
    """True when a path segment is almost certainly a file, not a folder to recurse into.

    Keeps hits like ``/vite.svg`` or ``/assets/app.js`` recorded, but skips burning the
    full wordlist under ``/vite.svg/…`` (useless on static file responses).
    """
    name = (segment or "").strip().strip("/")
    if not name or name in (".", ".."):
        return False
    # Version folders (v1.2, 2.0.1) and dotted dir names without a file suffix
    if _ENUM_VERSION_SEGMENT_RE.fullmatch(name):
        return False
    # ".well-known" is a directory; do not treat bare dotfiles without a real ext as files
    if name.startswith(".") and name.count(".") == 1 and not _ENUM_FILE_EXT_RE.search(name):
        return False
    return bool(_ENUM_FILE_EXT_RE.search(name))


def format_enum_path(path_segments):
    if not path_segments:
        return "/"
    return "/" + "/".join(path_segments)


def log_enum_batch_progress(
    output_callback,
    path_segments,
    depth,
    index,
    batch_size,
    total_words,
    *,
    stats=None,
    update_progress=None,
    progress_state=None,
    batch_words=None,
    use_cumulative_tested: bool = False,
):
    batch_num = index // batch_size + 1
    total_batches = max(1, (total_words + batch_size - 1) // batch_size)
    words_done = min(index + batch_size, total_words)
    word_pct = min(100, int(words_done * 100 / total_words)) if total_words else 100
    batch_pct = min(100, int(batch_num * 100 / total_batches))
    base = format_enum_path(path_segments)
    current_word = ""
    if batch_words:
        current_word = str(batch_words[0] or "")
    elif hasattr(stats, "enum_current_word"):
        current_word = str(getattr(stats, "enum_current_word", "") or "")

    # Always refresh cockpit counters / current probe — even when we skip log spam
    if stats is not None:
        if use_cumulative_tested and hasattr(stats, "note_enum_progress"):
            # Probe counter is advanced in check_word; only refresh current probe label here
            stats.note_enum_progress(
                int(getattr(stats, "enum_words_tested", 0) or 0),
                word=current_word,
                path=base,
                depth=depth,
            )
        elif hasattr(stats, "note_enum_progress"):
            stats.note_enum_progress(
                words_done,
                word=current_word,
                path=base,
                depth=depth,
            )
        else:
            stats.enum_words_tested = words_done
        if progress_state is not None and progress_state.get("started_at") is None:
            progress_state["started_at"] = time.time()
            if getattr(stats, "enum_started_at", None) is None:
                stats.enum_started_at = progress_state["started_at"]

    if stats is not None and use_cumulative_tested:
        display_done = int(getattr(stats, "enum_words_tested", 0) or 0)
        display_total = max(int(getattr(stats, "enum_words_total", 0) or 0), total_words, 1)
    else:
        display_done = words_done
        display_total = total_words or 1
    display_pct = min(100, int(display_done * 100 / display_total)) if display_total else 100

    if total_batches > 5000:
        log_every = 1
    elif total_batches > 500:
        log_every = 5
    else:
        log_every = 10
    if batch_num != 1 and batch_num % log_every != 0:
        if update_progress and display_total and stats is not None:
            update_progress(
                display_total,
                display_done,
                format_enum_progress(display_done, display_total, stats.enum_hits if stats else 0),
            )
        return

    eta_text = ""
    if progress_state is not None:
        now = time.time()
        if progress_state.get("started_at") is None:
            progress_state["started_at"] = now
        # Prefer enum-phase ETA from stats (blended); fall back to simple phase rate
        eta_sec = None
        if stats is not None and hasattr(stats, "enum_eta_seconds"):
            eta_sec = stats.enum_eta_seconds()
        if eta_sec is None:
            elapsed = max(now - progress_state["started_at"], 0.001)
            rate = display_done / elapsed
            progress_state["rate"] = rate
            if rate > 0 and display_done < display_total and (display_done >= 200 or elapsed >= 10):
                eta_sec = int((display_total - display_done) / rate)
        if eta_sec is not None and eta_sec >= 0 and display_done < display_total:
            if eta_sec >= 3600:
                eta_text = f" · ETA ~{eta_sec // 3600}h {(eta_sec % 3600) // 60}m"
            elif eta_sec >= 60:
                eta_text = f" · ETA ~{eta_sec // 60}m {eta_sec % 60}s"
            else:
                eta_text = f" · ETA ~{eta_sec}s"

    probe_bit = f" · trying {current_word}" if current_word else ""
    output_callback(
        f"Brute force depth {depth} ({display_pct}% · batch {batch_pct}%): "
        f"{display_done:,}/{display_total:,} probes · batch {batch_num:,}/{total_batches:,} "
        f"under {base}{probe_bit}{eta_text}"
    )
    if stats is not None:
        output_callback(stats.format_friendly_line())
    if update_progress and display_total:
        update_progress(
            display_total,
            display_done,
            format_enum_progress(display_done, display_total, stats.enum_hits if stats else 0),
        )


def save_enum_hit_sync(
    session,
    url,
    download_dir,
    output_callback,
    extensions,
    preserve_structure=True,
    rewrite_local=True,
    save_server_side_as_txt=True,
    bypass_forbidden=True,
    update_progress=None,
):
    try:
        response = session.get(url, timeout=15)
        raise_unless_acceptable(response, bypass_forbidden)
        content_type = response.headers.get("content-type", "")
        save_body_sync(
            url,
            response.content,
            download_dir,
            output_callback,
            extensions,
            preserve_structure,
            rewrite_local,
            content_type,
            save_server_side_as_txt,
            update_progress,
        )
    except requests.RequestException as error:
        output_callback(f"Could not save {url}: {error}")


async def save_enum_hit_async(
    client,
    url,
    download_dir,
    output_callback,
    extensions,
    manager=None,
    preserve_structure=True,
    rewrite_local=True,
    save_server_side_as_txt=True,
    download_semaphore=None,
    bypass_forbidden=True,
    update_progress=None,
    mirror_page_assets=True,
    running=None,
):
    async def _save():
        try:
            response = await client.get(url, timeout=15, follow_redirects=True)
            raise_unless_acceptable(response, bypass_forbidden)
            content_type = response.headers.get("content-type", "")
            asset_urls, _path = await save_body_async(
                url,
                response.content,
                download_dir,
                output_callback,
                extensions,
                manager,
                preserve_structure,
                rewrite_local,
                content_type,
                save_server_side_as_txt,
                update_progress,
                return_asset_urls=True,
            )
            if mirror_page_assets and asset_urls:
                await download_referenced_assets(
                    client,
                    url,
                    asset_urls,
                    download_dir,
                    output_callback,
                    manager=manager,
                    extensions=extensions,
                    preserve_structure=preserve_structure,
                    rewrite_local=rewrite_local,
                    save_server_side_as_txt=save_server_side_as_txt,
                    download_semaphore=download_semaphore,
                    bypass_forbidden=bypass_forbidden,
                    update_progress=update_progress,
                    running=running,
                )
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, OSError, ValueError) as error:
            output_callback(f"Could not save {url}: {error}")

    # Do not wrap the whole save in download_semaphore: _save → mirror assets
    # acquires the same semaphore per file (non-reentrant → self-deadlock).
    await _save()


def enumerate_directories_sync(
    base_url,
    wordlist_file,
    output_callback,
    is_running_func,
    output_file_path,
    download_files=False,
    download_dir=None,
    update_progress=None,
    extensions=None,
    max_depth=1,
    enum_batch_size=DEFAULT_ENUM_CONCURRENCY,
    discovered=None,
    preserve_structure=True,
    rewrite_local=True,
    save_server_side_as_txt=True,
):
    found_paths = []
    found_set = set()
    discovered = discovered if discovered is not None else set()
    words = load_wordlist(wordlist_file)
    session = requests.Session()
    session.headers.update(get_request_headers())
    baseline_length, baseline_status = get_sync_baseline(session, base_url)
    extensions = normalize_extensions(extensions)

    def enumerate_level(path_segments, depth):
        if depth > max_depth or not is_running_func():
            return
        if depth > 0:
            output_callback(
                f"Brute force depth {depth}: scanning {len(words)} paths under {format_enum_path(path_segments)}"
            )
        for index in range(0, len(words), enum_batch_size):
            if not is_running_func():
                return
            log_enum_batch_progress(
                output_callback, path_segments, depth, index, enum_batch_size, len(words)
            )
            batch = words[index : index + enum_batch_size]
            for word in batch:
                if not is_running_func():
                    return
                test_url = build_enum_url(base_url, path_segments, word)
                if not test_url:
                    continue
                try:
                    if sync_path_exists(session, test_url, baseline_length, baseline_status):
                        if test_url in found_set:
                            continue
                        found_set.add(test_url)
                        found_paths.append(test_url)
                        if test_url not in discovered:
                            discovered.add(test_url)
                            output_callback(f"Found: {test_url}")
                            log_to_file(output_file_path, test_url)
                        if download_files and download_dir:
                            save_enum_hit_sync(
                                session,
                                test_url,
                                download_dir,
                                output_callback,
                                extensions,
                                preserve_structure,
                                rewrite_local,
                                save_server_side_as_txt,
                            )
                        if looks_like_file_path_segment(word):
                            output_callback(
                                f"Skipping folder enum under file hit "
                                f"{format_enum_path(path_segments + [word])}"
                            )
                        else:
                            enumerate_level(path_segments + [word], depth + 1)
                except requests.RequestException as error:
                    output_callback(f"Error accessing {test_url}: {error}")

    enumerate_level([], 0)
    output_callback("Directory brute force finished.")
    return found_paths


async def enumerate_directories_async(
    base_url,
    wordlist_file,
    output_callback,
    is_running_func,
    output_file_path,
    client,
    download_files=False,
    download_dir=None,
    update_progress=None,
    manager=None,
    extensions=None,
    max_depth=3,
    enum_concurrency=DEFAULT_ENUM_CONCURRENCY,
    download_semaphore=None,
    discovered=None,
    preserve_structure=True,
    rewrite_local=True,
    save_server_side_as_txt=True,
):
    found_paths = []
    found_set = set()
    discovered = discovered if discovered is not None else set()
    words = load_wordlist(wordlist_file)
    baseline_length, baseline_status = await get_async_baseline(client, base_url)
    extensions = normalize_extensions(extensions)

    async def check_word(path_segments, word):
        if not is_running_func():
            return None
        test_url = build_enum_url(base_url, path_segments, word)
        if not test_url:
            return None
        if not is_running_func():
            return None
        if await async_path_exists(client, test_url, baseline_length, baseline_status):
            return word, test_url
        return None

    async def enumerate_level(path_segments, depth):
        if depth > max_depth or not is_running_func():
            return
        if depth > 0:
            output_callback(
                f"Brute force depth {depth}: scanning {len(words)} paths under {format_enum_path(path_segments)}"
            )

        for index in range(0, len(words), enum_concurrency):
            if not is_running_func():
                return
            log_enum_batch_progress(
                output_callback, path_segments, depth, index, enum_concurrency, len(words)
            )
            batch = words[index : index + enum_concurrency]
            tasks = [asyncio.create_task(check_word(path_segments, word)) for word in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if not is_running_func():
                    return
                if isinstance(result, Exception):
                    output_callback(f"Error during enumeration: {result}")
                    continue
                if not result:
                    continue
                word, test_url = result
                if test_url in found_set:
                    continue
                found_set.add(test_url)
                found_paths.append(test_url)
                if test_url not in discovered:
                    discovered.add(test_url)
                    output_callback(f"Found: {test_url}")
                    log_to_file(output_file_path, test_url)
                if download_files and download_dir:
                    await save_enum_hit_async(
                        client,
                        test_url,
                        download_dir,
                        output_callback,
                        extensions,
                        manager,
                        preserve_structure,
                        rewrite_local,
                        save_server_side_as_txt,
                        download_semaphore,
                    )
                if looks_like_file_path_segment(word):
                    output_callback(
                        f"Skipping folder enum under file hit "
                        f"{format_enum_path(path_segments + [word])}"
                    )
                else:
                    await enumerate_level(path_segments + [word], depth + 1)

    await enumerate_level([], 0)
    output_callback("Directory brute force finished.")
    return found_paths


def init_crawl_state(start_url, restrict_domain, ignore_robots=True, extra_seeds=None):
    discovered = set()
    queue = deque()
    seeds = list(seed_urls(start_url, restrict_domain, ignore_robots))
    if extra_seeds:
        seeds.extend(extra_seeds)
    for seed_url in seeds:
        if not is_valid_url(seed_url):
            continue
        if seed_url not in discovered:
            discovered.add(seed_url)
            queue.append(seed_url)
    return discovered, queue


def enqueue_discovered_url(
    url,
    discovered,
    queue,
    output_file_path,
    output_callback,
    stats=None,
    use_priority=False,
    link_depth=0,
    max_link_depth=0,
    link_depths=None,
):
    if max_link_depth and link_depth > max_link_depth:
        return False
    try:
        url = canonicalize_crawl_url(url, base_url=url)
    except Exception:
        pass
    if url in discovered:
        return False
    discovered.add(url)
    if link_depths is not None:
        link_depths[url] = link_depth
    output_callback(f"Found: {url}")
    log_to_file(output_file_path, url)
    if stats is not None:
        stats.links_found += 1
        if hasattr(stats, "discovered_urls"):
            stats.discovered_urls.add(url)
    if use_priority:
        import heapq

        priority = 0 if is_html_url(url) else 1
        heapq.heappush(queue, (priority, len(discovered), url))
    else:
        queue.append(url)
    return True


def _should_skip_url(current_url, visited, ignore_robots):
    if current_url in visited:
        return True
    if ignore_robots and urlparse(current_url).path.lower().endswith("robots.txt"):
        visited.add(current_url)
        return True
    return False


def run_bfs_crawl_sync(
    start_url,
    wordlist_file,
    output_callback,
    is_running_func,
    output_file_path,
    restrict_domain=True,
    download_files=False,
    download_dir=None,
    update_progress=None,
    extensions=None,
    max_depth=1,
    preserve_structure=True,
    rewrite_local=True,
    ignore_robots=True,
    save_server_side_as_txt=True,
):
    discovered, queue = init_crawl_state(start_url, restrict_domain, ignore_robots)
    visited = set()
    base_domain = urlparse(start_url).netloc
    session = requests.Session()
    session.headers.update(get_request_headers())
    extensions = normalize_extensions(extensions)

    while queue and is_running_func():
        current_url = queue.popleft()
        if _should_skip_url(current_url, visited, ignore_robots):
            continue
        output_callback(f"Crawling: {current_url}")
        visited.add(current_url)
        try:
            new_links, body, content_type, _headers = crawl_page_sync(
                session, current_url, visited, base_domain, restrict_domain, ignore_robots=ignore_robots
            )
            if download_files and download_dir:
                save_body_sync(
                    current_url,
                    body,
                    download_dir,
                    output_callback,
                    extensions,
                    preserve_structure,
                    rewrite_local,
                    content_type,
                    save_server_side_as_txt,
                )
            for link in new_links:
                enqueue_discovered_url(link, discovered, queue, output_file_path, output_callback)
        except requests.RequestException as error:
            output_callback(f"Error accessing {current_url}: {error}")

    if is_running_func():
        output_callback("\nEnumerating common directories:")
        enumerate_directories_sync(
            start_url,
            wordlist_file,
            output_callback,
            is_running_func,
            output_file_path,
            download_files,
            download_dir,
            update_progress,
            extensions,
            max_depth=max_depth,
            discovered=discovered,
            preserve_structure=preserve_structure,
            rewrite_local=rewrite_local,
            save_server_side_as_txt=save_server_side_as_txt,
        )


async def run_bfs_crawl_async(
    start_url,
    wordlist_file,
    output_callback,
    is_running_func,
    output_file_path,
    restrict_domain=True,
    download_files=False,
    download_dir=None,
    update_progress=None,
    manager=None,
    extensions=None,
    max_depth=3,
    enum_concurrency=DEFAULT_ENUM_CONCURRENCY,
    download_concurrency=DEFAULT_DOWNLOAD_CONCURRENCY,
    page_html_fetcher=None,
    deep_render=False,
    preserve_structure=True,
    rewrite_local=True,
    ignore_robots=True,
    save_server_side_as_txt=True,
):
    discovered, queue = init_crawl_state(start_url, restrict_domain, ignore_robots)
    visited = set()
    base_domain = urlparse(start_url).netloc
    download_semaphore = asyncio.Semaphore(download_concurrency)
    headers = get_request_headers()
    extensions = normalize_extensions(extensions)

    async with httpx.AsyncClient(http2=True, headers=headers, follow_redirects=True) as client:
        while queue and is_running_func():
            current_url = queue.popleft()
            if _should_skip_url(current_url, visited, ignore_robots):
                continue
            output_callback(f"Crawling: {current_url}")
            visited.add(current_url)
            try:
                page_html = None
                extra_urls = None
                use_browser = page_html_fetcher and is_html_url(current_url)
                if use_browser:
                    fetch_result = await page_html_fetcher(client, current_url, deep_render)
                    if isinstance(fetch_result, tuple):
                        page_html = fetch_result[0]
                        extra_urls = fetch_result[1] if len(fetch_result) > 1 else None
                    else:
                        page_html = fetch_result
                new_links, body, content_type, _headers = await crawl_page_async(
                    client,
                    current_url,
                    visited,
                    base_domain,
                    restrict_domain,
                    page_html=page_html,
                    extra_urls=extra_urls,
                    ignore_robots=ignore_robots,
                )
                if download_files and download_dir:
                    async with download_semaphore:
                        await save_body_async(
                            current_url,
                            body,
                            download_dir,
                            output_callback,
                            extensions,
                            manager,
                            preserve_structure,
                            rewrite_local,
                            content_type,
                            save_server_side_as_txt,
                        )
                for link in new_links:
                    enqueue_discovered_url(link, discovered, queue, output_file_path, output_callback)
            except Exception as error:
                output_callback(f"Error accessing {current_url}: {error}")

        if is_running_func():
            output_callback("\nEnumerating common directories:")
            await enumerate_directories_async(
                start_url,
                wordlist_file,
                output_callback,
                is_running_func,
                output_file_path,
                client,
                download_files,
                download_dir,
                update_progress,
                manager,
                extensions,
                max_depth=max_depth,
                enum_concurrency=enum_concurrency,
                download_semaphore=download_semaphore,
                discovered=discovered,
                preserve_structure=preserve_structure,
                rewrite_local=rewrite_local,
                save_server_side_as_txt=save_server_side_as_txt,
            )
