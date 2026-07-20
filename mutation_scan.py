"""Built-in paths and seed-token mutations — merged on top of file wordlists."""

from __future__ import annotations

import itertools
import re
from typing import Iterable, List, Set
from urllib.parse import urlparse

# High-value paths when no external wordlist is used
BUILTIN_COMMON_PATHS = (
    "admin", "administrator", "login", "signin", "dashboard", "api", "v1", "v2", "graphql",
    "backup", "backups", "bak", "old", "tmp", "temp", "test", "dev", "staging", "beta",
    "config", "configuration", "settings", "setup", "install", "console", "manager",
    "upload", "uploads", "files", "file", "data", "db", "database", "sql", "dump",
    "logs", "log", "debug", "trace", "status", "health", "metrics", "actuator",
    "wp-admin", "wp-content", "wp-includes", "wordpress", "phpmyadmin", "pma",
    ".git", ".svn", ".hg", ".env", ".htaccess", ".htpasswd", "web.config", "robots.txt",
    "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "server-status", "server-info", "info.php", "phpinfo.php", "test.php", "shell.php",
    "assets", "static", "public", "private", "internal", "secure", "secret",
    "cgi-bin", "scripts", "js", "css", "images", "img", "media", "content",
    "account", "accounts", "user", "users", "register", "signup", "oauth", "auth",
    "swagger", "swagger-ui", "openapi.json", "api-docs", "docs", "documentation",
    "vendor", "node_modules", "storage", "cache", "session", "sessions",
)

MUTATION_SUFFIXES = (
    "", "~", ".bak", ".old", ".save", ".swp", ".tmp", ".txt", ".zip", ".tar.gz",
    "_backup", "-backup", ".1", ".2", ".copy", ".orig",
)

MUTATION_PREFIXES = (".", "_", "-", "~")


def extract_seed_tokens(urls: Iterable[str], limit: int = 300) -> List[str]:
    tokens: List[str] = []
    seen: Set[str] = set()
    for url in urls:
        path = urlparse(url).path.strip("/")
        if not path:
            continue
        for part in re.split(r"[/._-]+", path):
            part = part.strip().lower()
            if len(part) < 2 or part in seen or part.isdigit():
                continue
            seen.add(part)
            tokens.append(part)
            if len(tokens) >= limit:
                return tokens
    return tokens


def mutate_token(token: str, extensions: List[str]) -> Set[str]:
    token = token.strip().strip("/").lower()
    if not token or token.startswith("#"):
        return set()
    out: Set[str] = set()
    bases = {token, token.upper(), token.capitalize(), token.replace("-", "_"), token.replace("_", "-")}
    for base in bases:
        if not base:
            continue
        out.add(base)
        for prefix in MUTATION_PREFIXES:
            if not base.startswith(prefix):
                out.add(prefix + base)
        for suffix in MUTATION_SUFFIXES:
            out.add(base + suffix)
        if "." not in base:
            for ext in extensions:
                ext = ext if ext.startswith(".") else f".{ext}"
                out.add(base + ext)
    return {item.strip("/") for item in out if item and len(item) < 120}


def build_mutation_wordlist(
    seed_urls: Iterable[str],
    *,
    use_builtin: bool = True,
    mutate_seeds: bool = True,
    extensions: List[str] | None = None,
    max_candidates: int = 50_000,
) -> List[str]:
    extensions = extensions or ["php", "bak", "txt", "zip", "old"]
    ordered: List[str] = []
    seen: Set[str] = set()

    def add(word: str):
        word = word.strip().strip("/")
        if not word or word in seen:
            return
        seen.add(word)
        ordered.append(word)

    if use_builtin:
        for path in BUILTIN_COMMON_PATHS:
            add(path)
            if len(ordered) >= max_candidates:
                return ordered

    if mutate_seeds:
        for token in extract_seed_tokens(seed_urls):
            for variant in mutate_token(token, extensions):
                add(variant)
                if len(ordered) >= max_candidates:
                    return ordered

    return ordered
