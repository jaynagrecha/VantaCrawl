import asyncio

from crawl_config import CrawlConfig
from enum_engine import (
    WildcardProfile,
    build_smart_wordlist,
    build_status_filter,
    body_fingerprint,
    follow_same_host_redirects,
    hosts_compatible,
    is_probe_hit,
    iter_gobuster_word_variants,
    parse_int_list,
    parse_status_code_list,
    ProbeResult,
)
from mutation_scan import build_mutation_wordlist
from false_positive_store import FalsePositiveStore


def test_gobuster_word_variants():
    config = CrawlConfig(start_url="https://example.com", gobuster_style_extensions=True, enum_extensions="php,txt")
    variants = iter_gobuster_word_variants("admin", config)
    assert variants == ["admin", "admin.php", "admin.txt"]
    assert iter_gobuster_word_variants("page.html", config) == ["page.html"]


def test_status_filter_blacklist():
    config = CrawlConfig(start_url="https://example.com", enum_status_blacklist="404,500")
    filt = build_status_filter(config)
    assert not filt.allows(404)
    assert not filt.allows(500)
    assert filt.allows(200)


def test_default_status_filter_scores_final_not_redirect():
    """Redirect codes are resolved before scoring — 301 alone is not a hit."""
    filt = build_status_filter(CrawlConfig(start_url="https://example.com"))
    assert filt.allows(200)
    assert filt.allows(401)
    assert filt.allows(403)
    assert not filt.allows(301)
    assert not filt.allows(302)
    assert not filt.allows(404)


def test_wildcard_rejects_cluster():
    config = CrawlConfig(start_url="https://example.com", wildcard_detection=True, smart_false_positive=True)
    filt = build_status_filter(config)
    wildcard = WildcardProfile(active=True, signatures={(200, 1234, "abc")})
    probe = ProbeResult("https://x.com/a", "a", 200, 1234, "abc", [])
    assert not is_probe_hit(
        probe,
        status_filter=filt,
        wildcard=wildcard,
        baseline=(0, 404),
        config=config,
        fp_store=None,
        exclude_lengths=set(),
        exclude_hashes=set(),
    )


def test_false_positive_store():
    store = FalsePositiveStore("")
    store.record(200, 100, "deadbeef", "https://x.com/a")
    assert store.is_false_positive(200, 100, "deadbeef", "https://x.com/a")


def test_build_mutation_wordlist_builtin():
    words = build_mutation_wordlist([], use_builtin=True, mutate_seeds=False, max_candidates=100)
    assert "admin" in words
    assert "api" in words
    assert len(words) <= 100


def test_build_mutation_wordlist_from_seeds():
    words = build_mutation_wordlist(
        ["https://example.com/my-app/dashboard"],
        use_builtin=False,
        mutate_seeds=True,
        extensions=["php"],
        max_candidates=500,
    )
    assert any("my" in w or "app" in w or "dashboard" in w for w in words)


def test_build_smart_wordlist_adds_mutations_with_wordlist():
    config = CrawlConfig(
        start_url="https://example.com",
        use_wordlist=True,
        mutation_enum=True,
        mutation_builtin=True,
        mutation_from_seeds=False,
        mutation_max_candidates=50,
    )
    words = build_smart_wordlist(
        config,
        seed_urls=["https://example.com"],
        merge_fn=lambda *a, **k: ["custompath"],
    )
    assert "admin" in words
    assert "custompath" in words
    assert len(words) >= 2


def test_build_smart_wordlist_mutations_without_file_wordlist():
    config = CrawlConfig(
        start_url="https://example.com",
        use_wordlist=False,
        mutation_enum=True,
        mutation_builtin=True,
        mutation_from_seeds=False,
        mutation_max_candidates=50,
    )
    words = build_smart_wordlist(
        config, seed_urls=["https://example.com"], merge_fn=lambda *a, **k: ["ignored"]
    )
    assert "admin" in words
    assert "ignored" not in words
    assert len(words) <= 50


def test_build_smart_wordlist_respects_enum_word_limit_at_load():
    """Limit must truncate during merge — not after reading an entire huge file."""
    calls = {}

    def merge(primary, extras, max_words=0):
        calls["max_words"] = max_words
        return [f"w{i}" for i in range(max_words or 100)]

    config = CrawlConfig(
        start_url="https://example.com",
        use_wordlist=True,
        mutation_enum=False,
        smart_wordlist_order=False,
        enum_word_limit=25,
    )
    words = build_smart_wordlist(
        config,
        seed_urls=["https://example.com/a/b"],
        merge_fn=merge,
    )
    assert calls.get("max_words") == 25
    assert len(words) <= 25


def test_hosts_compatible_www_and_scheme():
    assert hosts_compatible("http://www.example.com/a", "https://www.example.com/a")
    assert hosts_compatible("https://example.com/a", "https://www.example.com/a")
    assert not hosts_compatible("https://example.com/a", "https://evil.com/a")


def test_follow_redirect_to_404_final_status():
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith("http://www.example.com/"):
            return httpx.Response(
                301,
                headers={"Location": "https://www.example.com/.well-known/change-password"},
            )
        if "change-password" in url:
            return httpx.Response(404, text="We can't seem to find the page")
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)

    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            status, _length, _hash, body, final, hops = await follow_same_host_redirects(
                client,
                "http://www.example.com/.well-known/change-password",
                max_hops=5,
            )
            return status, body, final, hops

    status, body, final, hops = asyncio.run(_run())
    assert status == 404
    assert hops == 1
    assert final.startswith("https://www.example.com/")
    assert b"can't seem to find" in body
    filt = build_status_filter(CrawlConfig(start_url="https://www.example.com"))
    assert not filt.allows(status)


def test_follow_redirect_to_200_is_hit():
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/admin") and request.url.scheme == "http":
            return httpx.Response(302, headers={"Location": "https://example.com/admin"})
        return httpx.Response(200, text="login form")

    transport = httpx.MockTransport(handler)

    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await follow_same_host_redirects(client, "http://example.com/admin", max_hops=3)

    status, _length, _hash, body, final, hops = asyncio.run(_run())
    assert status == 200
    assert hops == 1
    assert b"login" in body
    filt = build_status_filter(CrawlConfig(start_url="https://example.com"))
    assert filt.allows(status)


def test_active_probe_detects_reflected_xss():
    from security_scan import run_active_vuln_probes

    class FakeResponse:
        def __init__(self, text):
            self.text = text

    class FakeClient:
        async def get(self, url, params=None, timeout=8, follow_redirects=True):
            params = params or {}
            joined = " ".join(str(v) for v in params.values())
            if "<crawler-xss-probe>" in joined:
                return FakeResponse("hello <crawler-xss-probe> world")
            return FakeResponse("hello world")

        async def post(self, url, data=None, timeout=8, follow_redirects=True):
            return FakeResponse("hello world")

    findings = asyncio.run(
        run_active_vuln_probes(
            FakeClient(),
            "https://example.com/search?q=test",
            max_params=1,
            max_forms=0,
        )
    )
    assert any(f[0] == "xss" and f[1] == "high" for f in findings)
