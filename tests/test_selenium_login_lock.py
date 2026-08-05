"""Runtime proof that Selenium login holds browser_fetch.selenium_driver_lock."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import auth_login
import browser_fetch as bf
from browser_fetch import apply_selenium_login, selenium_driver_lock


class _FakeEl:
    def __init__(self) -> None:
        self.cleared = 0
        self.keys: list[str] = []
        self.clicked = 0
        self.submitted = 0

    def clear(self) -> None:
        self.cleared += 1

    def send_keys(self, value: str) -> None:
        self.keys.append(str(value))

    def click(self) -> None:
        self.clicked += 1

    def submit(self) -> None:
        self.submitted += 1


class _FakeDriver:
    """Records whether selenium_driver_lock was owned at each WebDriver op."""

    def __init__(self) -> None:
        self.ops: list[tuple[str, bool]] = []
        self.current_url = "https://lab.example/login"
        self._user = _FakeEl()
        self._pass = _FakeEl()
        self._submit = _FakeEl()
        self.cookies = [{"name": "sid", "value": "abc"}]

    def _owned(self) -> bool:
        return bool(selenium_driver_lock()._is_owned())

    def get(self, url: str) -> None:
        self.ops.append(("get", self._owned()))
        self.current_url = str(url)

    def find_elements(self, by, selector: str):
        self.ops.append(("find_elements", self._owned()))
        sel = (selector or "").lower()
        if "password" in sel:
            return [self._pass]
        if "submit" in sel or "login" in sel or "button" in sel:
            return [self._submit]
        return [self._user]

    def get_cookies(self):
        self.ops.append(("get_cookies", self._owned()))
        return list(self.cookies)


def _cfg(**kwargs):
    base = dict(
        use_selenium_login=True,
        login_url="https://lab.example/login",
        login_username="u",
        login_password="p",
        proxy_url="",
        start_url="https://lab.example/",
        cookie_string="",
    )
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_selenium_login_fails_closed_without_shared_lock():
    with pytest.raises(RuntimeError, match="selenium_driver_lock"):
        auth_login.selenium_login(
            "https://lab.example/login",
            "u",
            "p",
            settle_seconds=0,
            driver_factory=lambda: _FakeDriver(),
        )


def test_apply_selenium_login_holds_lock_for_entire_driver_sequence(monkeypatch):
    driver = _FakeDriver()
    seen_owned_at_call: list[bool] = []

    def _factory():
        seen_owned_at_call.append(selenium_driver_lock()._is_owned())
        return driver

    monkeypatch.setattr(bf, "chrome_available", lambda: True)
    monkeypatch.setattr(bf, "pick_user_agent_for_selenium", lambda _c: "ua")
    monkeypatch.setattr(bf, "get_selenium_driver", lambda *a, **k: _factory())
    monkeypatch.setattr(auth_login.time, "sleep", lambda *_a, **_k: None)

    out = apply_selenium_login(_cfg())
    assert "sid=abc" in (out.cookie_string or "")
    assert seen_owned_at_call and all(seen_owned_at_call)
    assert driver.ops
    assert all(owned for _op, owned in driver.ops), driver.ops
    # Navigate + element lookup + cookie extract all covered
    names = [op for op, _ in driver.ops]
    assert "get" in names
    assert "find_elements" in names
    assert "get_cookies" in names
    # Lock released after success
    assert not selenium_driver_lock()._is_owned()


def test_apply_selenium_login_releases_lock_after_failure(monkeypatch):
    class _BoomDriver(_FakeDriver):
        def get(self, url: str) -> None:
            super().get(url)
            raise RuntimeError("nav failed")

    monkeypatch.setattr(bf, "chrome_available", lambda: True)
    monkeypatch.setattr(bf, "pick_user_agent_for_selenium", lambda _c: "ua")
    monkeypatch.setattr(bf, "get_selenium_driver", lambda *a, **k: _BoomDriver())
    monkeypatch.setattr(auth_login.time, "sleep", lambda *_a, **_k: None)

    with pytest.raises(RuntimeError, match="nav failed"):
        apply_selenium_login(_cfg())
    assert not selenium_driver_lock()._is_owned()


def test_login_and_xss_eval_cannot_use_driver_simultaneously(monkeypatch):
    """Login holds the shared lock for the full sequence; XSS wait cannot enter mid-flight."""
    login_entered = threading.Event()
    xss_blocked_while_login = threading.Event()
    release_login = threading.Event()
    errors: list[str] = []

    class _SlowLoginDriver(_FakeDriver):
        def get(self, url: str) -> None:
            super().get(url)
            login_entered.set()
            if not release_login.wait(timeout=3.0):
                errors.append("login timeout waiting for release")

    monkeypatch.setattr(bf, "chrome_available", lambda: True)
    monkeypatch.setattr(bf, "pick_user_agent_for_selenium", lambda _c: "ua")
    monkeypatch.setattr(bf, "get_selenium_driver", lambda *a, **k: _SlowLoginDriver())
    monkeypatch.setattr(auth_login.time, "sleep", lambda *_a, **_k: None)

    def _login():
        apply_selenium_login(_cfg())

    def _xss_critical():
        if not login_entered.wait(timeout=3.0):
            errors.append("xss never saw login enter")
            return
        # Non-blocking probe: if lock is free, XSS could race the shared driver.
        acquired = selenium_driver_lock().acquire(blocking=False)
        if acquired:
            errors.append("xss acquired lock while login held it")
            selenium_driver_lock().release()
            release_login.set()
            return
        xss_blocked_while_login.set()
        release_login.set()
        # After login finishes, lock must become available.
        with selenium_driver_lock():
            pass

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(_login), pool.submit(_xss_critical)]
        wait(futs, timeout=5.0)
        for f in futs:
            f.result(timeout=1.0)

    assert not errors, errors
    assert xss_blocked_while_login.is_set()
    assert not selenium_driver_lock()._is_owned()


def test_login_and_dom_clobber_cannot_use_driver_simultaneously(monkeypatch):
    login_entered = threading.Event()
    dc_blocked = threading.Event()
    release_login = threading.Event()
    errors: list[str] = []

    class _SlowLoginDriver(_FakeDriver):
        def get(self, url: str) -> None:
            super().get(url)
            login_entered.set()
            if not release_login.wait(timeout=3.0):
                errors.append("login timeout")

    monkeypatch.setattr(bf, "chrome_available", lambda: True)
    monkeypatch.setattr(bf, "pick_user_agent_for_selenium", lambda _c: "ua")
    monkeypatch.setattr(bf, "get_selenium_driver", lambda *a, **k: _SlowLoginDriver())
    monkeypatch.setattr(auth_login.time, "sleep", lambda *_a, **_k: None)

    def _login():
        apply_selenium_login(_cfg())

    def _dom_clobber_critical():
        if not login_entered.wait(timeout=3.0):
            errors.append("dc never saw login")
            return
        acquired = selenium_driver_lock().acquire(blocking=False)
        if acquired:
            errors.append("dom_clobber acquired lock while login held it")
            selenium_driver_lock().release()
            release_login.set()
            return
        dc_blocked.set()
        release_login.set()
        with selenium_driver_lock():
            pass

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(_login), pool.submit(_dom_clobber_critical)]
        wait(futs, timeout=5.0)
        for f in futs:
            f.result(timeout=1.0)

    assert not errors, errors
    assert dc_blocked.is_set()
    assert not selenium_driver_lock()._is_owned()


def test_nested_locked_helper_during_login_does_not_deadlock(monkeypatch):
    """get_selenium_driver re-enters the same RLock while login holds it."""
    calls: list[str] = []

    real_get = bf.get_selenium_driver

    def _wrapped_get(*a, **k):
        calls.append("get_selenium_driver")
        assert selenium_driver_lock()._is_owned()
        # Re-enter shared lock (same pattern as production nested helpers).
        with selenium_driver_lock():
            calls.append("nested")
            return _FakeDriver()

    monkeypatch.setattr(bf, "chrome_available", lambda: True)
    monkeypatch.setattr(bf, "pick_user_agent_for_selenium", lambda _c: "ua")
    monkeypatch.setattr(bf, "get_selenium_driver", _wrapped_get)
    monkeypatch.setattr(auth_login.time, "sleep", lambda *_a, **_k: None)

    apply_selenium_login(_cfg())
    assert calls == ["get_selenium_driver", "nested"]
    assert not selenium_driver_lock()._is_owned()
    del real_get  # silence unused


def test_login_sequence_serialized_under_single_critical_section(monkeypatch):
    """No lock release between get → find → interact → cookies."""
    ownership_trace: list[bool] = []
    driver = _FakeDriver()

    orig_get = driver.get
    orig_find = driver.find_elements
    orig_cookies = driver.get_cookies

    def _traced_get(url):
        ownership_trace.append(selenium_driver_lock()._is_owned())
        return orig_get(url)

    def _traced_find(by, selector):
        ownership_trace.append(selenium_driver_lock()._is_owned())
        return orig_find(by, selector)

    def _traced_cookies():
        ownership_trace.append(selenium_driver_lock()._is_owned())
        return orig_cookies()

    driver.get = _traced_get  # type: ignore[method-assign]
    driver.find_elements = _traced_find  # type: ignore[method-assign]
    driver.get_cookies = _traced_cookies  # type: ignore[method-assign]

    monkeypatch.setattr(bf, "chrome_available", lambda: True)
    monkeypatch.setattr(bf, "pick_user_agent_for_selenium", lambda _c: "ua")
    monkeypatch.setattr(bf, "get_selenium_driver", lambda *a, **k: driver)
    monkeypatch.setattr(auth_login.time, "sleep", lambda *_a, **_k: None)

    apply_selenium_login(_cfg())
    assert ownership_trace
    assert all(ownership_trace), ownership_trace


def test_boundary_gate_includes_auth_login_and_browser_fetch():
    """Closure must include login path modules; empty/missing roots fail closed."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    production_roots = [
        root / "browser_fetch.py",
        root / "auth_login.py",
        root / "web" / "worker" / "runner.py",
    ]
    missing = [str(p.relative_to(root)) for p in production_roots if not p.exists()]
    assert missing == [], missing

    entry_mods = ["browser_fetch", "auth_login", "web.worker.runner"]
    first_party = {
        "browser_fetch",
        "auth_login",
        "web",
        "crawler_common",
        "evasion_layer",
        "session_cookies",
    }

    def resolve(mod: str) -> Path:
        parts = mod.split(".")
        for cand in (root.joinpath(*parts).with_suffix(".py"), root.joinpath(*parts, "__init__.py")):
            if cand.exists():
                return cand
        raise AssertionError(f"unresolved production module: {mod}")

    def imports_of(mod: str) -> set[str]:
        tree = ast.parse(resolve(mod).read_text(encoding="utf-8"))
        out: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    out.add(a.name.split(".")[0])
                    out.add(a.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                out.add(node.module.split(".")[0])
                out.add(node.module)
        return out

    seen: set[str] = set()
    queue = list(entry_mods)
    while queue:
        mod = queue.pop(0)
        if mod in seen:
            continue
        try:
            resolve(mod)
        except AssertionError:
            if mod in entry_mods:
                raise
            continue
        seen.add(mod)
        for imp in imports_of(mod):
            top = imp.split(".")[0]
            if top in first_party or imp in first_party:
                if imp not in seen:
                    queue.append(imp)
    assert seen, "closure unexpectedly empty"
    assert "browser_fetch" in seen
    assert "auth_login" in seen

    # Fail-closed: unresolved required entry
    with pytest.raises(AssertionError, match="unresolved"):
        resolve("definitely_missing_login_module_xyz")
