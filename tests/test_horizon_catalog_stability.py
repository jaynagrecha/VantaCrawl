"""Horizon Catalog / vuln_playground stability checks."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "vuln_playground"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from registry import load_vuln_modules, resolve  # noqa: E402

load_vuln_modules()


def test_account_prefix_resolves_after_slash_strip():
    # app.py strips trailing slash before resolve — /account/ must still match.
    assert resolve("/account/") is not None
    assert resolve("/account") is not None
    assert resolve("/account/profile.css") is not None
    assert resolve("/account/profile.css").path == "/account/"


def test_race_withdraw_rejects_non_numeric_amount():
    from vulns.cloud_race import race_withdraw

    class _H:
        path = "/race/withdraw"
        command = "GET"
        headers = {}
        _code = None
        _body = b""

        def send_response(self, code, message=None):
            self._code = code

        def send_header(self, *a):
            pass

        def end_headers(self):
            pass

        @property
        def wfile(self):
            class _W:
                def write(_self, data):
                    self._body = data

            return _W()

    h = _H()
    race_withdraw(h, {"amount": "test"}, head_only=False)
    assert h._code == 400
    assert b"amount must be numeric" in h._body


def test_logic_cart_rejects_non_numeric_price_qty():
    from vulns.access_logic import logic_cart

    class _H:
        path = "/logic/cart"
        command = "POST"
        headers = {}
        _code = None
        _body = b""

        def send_response(self, code, message=None):
            self._code = code

        def send_header(self, *a):
            pass

        def end_headers(self):
            pass

        @property
        def wfile(self):
            class _W:
                def write(_self, data):
                    self._body = data

            return _W()

    h = _H()
    logic_cart(h, {"price": "test", "qty": "x"}, head_only=False)
    assert h._code == 400
    assert b"Invalid price/qty" in h._body
