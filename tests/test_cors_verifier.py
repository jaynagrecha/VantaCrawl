"""Phase-2 CORS verifier unit tests — no Horizon production hardcodes."""

from __future__ import annotations

import ast
import asyncio
import re
from pathlib import Path
from typing import Any, Dict

import pytest

from verifiers.cors.classify import classify_cors
from verifiers.cors.contract import (
    STATE_BROWSER_READ_BLOCKED,
    STATE_CORS_BROWSER_READ_CONFIRMED,
    STATE_PROOF_ORIGIN_UNAVAILABLE,
    STATE_REFLECTED_ORIGIN_WITHOUT_SENSITIVE_READ,
    STATE_UNCREDENTIALED_PUBLIC_READ,
    STATE_WILDCARD_WITH_CREDENTIALS_INVALID,
    is_confirmed,
    severity_for,
)
from verifiers.cors.discovery import classify_headers, observation_from_response, candidates_from_observation
from verifiers.cors.proof import mint_proof_token, proof_page_url, verify_proof_token
from verifiers.cors.url_safety import validate_proof_target
from verifiers.registry import get_verifier


class _FakeResp:
    def __init__(self, status: int, headers: Dict[str, str], body: str):
        self.status_code = status
        self.headers = headers
        self.text = body


class _FakeClient:
    def __init__(self, routes: Dict[str, _FakeResp]):
        self.routes = routes
        self.calls = []

    async def get(self, url: str, headers=None, timeout=10):
        self.calls.append((url, dict(headers or {})))
        # exact then prefix
        if url in self.routes:
            return self.routes[url]
        for k, v in self.routes.items():
            if url.startswith(k):
                return v
        return _FakeResp(404, {}, "missing")


def test_candidate_discovery_reasons():
    reasons = classify_headers(
        acao="https://proof.example",
        acac=True,
        request_origin="https://proof.example",
    )
    assert "reflected_origin" in reasons
    assert "credentials_allowed" in reasons
    obs = observation_from_response(
        "https://target.example/api",
        {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
        request_origin="https://evil.example",
    )
    assert obs is not None
    assert "wildcard_with_credentials_header" in obs.selection_reasons
    cands = candidates_from_observation(obs, scan_id="scan-1")
    assert len(cands) == 1
    assert cands[0].family == "cors"
    assert cands[0].candidate_id.startswith("scan-1:cand:")


def test_wildcard_plus_credentials_not_confirmed():
    out = classify_cors(
        mode="lab",
        selection_reasons=["wildcard_origin", "credentials_allowed", "wildcard_with_credentials_header"],
        acao="*",
        acac=True,
        proof_origin_available=True,
        browser_available=True,
        credential_mode="include",
        session_available=True,
        browser_result={"readable": False, "canary_found": False, "decision": "browser_read_blocked", "correlation_ok": True},
        replay_result=None,
        negative_result=None,
        sensitive=True,
        public_only=False,
    )
    assert out["result_state"] == STATE_WILDCARD_WITH_CREDENTIALS_INVALID
    assert not is_confirmed(out["result_state"])


def test_wildcard_plus_credentials_uncredentialed_read_still_not_confirmed():
    """ACAO:* + ACAC:true must never become cors_browser_read_confirmed."""
    out = classify_cors(
        mode="lab",
        selection_reasons=["wildcard_origin", "credentials_allowed", "wildcard_with_credentials_header"],
        acao="*",
        acac=True,
        proof_origin_available=True,
        browser_available=True,
        credential_mode="omit",
        session_available=False,
        browser_result={
            "readable": True,
            "canary_found": True,
            "decision": "confirmed_current_probe",
            "correlation_ok": True,
        },
        replay_result={"readable": True, "canary_found": True, "correlation_ok": True},
        negative_result={"readable": False, "canary_found": False, "correlation_ok": True},
        sensitive=True,
        public_only=False,
    )
    assert out["result_state"] == STATE_WILDCARD_WITH_CREDENTIALS_INVALID
    assert not is_confirmed(out["result_state"])


def test_public_uncredentialed_read_classification():
    out = classify_cors(
        mode="lab",
        selection_reasons=["wildcard_origin", "passive_header_observation"],
        acao="*",
        acac=False,
        proof_origin_available=True,
        browser_available=True,
        credential_mode="omit",
        session_available=False,
        browser_result={
            "readable": True,
            "canary_found": False,
            "canary_expected": "",
            "decision": "readable_without_canary",
            "correlation_ok": True,
        },
        replay_result={"readable": True, "canary_found": False, "correlation_ok": True},
        negative_result={"readable": False, "canary_found": False, "correlation_ok": True},
        sensitive=False,
        public_only=True,
    )
    assert out["result_state"] == STATE_UNCREDENTIALED_PUBLIC_READ


def test_reflected_origin_without_sensitive_read():
    out = classify_cors(
        mode="lab",
        selection_reasons=["reflected_origin", "credentials_allowed"],
        acao="https://proof.example",
        acac=True,
        proof_origin_available=True,
        browser_available=True,
        credential_mode="omit",
        session_available=False,
        browser_result={
            "readable": True,
            "canary_found": False,
            "canary_expected": "VCCORS_abc",
            "decision": "readable_canary_missing",
            "correlation_ok": True,
        },
        replay_result=None,
        negative_result=None,
        sensitive=False,
        public_only=False,
    )
    assert out["result_state"] == STATE_REFLECTED_ORIGIN_WITHOUT_SENSITIVE_READ


def test_confirmed_requires_canary_replay_and_negative():
    out = classify_cors(
        mode="lab",
        selection_reasons=["reflected_origin", "credentials_allowed"],
        acao="https://proof.example",
        acac=True,
        proof_origin_available=True,
        browser_available=True,
        credential_mode="omit",
        session_available=False,
        browser_result={
            "readable": True,
            "canary_found": True,
            "canary_expected": "VCCORS_abc",
            "decision": "confirmed_current_probe",
            "correlation_ok": True,
        },
        replay_result={"readable": True, "canary_found": True, "correlation_ok": True},
        negative_result={"readable": False, "canary_found": False, "correlation_ok": True},
        sensitive=True,
        public_only=False,
    )
    assert out["result_state"] == STATE_CORS_BROWSER_READ_CONFIRMED
    assert out["severity"] in ("medium", "high")


def test_proof_origin_unavailable():
    out = classify_cors(
        mode="lab",
        selection_reasons=["reflected_origin"],
        acao="https://x",
        acac=True,
        proof_origin_available=False,
        browser_available=True,
        credential_mode="omit",
        session_available=False,
        browser_result=None,
        replay_result=None,
        negative_result=None,
        sensitive=False,
        public_only=False,
    )
    assert out["result_state"] == STATE_PROOF_ORIGIN_UNAVAILABLE


def test_token_mint_verify_and_reject_private():
    secret = "unit-test-secret"
    tok = mint_proof_token(
        secret=secret,
        scan_id="s1",
        candidate_id="s1:cand:/x:cors",
        probe_id="cors_1",
        nonce="VCCORS_n1",
        target_url="https://target.example/cors/open?canary=VCCORS_n1",
        target_origin="https://target.example",
        credential_mode="omit",
        canary="VCCORS_n1",
    )
    payload, reason = verify_proof_token(tok, secret=secret)
    assert reason == "ok"
    assert payload["sid"] == "s1"
    assert payload["tu"].startswith("https://target.example/")
    page = proof_page_url("https://proof.example", tok)
    assert page.startswith("https://proof.example/api/cors-proof/run?t=")

    ok, why = validate_proof_target(
        "http://127.0.0.1/secret", expected_origin="http://127.0.0.1"
    )
    assert not ok and why == "host_blocked"

    with pytest.raises(ValueError):
        mint_proof_token(
            secret=secret,
            scan_id="s1",
            candidate_id="c",
            probe_id="p",
            nonce="n",
            target_url="http://169.254.169.254/latest/meta-data",
            target_origin="http://169.254.169.254",
            credential_mode="omit",
            canary="",
        )


def test_stale_nonce_and_wrong_ids_rejected_in_browser_helper(monkeypatch):
    from verifiers.cors import browser as br

    class _El:
        def __init__(self, text):
            self.text = text

        def get_attribute(self, _n):
            return self.text

    class _Drv:
        current_url = "https://proof.example/api/cors-proof/run?t=x"

        def set_page_load_timeout(self, *_a, **_k):
            return None

        def get(self, url):
            self.current_url = url

        def delete_all_cookies(self):
            return None

        def execute_script(self, *_a, **_k):
            return None

        def find_element(self, by, value):
            if value == "vc-cors-result":
                return _El('{"readable":true,"status":200,"canary_found":true,"content_type":"text/html","body_len":10,"body_hash":"abc","error":""}')
            if value == "vc-cors-meta":
                return _El('{"sid":"OTHER","cid":"c1","pid":"p1","n":"n1","tu":"https://t.example/x"}')
            raise RuntimeError("missing")

    class _Lock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(br, "selenium_driver_lock", lambda: _Lock())
    monkeypatch.setattr(br, "get_selenium_driver", lambda: _Drv())
    out = br.run_cors_browser_proof(
        proof_page_url="https://proof.example/api/cors-proof/run?t=x",
        expected_scan_id="s1",
        expected_candidate_id="c1",
        expected_probe_id="p1",
        expected_nonce="n1",
        expected_target_url="https://t.example/x",
        expected_canary="CAN",
    )
    assert out["decision"] == "stale_or_mismatched_evidence"
    assert out["readable"] is False


def test_verify_cors_url_confirmed_with_mocked_browser(monkeypatch):
    from verifiers.cors import verify as vz

    target = "https://target.example/cors/open"
    proof = "https://proof.example"
    body = "canary=VCCORS_deadbeef hello"
    client = _FakeClient(
        {
            target: _FakeResp(
                200,
                {
                    "Access-Control-Allow-Origin": proof,
                    "Access-Control-Allow-Credentials": "true",
                    "Content-Type": "text/html",
                },
                body,
            )
        }
    )

    def _fake_proof(**kwargs):
        denied = "/__vc_cors_denied_" in str(kwargs.get("expected_target_url") or "")
        if denied:
            return {
                "ok": False,
                "readable": False,
                "status": 0,
                "canary_found": False,
                "canary_expected": kwargs.get("expected_canary"),
                "decision": "browser_read_blocked",
                "correlation_ok": True,
                "browser_context_id": "selenium:1:neg",
                "body_len": 0,
                "body_hash": "",
                "content_type": "",
                "error": "Failed to fetch",
            }
        return {
            "ok": True,
            "readable": True,
            "status": 200,
            "canary_found": True,
            "canary_expected": kwargs.get("expected_canary"),
            "decision": "confirmed_current_probe",
            "correlation_ok": True,
            "browser_context_id": "selenium:1:abc",
            "body_len": 20,
            "body_hash": "abcd",
            "content_type": "text/html",
            "error": "",
        }

    monkeypatch.setattr(vz, "run_cors_browser_proof", _fake_proof)

    class Stats:
        def __init__(self):
            self.cors_metrics = {}

        def record_request(self, **kwargs):
            return None

    findings = asyncio.run(
        vz.verify_cors_url(
            client,
            target,
            mode="lab",
            scan_id="scan-xyz",
            stats=Stats(),
            proof_origin_base=proof,
            proof_secret="secret",
            browser_available=True,
            session_available=False,
            credential_mode="omit",
        )
    )
    assert findings
    assert findings[0][0] == "cors"
    meta = findings[0][4]
    assert meta["result_state"] == STATE_CORS_BROWSER_READ_CONFIRMED


def test_cors_verifier_registered():
    v = get_verifier("cors")
    assert v is not None
    assert v.family == "cors"
    assert v.phase == 2


def test_no_horizon_hardcodes_in_cors_package():
    root = Path(__file__).resolve().parents[1]
    banned = (
        "horizon_benchmark",
        "horizon-catalog",
        "onrender.com",
        "/cors/open",
        "/cors/null-origin",
        "cors-null-session",
        "trusted.example",
    )
    # Production package may not embed fixture paths/hosts. trusted.example appears only
    # in playground — ensure verifiers/cors is clean of Horizon/onrender and fixture paths.
    pkg = root / "verifiers" / "cors"
    for path in pkg.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for b in ("horizon_benchmark", "horizon-catalog", "onrender.com", "/cors/open", "/cors/null-origin", "cors-null-session"):
            assert b not in text, f"{path} contains {b}"
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert not a.name.startswith("horizon_benchmark")
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("horizon_benchmark")


def test_severity_model():
    assert severity_for(STATE_CORS_BROWSER_READ_CONFIRMED, credential_mode="include", sensitive=True) == "high"
    assert severity_for(STATE_CORS_BROWSER_READ_CONFIRMED, sensitive=True) == "medium"
    assert severity_for(STATE_UNCREDENTIALED_PUBLIC_READ, public_only=True) == "low"


def test_api_cors_proof_route_rejects_bad_token():
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "web" / "api"))
    from fastapi.testclient import TestClient
    from vantacrawl_api.main import app

    client = TestClient(app)
    r = client.get("/api/cors-proof/run", params={"t": "not-a-valid-token-value"})
    assert r.status_code == 400


def test_lock_used_by_browser_module_source():
    text = Path("verifiers/cors/browser.py").read_text(encoding="utf-8")
    assert "selenium_driver_lock" in text
    assert "with selenium_driver_lock()" in text


def test_finalize_prefers_classified_cors_state_over_raw_browser_decision():
    from verifiers.runtime.execution_plan import (
        CandidateSurface,
        DependencyAvailability,
        build_execution_plan,
    )
    from verifiers.runtime.finalize import apply_ledger_to_lifecycle

    surf = CandidateSurface(
        candidate_id="s:cand:/cors/wildcard-creds:cors",
        url="https://target.example/cors/wildcard-creds",
        path="/cors/wildcard-creds",
        family="cors",
        capability_id="cors_browser_read",
        classification="control",
        must_not_confirm=True,
        modes=["lab", "extended"],
        support_classification="supported_active",
    )
    plan = build_execution_plan(
        mode="lab",
        surfaces=[surf],
        deps=DependencyAvailability(browser=True, cors_proof_origin=True),
    )
    assert plan and plan[0].schedule_status == "attempted"
    ledger = [
        {
            "phase": "active_probe",
            "probe_class": "cors",
            "url": "https://target.example/cors/wildcard-creds",
            "probe_role": "cors_browser_proof",
            "result_state": "confirmed_current_probe",
            "scan_id": "s",
            "candidate_id": surf.candidate_id,
        },
        {
            "phase": "active_probe",
            "probe_class": "cors",
            "url": "https://target.example/cors/wildcard-creds",
            "probe_role": "cors_classified",
            "result_state": "wildcard_with_credentials_invalid",
            "scan_id": "s",
            "candidate_id": surf.candidate_id,
        },
    ]
    rows = apply_ledger_to_lifecycle(
        plan,
        mode="lab",
        ledger=ledger,
        findings=[],
        scan_id="s",
    )
    assert rows[0]["terminal_result_state"] == "wildcard_with_credentials_invalid"
    assert rows[0]["lifecycle_outcome"] == "terminal_negative"
