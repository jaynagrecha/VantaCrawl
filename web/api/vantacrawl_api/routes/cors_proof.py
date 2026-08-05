"""Controlled CORS proof origin — signed tokens only; not a public proxy."""

from __future__ import annotations

import hashlib
import html
import json
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from verifiers.cors.proof import verify_proof_token

from ..config import get_settings

router = APIRouter(prefix="/cors-proof", tags=["cors-proof"])


def _proof_secret() -> str:
    settings = get_settings()
    # Dedicated override via env CORS_PROOF_SECRET, else app secret_key
    import os

    return (os.environ.get("CORS_PROOF_SECRET") or settings.secret_key or "").strip()


_PROOF_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>VantaCrawl CORS proof</title>
</head>
<body>
  <h1>CORS proof</h1>
  <pre id="vc-cors-meta">__META__</pre>
  <pre id="vc-cors-result">pending</pre>
  <script>
  (function(){
    const cfg = __CFG__;
    function bodyHash(text){
      // FNV-1a 32-bit — fingerprint only; not a security hash
      let h = 0x811c9dc5;
      for (let i=0;i<text.length;i++){
        h ^= text.charCodeAt(i);
        h = (h + ((h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24))) >>> 0;
      }
      return ('00000000'+h.toString(16)).slice(-8);
    }
    async function run(){
      const out = {
        readable: false,
        status: 0,
        canary_found: false,
        content_type: '',
        body_len: 0,
        body_hash: '',
        error: ''
      };
      try {
        const resp = await fetch(cfg.target_url, {
          method: cfg.method || 'GET',
          mode: 'cors',
          credentials: cfg.credential_mode || 'omit',
          cache: 'no-store'
        });
        out.status = resp.status;
        out.content_type = resp.headers.get('content-type') || '';
        const text = await resp.text();
        out.readable = true;
        out.body_len = text.length;
        out.body_hash = bodyHash(text);
        out.canary_found = !!(cfg.canary && text.indexOf(cfg.canary) !== -1);
      } catch (e) {
        out.error = String((e && e.message) || e);
        out.readable = false;
      }
      const el = document.getElementById('vc-cors-result');
      el.textContent = JSON.stringify(out);
      document.documentElement.setAttribute('data-vc-cors', out.readable ? 'readable' : 'blocked');
    }
    run();
  })();
  </script>
</body>
</html>
"""


@router.get("/run", response_class=HTMLResponse)
def cors_proof_run(t: str = Query(..., min_length=16, max_length=8192)) -> HTMLResponse:
    """Serve the fixed proof page for a valid job-bound token."""
    secret = _proof_secret()
    if not secret:
        raise HTTPException(status_code=503, detail="cors_proof_secret_unavailable")
    payload, reason = verify_proof_token(t, secret=secret, resolve_dns=True)
    if not payload:
        raise HTTPException(status_code=400, detail=f"invalid_token:{reason}")

    cfg: Dict[str, Any] = {
        "target_url": payload["tu"],
        "credential_mode": payload.get("cm") or "omit",
        "canary": payload.get("canary") or "",
        "method": payload.get("method") or "GET",
    }
    meta = {
        "sid": payload.get("sid"),
        "cid": payload.get("cid"),
        "pid": payload.get("pid"),
        "n": payload.get("n"),
        "tu": payload.get("tu"),
        "to": payload.get("to"),
        "cm": payload.get("cm"),
    }
    # Embed JSON safely
    cfg_json = json.dumps(cfg, separators=(",", ":"))
    meta_json = json.dumps(meta, separators=(",", ":"))
    page = (
        _PROOF_HTML.replace("__CFG__", cfg_json)
        .replace("__META__", html.escape(meta_json))
    )
    return HTMLResponse(
        content=page,
        headers={
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex",
            "Referrer-Policy": "no-referrer",
        },
    )


@router.get("/health")
def cors_proof_health() -> Dict[str, Any]:
    return {"ok": bool(_proof_secret()), "service": "cors-proof"}
