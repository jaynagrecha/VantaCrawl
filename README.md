# Horizon Catalog

Intentionally vulnerable web playground for scanner QA and crawl-policy testing.

Public demo: [horizon-catalog.onrender.com](https://horizon-catalog.onrender.com/)

## Quick start

```bash
python3 -m pip install -r requirements.txt
./run.sh
# or (Render / Waitress)
python -m waitress --host=0.0.0.0 --port=${PORT:-9080} --threads=8 wsgi:app
```

Open `http://127.0.0.1:9080/`. Machine catalog: `/catalog.json`.

## What it covers

XSS, SQLi (error/blind/time/second-order), SSRF, SSTI engines, RCE, LFI/RFI, command injection,
auth/logic flaws (IDOR, JWT, SAML, OTP), CSRF/CORS/cookies, GraphQL, deserialization,
cloud/exposure surfaces, and a **robots.txt Disallow bypass** testbed under `/private/*`
(marker: `ROBOTS_BYPASS_CANARY`).

See `EXPECTED.md` for ground-truth scoring notes.

## Safety

This app is deliberately unsafe. Run only in isolated lab environments you own.
