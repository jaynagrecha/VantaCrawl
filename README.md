# VantaCrawl

Authorized web crawler, directory bruteforcer, and security recon toolkit — desktop GUI/CLI plus self-hosted web SaaS.

Single desktop entry point: **`python app.py`** (GUI) or **`python app.py --cli ...`** (headless).

Web UI docs: [`web/README.md`](web/README.md) · Render blueprint: [`render.yaml`](render.yaml)

## Quick start (desktop)

```bash
pip install -r requirements.txt
python app.py
```

CLI example:

```bash
python app.py --cli --url https://example.com --download --profile full
```

Docker (desktop engine):

```bash
docker compose build
docker compose run crawler --cli --url https://example.com --download
```

## GUI tabs

| Tab | Purpose |
|-----|---------|
| **Basic** | URL, wordlist, mirror mode, profiles, depth limits, 403 bypass |
| **Discovery** | Wayback, Common Crawl, subdomains, OpenAPI, JS routes, RSS |
| **Brute Force** | False-positive tuning, extension wordlist, enum options |
| **Security** | Secret scan, headers, CORS, parameters (authorized targets only) |
| **Reporting** | Search conclusion report, HTML/JSON/SQLite/CSV, WARC, graphs |
| **Advanced** | Proxy, auth cookies, checkpoint resume, Redis, disk guard |
| **Tools** | Login wizard, compare runs, scheduler, Nuclei, concurrency |

## Web SaaS (self-hosted)

Register → Gmail SMTP OTP → login → queue scans → live progress → interactive HTML report.

```bash
# Redis, then API + worker (see web/README.md)
uvicorn vantacrawl_api.main:app --reload --app-dir web/api --host 0.0.0.0 --port 8000
python web/worker/worker.py
```

On Render: connect this repo; set `ADMIN_*`, `SMTP_*`, and `PUBLIC_BASE_URL` in the Dashboard.

## Outputs

| Path | Content |
|------|---------|
| `found_urls.txt` | All discovered URLs |
| `Downloaded Files/` | HTTrack-style mirror |
| `Reports/` | Search report, findings, Burp/ZAP exports, site map graph |
| `crawl_checkpoint.json` | Resume state |

## Tests

```bash
pip install pytest
pytest tests/
```

## Authorized use only

Only scan systems you own or have written permission to test. Every web job requires an explicit authorization confirmation.
