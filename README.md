# VantaCrawl

Authorized web crawler, directory bruteforcer, and security recon toolkit.

Desktop GUI / CLI for local engagements, plus a self-hosted web SaaS (FastAPI + React + Redis + Postgres) for queued scans, live progress, and interactive reports.

> **Authorized use only.** Scan systems you own or have written permission to test. Web jobs require an explicit authorization confirmation. Private / loopback / cloud-metadata targets are rejected by the SSRF guard.

---

## What it does

| Area | Capabilities |
|------|----------------|
| **Crawl** | BFS link discovery, scope controls, checkpoint resume, optional Chrome deep render |
| **Directory enum** | Wordlist + mutations, multi-shape wildcard calibration, content-equivalence clustering, provisional → confirmed / revoked hits, edge-checkpoint abort |
| **Discovery** | Wayback / Common Crawl seeds, subdomains, OpenAPI / JS routes, forms, RSS, cloud buckets, vhosts |
| **Security** | Secrets, headers, CORS, cookies, sensitive paths, vuln patterns, defense / WAF evidence (authorized targets) |
| **Reporting** | Search conclusion, assessment HTML, JSON / CSV / SQLite, WARC, `found_urls.txt`, offline mirror |
| **Web SaaS** | Register → SMTP OTP → login → queue scans → WebSocket progress → pause / resume / stop → embedded report |

It is **not** a turnkey exploit framework. Findings are evidence-backed observations for authorized assessment; many signals are inconclusive under WAF / edge checkpoints and are reported that way.

---

## Quick start (desktop)

**Requirements:** Python 3.10+ (3.11 recommended), pip. Optional: Chrome for deep render / browser login.

```bash
pip install -r requirements.txt
python app.py
```

Headless CLI:

```bash
python app.py --cli --url https://example.com --download --profile full
```

Useful flags:

```bash
python app.py --cli --url https://example.com \
  --wordlist Wordlist/directory-list-2.3-big.txt \
  --profile stealth \
  --enum-only \
  --resume
```

| Flag | Purpose |
|------|---------|
| `--cli` | Headless mode (no GUI) |
| `--url` / `--targets-file` | Target(s) |
| `--wordlist` | Directory wordlist (defaults under `Wordlist/`) |
| `--download` | Save an offline mirror under `Downloaded Files/` |
| `--profile` | `full` · `quick` · `stealth` · `gobuster` |
| `--enum-only` | Skip crawl; run enumeration only |
| `--resume` / `--resume-enum` | Resume crawl / enum checkpoints |
| `--selenium` / `--deep-mirror` | Browser-assisted fetch / mirror |

Docker (desktop engine):

```bash
docker compose build
docker compose run crawler --cli --url https://example.com --download
```

---

## Desktop GUI

Single entry point: `python app.py`.

| Tab | Purpose |
|-----|---------|
| **Basic** | URL, wordlist, mirror mode, profiles, depth limits, 403 bypass |
| **Discovery** | Wayback, Common Crawl, subdomains, OpenAPI, JS routes, RSS |
| **Brute Force** | False-positive tuning, extensions, enum options |
| **Security** | Secret scan, headers, CORS, parameters |
| **Reporting** | Search / assessment reports, HTML / JSON / SQLite / CSV, WARC |
| **Advanced** | Proxy, auth cookies, checkpoint resume, Redis, disk guard |
| **Tools** | Login wizard, compare runs, scheduler, Nuclei, concurrency |

---

## Outputs

| Path | Content |
|------|---------|
| `found_urls.txt` | Discovered URLs (deduped) |
| `Downloaded Files/` | Offline mirror (when download is enabled) |
| `Reports/` | Search report, assessment HTML, findings JSON/CSV/SQLite, graphs |
| `crawl_checkpoint.json` | Crawl resume state |
| Enum checkpoint file | Directory-enum resume state (configured per run) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Surfaces                                                    │
│  app.py (PyQt5 GUI / CLI)     web/ui (React) + web/api       │
└───────────────┬─────────────────────────────┬───────────────┘
                │                             │
                ▼                             ▼
        crawl_orchestrator              Redis job queue
        enum_engine + enum_validation   web/worker (or embedded)
        discovery_* / api_recon/*       Postgres (users, jobs)
        security_scan / tier_security
        reporting / detailed_report
                │
                ▼
        found_urls · Reports/ · WARC · SQLite · mirror
```

### Core engine (repo root)

| Module | Role |
|--------|------|
| `crawl_orchestrator.py` | Crawl loop, enqueue, security hooks, checkpoints |
| `enum_engine.py` / `enum_validation.py` | Directory brute force, wildcard calibration, hit provenance |
| `edge_checkpoint.py` | Vercel / edge interstitial detection and enum abort |
| `evasion_layer.py` / `browser_fetch.py` | Stealth HTTP + optional Chrome |
| `security_scan.py` / `tier_security.py` / `finding_*.py` | Finding production, impact, proof |
| `defense_verify.py` / `protection_evidence.py` | WAF / bot-defense observation |
| `reporting.py` / `detailed_report.py` / `assessment_*.py` | Exports and human reports |
| `api_recon/` | API discovery and differential probing |
| `Wordlist/` | Bundled wordlists |

### Web SaaS (`web/`)

| Path | Role |
|------|------|
| `web/api` | FastAPI app, auth (SMTP OTP), jobs API, health |
| `web/ui` | React SPA (built into API static) |
| `web/worker` | Queue consumer (or embedded in API via `EMBED_WORKER=true`) |
| `web/data` | Persistent reports / jobs (disk mount on Render) |

Deep web/deploy notes: [`web/README.md`](web/README.md).

---

## Web SaaS (self-hosted)

Register → Gmail SMTP OTP → login → queue scans → live progress → interactive HTML report.

### Local

```bash
# 1) Redis
docker run -p 6379:6379 redis:7-alpine

# 2) API deps
cd web/api
pip install -r requirements.txt
pip install -r ../../requirements.txt
# copy web/.env.example → web/api/.env  (SMTP + ADMIN_*)

# 3) UI
cd ../ui && npm install && npm run build

# 4) From repo root — API
export PYTHONPATH=web/api:.
uvicorn vantacrawl_api.main:app --reload --app-dir web/api --host 0.0.0.0 --port 8000

# 5) Worker (separate terminal)
export PYTHONPATH=web/api:.
python web/worker/worker.py
```

Open http://localhost:8000 — admin can log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`.

Docker Compose (web stack):

```bash
cd web/ui && npm install && npm run build
cd ..
# set SMTP_USER / SMTP_PASSWORD in env
docker compose up --build
```

### Render

Blueprint: [`render.yaml`](render.yaml).

| Service | Role |
|---------|------|
| `vantacrawl-api` | FastAPI + SPA + **embedded worker** + persistent disk |
| `vantacrawl-db` | Postgres |
| `vantacrawl-redis` | Valkey / Redis queue |
| `vantacrawl-worker` | Optional; suspend in production when `EMBED_WORKER=true` |

**Why the worker is embedded:** Render attaches a disk to one service. Reports live on the API disk (`/opt/render/project/src/web/data`), so production sets `EMBED_WORKER=true` and suspends the separate worker to avoid double consumers.

Dashboard secrets (`sync: false`): `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `SMTP_*`, `PUBLIC_BASE_URL`.

Health: `GET /api/health` (API, DB, Redis, embedded worker when enabled).

---

## Configuration highlights

### Engagement profiles (desktop / CLI)

| Profile | Intent |
|---------|--------|
| `full` | Crawl + enum + security defaults |
| `quick` | Faster / shallower pass |
| `stealth` | Lower concurrency, more browser-like pacing |
| `gobuster` | Enum-heavy posture |

Web jobs expose the same mode / speed / settings parity via desktop presets (`gui_presets` / scan settings API).

### Enum integrity (high level)

1. Edge checkpoint / rate-limit / auth denial classified **before** accepting hits  
2. New fingerprints start **provisional**, never auto-confirmed  
3. Content-equivalent clusters with many unrelated paths → **`ENUM-REVOKE`** of the anchor  
4. Uniform checkpoint early in the wordlist → enum **aborts** as inconclusive  
5. Application findings (e.g. HSTS) are **not** raised from checkpoint interstitial pages  

### Environment (web)

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Postgres |
| `REDIS_URL` | Queue / pub-sub |
| `SECRET_KEY` | Session / crypto |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Bootstrap admin |
| `SMTP_*` | OTP email (Gmail app password recommended) |
| `PUBLIC_BASE_URL` | Canonical public URL |
| `EMBED_WORKER` | Run queue consumer inside the API process |
| `DATA_DIR` / `REPORTS_DIR` / `JOBS_DIR` | Persistent paths |
| `MAX_CONCURRENT_SCANS` | Global concurrency cap |

---

## Tests

```bash
pip install -r requirements.txt
pytest tests/
```

Web API tests may need `PYTHONPATH=web/api:web/worker:.`.

---

## Repository map

```
app.py                 Desktop GUI + CLI entry
crawl_*.py / enum_*.py Engine
security_scan.py       Security checks
reporting.py           Snapshot + exports
web/                   Self-hosted SaaS
Wordlist/              Bundled wordlists
tests/                 Pytest suite
render.yaml            Render blueprint
scripts/               Deploy helpers (e.g. Chrome install)
```

---

## Safety and ethics

- Only use on systems you **own** or have **written authorization** to test.  
- Web UI jobs require an explicit authorization checkbox / confirmation.  
- Targets that resolve to loopback, private, link-local, or cloud metadata addresses are blocked.  
- Stealth / evasion options exist to reduce false WAF blocks during **authorized** testing — not to bypass third-party protections without permission.  
- Stopping a scan flushes live state into reports; partial / checkpoint-interfered assessments are labeled inconclusive rather than inventing risk ratings.

---

## License / contact

Private / project-owned repository. For deployment issues on Render, see [`web/README.md`](web/README.md) and the Render Dashboard env checklist above.
