# VantaCrawl Web (Option B)

Self-hosted web UI for the crawler / directory bruteforcer engine.

- **Auth:** register → Gmail SMTP OTP → login (admin from `ADMIN_EMAIL` / `ADMIN_PASSWORD`, pre-verified)
- **Jobs:** full mode/speed/settings parity with desktop presets
- **Live:** WebSocket progress, pause / resume / stop
- **Reports:** dark VantaCrawl HTML report embedded in the job page
- **Hosting:** FastAPI serves the built React SPA (one web process)

## Local quick start

### 1) Redis

```bash
docker run -p 6379:6379 redis:7-alpine
```

### 2) API deps

```bash
cd web/api
pip install -r requirements.txt
pip install -r ../../requirements.txt
```

Copy `web/.env.example` → `web/api/.env` (or export env vars) and fill Gmail SMTP + admin.

### 3) UI

```bash
cd web/ui
npm install
npm run build
# optional hot reload: npm run dev  (proxies /api → :8000)
```

### 4) Run API + worker

```bash
# terminal A — from repo root
set PYTHONPATH=web/api;.
uvicorn vantacrawl_api.main:app --reload --app-dir web/api --host 0.0.0.0 --port 8000

# terminal B
set PYTHONPATH=web/api;.
python web/worker/worker.py
```

Open http://localhost:8000

Admin can log in immediately with `ADMIN_EMAIL` / `ADMIN_PASSWORD`.  
Normal users: Register → OTP email → Verify → Login.

## Docker Compose

```bash
cd web/ui && npm install && npm run build
cd ../
# set SMTP_USER / SMTP_PASSWORD in env
docker compose up --build
```

## Render

`render.yaml` at repo root defines:

- Postgres
- Redis (Key Value)
- Web service (`vantacrawl-api`) — UI + API + **embedded job worker** (`EMBED_WORKER=true`)

Render free plans cannot create Background Workers, so the queue consumer runs inside the web process. On a paid plan you can set `EMBED_WORKER=false` and run `python web/worker/worker.py` separately.

Set in Dashboard (sync: false):

- `ADMIN_EMAIL`, `ADMIN_PASSWORD`
- `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`
- `PUBLIC_BASE_URL` = your `https://….onrender.com`

**Storage:** free Render filesystems are ephemeral — `DATA_DIR` / `REPORTS_DIR` / `JOBS_DIR` reset on redeploy or spin-down. Attach a persistent disk (paid) mounting at `web/data`, or sync reports to object storage. Wordlist catalogs under repo `Wordlist/` survive deploys.

**Browser render:** the build runs `scripts/install_chrome_linux.sh` (Chrome for Testing). If Chrome is missing at runtime, scans continue over HTTP and log one skip line. Free-tier RAM may still OOM on heavy JS pages.

**SSRF guard:** job `start_url` / targets that resolve to loopback, private, link-local, or cloud metadata addresses are rejected.

**Health:** `GET /api/health` checks API, database, Redis, and the embedded worker thread.

## Gmail SMTP

1. Enable 2FA on the Google account  
2. Create an **App Password**  
3. Use that as `SMTP_PASSWORD` (not your normal password)

## Authorized use

Every job requires `authorized_confirmed: true` in the UI. Only scan systems you own or have written permission to test.
