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

## Render (current production layout)

Live stack (Oregon):

| Service | Role | Plan |
|---------|------|------|
| `vantacrawl-api` | FastAPI + SPA + **embedded scan worker** + 10 GB disk | **Standard** (2 GB / 1 CPU) |
| `vantacrawl-worker` | Optional / suspended — see disk note below | Standard (idle = still billed) |
| `vantacrawl-db` | Postgres 16 | Often still **Free** until upgraded |
| `vantacrawl-redis` | Valkey / Redis queue + pub/sub | Often still **Free** until upgraded |

### Why scans run on the API (not the Background Worker)

Render attaches a persistent disk to **one** service only. Ours is on `vantacrawl-api` at `/opt/render/project/src/web/data`. A separate Background Worker cannot see that disk, so reports and job uploads would vanish or go missing from the UI.

**Production choice:** `EMBED_WORKER=true` on `vantacrawl-api`, and **Suspend** `vantacrawl-worker` in the Dashboard (stops double queue consumers and an unused Standard charge).

Later, with object storage for reports/uploads, you can revive the dedicated worker and set `EMBED_WORKER=false`.

### Dashboard checklist

1. `vantacrawl-api` → Environment → **`EMBED_WORKER=true`** (then Save / redeploy if needed).
2. `vantacrawl-worker` → **Suspend Background Worker**.
3. Confirm `REPORTS_DIR` / `JOBS_DIR` / `DATA_DIR` stay under `/opt/render/project/src/web/data` (the mounted disk).

### Persistent disk (web)

**10 GB** at `/opt/render/project/src/web/data` — same paths as `DATA_DIR`, `REPORTS_DIR`, `JOBS_DIR`. Reports and uploads survive redeploys. Disk can grow later; it cannot shrink.

Catalog wordlists under repo `Wordlist/` live in the git checkout (not the disk).

### Browser / Selenium

API build runs `scripts/install_chrome_linux.sh`. With Standard 2 GB, headless Chrome is practical for normal pages; if the binary is missing, scans log one skip line and continue over HTTP.

### Data-plane plans to watch

- **Postgres Free** expires after ~30 days unless upgraded — upgrade before the Dashboard expiry date or you lose job history / users.
- **Key Value Free** is tiny (~25 MB). Fine for light queues; upgrade if you see Redis connection errors.

### Dashboard secrets (`sync: false`)

- `ADMIN_EMAIL`, `ADMIN_PASSWORD`
- `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`
- `PUBLIC_BASE_URL` = your `https://….onrender.com`

### Security / ops notes

- **SSRF guard:** job targets that resolve to loopback, private, link-local, or cloud metadata addresses are rejected.
- **Health:** `GET /api/health` checks API, database, Redis, and the embedded worker thread when `EMBED_WORKER=true`.

## Gmail SMTP

1. Enable 2FA on the Google account  
2. Create an **App Password**  
3. Use that as `SMTP_PASSWORD` (not your normal password)

## Authorized use

Every job requires `authorized_confirmed: true` in the UI. Only scan systems you own or have written permission to test.
