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

| Service | Role | Typical plan |
|---------|------|----------------|
| `vantacrawl-api` | FastAPI + SPA, job API, WebSockets | **Standard** (2 GB / 1 CPU) |
| `vantacrawl-worker` | Queue consumer — runs crawls / enum / Chrome | **Standard** (2 GB / 1 CPU) |
| `vantacrawl-db` | Postgres 16 | Often still **Free** until upgraded |
| `vantacrawl-redis` | Valkey / Redis queue + pub/sub | Often still **Free** until upgraded |

`render.yaml` at repo root defines these. Blueprint-managed env vars sync on deploy; secrets marked `sync: false` stay in the Dashboard.

### Worker handoff (important)

With `vantacrawl-worker` Live, the web service must **not** also consume the queue:

- Set **`EMBED_WORKER=false`** on `vantacrawl-api` (blueprint default is now `false`).
- If both are `true`, two consumers fight over the same Redis jobs.

Confirm in Dashboard → `vantacrawl-api` → Environment after the next deploy.

### Persistent disk (web)

`vantacrawl-api` mounts a **10 GB** disk at `/opt/render/project/src/web/data` (same as `DATA_DIR` / `REPORTS_DIR` / `JOBS_DIR`). Reports and job uploads survive redeploys. Disk size can grow later; it cannot shrink.

Wordlist catalogs under repo `Wordlist/` are in the git checkout (not the disk).

### Browser / Selenium

Both web and worker builds run `scripts/install_chrome_linux.sh` (Chrome for Testing). The **worker** is where scans actually run Chromium. On Standard (2 GB) headless Chrome is practical for normal pages; if the binary is missing, the worker logs one skip line and continues over HTTP.

### Data-plane plans to watch

Compute can be Standard while **Postgres / Redis stay Free**:

- **Postgres Free** expires after ~30 days unless upgraded — upgrade before the Dashboard expiry date or you lose job history / users.
- **Key Value Free** is tiny (e.g. ~25 MB, low connection limit). Fine for light queues; upgrade if you see Redis connection errors under concurrent scans.

### Dashboard secrets (`sync: false`)

- `ADMIN_EMAIL`, `ADMIN_PASSWORD`
- `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`
- `PUBLIC_BASE_URL` = your `https://….onrender.com`

### Security / ops notes

- **SSRF guard:** job `start_url` / targets that resolve to loopback, private, link-local, or cloud metadata addresses are rejected.
- **Health:** `GET /api/health` checks API, database, Redis, and (only if embedded) the in-process worker thread. With `EMBED_WORKER=false`, expect `embedded_worker: null` while Redis/DB stay green.

## Gmail SMTP

1. Enable 2FA on the Google account  
2. Create an **App Password**  
3. Use that as `SMTP_PASSWORD` (not your normal password)

## Authorized use

Every job requires `authorized_confirmed: true` in the UI. Only scan systems you own or have written permission to test.
