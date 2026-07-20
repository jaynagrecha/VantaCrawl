from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .bootstrap import startup
from .config import get_settings
from .routes import auth, jobs, meta, reports
from .services.embedded_worker import start_embedded_worker, stop_embedded_worker

logging.basicConfig(level=logging.INFO)
settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    startup()
    if settings.embed_worker:
        start_embedded_worker()
    yield
    stop_embedded_worker()


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PREFIX = "/api"
app.include_router(auth.router, prefix=PREFIX)
app.include_router(jobs.router, prefix=PREFIX)
app.include_router(reports.router, prefix=PREFIX)
app.include_router(meta.router, prefix=PREFIX)


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "app": settings.app_name,
        "embed_worker": settings.embed_worker,
    }


ui_dist = Path(settings.ui_dist_dir)
if ui_dist.is_dir():
    assets = ui_dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    @app.get("/{full_path:path}")
    def spa_fallback(full_path: str):
        if full_path.startswith("api"):
            return {"detail": "Not found"}
        index = ui_dist / "index.html"
        candidate = ui_dist / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        if index.is_file():
            return FileResponse(index)
        return {"detail": "UI not built. Run: cd web/ui && npm install && npm run build"}
else:

    @app.get("/")
    def root_no_ui():
        return {
            "app": settings.app_name,
            "message": "API up. Build the UI into web/ui/dist to serve the SPA.",
            "docs": "/docs",
        }
