"""Redis queue consumer for VantaCrawl scan jobs."""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB_API = Path(__file__).resolve().parents[1] / "api"
for path in (str(ROOT), str(WEB_API)):
    if path not in sys.path:
        sys.path.insert(0, path)

from vantacrawl_api.bootstrap import startup  # noqa: E402
from vantacrawl_api.config import get_settings  # noqa: E402
from vantacrawl_api.services.queue import redis_client  # noqa: E402
from runner import run_job  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("vantacrawl.worker")


def main() -> None:
    startup()
    settings = get_settings()
    client = redis_client()
    log.info("Worker online · queue=%s redis=%s", settings.job_queue_key, settings.redis_url)
    while True:
        try:
            item = client.brpop(settings.job_queue_key, timeout=5)
        except Exception as exc:
            log.error("Redis error: %s", exc)
            time.sleep(2)
            continue
        if not item:
            continue
        _, job_id = item
        log.info("Picked job %s", job_id)
        try:
            asyncio.run(run_job(job_id))
        except Exception:
            log.exception("Unhandled job failure %s", job_id)


if __name__ == "__main__":
    main()
