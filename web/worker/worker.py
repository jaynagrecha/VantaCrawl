"""Standalone Redis queue consumer (Render Background Worker / Docker).

Shares the same concurrent worker_loop as the embedded in-API consumer.
On paid Render: deploy this service and set EMBED_WORKER=false on the web service
so scans are not double-consumed from the API process.
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB_API = Path(__file__).resolve().parents[1] / "api"
for path in (str(ROOT), str(WEB_API)):
    if path not in sys.path:
        sys.path.insert(0, path)

from vantacrawl_api.bootstrap import startup  # noqa: E402
from vantacrawl_api.services.embedded_worker import worker_loop  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("vantacrawl.standalone_worker")


def main() -> None:
    import os
    import time

    # Park this process when scans should run only via EMBED_WORKER on the API
    # (Render disks cannot be shared with a Background Worker).
    if os.environ.get("DISABLE_QUEUE_CONSUMER", "").strip().lower() in {"1", "true", "yes"}:
        log.info(
            "DISABLE_QUEUE_CONSUMER is set — not claiming Redis jobs. "
            "Suspend this service in the Dashboard to stop billing."
        )
        while True:
            time.sleep(3600)

    startup()
    stop = threading.Event()

    def _handle_sigterm(signum, frame) -> None:  # noqa: ARG001
        log.info("SIGTERM — draining in-flight scans, then exit")
        stop.set()

    signal.signal(signal.SIGTERM, _handle_sigterm)
    try:
        signal.signal(signal.SIGINT, _handle_sigterm)
    except Exception:
        pass

    try:
        worker_loop(stop)
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
