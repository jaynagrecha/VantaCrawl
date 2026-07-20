"""Standalone Redis queue consumer (paid Render Background Worker / Docker)."""

from __future__ import annotations

import logging
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


def main() -> None:
    startup()
    stop = threading.Event()
    try:
        worker_loop(stop)
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
