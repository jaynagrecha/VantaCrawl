"""Optional Nuclei scanner integration (requires nuclei on PATH)."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import Callable, List


def nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def run_nuclei_scan(
    urls: List[str],
    output_dir: str,
    output_callback: Callable[[str], None],
    severity: str = "medium,high,critical",
    timeout_seconds: int = 600,
) -> str | None:
    if not nuclei_available():
        output_callback("Nuclei not found on PATH — skipping template scan.")
        return None
    os.makedirs(output_dir, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as handle:
        for url in urls[:5000]:
            handle.write(url + "\n")
        list_path = handle.name
    out_path = os.path.join(output_dir, "nuclei_results.txt")
    cmd = [
        "nuclei",
        "-l", list_path,
        "-o", out_path,
        "-severity", severity,
        "-silent",
    ]
    output_callback(f"Running Nuclei on {min(len(urls), 5000)} URLs…")
    try:
        subprocess.run(cmd, timeout=timeout_seconds, check=False)
        output_callback(f"Nuclei results: {out_path}")
        return out_path
    except subprocess.TimeoutExpired:
        output_callback("Nuclei scan timed out.")
        return None
    except OSError as error:
        output_callback(f"Nuclei failed: {error}")
        return None
    finally:
        try:
            os.remove(list_path)
        except OSError:
            pass
