"""Shared network download primitive used by upstream and converter stages."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

try:
    from .common import log_error, log_info, log_warn
except ImportError:  # Support direct script execution.
    from common import log_error, log_info, log_warn  # type: ignore[no-redef]


DEFAULT_MAX_RETRIES = 5
DEFAULT_CONNECT_TIMEOUT = 30
DEFAULT_RETRY_DELAY = 5.0
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/134.0.0.0 Safari/537.36"
)


def download_file(
    url: str,
    output: Path,
    *,
    max_retries: int = DEFAULT_MAX_RETRIES,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    retry_delay: float = DEFAULT_RETRY_DELAY,
) -> bool:
    """Download one URL using the repository-wide retry and atomicity policy."""

    if max_retries < 1:
        raise ValueError("max_retries must be at least one")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    for attempt in range(1, max_retries + 1):
        log_info(f"Downloading (attempt {attempt}/{max_retries}): {url}")
        command = (
            "curl",
            "-f",
            "-sS",
            "-L",
            "--connect-timeout",
            str(connect_timeout),
            "--continue-at",
            "-",
            "-H",
            USER_AGENT,
            "-o",
            str(output),
            url,
        )
        try:
            return_code = subprocess.run(command, check=False).returncode
        except OSError as exc:
            return_code = 127
            log_error(f"Download command failed: {url}: {exc}")

        if return_code == 0:
            try:
                if output.is_file() and output.stat().st_size > 0:
                    return True
            except OSError as exc:
                log_warn(f"Unable to inspect downloaded file: {output}: {exc}")
            log_warn(f"Downloaded file is empty: {url}")
        else:
            log_error(f"Download failed: {url}")

        if attempt < max_retries and retry_delay > 0:
            log_info(f"Retrying after {retry_delay:g} seconds...")
            time.sleep(retry_delay)
    return False
