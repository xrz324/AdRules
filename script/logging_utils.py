"""Shared logging setup for standalone stages and the rule pipeline.

Stage modules are also imported as libraries by :mod:`pipeline`.  Configuring
the process-wide logging handler while importing one of those modules makes
the final output depend on import order.  Keep configuration at the CLI
boundary instead and use one compact formatter everywhere.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional, TextIO


class CompactFormatter(logging.Formatter):
    """Render one searchable, timestamp-free line per log record."""

    _LEVEL_NAMES = {
        logging.DEBUG: "DEBUG",
        logging.INFO: "INFO",
        logging.WARNING: "WARN",
        logging.ERROR: "ERROR",
        logging.CRITICAL: "ERROR",
    }

    def format(self, record: logging.LogRecord) -> str:
        level = self._LEVEL_NAMES.get(record.levelno, record.levelname)
        return f"[{level}] {record.getMessage()}"


def configure_logging(
    *,
    level: int = logging.INFO,
    stream: Optional[TextIO] = None,
) -> None:
    """Install the repository's single CLI logging handler.

    This function is intentionally called only from ``main`` functions.  A
    library import therefore never changes the host application's logging
    configuration.  Replacing existing handlers is appropriate for a command
    line process and also prevents duplicate records when a stage is invoked
    after another stage CLI in tests.
    """

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(CompactFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
