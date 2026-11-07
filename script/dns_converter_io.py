#!/usr/bin/env python3
"""I/O and publication primitives shared by DNS converter stages."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Optional

try:
    from common import (
        atomic_write_bytes,
        atomic_write_lines,
        atomic_write_text,
        byte_sort_unique,
        log_error,
        log_info,
        log_warn,
        read_utf8_lines,
    )
except ImportError:  # Support ``python -m script.dns_converter``.
    from .common import (  # type: ignore[no-redef]
        atomic_write_bytes,
        atomic_write_lines,
        atomic_write_text,
        byte_sort_unique,
        log_error,
        log_info,
        log_warn,
        read_utf8_lines,
    )

try:
    from dns_converter_model import ConversionStageError
except ImportError:  # Support ``python -m script.dns_converter``.
    from .dns_converter_model import ConversionStageError  # type: ignore[no-redef]


_LOGRUS_PREFIX_RE = re.compile(
    r"^(DEBU|INFO|WARN|ERRO|FATA|PANI)\[\d+\]\s*"
)
_LOGRUS_LEVELS = {
    "DEBU": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "ERRO": logging.ERROR,
    "FATA": logging.CRITICAL,
    "PANI": logging.CRITICAL,
}


def remove(path: Path) -> None:
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        log_warn(f"Failed to remove temporary file: {path}: {exc}")


def read_lines(path: Path) -> list[str]:
    try:
        return read_utf8_lines(Path(path))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ConversionStageError(f"Failed to read converter input: {path}: {exc}") from exc


def emit_process_stderr(payload: bytes) -> None:
    if not payload:
        return
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        sys.stderr.buffer.write(payload)
        sys.stderr.flush()
        return
    sys.stderr.write(text)
    if not text.endswith("\n"):
        sys.stderr.write("\n")
    sys.stderr.flush()


def emit_normalized_process_logs(payload: bytes) -> None:
    """Route Logrus lines through project logging and preserve other output."""

    if not payload:
        return
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        emit_process_stderr(payload)
        return

    logger = logging.getLogger("adrules")
    for line in text.splitlines():
        match = _LOGRUS_PREFIX_RE.match(line)
        if match is None:
            sys.stderr.write(f"{line}\n")
            continue
        logger.log(_LOGRUS_LEVELS[match.group(1)], line[match.end() :])
    sys.stderr.flush()


def temporary_output(path: Path) -> Path:
    """Reserve a same-directory temporary path retaining the output suffix."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix or ".tmp"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=suffix, dir=path.parent
    )
    os.close(descriptor)
    remove(Path(temporary_name))
    return Path(temporary_name)


def run_binary(
    command: Sequence[str],
    *,
    cwd: Path,
    label: str,
    environment: Mapping[str, str],
    normalize_stderr: bool = False,
) -> None:
    try:
        completed = subprocess.run(
            tuple(command),
            cwd=cwd,
            env=dict(environment),
            stderr=subprocess.PIPE if normalize_stderr else None,
            check=False,
        )
    except OSError as exc:
        raise ConversionStageError(f"{label} execution failed: {exc}") from exc
    if normalize_stderr:
        emit_normalized_process_logs(completed.stderr or b"")
    if completed.returncode != 0:
        raise ConversionStageError(f"{label} conversion failed (rc={completed.returncode})")


def write_executable(path: Path, data: bytes) -> None:
    atomic_write_bytes(path, data, mode=0o755)


def _reserve_backup(path: Path) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".bak", dir=path.parent
    )
    os.close(descriptor)
    remove(Path(temporary_name))
    return Path(temporary_name)


def publish_artifacts(replacements: Sequence[tuple[Path, Path]]) -> None:
    """Publish one or more prepared files as a rollback-capable transaction.

    Each temporary source is created in the destination directory, so every
    rename remains on one filesystem.  A process crash cannot make the group
    truly multi-file atomic, but ordinary conversion errors are rolled back
    and never leave a partially published generation.
    """

    if not replacements:
        return
    normalized = [(Path(source), Path(destination)) for source, destination in replacements]
    destinations = [destination for _, destination in normalized]
    if len(set(destinations)) != len(destinations):
        raise ValueError("artifact transaction contains duplicate destinations")
    for source, destination in normalized:
        if not source.is_file():
            raise ConversionStageError(f"Conversion produced no output file: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)

    backups: list[tuple[Path, Optional[Path]]] = []
    committed: list[Path] = []
    try:
        for _, destination in normalized:
            backup: Optional[Path] = None
            if destination.exists():
                backup = _reserve_backup(destination)
                os.replace(destination, backup)
            backups.append((destination, backup))
        for source, destination in normalized:
            os.replace(source, destination)
            committed.append(destination)
    except BaseException:
        # Remove any newly committed files before restoring their backups.
        for destination in reversed(committed):
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
        for destination, backup in reversed(backups):
            if backup is None:
                continue
            try:
                os.replace(backup, destination)
            except OSError as restore_error:
                log_error(
                    f"Failed to restore artifact: {backup} -> {destination}: {restore_error}"
                )
        raise
    finally:
        for _, backup in backups:
            if backup is not None:
                remove(backup)
