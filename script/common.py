#!/usr/bin/env python3
"""Small shared primitives used by the rule-generation stages.

The project exposes each stage as both a library and a standalone script.  This
module deliberately contains only dependency-free file, ordering, timestamp,
and logging helpers so those two entry points share the same behavior without
introducing a broader framework.
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence


GMT_PLUS_8 = timezone(timedelta(hours=8))


def read_utf8_bytes(path: Path, *, required: bool = True) -> bytes:
    """Read raw bytes while validating that the file is UTF-8 decodable."""

    target = Path(path)
    if not target.is_file():
        if required:
            raise FileNotFoundError(target)
        return b""
    raw = target.read_bytes()
    raw.decode("utf-8")
    return raw


def read_utf8_text(path: Path, *, required: bool = True) -> str:
    """Read one UTF-8 file while preserving transport newlines."""

    return read_utf8_bytes(path, required=required).decode("utf-8")


def read_utf8_lines(
    path: Path,
    *,
    required: bool = True,
    reject_cr: bool = False,
    normalize_crlf: bool = False,
) -> list[str]:
    """Read UTF-8 lines with explicit CRLF policy.

    ``reject_cr`` is used for generated artifacts that must be LF-only.
    ``normalize_crlf`` mirrors the upstream transport behavior while still
    rejecting carriage returns embedded inside a logical record.
    """

    text = read_utf8_text(path, required=required)
    if reject_cr and "\r" in text:
        raise ValueError(f"file must use LF line endings: {path}")
    if normalize_crlf:
        raw_lines = text.split("\n")
        if raw_lines and raw_lines[-1] == "":
            raw_lines.pop()
        lines: list[str] = []
        for line in raw_lines:
            if line.endswith("\r"):
                line = line[:-1]
            if "\r" in line:
                raise ValueError(f"embedded carriage return in file: {path}")
            lines.append(line)
        return lines
    return text.splitlines()


def byte_sort_unique(lines: Iterable[str]) -> list[str]:
    """Implement the repository's deterministic ``LC_ALL=C sort -u``."""

    # UTF-8 preserves Unicode scalar-value ordering.  Sorting the strings
    # directly avoids encoding every record merely to construct a sort key.
    return sorted(set(lines))


def atomic_write_bytes(
    path: Path,
    data: bytes,
    *,
    mode: Optional[int] = None,
    preserve_mode: bool = True,
) -> None:
    """Atomically replace a file using a same-directory temporary file."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if mode is None and preserve_mode:
        try:
            mode = stat.S_IMODE(target.stat().st_mode)
        except FileNotFoundError:
            mode = 0o644
    if mode is None:
        mode = 0o644

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(data)
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, target)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(path: Path, text: str, *, mode: Optional[int] = None) -> None:
    """Atomically write UTF-8 text with LF transport semantics."""

    atomic_write_bytes(Path(path), text.encode("utf-8"), mode=mode)


def text_matches_ignoring_prefixed_lines(
    existing: str,
    generated: str,
    prefixes: Sequence[str],
) -> bool:
    """Compare generated text while ignoring selected metadata line values."""

    if existing == generated:
        return True
    existing_lines = existing.splitlines(keepends=True)
    generated_lines = generated.splitlines(keepends=True)
    if len(existing_lines) != len(generated_lines):
        return False
    for old_line, new_line in zip(existing_lines, generated_lines):
        if old_line == new_line:
            continue
        if any(
            old_line.startswith(prefix) and new_line.startswith(prefix)
            for prefix in prefixes
        ):
            continue
        return False
    return True


def atomic_write_lines(
    path: Path,
    lines: Sequence[str],
    *,
    mode: Optional[int] = None,
) -> None:
    """Atomically write one LF-delimited UTF-8 record per item."""

    text = "\n".join(lines)
    if lines:
        text += "\n"
    atomic_write_text(Path(path), text, mode=mode)


def atomic_write_text_bundle(entries: Mapping[Path, str]) -> None:
    """Replace several text files together, restoring prior files on failure.

    All temporary files are prepared before the first target is replaced.  If a
    later replacement fails, files already replaced in this process are
    restored from same-directory backups.  This provides stage-level rollback
    for ordinary exceptions while retaining each file's atomic replacement
    semantics.
    """

    if not entries:
        return
    targets = [Path(path) for path in entries]
    if len(set(targets)) != len(targets):
        raise ValueError("atomic write bundle contains duplicate paths")

    temporary_paths: dict[Path, Path] = {}
    backup_paths: dict[Path, Optional[Path]] = {}
    replaced: list[Path] = []
    try:
        for target, text in ((Path(path), value) for path, value in entries.items()):
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                mode = stat.S_IMODE(target.stat().st_mode)
            except FileNotFoundError:
                mode = 0o644
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
            )
            temporary = Path(temporary_name)
            temporary_paths[target] = temporary
            with os.fdopen(descriptor, "wb") as destination:
                destination.write(text.encode("utf-8"))
            os.chmod(temporary, mode)

            if target.exists():
                descriptor, backup_name = tempfile.mkstemp(
                    prefix=f".{target.name}.", suffix=".bak", dir=target.parent
                )
                os.close(descriptor)
                backup = Path(backup_name)
                backup_paths[target] = backup
                try:
                    backup.unlink()
                    os.link(target, backup)
                except OSError:
                    # Hard links are cheap and preserve the old inode; fall
                    # back to a copy on filesystems that disallow linking.
                    shutil.copy2(target, backup)
            else:
                backup_paths[target] = None

        for target in targets:
            os.replace(temporary_paths[target], target)
            replaced.append(target)
    except BaseException:
        for target in reversed(replaced):
            backup = backup_paths.get(target)
            try:
                if backup is None:
                    target.unlink(missing_ok=True)
                else:
                    os.replace(backup, target)
                    backup_paths[target] = None
            except OSError:
                # Preserve the original exception; callers still receive a
                # failure rather than a misleading success result.
                pass
        raise
    finally:
        for temporary in temporary_paths.values():
            temporary.unlink(missing_ok=True)
        for backup in backup_paths.values():
            if backup is not None:
                backup.unlink(missing_ok=True)


def atomic_write_lines_bundle(entries: Mapping[Path, Sequence[str]]) -> None:
    """Atomically replace several LF-delimited text files as one stage."""

    atomic_write_text_bundle(
        {
            Path(path): "\n".join(lines) + ("\n" if lines else "")
            for path, lines in entries.items()
        }
    )


def now_gmt8() -> datetime:
    """Return the single timezone-aware build clock used by outputs."""

    return datetime.now(GMT_PLUS_8)


def format_gmt8_timestamp(value: Optional[datetime] = None) -> str:
    """Format one timestamp consistently across published text artifacts."""

    current = value if value is not None else now_gmt8()
    if current.tzinfo is None:
        current = current.replace(tzinfo=GMT_PLUS_8)
    return current.astimezone(GMT_PLUS_8).strftime("%Y-%m-%d %H:%M:%S")


def _stage_logger(logger: Optional[logging.Logger] = None) -> logging.Logger:
    return logger if logger is not None else logging.getLogger("adrules")


def log_info(message: str, logger: Optional[logging.Logger] = None) -> None:
    _stage_logger(logger).info(message)


def log_warn(message: str, logger: Optional[logging.Logger] = None) -> None:
    _stage_logger(logger).warning(message)


def log_error(message: str, logger: Optional[logging.Logger] = None) -> None:
    _stage_logger(logger).error(message)
