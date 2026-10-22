#!/usr/bin/env python3
"""Snapshot and compare inactive DNS prune cache entries for CI reporting."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path
from typing import Dict, Iterable

try:
    from inactive_domain_repository import load_cache
except ImportError:  # Support ``python -m script.dns_cache_report``.
    from .inactive_domain_repository import load_cache  # type: ignore[no-redef]


def _inactive_domains(path: Path) -> set[str]:
    """Return domains marked ``dead`` in a cache, or an empty set on error."""

    loaded = load_cache(path, allow_legacy=True)
    return {
        domain for domain, entry in loaded.entries.items() if entry.status == "dead"
    }


def _write_outputs(path: Path | None, values: Dict[str, int]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8", newline="\n") as target:
        for key, value in values.items():
            target.write(f"{key}={value}\n")


def snapshot_cache(cache_path: Path, snapshot_path: Path) -> int:
    """Copy the current cache and return its inactive-domain count."""

    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    if not cache_path.is_file():
        snapshot_path.unlink(missing_ok=True)
        return 0
    shutil.copyfile(cache_path, snapshot_path)
    return len(_inactive_domains(cache_path))


def compare_cache(before_path: Path, after_path: Path) -> Dict[str, int]:
    """Return final inactive count and added/removed inactive domains."""

    before = _inactive_domains(before_path)
    after = _inactive_domains(after_path)
    return {
        "inactive_entries": len(after),
        "inactive_added": len(after - before),
        "inactive_removed": len(before - after),
    }


def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--cache", type=Path, required=True)
    snapshot.add_argument("--snapshot", type=Path, required=True)
    snapshot.add_argument("--github-output", type=Path)

    compare = subparsers.add_parser("compare")
    compare.add_argument("--before", type=Path, required=True)
    compare.add_argument("--after", type=Path, required=True)
    compare.add_argument("--github-output", type=Path)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.command == "snapshot":
            entries = snapshot_cache(args.cache, args.snapshot)
            _write_outputs(args.github_output, {"inactive_before": entries})
            print(f"[INFO] DNS prune cache baseline: inactive={entries}")
        else:
            values = compare_cache(args.before, args.after)
            _write_outputs(args.github_output, values)
            print(
                "[INFO] DNS prune cache: "
                f"inactive={values['inactive_entries']} "
                f"added={values['inactive_added']} "
                f"removed={values['inactive_removed']}"
            )
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"[ERROR] DNS prune cache report: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
