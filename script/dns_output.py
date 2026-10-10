#!/usr/bin/env python3
"""Render the rule-only DNS snapshot as the published AdGuard artifact.

The deterministic DNS builder and the prune/conversion stages operate on a
header-free rule snapshot.  This module owns the small presentation boundary
that adds the repository title, count, and update timestamp for the Actions
pipeline.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence

try:
    from common import (
        atomic_write_text,
        format_gmt8_timestamp,
        read_utf8_lines,
        read_utf8_text,
        text_matches_ignoring_prefixed_lines,
    )
except ImportError:  # Support ``python -m script.dns_output``.
    from .common import (  # type: ignore[no-redef]
        atomic_write_text,
        format_gmt8_timestamp,
        read_utf8_lines,
        read_utf8_text,
        text_matches_ignoring_prefixed_lines,
    )



class DnsOutputError(RuntimeError):
    """Raised when the DNS publication snapshot cannot be rendered safely."""


@dataclass(frozen=True)
class DnsOutputResult:
    output_file: Path
    rule_count: int


def _read_lines(
    path: Path, *, required: bool = False, label: str = "DNS file"
) -> list[str]:
    try:
        if path.exists() and not path.is_file():
            raise DnsOutputError(f"File not found ({label}): {path}")
        return read_utf8_lines(path, required=required, reject_cr=True)
    except (OSError, UnicodeError, ValueError) as exc:
        raise DnsOutputError(f"Failed to read DNS file: {path}: {exc}") from exc


def render_dns_output(
    title_lines: Sequence[str],
    rules: Sequence[str],
    timestamp: Optional[datetime] = None,
) -> str:
    """Return the published AdGuard text for one header-free rule snapshot."""

    normalized_title = list(title_lines)
    if normalized_title:
        normalized_title[0] = normalized_title[0].lstrip("\ufeff")
    if any("\r" in line for line in (*normalized_title, *rules)):
        raise DnsOutputError("DNS header or rules contain CR characters")
    lines = [
        *normalized_title,
        f"! Total count: {len(rules)}",
        f"! Update: {format_gmt8_timestamp(timestamp)}(GMT+8)",
        *rules,
    ]
    # Match the historical ``sed '/^$/d'`` behavior while retaining spaces
    # inside a meaningful rule or title line.
    lines = [line for line in lines if line != ""]
    return "\n".join(lines) + "\n"


def finalize_dns_output(
    input_file: Path,
    *,
    title_file: Optional[Path] = None,
    output_file: Optional[Path] = None,
    previous_output_file: Optional[Path] = None,
    timestamp: Optional[datetime] = None,
) -> DnsOutputResult:
    """Add the title/count/update headers and atomically publish ``dns.txt``."""

    input_path = Path(input_file).resolve()
    output_path = Path(output_file or input_path).resolve()
    rules = _read_lines(input_path, required=True, label="DNS input file")
    title_lines = _read_lines(Path(title_file), required=False) if title_file else []
    output_text = render_dns_output(title_lines, rules, timestamp)
    comparison_path = (
        Path(previous_output_file).resolve()
        if previous_output_file is not None
        else output_path
    )
    previous_output = read_utf8_text(comparison_path, required=False)
    if text_matches_ignoring_prefixed_lines(
        previous_output,
        output_text,
        ("! Update: ",),
    ):
        if read_utf8_text(output_path, required=False) != previous_output:
            atomic_write_text(output_path, previous_output)
    else:
        atomic_write_text(output_path, output_text)
    return DnsOutputResult(output_file=output_path, rule_count=len(rules))


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("dns.txt"))
    parser.add_argument("--title", type=Path, default=Path("mod/title/dns-title.txt"))
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        result = finalize_dns_output(
            args.input,
            title_file=args.title,
            output_file=args.output,
        )
    except (DnsOutputError, OSError, UnicodeError, ValueError) as exc:
        print(f"[ERROR] DNS output: {exc}", file=sys.stderr)
        return 1
    print(f"[INFO] DNS output complete: rules={result.rule_count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
