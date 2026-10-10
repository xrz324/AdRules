#!/usr/bin/env python3
"""Build the Adblock content list from curated and downloaded rule sources.

The module owns the content-stage policy.  The functions below are the stage
API used by the Actions pipeline and can be exercised without a shell or a
network.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional, Sequence

try:
    from common import (
        atomic_write_text,
        byte_sort_unique,
        format_gmt8_timestamp,
        read_utf8_lines,
        read_utf8_text,
        text_matches_ignoring_prefixed_lines,
    )
except ImportError:  # Support ``python -m script.content_pipeline``.
    from .common import (  # type: ignore[no-redef]
        atomic_write_text,
        byte_sort_unique,
        format_gmt8_timestamp,
        read_utf8_lines,
        read_utf8_text,
        text_matches_ignoring_prefixed_lines,
    )

try:
    from content_minimizer import (
        DEFAULT_MAX_LINE_BYTES,
        MinimizerError,
        MinimizeResult,
        minimize_lines,
    )
    from dns_minimizer import minimize_adblock_domain_lines
except ImportError:  # Support ``python -m script.content_pipeline`` as well.
    from .content_minimizer import (  # type: ignore[no-redef]
        DEFAULT_MAX_LINE_BYTES,
        MinimizerError,
        MinimizeResult,
        minimize_lines,
    )
    from .dns_minimizer import minimize_adblock_domain_lines  # type: ignore[no-redef]


ROOT_DIR = Path(__file__).resolve().parents[1]
CONTENT_MAX_LINE_BYTES = DEFAULT_MAX_LINE_BYTES

# These are the cosmetic forms accepted by the old awk filter.  Keep this
# list narrower than the minimizer's parser: accepting a new marker here is a
# policy change and should happen explicitly.
COSMETIC_PREFIXES = (
    "##",
    "#@#",
    "#?#",
    "#@?#",
    "#$#",
    "#@$#",
    "#$?#",
    "#@$?#",
    "#%#",
    "#@%#",
)

class ContentPipelineError(RuntimeError):
    """Raised when content inputs cannot be processed safely."""


@dataclass(frozen=True)
class ContentPaths:
    """Repository paths used by the content stage."""

    root_dir: Path
    rules_file: Path
    content_dir: Path
    remove_file: Path
    title_file: Path
    output_file: Path

    @classmethod
    def from_root(
        cls,
        root_dir: Path,
        output_file: Optional[Path] = None,
    ) -> "ContentPaths":
        root = Path(root_dir).resolve()
        configured_output = Path(output_file) if output_file is not None else Path("adblock.txt")
        if not configured_output.is_absolute():
            configured_output = root / configured_output
        else:
            configured_output = configured_output.resolve()
        return cls(
            root_dir=root,
            rules_file=root / "mod" / "rules" / "adblock-rules.txt",
            content_dir=root / "tmp" / "content",
            remove_file=root / "mod" / "rules" / "adblock-need-remove.txt",
            title_file=root / "mod" / "title" / "adblock-title.txt",
            output_file=configured_output,
        )


@dataclass(frozen=True)
class ContentBuildResult:
    """Summary returned by :func:`build_content`."""

    output_file: Path
    rule_count: int
    source_line_count: int
    remove_list_input_count: int
    minimized: MinimizeResult


def _read_lines(path: Path, *, required: bool = False) -> list[str]:
    """Read LF-delimited UTF-8 lines and normalize CRLF transport endings."""

    try:
        if path.exists() and not path.is_file():
            raise ContentPipelineError(f"content path is not a regular file: {path}")
        return read_utf8_lines(
            path,
            required=required,
            normalize_crlf=True,
        )
    except (OSError, UnicodeError) as exc:
        raise ContentPipelineError(
            f"failed to read content file {path}: {exc}"
        ) from exc
    except ValueError as exc:
        raise ContentPipelineError(str(exc)) from exc


def _byte_sort_unique(lines: Iterable[str]) -> list[str]:
    """Implement ``LC_ALL=C sort -u`` for Unicode text."""

    return byte_sort_unique(lines)


def _filter_rule_line(line: str) -> Optional[str]:
    if not line.strip():
        return None

    left_trimmed = line.lstrip()
    if left_trimmed.startswith(("!", "[")):
        return None
    if left_trimmed.startswith("#"):
        if any(left_trimmed.startswith(prefix) for prefix in COSMETIC_PREFIXES):
            return line
        return None
    return line


def filter_rule_lines(lines: Iterable[str]) -> list[str]:
    """Drop comments/empty records while retaining supported cosmetic rules."""

    filtered: list[str] = []
    for line in lines:
        filtered_line = _filter_rule_line(line)
        if filtered_line is not None:
            filtered.append(filtered_line)
    return filtered


def iter_source_lines(paths: ContentPaths) -> Iterable[str]:
    """Yield source records one file at a time to bound pipeline memory."""

    yield from _read_lines(paths.rules_file)
    if not paths.content_dir.is_dir():
        return

    content_files = sorted(
        (
            path
            for path in paths.content_dir.glob("*.txt")
            if path.is_file()
        ),
        key=lambda path: path.name.encode("utf-8"),
    )
    for content_file in content_files:
        yield from _read_lines(content_file, required=True)


def read_source_lines(paths: ContentPaths) -> list[str]:
    """Read curated rules followed by downloaded ``tmp/content/*.txt`` files."""

    return list(iter_source_lines(paths))


def apply_remove_list(lines: Iterable[str], remove_file: Path) -> list[str]:
    """Remove records matching the exact lines in ``remove_file``."""

    remove_patterns = set(_read_lines(remove_file))
    if not remove_patterns:
        return list(lines)
    return [line for line in lines if line not in remove_patterns]


def prune_covered_content_domains(lines: Sequence[str]) -> list[str]:
    """Compatibility facade for the shared domain minimizer."""

    minimized, _stats = minimize_adblock_domain_lines(lines)
    return minimized


def _render_output(
    title_text: str,
    rules: Sequence[str],
    timestamp: Optional[datetime] = None,
) -> str:
    if "\r" in title_text:
        raise ContentPipelineError("title file must use LF line endings")
    title = title_text.lstrip("\ufeff")
    if title and not title.endswith("\n"):
        title += "\n"

    body = "\n".join(rules)
    if body:
        body += "\n"
    return (
        f"{title}! Version: {format_gmt8_timestamp(timestamp)}(GMT+8)\n"
        f"! Total count: {len(rules)}\n"
        f"{body}"
    )


def build_content(
    root_dir: Path = ROOT_DIR,
    *,
    max_line_bytes: int = CONTENT_MAX_LINE_BYTES,
    timestamp: Optional[datetime] = None,
    output_file: Optional[Path] = None,
) -> ContentBuildResult:
    """Build and atomically write the configured adblock artifact."""

    paths = ContentPaths.from_root(root_dir, output_file=output_file)
    remove_patterns = set(_read_lines(paths.remove_file))
    filtered: list[str] = []
    source_line_count = 0
    remove_list_input_count = 0
    for source_line in iter_source_lines(paths):
        source_line_count += 1
        filtered_line = _filter_rule_line(source_line)
        if filtered_line is not None:
            remove_list_input_count += 1
            if filtered_line in remove_patterns:
                continue
            filtered.append(filtered_line)
    del remove_patterns
    ordered = _byte_sort_unique(filtered)
    del filtered
    minimized = minimize_lines(ordered, max_line_bytes=max_line_bytes)
    del ordered

    title_text = "".join(
        f"{line}\n" for line in _read_lines(paths.title_file, required=True)
    )
    output_text = _render_output(title_text, minimized.lines, timestamp)
    existing_output = read_utf8_text(paths.output_file, required=False)
    if not text_matches_ignoring_prefixed_lines(
        existing_output,
        output_text,
        ("! Version: ",),
    ):
        atomic_write_text(paths.output_file, output_text)

    return ContentBuildResult(
        output_file=paths.output_file,
        rule_count=len(minimized.lines),
        source_line_count=source_line_count,
        remove_list_input_count=remove_list_input_count,
        minimized=minimized,
    )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT_DIR,
        help="repository root (default: directory containing mod/ and tmp/)",
    )
    parser.add_argument(
        "--max-line-bytes",
        type=int,
        default=CONTENT_MAX_LINE_BYTES,
        help=f"maximum generated rule length in UTF-8 bytes (default: {CONTENT_MAX_LINE_BYTES})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="adblock output path, relative to --root when not absolute",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        result = build_content(
            args.root,
            max_line_bytes=args.max_line_bytes,
            output_file=args.output,
        )
    except MinimizerError as exc:
        print(f"[CONTENT-MIN][ERROR] {exc}", file=sys.stderr)
        return 1
    except (ContentPipelineError, OSError, UnicodeError, ValueError) as exc:
        print(f"[ERROR] content pipeline: {exc}", file=sys.stderr)
        return 1

    print(
        f"[INFO] Content output complete: rules={result.rule_count} "
        f"source-lines={result.source_line_count}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
