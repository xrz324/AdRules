#!/usr/bin/env python3
"""Conservatively minimize content-filter rules without changing their scope."""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Optional, Sequence

try:
    from common import atomic_write_text, read_utf8_text
    from content_cosmetic import (
        CosmeticRule,
        minimize_cosmetic,
        parse_cosmetic_rule,
    )
    from content_models import (
        MinimizerError,
        StageStats,
        serialized_bytes,
    )
    from content_network import (
        canonicalize_content_rule,
        minimize_removeparam,
        minimize_simple_url_host_patterns,
    )
    from rule_canonical import semantic_duplicate_indices
    from dns_minimizer import minimize_adblock_domain_lines
except ImportError:  # Support ``python -m script.content_minimizer``.
    from .common import (  # type: ignore[no-redef]
        atomic_write_text,
        read_utf8_text,
    )
    from .content_cosmetic import (  # type: ignore[no-redef]
        CosmeticRule,
        minimize_cosmetic,
        parse_cosmetic_rule,
    )
    from .content_models import (  # type: ignore[no-redef]
        MinimizerError,
        StageStats,
        serialized_bytes,
    )
    from .content_network import (  # type: ignore[no-redef]
        canonicalize_content_rule,
        minimize_removeparam,
        minimize_simple_url_host_patterns,
    )
    from .rule_canonical import semantic_duplicate_indices  # type: ignore[no-redef]
    from .dns_minimizer import (  # type: ignore[no-redef]
        minimize_adblock_domain_lines,
    )


DEFAULT_MAX_LINE_BYTES = 4096
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())


@dataclass(frozen=True)
class MinimizeResult:
    lines: tuple[str, ...]
    cosmetic: StageStats
    removeparam: StageStats
    input_bytes: int
    output_bytes: int
    semantic_duplicate_count: int
    domain_redundancy_count: int
    url_pattern_redundancy_count: int


def _parse_cosmetic_rule(line: str) -> Optional[CosmeticRule]:
    return parse_cosmetic_rule(line)


def minimize_lines(
    lines: Sequence[str], max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
) -> MinimizeResult:
    if max_line_bytes <= 0:
        raise ValueError("max_line_bytes must be positive")
    if any("\n" in line or "\r" in line for line in lines):
        raise MinimizerError("lines must not contain newline characters")

    original = lines if isinstance(lines, list) else list(lines)
    original_count = len(original)
    input_bytes = serialized_bytes(original)
    started = perf_counter()
    canonical_keys = []
    duplicate_indices = semantic_duplicate_indices(
        original,
        canonicalize_content_rule,
        key_output=canonical_keys,
    )
    deduplicated = [
        line for index, line in enumerate(original) if index not in duplicate_indices
    ]
    canonical_key_by_line = {
        line: key
        for line, key in zip(original, canonical_keys)
        if key is not None
    }
    deduplicated_count = len(deduplicated)
    del original
    LOGGER.info(
        "Content semantic deduplication: %d -> %d (%.2fs)",
        original_count,
        deduplicated_count,
        perf_counter() - started,
    )
    started = perf_counter()
    pattern_minimized, pattern_redundancy_count = (
        minimize_simple_url_host_patterns(deduplicated)
    )
    del deduplicated
    LOGGER.info(
        "Content URL-pattern minimization: %d -> %d (%.2fs)",
        deduplicated_count,
        len(pattern_minimized),
        perf_counter() - started,
    )
    started = perf_counter()
    # URL-pattern minimization only removes records; it does not rewrite them.
    # Reuse the canonical keys from semantic deduplication for the remaining
    # records instead of parsing every domain rule a second time.
    pattern_domain_keys = [canonical_key_by_line.get(line) for line in pattern_minimized]
    domain_minimized, domain_stats = minimize_adblock_domain_lines(
        pattern_minimized,
        canonical_keys=pattern_domain_keys,
    )
    del canonical_keys, canonical_key_by_line, pattern_domain_keys
    pattern_input_count = len(pattern_minimized)
    del pattern_minimized
    LOGGER.info(
        "Content domain minimization: %d -> %d (%.2fs)",
        pattern_input_count,
        len(domain_minimized),
        perf_counter() - started,
    )
    started = perf_counter()
    cosmetic_lines, cosmetic_stats = minimize_cosmetic(
        domain_minimized,
        max_line_bytes,
    )
    domain_input_count = len(domain_minimized)
    del domain_minimized
    LOGGER.info(
        "Content cosmetic minimization: %d -> %d (%.2fs)",
        domain_input_count,
        len(cosmetic_lines),
        perf_counter() - started,
    )
    started = perf_counter()
    output, removeparam_stats = minimize_removeparam(
        cosmetic_lines, max_line_bytes
    )
    cosmetic_input_count = len(cosmetic_lines)
    del cosmetic_lines
    LOGGER.info(
        "Content removeparam minimization: %d -> %d (%.2fs)",
        cosmetic_input_count,
        len(output),
        perf_counter() - started,
    )
    return MinimizeResult(
        lines=tuple(output),
        cosmetic=cosmetic_stats,
        removeparam=removeparam_stats,
        input_bytes=input_bytes,
        output_bytes=serialized_bytes(output),
        semantic_duplicate_count=len(duplicate_indices),
        domain_redundancy_count=domain_stats.removed,
        url_pattern_redundancy_count=pattern_redundancy_count,
    )


def _format_stage(stats: StageStats) -> str:
    return (
        f"{stats.name} lines:{stats.input_lines}->{stats.output_lines} "
        f"(-{stats.saved_lines}) bytes:{stats.input_bytes}->{stats.output_bytes} "
        f"(-{stats.saved_bytes}) eligible:{stats.eligible_lines} "
        f"groups:{stats.groups} changed:{stats.changed_groups} "
        f"oversize:{stats.oversize_groups}"
    )


def minimize_file(path: Path, max_line_bytes: int) -> MinimizeResult:
    text = read_utf8_text(path)
    if "\r" in text:
        raise MinimizerError("input must use LF line endings")

    lines = text.splitlines()
    result = minimize_lines(lines, max_line_bytes=max_line_bytes)
    output_text = "\n".join(result.lines)
    if result.lines:
        output_text += "\n"
    if output_text == text:
        return result

    atomic_write_text(path, output_text)
    return result


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Conservatively minimize scoped content-filter rules in place."
    )
    parser.add_argument("path", type=Path)
    parser.add_argument(
        "--max-line-bytes",
        type=int,
        default=DEFAULT_MAX_LINE_BYTES,
        help=f"Maximum generated line length in UTF-8 bytes (default: {DEFAULT_MAX_LINE_BYTES})",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        result = minimize_file(args.path, args.max_line_bytes)
    except (MinimizerError, OSError, UnicodeError, ValueError) as exc:
        print(f"[CONTENT-MIN][ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"[CONTENT-MIN] {_format_stage(result.cosmetic)}", file=sys.stderr)
    print(f"[CONTENT-MIN] {_format_stage(result.removeparam)}", file=sys.stderr)
    total_removed = (
        result.semantic_duplicate_count
        + result.domain_redundancy_count
        + result.url_pattern_redundancy_count
        + result.cosmetic.saved_lines
        + result.removeparam.saved_lines
    )
    print(
        f"[CONTENT-MIN] total lines:{len(result.lines) + total_removed}"
        f"->{len(result.lines)} (-{total_removed}) "
        f"semantic-duplicates:{result.semantic_duplicate_count} "
        f"domain-redundancies:{result.domain_redundancy_count} "
        f"url-pattern-redundancies:{result.url_pattern_redundancy_count} "
        f"bytes:{result.input_bytes}->{result.output_bytes} "
        f"(-{result.input_bytes - result.output_bytes})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
