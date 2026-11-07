#!/usr/bin/env python3
"""Find and remove exact DNS rules covered by broader rules.

This module owns coverage orchestration: it parses one immutable snapshot,
evaluates suffix, hostname-glob, and regex coverage, and applies the resulting
exact-domain removals. Perl regex execution is isolated in
``dns_regex_coverage`` so subprocess concerns do not leak into this boundary.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Iterable, Optional, Sequence

try:
    from common import atomic_write_lines, byte_sort_unique, read_utf8_lines
    from dns_regex_coverage import (
        DnsRegexCoverageError,
        RegexCoverageRule,
        match_regex_coverage,
        parse_regex_coverage_rules,
    )
    from rule_canonical import DomainGlobIndex, canonicalize_adblock_domain
except ImportError:  # Support ``python -m script.dns_coverage``.
    from .common import (  # type: ignore[no-redef]
        atomic_write_lines,
        byte_sort_unique,
        read_utf8_lines,
    )
    from .dns_regex_coverage import (  # type: ignore[no-redef]
        DnsRegexCoverageError,
        RegexCoverageRule,
        match_regex_coverage,
        parse_regex_coverage_rules,
    )
    from .rule_canonical import (  # type: ignore[no-redef]
        DomainGlobIndex,
        canonicalize_adblock_domain,
    )


ROOT_DIR = Path(__file__).resolve().parents[1]
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())


class DnsCoverageError(RuntimeError):
    """Raised when coverage analysis cannot complete."""


@dataclass(frozen=True)
class CoverageSnapshot:
    """Rule categories required by coverage evaluation after one parse pass."""

    domains: tuple[str, ...]
    suffixes: tuple[str, ...]
    globs: tuple[str, ...]
    regex_rules: tuple[RegexCoverageRule, ...]


@dataclass(frozen=True)
class CoverageStats:
    suffix: int = 0
    wildcard: int = 0
    regex: int = 0
    invalid_regex: int = 0

    @property
    def total(self) -> int:
        return self.suffix + self.wildcard + self.regex


@dataclass(frozen=True)
class CoverageResult:
    """Covered domains and counts produced from one rule snapshot."""

    covered_domains: tuple[str, ...]
    stats: CoverageStats


def _byte_sort_unique(lines: Iterable[str]) -> list[str]:
    return byte_sort_unique(lines)


def read_rule_lines(path: Path) -> list[str]:
    """Read one UTF-8 rule snapshot without changing record order."""

    try:
        return read_utf8_lines(path)
    except (OSError, UnicodeError, ValueError) as exc:
        raise DnsCoverageError(f"Failed to read DNS rules: {path}: {exc}") from exc


def parse_coverage_snapshot(lines: Iterable[str]) -> CoverageSnapshot:
    """Classify DNS coverage inputs while canonicalizing each line once."""

    domains: set[str] = set()
    wildcard_targets: set[str] = set()
    disabled_wildcard_targets: set[str] = set()
    regex_lines: list[str] = []

    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("/"):
            regex_lines.append(line)

        key = canonicalize_adblock_domain(line)
        if key is None:
            continue
        if (
            key.modifiers
            and all(modifier == "badfilter" for modifier in key.modifiers)
            and "*" in key.target
        ):
            disabled_wildcard_targets.add(key.target)
            continue
        if key.modifiers:
            continue
        if "*" in key.target:
            wildcard_targets.add(key.target)
        else:
            domains.add(key.target)

    active_wildcards = wildcard_targets - disabled_wildcard_targets
    suffixes = {
        target[2:]
        for target in active_wildcards
        if target.startswith("*.") and target.count("*") == 1
    }
    globs = {
        target
        for target in active_wildcards
        if not (target.startswith("*.") and target.count("*") == 1)
    }
    return CoverageSnapshot(
        domains=tuple(_byte_sort_unique(domains)),
        suffixes=tuple(_byte_sort_unique(suffixes)),
        globs=tuple(_byte_sort_unique(globs)),
        regex_rules=parse_regex_coverage_rules(regex_lines),
    )


def _domains_covered_by_suffixes(
    domains: Sequence[str], suffixes: Sequence[str]
) -> set[str]:
    suffix_set = set(suffixes)
    covered: set[str] = set()
    for domain in domains:
        labels = domain.split(".")
        # A suffix wildcard covers descendants, but not the suffix itself.
        if any(
            ".".join(labels[index:]) in suffix_set
            for index in range(1, len(labels))
        ):
            covered.add(domain)
    return covered


def _domains_covered_by_globs(
    domains: Sequence[str], patterns: Sequence[str]
) -> set[str]:
    index = DomainGlobIndex(patterns)
    return {domain for domain in domains if index.covers_domain(domain)}


def analyze_coverage(lines: Sequence[str]) -> CoverageResult:
    """Calculate all plain domains covered by the current rule snapshot."""

    started = perf_counter()
    snapshot = parse_coverage_snapshot(lines)
    LOGGER.info(
        "DNS coverage parsed: domains=%d suffixes=%d globs=%d regex=%d (%.2fs)",
        len(snapshot.domains),
        len(snapshot.suffixes),
        len(snapshot.globs),
        len(snapshot.regex_rules),
        perf_counter() - started,
    )
    if not snapshot.domains:
        return CoverageResult((), CoverageStats())

    started = perf_counter()
    suffix_covered = _domains_covered_by_suffixes(
        snapshot.domains,
        snapshot.suffixes,
    )
    LOGGER.info(
        "DNS suffix coverage: matched=%d (%.2fs)",
        len(suffix_covered),
        perf_counter() - started,
    )

    started = perf_counter()
    glob_covered = _domains_covered_by_globs(
        snapshot.domains,
        snapshot.globs,
    )
    LOGGER.info(
        "DNS glob coverage: matched=%d (%.2fs)",
        len(glob_covered),
        perf_counter() - started,
    )

    started = perf_counter()
    try:
        regex_match = match_regex_coverage(
            snapshot.domains,
            snapshot.regex_rules,
        )
    except DnsRegexCoverageError as exc:
        raise DnsCoverageError(str(exc)) from exc
    regex_covered = set(regex_match.covered_domains)
    LOGGER.info(
        "DNS regex coverage: matched=%d invalid=%d workers=%d (%.2fs)",
        len(regex_covered),
        regex_match.invalid_rule_count,
        regex_match.worker_count,
        perf_counter() - started,
    )

    covered = _byte_sort_unique(suffix_covered | glob_covered | regex_covered)
    return CoverageResult(
        tuple(covered),
        CoverageStats(
            suffix=len(suffix_covered),
            wildcard=len(glob_covered),
            regex=len(regex_covered),
            invalid_regex=regex_match.invalid_rule_count,
        ),
    )


def apply_coverage(lines: Sequence[str], covered_domains: Iterable[str]) -> list[str]:
    """Remove only exact plain ``||domain^`` rules from a coverage result."""

    covered_rules = {f"||{domain}^" for domain in covered_domains}
    return [line for line in lines if line not in covered_rules]


def write_rule_lines(path: Path, lines: Sequence[str]) -> None:
    """Atomically replace a rule snapshot using UTF-8 and LF endings."""

    atomic_write_lines(path, lines)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--mode", choices=("report-only", "apply"), default="apply")
    parser.add_argument("--export-covered", type=Path, default=None)
    parser.add_argument("--print-covered", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        from logging_utils import configure_logging
    except ImportError:  # Support ``python -m script.dns_coverage``.
        from .logging_utils import configure_logging  # type: ignore[no-redef]

    configure_logging()
    args = _parse_args(argv)
    try:
        lines = read_rule_lines(args.input)
        result = analyze_coverage(lines)
        if args.export_covered is not None:
            write_rule_lines(args.export_covered, result.covered_domains)
        if args.print_covered:
            for domain in result.covered_domains:
                print(domain)
        if args.mode == "apply" and result.covered_domains:
            kept = apply_coverage(lines, result.covered_domains)
            write_rule_lines(args.input, kept)
            LOGGER.info(
                "Coverage cleanup %d -> %d (-%d; suffix:%d wildcard:%d regex:%d)",
                len(lines),
                len(kept),
                len(lines) - len(kept),
                result.stats.suffix,
                result.stats.wildcard,
                result.stats.regex,
            )
        else:
            LOGGER.info(
                "Coverage candidates %d (suffix:%d wildcard:%d regex:%d)",
                len(result.covered_domains),
                result.stats.suffix,
                result.stats.wildcard,
                result.stats.regex,
            )
    except (DnsCoverageError, OSError, UnicodeError, ValueError) as exc:
        print(f"[ERROR] DNS coverage: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
