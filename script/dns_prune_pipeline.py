#!/usr/bin/env python3
"""Coordinate coverage-aware DNS pruning.

The DNS rule builder and the binary converters have different lifecycles.  In
between them, coverage analysis and inactive-domain probing form one logical
stage: coverage must be calculated from the deduplicated snapshot before any
probe is scheduled, and the redundant exact rules must be removed afterwards.

This module owns that orchestration boundary.  ``run_dns_policy`` is the sole
API used by the GitHub Actions pipeline.  The coverage set is passed to
``dns_prune.run_prune`` in memory instead of through a temporary file.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence, Union

try:
    from dns_coverage import (
        CoverageResult,
        analyze_coverage,
        apply_coverage,
        read_rule_lines,
        write_rule_lines,
    )
    from dns_prune_config import parse_args as parse_prune_args
    from dns_prune import run_prune
    from rule_canonical import canonicalize_adblock_domain
except ImportError:  # Support ``python -m script.dns_prune_pipeline``.
    from .dns_coverage import (  # type: ignore[no-redef]
        CoverageResult,
        analyze_coverage,
        apply_coverage,
        read_rule_lines,
        write_rule_lines,
    )
    from .dns_prune_config import parse_args as parse_prune_args  # type: ignore[no-redef]
    from .dns_prune import run_prune  # type: ignore[no-redef]
    from .rule_canonical import canonicalize_adblock_domain  # type: ignore[no-redef]


ROOT_DIR = Path(__file__).resolve().parents[1]
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())


class DnsPrunePipelineError(RuntimeError):
    """Raised when coverage-aware pruning cannot complete."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class DnsPrunePaths:
    """Resolved files crossing the coverage/prune stage boundary."""

    root_dir: Path
    input_file: Path
    cache_file: Path
    removed_log: Path

    @classmethod
    def from_root(
        cls,
        root_dir: Path = ROOT_DIR,
        *,
        input_file: Optional[Path] = None,
        cache_file: Optional[Path] = None,
        removed_log: Optional[Path] = None,
        environment: Mapping[str, str],
    ) -> "DnsPrunePaths":
        root = Path(root_dir).resolve()

        def resolve(value: Optional[Path], default: Path) -> Path:
            candidate = Path(value) if value is not None else default
            if not candidate.is_absolute():
                candidate = root / candidate
            return candidate.resolve()

        configured_cache = cache_file
        if configured_cache is None:
            cache_value = str(environment.get("DNS_PRUNE_CACHE_FILE", "")).strip()
            configured_cache = Path(cache_value or "dns_prune_cache.json")
        configured_log = removed_log
        if configured_log is None:
            log_value = str(environment.get("DNS_PRUNE_REMOVED_LOG", "")).strip()
            configured_log = Path(
                log_value or str(Path("tmp") / "dns_prune_removed_rules.txt")
            )

        return cls(
            root_dir=root,
            input_file=resolve(input_file, Path("dns.txt")),
            cache_file=resolve(configured_cache, Path("dns_prune_cache.json")),
            removed_log=resolve(
                configured_log,
                Path("tmp") / "dns_prune_removed_rules.txt",
            ),
        )


@dataclass(frozen=True)
class DnsPrunePipelineResult:
    """Summary of the two coverage passes surrounding one prune run."""

    before_rule_count: int
    covered_domain_count: int
    after_prune_rule_count: int
    final_rule_count: int
    coverage: CoverageResult


@dataclass(frozen=True)
class DnsCoveragePipelineResult:
    """Summary returned by the coverage-only DNS cleanup stage."""

    before_rule_count: int
    covered_domain_count: int
    final_rule_count: int
    coverage: CoverageResult


DnsPolicyResult = Union[DnsPrunePipelineResult, DnsCoveragePipelineResult]


def _byte_sort_unique(lines: Iterable[str]) -> list[str]:
    return sorted(set(lines), key=lambda line: line.encode("utf-8"))


def _active_wildcard_was_removed(
    before_lines: Sequence[str],
    after_lines: Sequence[str],
) -> bool:
    """Return whether pruning may have changed wildcard coverage semantics."""

    after_set = set(after_lines)
    for line in before_lines:
        if line in after_set:
            continue
        key = canonicalize_adblock_domain(line)
        if key is not None and not key.modifiers and "*" in key.target:
            return True
    return False


def _prune_argv(paths: DnsPrunePaths, require_dead_capable: Optional[bool]) -> list[str]:
    argv = [
        "--input",
        str(paths.input_file),
        "--cache",
        str(paths.cache_file),
        "--removed-log",
        str(paths.removed_log),
    ]
    if require_dead_capable is True:
        argv.append("--require-dead-capable")
    elif require_dead_capable is False:
        argv.append("--no-require-dead-capable")
    return argv


def _run_dns_prune(
    root_dir: Path = ROOT_DIR,
    *,
    input_file: Optional[Path] = None,
    cache_file: Optional[Path] = None,
    removed_log: Optional[Path] = None,
    require_dead_capable: bool,
    environment: Mapping[str, str],
) -> DnsPrunePipelineResult:
    """Run coverage report, prune, and coverage apply as one stage.

    The first coverage result is passed directly to the prune implementation,
    guaranteeing that covered domains never consume probe budget.  It remains
    valid after exact-domain pruning and is recalculated only if pruning removes
    a wildcard coverage source.
    """

    paths = DnsPrunePaths.from_root(
        root_dir,
        input_file=input_file,
        cache_file=cache_file,
        removed_log=removed_log,
        environment=environment,
    )
    if not paths.input_file.is_file():
        raise DnsPrunePipelineError(
            f"DNS input file does not exist: {paths.input_file}",
            exit_code=2,
        )

    before_lines = read_rule_lines(paths.input_file)
    before_coverage = analyze_coverage(before_lines)
    LOGGER.info(
        "Coverage analysis complete: covered=%d suffix=%d wildcard=%d regex=%d",
        len(before_coverage.covered_domains),
        before_coverage.stats.suffix,
        before_coverage.stats.wildcard,
        before_coverage.stats.regex,
    )

    prune_args = parse_prune_args(
        _prune_argv(paths, require_dead_capable),
        environment=environment,
    )
    return_code = run_prune(
        prune_args,
        skip_domains=before_coverage.covered_domains,
    )
    if return_code != 0:
        raise DnsPrunePipelineError(
            f"DNS prune failed with exit code {return_code}",
            exit_code=return_code,
        )

    after_prune_lines = _byte_sort_unique(read_rule_lines(paths.input_file))
    if _active_wildcard_was_removed(before_lines, after_prune_lines):
        LOGGER.info("Wildcard coverage source removed; recalculating coverage")
        after_coverage = analyze_coverage(after_prune_lines)
    else:
        LOGGER.info("Coverage sources unchanged; reusing pre-prune analysis")
        after_coverage = before_coverage
    final_lines = apply_coverage(
        after_prune_lines,
        after_coverage.covered_domains,
    )
    if final_lines != after_prune_lines:
        write_rule_lines(paths.input_file, final_lines)

    LOGGER.info(
        "Coverage cleanup complete: %d -> %d (-%d)",
        len(after_prune_lines),
        len(final_lines),
        len(after_prune_lines) - len(final_lines),
    )
    return DnsPrunePipelineResult(
        before_rule_count=len(before_lines),
        covered_domain_count=len(before_coverage.covered_domains),
        after_prune_rule_count=len(after_prune_lines),
        final_rule_count=len(final_lines),
        coverage=before_coverage,
    )


def _run_dns_coverage(
    root_dir: Path = ROOT_DIR,
    *,
    input_file: Optional[Path] = None,
    environment: Mapping[str, str],
) -> DnsCoveragePipelineResult:
    """Apply coverage cleanup without scheduling inactive-domain probes."""

    paths = DnsPrunePaths.from_root(
        root_dir,
        input_file=input_file,
        environment=environment,
    )
    if not paths.input_file.is_file():
        raise DnsPrunePipelineError(
            f"DNS input file does not exist: {paths.input_file}",
            exit_code=2,
        )

    before_lines = read_rule_lines(paths.input_file)
    coverage = analyze_coverage(before_lines)
    final_lines = apply_coverage(before_lines, coverage.covered_domains)
    if final_lines != before_lines:
        write_rule_lines(paths.input_file, final_lines)
    LOGGER.info(
        "Coverage cleanup complete: %d -> %d (-%d)",
        len(before_lines),
        len(final_lines),
        len(before_lines) - len(final_lines),
    )
    return DnsCoveragePipelineResult(
        before_rule_count=len(before_lines),
        covered_domain_count=len(coverage.covered_domains),
        final_rule_count=len(final_lines),
        coverage=coverage,
    )


def run_dns_policy(
    root_dir: Path = ROOT_DIR,
    *,
    input_file: Optional[Path] = None,
    prune_enabled: bool = True,
    cache_file: Optional[Path] = None,
    removed_log: Optional[Path] = None,
    require_dead_capable: bool,
    environment: Mapping[str, str],
) -> DnsPolicyResult:
    """Apply the configured DNS policy through one stable stage boundary."""

    if prune_enabled:
        return _run_dns_prune(
            root_dir,
            input_file=input_file,
            cache_file=cache_file,
            removed_log=removed_log,
            require_dead_capable=require_dead_capable,
            environment=environment,
        )
    return _run_dns_coverage(
        root_dir,
        input_file=input_file,
        environment=environment,
    )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT_DIR,
        help="repository root (default: project containing dns.txt)",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="DNS rule file (relative to --root by default)",
    )
    parser.add_argument("--cache", type=Path, default=None)
    parser.add_argument("--removed-log", type=Path, default=None)
    parser.add_argument(
        "--coverage-only",
        action="store_true",
        help="apply coverage cleanup without inactive-domain probing",
    )
    parser.add_argument(
        "--require-dead-capable",
        dest="require_dead_capable",
        action="store_true",
        default=None,
        help="fail when resolver availability cannot support dead classification",
    )
    parser.add_argument(
        "--no-require-dead-capable",
        dest="require_dead_capable",
        action="store_false",
        help="override STRICT_DNS_PRUNE and allow a degraded probe run",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        from logging_utils import configure_logging
    except ImportError:  # Support ``python -m script.dns_prune_pipeline``.
        from .logging_utils import configure_logging  # type: ignore[no-redef]

    configure_logging()
    try:
        if args.coverage_only:
            prune_enabled = False
        else:
            prune_enabled = True
        require_dead_capable = args.require_dead_capable
        if require_dead_capable is None:
            require_dead_capable = str(
                os.environ.get("STRICT_DNS_PRUNE", "false")
            ).strip().lower() in {"1", "true", "yes", "y", "on"}
        result = run_dns_policy(
            args.root,
            input_file=args.input,
            prune_enabled=prune_enabled,
            cache_file=args.cache,
            removed_log=args.removed_log,
            require_dead_capable=require_dead_capable,
            environment=dict(os.environ),
        )
    except DnsPrunePipelineError as exc:
        print(f"[ERROR] DNS prune pipeline: {exc}", file=sys.stderr)
        return exc.exit_code
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        print(f"[ERROR] DNS prune pipeline: {exc}", file=sys.stderr)
        return 1

    if args.coverage_only:
        LOGGER.info(
            "Coverage stage complete: rules=%d covered=%d final=%d",
            result.before_rule_count,
            result.covered_domain_count,
            result.final_rule_count,
        )
    else:
        LOGGER.info(
            "Inactive-domain stage complete: rules=%d covered=%d final=%d",
            result.before_rule_count,
            result.covered_domain_count,
            result.final_rule_count,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
