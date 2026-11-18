#!/usr/bin/env python3
"""Coordinate coverage-aware DNS pruning.

The DNS rule builder and the binary converters have different lifecycles.  In
between them, coverage analysis and inactive-domain probing form one logical
stage: coverage must be calculated from the deduplicated snapshot before any
probe is scheduled, and the redundant exact rules must be removed afterwards.

This module owns that orchestration boundary.  The GitHub Actions pipeline
uses ``execute_dns_policy`` with a typed request; ``run_dns_policy`` remains a
compatibility adapter for CLI callers and embedders.  The coverage set is
passed to ``dns_prune.run_prune`` in memory instead of through a temporary
file.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence

try:
    from dns_coverage import (
        CoverageResult,
        analyze_coverage,
        apply_coverage,
        read_rule_lines,
        write_rule_lines,
    )
    from dns_prune_config import build_prune_request
    from dns_prune import run_prune_detailed
    from dns_prune_model import DnsPolicyMode, PruneRequest
    from rule_canonical import canonicalize_adblock_domain
except ImportError:  # Support ``python -m script.dns_prune_pipeline``.
    from .dns_coverage import (  # type: ignore[no-redef]
        CoverageResult,
        analyze_coverage,
        apply_coverage,
        read_rule_lines,
        write_rule_lines,
    )
    from .dns_prune_config import build_prune_request  # type: ignore[no-redef]
    from .dns_prune import run_prune_detailed  # type: ignore[no-redef]
    from .dns_prune_model import DnsPolicyMode, PruneRequest  # type: ignore[no-redef]
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
class DnsPolicyResult:
    """Stable summary returned by every DNS cleanup mode.

    Coverage fields always describe the final rule set.  ``mode`` and the
    optional prune fields keep compatibility with existing embedders while
    making the result's execution path explicit.
    """

    before_rule_count: int
    covered_domain_count: int
    final_rule_count: int
    coverage: CoverageResult
    after_prune_rule_count: Optional[int] = None
    prune_status: str = "skipped"
    prune_reason: str = ""
    mode: Optional[DnsPolicyMode] = None

    def __post_init__(self) -> None:
        # Infer the mode for legacy constructors that predate the tagged
        # result.  New stage executions always provide it explicitly.
        if self.mode is None:
            inferred = (
                DnsPolicyMode.COVERAGE_ONLY
                if self.prune_status == "skipped" and self.after_prune_rule_count is None
                else DnsPolicyMode.PROBE
            )
            object.__setattr__(self, "mode", inferred)

    @property
    def effective_after_prune_rule_count(self) -> int:
        return (
            self.before_rule_count
            if self.after_prune_rule_count is None
            else self.after_prune_rule_count
        )

    @property
    def pruned_rule_count(self) -> int:
        return max(
            0,
            self.before_rule_count - self.effective_after_prune_rule_count,
        )


@dataclass(frozen=True)
class DnsPolicyStageRequest:
    """Inputs accepted by the DNS policy boundary before request resolution."""

    root_dir: Path
    input_file: Optional[Path]
    mode: DnsPolicyMode
    cache_file: Optional[Path]
    removed_log: Optional[Path]
    require_dead_capable: bool
    environment: Optional[Mapping[str, str]] = None
    prune_request: Optional[PruneRequest] = None
    paths: Optional[DnsPrunePaths] = None


# Compatibility aliases for embedders importing the previous mode-specific names.
DnsPrunePipelineResult = DnsPolicyResult
DnsCoveragePipelineResult = DnsPolicyResult


def _byte_sort_unique(lines: Iterable[str]) -> list[str]:
    return sorted(set(lines))


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


def _run_dns_prune(
    request: DnsPolicyStageRequest,
) -> DnsPolicyResult:
    """Run coverage report, prune, and coverage apply as one stage.

    The first coverage result is passed directly to the prune implementation,
    guaranteeing that covered domains never consume probe budget.  It remains
    valid after exact-domain pruning and is recalculated only if pruning removes
    a wildcard coverage source.
    """

    if request.prune_request is not None:
        prune_request = request.prune_request
    else:
        if request.environment is None:
            raise DnsPrunePipelineError(
                "DNS policy request requires a prepared prune request or environment",
                exit_code=2,
            )
        paths = DnsPrunePaths.from_root(
            request.root_dir,
            input_file=request.input_file,
            cache_file=request.cache_file,
            removed_log=request.removed_log,
            environment=request.environment,
        )
        prune_request = build_prune_request(
            environment=request.environment,
            input_path=paths.input_file,
            cache_path=paths.cache_file,
            removed_log_path=paths.removed_log,
            require_dead_capable=request.require_dead_capable,
        )

    paths = request.paths or DnsPrunePaths.from_root(
        request.root_dir,
        input_file=request.input_file,
        cache_file=request.cache_file,
        removed_log=request.removed_log,
        environment=request.environment or {},
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

    prune_result = run_prune_detailed(
        prune_request,
        skip_domains=before_coverage.covered_domains,
        mode=request.mode,
    )
    if prune_result.exit_code != 0:
        raise DnsPrunePipelineError(
            f"DNS prune failed with exit code {prune_result.exit_code}",
            exit_code=prune_result.exit_code,
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
    return DnsPolicyResult(
        before_rule_count=len(before_lines),
        covered_domain_count=len(after_coverage.covered_domains),
        after_prune_rule_count=len(after_prune_lines),
        final_rule_count=len(final_lines),
        coverage=after_coverage,
        prune_status=prune_result.status,
        prune_reason=prune_result.reason,
        mode=request.mode,
    )


def _run_dns_coverage(
    request: DnsPolicyStageRequest,
) -> DnsPolicyResult:
    """Apply coverage cleanup without scheduling inactive-domain probes."""

    paths = request.paths or DnsPrunePaths.from_root(
        request.root_dir,
        input_file=request.input_file,
        environment=request.environment or {},
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
    return DnsPolicyResult(
        before_rule_count=len(before_lines),
        covered_domain_count=len(coverage.covered_domains),
        final_rule_count=len(final_lines),
        coverage=coverage,
        mode=DnsPolicyMode.COVERAGE_ONLY,
    )


def execute_dns_policy(
    request: DnsPolicyStageRequest,
) -> DnsPolicyResult:
    """Execute one typed DNS policy stage request."""

    if request.mode is not DnsPolicyMode.COVERAGE_ONLY:
        return _run_dns_prune(request)
    return _run_dns_coverage(request)


def run_dns_policy(
    root_dir: Path = ROOT_DIR,
    *,
    input_file: Optional[Path] = None,
    mode: DnsPolicyMode = DnsPolicyMode.PROBE,
    cache_file: Optional[Path] = None,
    removed_log: Optional[Path] = None,
    require_dead_capable: bool,
    environment: Mapping[str, str],
) -> DnsPolicyResult:
    """Compatibility adapter for CLI callers and existing embedders."""

    return execute_dns_policy(
        DnsPolicyStageRequest(
            root_dir=Path(root_dir),
            input_file=input_file,
            mode=mode,
            cache_file=cache_file,
            removed_log=removed_log,
            require_dead_capable=require_dead_capable,
            environment=environment,
        )
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
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--coverage-only",
        action="store_true",
        help="apply coverage cleanup without inactive-domain pruning",
    )
    mode_group.add_argument(
        "--cache-only",
        action="store_true",
        help="prune from a compatible cache without DNS probing",
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
        mode = (
            DnsPolicyMode.COVERAGE_ONLY
            if args.coverage_only
            else DnsPolicyMode.CACHE_ONLY
            if args.cache_only
            else DnsPolicyMode.PROBE
        )
        require_dead_capable = args.require_dead_capable
        if require_dead_capable is None:
            require_dead_capable = str(
                os.environ.get("STRICT_DNS_PRUNE", "false")
            ).strip().lower() in {"1", "true", "yes", "y", "on"}
        result = run_dns_policy(
            args.root,
            input_file=args.input,
            mode=mode,
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
