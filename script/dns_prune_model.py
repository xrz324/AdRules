#!/usr/bin/env python3
"""Immutable models and policy constants for DNS pruning."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from inactive_domain_model import (
        CacheEntry,
        CacheLoadResult,
        CacheReusePolicy,
        CacheTtlPolicy,
        InactiveDomainSelection,
        CACHE_FORMAT_VERSION,
    )
except ImportError:  # Support ``python -m script.dns_prune_model``.
    from .inactive_domain_model import (  # type: ignore[no-redef]
        CacheEntry,
        CacheLoadResult,
        CacheReusePolicy,
        CacheTtlPolicy,
        InactiveDomainSelection,
        CACHE_FORMAT_VERSION,
    )


PROBE_POLICY_VERSION = 8

DEFAULT_RESOLVERS_GLOBAL = (
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
)
DEFAULT_RESOLVERS_CN = (
    "223.5.5.5",
    "223.6.6.6",
    "114.114.114.114",
    "119.29.29.29",
)

DEFAULT_MIN_ONLINE_RESOLVERS = 2
DEFAULT_MIN_ONLINE_RESOLVERS_CN = 2
DEFAULT_MIN_ONLINE_RESOLVERS_GLOBAL = 2
DEFAULT_BUDGET = 16_000
DEFAULT_NEW_BUDGET = 10_000
DEFAULT_RECHECK_BUDGET = 6_000
DEFAULT_CONCURRENCY = 64
DEFAULT_GLOBAL_CONCURRENCY = 64
DEFAULT_INFLIGHT_PER_RESOLVER = 1
DEFAULT_TIMEOUT_MS = 800
DEFAULT_RETRIES = 0
DEFAULT_JITTER_MS = 50
DEFAULT_GLOBAL_INFLIGHT_PER_RESOLVER = 16
DEFAULT_TTL_ALIVE_DAYS = 35
DEFAULT_TTL_DEAD_DAYS = 14
DEFAULT_TTL_UNKNOWN_DAYS = 2
DEFAULT_TTL_DEAD_RECHECK_DAYS = 7

DEFAULT_CN_QUERY_DELAY_MS = 500
DEFAULT_CN_BACKOFF_BASE_MS = 500
DEFAULT_CN_BACKOFF_MAX_MS = 8_000
DEFAULT_CN_FAILURE_THRESHOLD = 3
DEFAULT_CN_COOLDOWN_MS = 10_000
DEFAULT_CN_SLOW_THRESHOLD_MS = 4_000
DEFAULT_CN_MAX_RETRIES = 3


class DnsPolicyMode(str, Enum):
    """Mutually exclusive DNS cleanup strategies."""

    COVERAGE_ONLY = "coverage"
    CACHE_ONLY = "cache"
    PROBE = "probe"


@dataclass(frozen=True)
class PruneIO:
    """Filesystem boundary for one prune transaction."""

    input: Optional[Path]
    output: Optional[Path]
    cache_file: Optional[Path]
    removed_log: Optional[Path]


@dataclass(frozen=True)
class PruneExecutionPolicy:
    """Top-level execution and failure behavior."""

    dry_run: bool
    print_policy_fingerprint: bool
    require_dead_capable: bool
    remove_nodata: bool


@dataclass(frozen=True)
class ResolverPolicy:
    """Resolver identity and health quorum policy."""

    resolvers_cn: Tuple[str, ...]
    resolvers_global: Tuple[str, ...]
    health_domain: str
    min_online_resolvers: int
    min_online_resolvers_cn: int
    min_online_resolvers_global: int


@dataclass(frozen=True)
class ProbeBudget:
    """Allocation limits for new and cached DNS candidates."""

    budget: int
    new_budget: int
    recheck_budget: int


@dataclass(frozen=True)
class DnsQuerySettings:
    """Resolver query timeout and retry policy."""

    timeout_ms: int
    retries: int


@dataclass(frozen=True)
class GlobalProbeSettings:
    """Concurrency limits for the GLOBAL resolver round."""

    concurrency: int
    inflight_per_resolver: int


@dataclass(frozen=True)
class CnProbeSettings:
    """CN resolver concurrency, pacing, retry, and circuit-breaker policy."""

    concurrency: int
    inflight_per_resolver: int
    jitter_ms: int
    query_delay_ms: int
    backoff_base_ms: int
    backoff_max_ms: int
    failure_threshold: int
    cooldown_ms: int
    slow_threshold_ms: int
    max_retries: int


@dataclass(frozen=True)
class ProbeSettings:
    """Composed DNS probe policies shared by planning and execution."""

    budget: ProbeBudget
    query: DnsQuerySettings
    global_probe: GlobalProbeSettings
    cn_probe: CnProbeSettings


@dataclass(frozen=True)
class PruneRequest:
    """Validated aggregate composed from narrow prune policies."""

    io: PruneIO
    execution: PruneExecutionPolicy
    resolvers: ResolverPolicy
    probe: ProbeSettings
    cache_ttl: CacheTtlPolicy


@dataclass(frozen=True)
class PruneExecutionResult:
    """Machine-readable result for orchestration and CLI compatibility."""

    exit_code: int
    status: str
    reason: str = ""

    @property
    def degraded(self) -> bool:
        return self.status == "degraded"


@dataclass(frozen=True)
class DnsReply:
    rcode: int
    ancount: int
    nscount: Optional[int] = None


@dataclass(frozen=True)
class ResolverProbe:
    resolver: str
    status: str
    reason: str
    elapsed_ms: float


@dataclass(frozen=True)
class ProbePlan:
    targets: List[str]
    new_count: int
    recheck_count: int
    dead_recheck_count: int
    stale_recheck_count: int
    overflow_count: int
    new_candidate_count: int
    dead_recheck_candidate_count: int
    stale_candidate_count: int
    fresh_alive_count: int
    fresh_dead_count: int
    fresh_unknown_count: int


@dataclass(frozen=True)
class ProbePolicy:
    version: int
    resolvers: Tuple[str, ...]
    resolvers_cn: Tuple[str, ...]
    resolvers_global: Tuple[str, ...]
    health_domain: str
    min_online_resolvers: int
    min_online_resolvers_cn: int
    min_online_resolvers_global: int
    timeout_ms: int
    retries: int
    cn_query_delay_ms: int = DEFAULT_CN_QUERY_DELAY_MS
    cn_backoff_base_ms: int = DEFAULT_CN_BACKOFF_BASE_MS
    cn_backoff_max_ms: int = DEFAULT_CN_BACKOFF_MAX_MS
    cn_failure_threshold: int = DEFAULT_CN_FAILURE_THRESHOLD
    cn_cooldown_ms: int = DEFAULT_CN_COOLDOWN_MS
    cn_slow_threshold_ms: int = DEFAULT_CN_SLOW_THRESHOLD_MS
    cn_max_retries: int = DEFAULT_CN_MAX_RETRIES
    global_inflight_per_resolver: int = DEFAULT_GLOBAL_INFLIGHT_PER_RESOLVER

    def to_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "resolvers": list(self.resolvers),
            "resolvers_cn": list(self.resolvers_cn),
            "resolvers_global": list(self.resolvers_global),
            "health_domain": self.health_domain,
            "min_online_resolvers": self.min_online_resolvers,
            "min_online_resolvers_cn": self.min_online_resolvers_cn,
            "min_online_resolvers_global": self.min_online_resolvers_global,
            "timeout_ms": self.timeout_ms,
            "retries": self.retries,
            "cn_query_delay_ms": self.cn_query_delay_ms,
            "cn_backoff_base_ms": self.cn_backoff_base_ms,
            "cn_backoff_max_ms": self.cn_backoff_max_ms,
            "cn_failure_threshold": self.cn_failure_threshold,
            "cn_cooldown_ms": self.cn_cooldown_ms,
            "cn_slow_threshold_ms": self.cn_slow_threshold_ms,
            "cn_max_retries": self.cn_max_retries,
            "global_inflight_per_resolver": self.global_inflight_per_resolver,
        }

    def fingerprint(self) -> str:
        payload = {
            "cache_format_version": CACHE_FORMAT_VERSION,
            "probe_policy": self.to_dict(),
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


DeadSetResult = InactiveDomainSelection
