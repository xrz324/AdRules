#!/usr/bin/env python3
"""Immutable models and policy constants for DNS pruning."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


CACHE_FORMAT_VERSION = 2
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
    "119.29.29.29",
    "114.114.114.114",
)

DEFAULT_CN_QUERY_DELAY_MS = 500
DEFAULT_CN_BACKOFF_BASE_MS = 500
DEFAULT_CN_BACKOFF_MAX_MS = 8_000
DEFAULT_CN_FAILURE_THRESHOLD = 3
DEFAULT_CN_COOLDOWN_MS = 15_000
DEFAULT_CN_SLOW_THRESHOLD_MS = 3_000
DEFAULT_CN_MAX_RETRIES = 3


@dataclass(frozen=True)
class CacheEntry:
    status: str
    checked_at: int
    reason: str


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


@dataclass
class CnWindowState:
    resolver: str
    failure_streak: int = 0
    pause_count: int = 0
    active: bool = False


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
    global_inflight_per_resolver: int = 0

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


@dataclass(frozen=True)
class CacheLoadResult:
    entries: Dict[str, CacheEntry]
    state: str


@dataclass(frozen=True)
class DeadSetResult:
    dead: Dict[str, CacheEntry]
    reusable_count: int
    blocked_pending_recheck_count: int
