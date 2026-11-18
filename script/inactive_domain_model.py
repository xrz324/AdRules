"""Generic models for reusable inactive-domain cache observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping, Optional

CACHE_FORMAT_VERSION = 2


@dataclass(frozen=True)
class CacheEntry:
    """One cached observation for a normalized domain."""

    status: str
    checked_at: int
    reason: str


@dataclass(frozen=True)
class CacheLoadResult:
    """Validated cache entries and the reason a cache was or was not used."""

    entries: Dict[str, CacheEntry]
    state: str


@dataclass(frozen=True)
class InactiveDomainSelection:
    """Reusable inactive entries selected for a caller's candidate set."""

    inactive: Dict[str, CacheEntry]
    reusable_count: int
    blocked_pending_recheck_count: int
    cache_state: str = "loaded"

    @property
    def dead(self) -> Dict[str, CacheEntry]:
        """Compatibility view for older DNS callers."""

        return self.inactive


@dataclass(frozen=True)
class CacheTtlPolicy:
    """Freshness and mandatory recheck windows for cached observations."""

    ttl_alive_days: int
    ttl_dead_days: int
    ttl_unknown_days: int
    ttl_dead_recheck_days: int


@dataclass(frozen=True)
class CacheReusePolicy:
    """Cache compatibility metadata and freshness policy.

    ``compatibility`` is intentionally an opaque serialized policy.  The
    cache service does not know whether it came from DNS, HTTP, or another
    observation producer.
    """

    compatibility: Optional[Mapping[str, object]]
    ttl: CacheTtlPolicy

    @property
    def probe(self) -> Optional[Mapping[str, object]]:
        """Compatibility view for callers using the former DNS name."""

        return self.compatibility
