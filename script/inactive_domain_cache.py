"""Select reusable inactive domains from an observation cache.

This module deliberately knows nothing about DNS resolvers or environment
variables.  The producer owns compatibility-policy construction; consumers
provide the already-resolved policy at the boundary.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable, Mapping, Optional, Set

try:
    from inactive_domain_model import (
        CacheEntry,
        CacheReusePolicy,
        CacheTtlPolicy,
        InactiveDomainSelection,
    )
    from inactive_domain_repository import (
        cache_is_fresh,
        load_cache,
        should_recheck_dead_entry,
    )
except ImportError:  # Support ``python -m script.inactive_domain_cache``.
    from .inactive_domain_model import (  # type: ignore[no-redef]
        CacheEntry,
        CacheReusePolicy,
        CacheTtlPolicy,
        InactiveDomainSelection,
    )
    from .inactive_domain_repository import (  # type: ignore[no-redef]
        cache_is_fresh,
        load_cache,
        should_recheck_dead_entry,
    )


def select_reusable_inactive_domains(
    cache: Mapping[str, CacheEntry],
    *,
    ttl_policy: CacheTtlPolicy,
    active_domains: Optional[Iterable[str]] = None,
    rechecked_domains: Iterable[str] = (),
    now_ts: Optional[int] = None,
    cache_state: str = "loaded",
) -> InactiveDomainSelection:
    """Select fresh inactive entries that have no pending mandatory recheck."""

    checked_at = int(time.time()) if now_ts is None else int(now_ts)
    candidates = set(cache) if active_domains is None else set(active_domains)
    rechecked: Set[str] = set(rechecked_domains)
    inactive: dict[str, CacheEntry] = {}
    blocked_pending_recheck_count = 0
    for domain in candidates:
        entry = cache.get(domain)
        if entry is None or entry.status != "dead":
            continue
        if not cache_is_fresh(
            entry,
            checked_at,
            ttl_policy.ttl_alive_days,
            ttl_policy.ttl_dead_days,
            ttl_policy.ttl_unknown_days,
        ):
            continue
        if (
            should_recheck_dead_entry(
                entry,
                checked_at,
                ttl_policy.ttl_dead_recheck_days,
            )
            and domain not in rechecked
        ):
            blocked_pending_recheck_count += 1
            continue
        inactive[domain] = entry
    return InactiveDomainSelection(
        inactive=inactive,
        reusable_count=len(inactive),
        blocked_pending_recheck_count=blocked_pending_recheck_count,
        cache_state=cache_state,
    )


def load_reusable_inactive_domains(
    path: str | Path,
    *,
    policy: CacheReusePolicy,
    active_domains: Optional[Iterable[str]] = None,
    now_ts: Optional[int] = None,
) -> InactiveDomainSelection:
    """Load one compatible cache and expose reusable inactive domains."""

    loaded = load_cache(path, expected_compatibility=policy.compatibility)
    return select_reusable_inactive_domains(
        loaded.entries,
        ttl_policy=policy.ttl,
        active_domains=active_domains,
        now_ts=now_ts,
        cache_state=loaded.state,
    )

