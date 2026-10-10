#!/usr/bin/env python3
"""Cache persistence and TTL policy for DNS pruning."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence

try:
    from common import atomic_write_text
    from dns_prune_model import ProbePolicy
    from inactive_domain_repository import (
        cache_is_fresh,
        load_cache as load_inactive_cache,
        render_cache as render_inactive_cache,
        should_recheck_dead_entry,
        ttl_seconds,
    )
    from inactive_domain_model import CacheEntry, CacheLoadResult
except ImportError:  # Support ``python -m script.dns_prune_cache``.
    from .common import atomic_write_text  # type: ignore[no-redef]
    from .dns_prune_model import ProbePolicy  # type: ignore[no-redef]
    from .inactive_domain_repository import (  # type: ignore[no-redef]
        cache_is_fresh,
        load_cache as load_inactive_cache,
        render_cache as render_inactive_cache,
        should_recheck_dead_entry,
        ttl_seconds,
    )
    from .inactive_domain_model import CacheEntry, CacheLoadResult  # type: ignore[no-redef]


def load_cache(
    path: str,
    probe_policy: Optional[ProbePolicy | Mapping[str, object]] = None,
) -> CacheLoadResult:
    """Load one compatible cache through the shared repository."""

    expected_policy = (
        probe_policy
        if isinstance(probe_policy, Mapping)
        else probe_policy.to_dict()
        if probe_policy is not None
        else None
    )
    return load_inactive_cache(path, expected_compatibility=expected_policy)


def save_cache(
    path: str,
    cache: Dict[str, CacheEntry],
    active_domains: Optional[Sequence[str]] = None,
    probe_policy: Optional[ProbePolicy] = None,
) -> None:
    """Persist only active domains when an active set is explicitly supplied."""

    if not path:
        return

    atomic_write_text(Path(path), render_cache(cache, active_domains, probe_policy))


def render_cache(
    cache: Dict[str, CacheEntry],
    active_domains: Optional[Sequence[str]] = None,
    probe_policy: Optional[ProbePolicy] = None,
) -> str:
    """Serialize cache state without performing I/O."""

    compatibility = (
        probe_policy
        if isinstance(probe_policy, Mapping)
        else probe_policy.to_dict()
        if probe_policy is not None
        else None
    )
    return render_inactive_cache(
        cache,
        active_domains=active_domains,
        compatibility=compatibility,
    )
