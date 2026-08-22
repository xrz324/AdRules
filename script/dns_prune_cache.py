#!/usr/bin/env python3
"""Cache persistence and TTL policy for DNS pruning."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Dict, Optional, Sequence

try:
    from common import atomic_write_text, read_utf8_text
    from dns_prune_model import (
        CACHE_FORMAT_VERSION,
        CacheEntry,
        CacheLoadResult,
        ProbePolicy,
    )
except ImportError:  # Support ``python -m script.dns_prune_cache``.
    from .common import atomic_write_text, read_utf8_text  # type: ignore[no-redef]
    from .dns_prune_model import (  # type: ignore[no-redef]
        CACHE_FORMAT_VERSION,
        CacheEntry,
        CacheLoadResult,
        ProbePolicy,
    )


LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())


def load_cache(
    path: str,
    probe_policy: Optional[ProbePolicy] = None,
) -> CacheLoadResult:
    """Load one compatible cache, treating malformed data as a cache miss."""

    if not path or not Path(path).is_file():
        return CacheLoadResult(entries={}, state="miss")

    try:
        raw = json.loads(read_utf8_text(Path(path)))
    except Exception as exc:  # noqa: BLE001 - a corrupt cache is recoverable.
        LOGGER.warning("Cache read failed; ignoring and rebuilding: %s (%s)", path, exc)
        return CacheLoadResult(entries={}, state="read-error")

    version = raw.get("version")
    if version != CACHE_FORMAT_VERSION:
        LOGGER.warning(
            "Cache version is incompatible; ignoring and rebuilding: %s (version=%s)",
            path,
            version,
        )
        return CacheLoadResult(entries={}, state="version-mismatch")

    if probe_policy is not None and raw.get("probe_policy") != probe_policy.to_dict():
        LOGGER.warning("Probe policy changed; ignoring and rebuilding cache: %s", path)
        return CacheLoadResult(entries={}, state="policy-mismatch")

    domains = raw.get("domains")
    if not isinstance(domains, dict):
        return CacheLoadResult(entries={}, state="invalid")

    parsed: Dict[str, CacheEntry] = {}
    for domain, entry in domains.items():
        if not isinstance(domain, str) or not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or "").strip()
        checked_at = entry.get("checked_at")
        reason = str(entry.get("reason") or "").strip()
        if status not in {"alive", "dead", "unknown"}:
            continue
        if not isinstance(checked_at, int) or checked_at <= 0:
            continue
        parsed[domain] = CacheEntry(status=status, checked_at=checked_at, reason=reason)
    return CacheLoadResult(entries=parsed, state="loaded")


def save_cache(
    path: str,
    cache: Dict[str, CacheEntry],
    active_domains: Optional[Sequence[str]] = None,
    probe_policy: Optional[ProbePolicy] = None,
) -> None:
    """Persist only active domains when an active set is explicitly supplied."""

    if not path:
        return

    cache_items = cache.items()
    if active_domains is not None:
        active_domain_set = set(active_domains)
        cache_items = (
            (domain, entry)
            for domain, entry in cache.items()
            if domain in active_domain_set
        )

    payload = {
        "version": CACHE_FORMAT_VERSION,
        "generated_at": time.time_ns() // 1_000_000_000,
        "probe_policy": probe_policy.to_dict() if probe_policy is not None else None,
        "domains": {
            domain: {
                "status": entry.status,
                "checked_at": entry.checked_at,
                "reason": entry.reason,
            }
            for domain, entry in sorted(cache_items)
        },
    }
    atomic_write_text(
        Path(path),
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
    )


def ttl_seconds(
    status: str,
    ttl_alive_days: int,
    ttl_dead_days: int,
    ttl_unknown_days: int,
) -> int:
    if status == "alive":
        return max(0, ttl_alive_days) * 86400
    if status == "dead":
        return max(0, ttl_dead_days) * 86400
    return max(0, ttl_unknown_days) * 86400


def cache_is_fresh(
    entry: CacheEntry,
    now_ts: int,
    ttl_alive_days: int,
    ttl_dead_days: int,
    ttl_unknown_days: int,
) -> bool:
    ttl = ttl_seconds(entry.status, ttl_alive_days, ttl_dead_days, ttl_unknown_days)
    if ttl == 0:
        return False
    return (now_ts - entry.checked_at) <= ttl


def should_recheck_dead_entry(
    entry: CacheEntry,
    now_ts: int,
    ttl_dead_recheck_days: int,
) -> bool:
    if entry.status != "dead":
        return False
    ttl = max(0, ttl_dead_recheck_days) * 86400
    if ttl == 0:
        return False
    return (now_ts - entry.checked_at) >= ttl
