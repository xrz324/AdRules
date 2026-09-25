"""Persistence for the shared inactive-domain observation cache."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence

try:
    from common import read_utf8_text
    from inactive_domain_model import CACHE_FORMAT_VERSION, CacheEntry, CacheLoadResult
except ImportError:  # Support ``python -m script.inactive_domain_repository``.
    from .common import read_utf8_text  # type: ignore[no-redef]
    from .inactive_domain_model import (  # type: ignore[no-redef]
        CACHE_FORMAT_VERSION,
        CacheEntry,
        CacheLoadResult,
    )


LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())

def load_cache(
    path: str | Path,
    *,
    expected_compatibility: Optional[Mapping[str, object]] = None,
    allow_legacy: bool = False,
) -> CacheLoadResult:
    """Load and validate the shared cache schema."""

    cache_path = Path(path)
    if not str(path) or not cache_path.is_file():
        return CacheLoadResult(entries={}, state="miss")
    try:
        raw = json.loads(read_utf8_text(cache_path))
    except Exception as exc:  # noqa: BLE001 - corrupt cache is recoverable.
        LOGGER.warning("Cache read failed; ignoring and rebuilding: %s (%s)", path, exc)
        return CacheLoadResult(entries={}, state="read-error")
    if not isinstance(raw, dict):
        LOGGER.warning("Cache root is not an object; ignoring and rebuilding: %s", path)
        return CacheLoadResult(entries={}, state="invalid")
    if not allow_legacy and raw.get("version") != CACHE_FORMAT_VERSION:
        LOGGER.warning(
            "Cache version is incompatible; ignoring and rebuilding: %s (version=%s)",
            path,
            raw.get("version"),
        )
        return CacheLoadResult(entries={}, state="version-mismatch")
    if (
        expected_compatibility is not None
        and raw.get("probe_policy") != dict(expected_compatibility)
    ):
        LOGGER.warning("Cache compatibility changed; ignoring and rebuilding: %s", path)
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
        if allow_legacy and not isinstance(checked_at, int):
            checked_at = 1
        if (
            not isinstance(checked_at, int)
            or isinstance(checked_at, bool)
            or checked_at <= 0
        ):
            continue
        parsed[domain] = CacheEntry(status=status, checked_at=checked_at, reason=reason)
    return CacheLoadResult(entries=parsed, state="loaded")


def render_cache(
    cache: Mapping[str, CacheEntry],
    *,
    active_domains: Optional[Sequence[str]] = None,
    compatibility: Optional[Mapping[str, object]] = None,
) -> str:
    """Serialize the shared cache schema without performing I/O."""

    selected = cache.items()
    if active_domains is not None:
        active = set(active_domains)
        selected = (
            (domain, entry)
            for domain, entry in cache.items()
            if domain in active
        )
    payload = {
        "version": CACHE_FORMAT_VERSION,
        "generated_at": time.time_ns() // 1_000_000_000,
        "probe_policy": dict(compatibility) if compatibility is not None else None,
        "domains": {
            domain: {
                "status": entry.status,
                "checked_at": entry.checked_at,
                "reason": entry.reason,
            }
            for domain, entry in sorted(selected)
        },
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"


def cache_is_fresh(
    entry: CacheEntry,
    now_ts: int,
    ttl_alive_days: int,
    ttl_dead_days: int,
    ttl_unknown_days: int,
) -> bool:
    """Return whether an observation is inside its status-specific TTL."""

    ttl = ttl_seconds(
        entry.status,
        ttl_alive_days,
        ttl_dead_days,
        ttl_unknown_days,
    )
    return ttl > 0 and (now_ts - entry.checked_at) <= ttl


def ttl_seconds(
    status: str,
    ttl_alive_days: int,
    ttl_dead_days: int,
    ttl_unknown_days: int,
) -> int:
    """Return the status-specific cache TTL in seconds."""

    ttl_days = {
        "alive": ttl_alive_days,
        "dead": ttl_dead_days,
        "unknown": ttl_unknown_days,
    }.get(status, ttl_unknown_days)
    return max(0, ttl_days) * 86400


def should_recheck_dead_entry(
    entry: CacheEntry,
    now_ts: int,
    ttl_dead_recheck_days: int,
) -> bool:
    """Return whether a dead observation requires a fresh probe."""

    if entry.status != "dead":
        return False
    ttl = max(0, ttl_dead_recheck_days) * 86400
    return ttl > 0 and (now_ts - entry.checked_at) >= ttl
