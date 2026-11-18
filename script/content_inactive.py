"""Reuse DNS inactive cache entries to clean safe Adblock domain rules."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from common import atomic_write_text, read_utf8_lines
    from inactive_domain_cache import load_reusable_inactive_domains
    from inactive_domain_model import CacheReusePolicy
    from rule_canonical import canonicalize_adblock_domain
except ImportError:  # Support ``python -m script.content_inactive``.
    from .common import atomic_write_text, read_utf8_lines  # type: ignore[no-redef]
    from .inactive_domain_cache import (  # type: ignore[no-redef]
        load_reusable_inactive_domains,
    )
    from .inactive_domain_model import CacheReusePolicy  # type: ignore[no-redef]
    from .rule_canonical import canonicalize_adblock_domain  # type: ignore[no-redef]


TOTAL_COUNT_RE = re.compile(r"^! Total count: [0-9]+$")


class ContentInactiveCleanupError(RuntimeError):
    """Raised when a content cache cleanup cannot preserve rule structure."""


@dataclass(frozen=True)
class ContentInactiveCleanupResult:
    output_file: Path
    before_rule_count: int
    after_rule_count: int
    removed_rule_count: int
    reusable_dead_count: int
    cache_state: str


def _safe_domain(line: str) -> Optional[str]:
    """Return only unmodified, exact, non-IP blocking domains."""

    key = canonicalize_adblock_domain(line)
    if key is None or key.modifiers or "*" in key.target:
        return None
    target = key.target.rstrip(".")
    if "." not in target:
        return None
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return target
    return None


def cleanup_content_with_cache(
    output_file: Path,
    *,
    cache_file: Path,
    policy: CacheReusePolicy,
    enabled: bool = True,
    now_ts: Optional[int] = None,
) -> ContentInactiveCleanupResult:
    """Remove safely identifiable content rules using reusable DNS cache only."""

    path = Path(output_file).resolve()
    try:
        lines = read_utf8_lines(path, required=True, reject_cr=True)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ContentInactiveCleanupError(
            f"failed to read content artifact {path}: {exc}"
        ) from exc

    total_count_index = next(
        (
            index
            for index, line in enumerate(lines)
            if TOTAL_COUNT_RE.fullmatch(line)
        ),
        None,
    )
    if total_count_index is None:
        raise ContentInactiveCleanupError(
            f"content artifact has no total-count header: {path}"
        )

    rule_indices = [
        index
        for index in range(total_count_index + 1, len(lines))
        if lines[index] and not lines[index].lstrip().startswith("!")
    ]
    before_rule_count = len(rule_indices)
    if not enabled:
        return ContentInactiveCleanupResult(
            output_file=path,
            before_rule_count=before_rule_count,
            after_rule_count=before_rule_count,
            removed_rule_count=0,
            reusable_dead_count=0,
            cache_state="disabled",
        )
    rule_domains: dict[int, str] = {}
    for index in rule_indices:
        domain = _safe_domain(lines[index])
        if domain is not None:
            rule_domains[index] = domain
    candidate_domains = set(rule_domains.values())
    reusable = load_reusable_inactive_domains(
        cache_file,
        policy=policy,
        active_domains=candidate_domains,
        now_ts=now_ts,
    )
    dead_domains = set(reusable.inactive)
    if not dead_domains:
        return ContentInactiveCleanupResult(
            output_file=path,
            before_rule_count=before_rule_count,
            after_rule_count=before_rule_count,
            removed_rule_count=0,
            reusable_dead_count=reusable.reusable_count,
            cache_state=reusable.cache_state,
        )

    kept_lines: list[str] = []
    removed = 0
    for index, line in enumerate(lines):
        if rule_domains.get(index) in dead_domains:
            removed += 1
            continue
        kept_lines.append(line)

    kept_lines[total_count_index] = f"! Total count: {before_rule_count - removed}"

    atomic_write_text(path, "\n".join(kept_lines) + "\n")
    return ContentInactiveCleanupResult(
        output_file=path,
        before_rule_count=before_rule_count,
        after_rule_count=before_rule_count - removed,
        removed_rule_count=removed,
        reusable_dead_count=reusable.reusable_count,
        cache_state=reusable.cache_state,
    )
