#!/usr/bin/env python3
"""Rule-domain extraction helpers for DNS pruning."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

try:
    from rule_canonical import canonicalize_adblock_domain
except ImportError:  # Support ``python -m script.dns_prune_rules``.
    from .rule_canonical import canonicalize_adblock_domain  # type: ignore[no-redef]


def extract_check_domain(line: str) -> Optional[str]:
    stripped = (line or "").strip()
    if not stripped:
        return None

    key = canonicalize_adblock_domain(stripped)
    if key is None or "badfilter" in key.modifiers:
        return None

    target = key.target.rstrip(".")
    if not target or "." not in target:
        return None
    if "*" not in target:
        return target

    # Only the common suffix wildcard can be probed safely.
    if target.startswith("*.") and target.count("*") == 1:
        base = target[2:]
        if base and "." in base:
            return base
    return None


def has_badfilter_modifier(rule: str) -> bool:
    """Return whether one rule contains a badfilter modifier token."""

    key = canonicalize_adblock_domain((rule or "").strip())
    return key is not None and "badfilter" in key.modifiers


def iter_check_domains(lines: Iterable[str]) -> List[str]:
    domains: Dict[str, None] = {}
    for line in lines:
        domain = extract_check_domain(line)
        if domain:
            domains[domain] = None
    return sorted(domains)
