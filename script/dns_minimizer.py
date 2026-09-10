#!/usr/bin/env python3
"""Semantics-preserving minimization for DNS and Mihomo rule sets."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

try:
    from common import atomic_write_lines, read_utf8_lines
    from rule_canonical import (
        DomainGlobIndex,
        RuleCanonicalKey,
        canonicalize_adblock_domain,
        canonicalize_mihomo_domain,
        fixed_prefix as _fixed_prefix,
        fixed_suffix as _fixed_suffix,
        glob_is_covered_by_domain,
        glob_is_subset,
        semantic_duplicate_indices,
    )
except ImportError:  # Support ``python -m script.dns_minimizer``.
    from .common import (  # type: ignore[no-redef]
        atomic_write_lines,
        read_utf8_lines,
    )
    from .rule_canonical import (  # type: ignore[no-redef]
        DomainGlobIndex,
        RuleCanonicalKey,
        canonicalize_adblock_domain,
        canonicalize_mihomo_domain,
        fixed_prefix as _fixed_prefix,
        fixed_suffix as _fixed_suffix,
        glob_is_covered_by_domain,
        glob_is_subset,
        semantic_duplicate_indices,
    )


@dataclass
class MinimizeStats:
    semantic_duplicate_count: int = 0
    disabled_base: int = 0
    important_base: int = 0
    parent_domain: int = 0
    domain_by_wildcard: int = 0
    wildcard_by_domain: int = 0
    wildcard_by_wildcard: int = 0
    third_party_by_domain: int = 0
    third_party_by_wildcard: int = 0
    mihomo_suffix: int = 0
    mihomo_domain: int = 0
    mihomo_wildcard: int = 0

    @property
    def removed(self) -> int:
        return sum(vars(self).values())


@dataclass(frozen=True)
class DomainRule:
    index: int
    target: str
    modifiers: tuple[str, ...] = field(default_factory=tuple)

    @property
    def key(self) -> RuleCanonicalKey:
        return RuleCanonicalKey(
            format="adblock",
            kind="domain",
            target=self.target,
            modifiers=self.modifiers,
        )

    @property
    def is_wildcard(self) -> bool:
        return "*" in self.target


def _parse_domain_rule(index: int, line: str) -> DomainRule | None:
    key = canonicalize_adblock_domain(line)
    if key is None:
        return None
    return DomainRule(
        index=index,
        target=key.target,
        modifiers=key.modifiers,
    )


def _parse_domain_rules_once(
    lines: Sequence[str],
    canonical_keys: Sequence[RuleCanonicalKey | None] | None = None,
) -> tuple[set[int], list[DomainRule]]:
    """Canonicalize domain rules once while selecting stable duplicates."""

    representatives: dict[RuleCanonicalKey, int] = {}
    duplicate_indices: set[int] = set()
    parsed: list[tuple[int, RuleCanonicalKey]] = []
    for index, line in enumerate(lines):
        key = (
            canonical_keys[index]
            if canonical_keys is not None
            else canonicalize_adblock_domain(line)
        )
        if key is None or key.kind != "domain":
            continue
        parsed.append((index, key))
        previous = representatives.get(key)
        if previous is None:
            representatives[key] = index
        elif line < lines[previous]:
            duplicate_indices.add(previous)
            representatives[key] = index
        else:
            duplicate_indices.add(index)

    rules = [
        DomainRule(index=index, target=key.target, modifiers=key.modifiers)
        for index, key in parsed
        if index not in duplicate_indices
    ]
    return duplicate_indices, rules


def _parent_domains(domain: str) -> Iterable[str]:
    labels = domain.split(".")
    for index in range(1, len(labels)):
        yield ".".join(labels[index:])


def _disabled_rule_keys(rules: Sequence[DomainRule]) -> set[RuleCanonicalKey]:
    disabled: set[RuleCanonicalKey] = set()
    for rule in rules:
        if "badfilter" not in rule.modifiers:
            continue
        remaining = tuple(modifier for modifier in rule.modifiers if modifier != "badfilter")
        disabled.add(
            RuleCanonicalKey(
                format="adblock",
                kind="domain",
                target=rule.target,
                modifiers=remaining,
            )
        )
    return disabled


def _redundant_wildcards(patterns: Sequence[str]) -> set[str]:
    """Find non-maximal glob languages while retaining one stable equivalent."""

    ordered = sorted(set(patterns))
    if len(ordered) < 2:
        return set()

    subset: dict[tuple[str, str], bool] = {}
    for subject in ordered:
        for covering in ordered:
            if subject == covering:
                subset[(subject, covering)] = True
            elif not (
                _fixed_prefix(subject).startswith(_fixed_prefix(covering))
                and _fixed_suffix(subject).endswith(_fixed_suffix(covering))
            ):
                # These are necessary conditions for language inclusion. Skip
                # the automaton entirely for incompatible prefix/suffix pairs.
                subset[(subject, covering)] = False
            else:
                subset[(subject, covering)] = glob_is_subset(subject, covering)

    parent = {pattern: pattern for pattern in ordered}

    def find(pattern: str) -> str:
        while parent[pattern] != pattern:
            parent[pattern] = parent[parent[pattern]]
            pattern = parent[pattern]
        return pattern

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        representative = min(left_root, right_root)
        parent[left_root] = representative
        parent[right_root] = representative

    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            if subset[(left, right)] and subset[(right, left)]:
                union(left, right)

    classes: dict[str, list[str]] = {}
    for pattern in ordered:
        classes.setdefault(find(pattern), []).append(pattern)

    representative = {root: min(members) for root, members in classes.items()}
    redundant = {
        pattern
        for root, members in classes.items()
        for pattern in members
        if pattern != representative[root]
    }

    roots = sorted(classes)
    for root in roots:
        subject = representative[root]
        if any(
            other_root != root and subset[(subject, representative[other_root])]
            for other_root in roots
        ):
            redundant.update(classes[root])

    return redundant


def minimize_adblock_domain_lines(
    lines: Sequence[str],
    canonical_keys: Sequence[RuleCanonicalKey | None] | None = None,
) -> tuple[list[str], MinimizeStats]:
    """Minimize ABP blocking-domain records while preserving other lines."""

    duplicate_indices, rules = _parse_domain_rules_once(lines, canonical_keys)
    disabled = _disabled_rule_keys(rules)
    important_targets = {
        rule.target
        for rule in rules
        if rule.modifiers == ("important",) and rule.key not in disabled
    }

    removed: set[int] = set(duplicate_indices)
    stats = MinimizeStats()
    stats.semantic_duplicate_count = len(duplicate_indices)

    for rule in rules:
        if "badfilter" in rule.modifiers:
            continue
        if rule.key in disabled:
            removed.add(rule.index)
            stats.disabled_base += 1
        elif not rule.modifiers and rule.target in important_targets:
            removed.add(rule.index)
            stats.important_base += 1

    active_plain = {
        rule.target
        for rule in rules
        if not rule.modifiers
        and not rule.is_wildcard
        and rule.index not in removed
    }
    active_wildcard_rules = [
        rule
        for rule in rules
        if not rule.modifiers
        and rule.is_wildcard
        and rule.index not in removed
    ]
    active_plain_wildcards = tuple(rule.target for rule in active_wildcard_rules)
    wildcard_index = DomainGlobIndex(
        active_plain_wildcards
    )

    for rule in rules:
        if rule.modifiers or rule.is_wildcard or rule.index in removed:
            continue
        if any(parent in active_plain for parent in _parent_domains(rule.target)):
            removed.add(rule.index)
            stats.parent_domain += 1
            continue
        if wildcard_index.covers_domain(rule.target):
            removed.add(rule.index)
            stats.domain_by_wildcard += 1

    # A plain blocking rule has the same blocking action for every request,
    # so it subsumes the narrower third-party form for the same target and
    # descendants. Keep this intentionally limited to the canonical pure
    # modifier: redirect, important, badfilter, and other action/scope
    # modifiers have distinct semantics and must remain separate.
    for rule in rules:
        if rule.index in removed or rule.modifiers != ("third-party",):
            continue

        if "*" not in rule.target and (
            rule.target in active_plain
            or any(parent in active_plain for parent in _parent_domains(rule.target))
        ):
            removed.add(rule.index)
            stats.third_party_by_domain += 1
        elif "*" not in rule.target and wildcard_index.covers_domain(rule.target):
            removed.add(rule.index)
            stats.third_party_by_wildcard += 1
        elif "*" in rule.target:
            fixed_suffix = _fixed_suffix(rule.target).lstrip(".")
            candidate_domains = [
                candidate
                for candidate in (fixed_suffix, *_parent_domains(fixed_suffix))
                if candidate in active_plain
            ]
            if any(
                glob_is_covered_by_domain(rule.target, domain)
                for domain in candidate_domains
            ):
                removed.add(rule.index)
                stats.third_party_by_domain += 1
            elif any(
                glob_is_subset(rule.target, covering)
                for covering in active_plain_wildcards
            ):
                removed.add(rule.index)
                stats.third_party_by_wildcard += 1

    wildcard_covered_by_domain: set[str] = set()
    for rule in active_wildcard_rules:
        fixed_suffix = _fixed_suffix(rule.target).lstrip(".")
        candidate_domains = [
            candidate
            for candidate in (fixed_suffix, *_parent_domains(fixed_suffix))
            if candidate in active_plain
        ]
        if any(glob_is_covered_by_domain(rule.target, domain) for domain in candidate_domains):
            removed.add(rule.index)
            wildcard_covered_by_domain.add(rule.target)
            stats.wildcard_by_domain += 1

    remaining_wildcards = [
        rule.target
        for rule in active_wildcard_rules
        if rule.target not in wildcard_covered_by_domain
    ]
    redundant_wildcards = _redundant_wildcards(remaining_wildcards)
    for rule in active_wildcard_rules:
        if rule.target in redundant_wildcards and rule.index not in removed:
            removed.add(rule.index)
            stats.wildcard_by_wildcard += 1

    return [line for index, line in enumerate(lines) if index not in removed], stats


def minimize_dns_lines(lines: Sequence[str]) -> tuple[list[str], MinimizeStats]:
    """Backward-compatible DNS entry point for ABP domain minimization."""

    return minimize_adblock_domain_lines(lines)


def _suffix_covers_domain(suffix: str, domain: str) -> bool:
    return domain == suffix or domain.endswith(f".{suffix}")


def minimize_mihomo_lines(lines: Sequence[str]) -> tuple[list[str], MinimizeStats]:
    duplicate_indices = semantic_duplicate_indices(lines, canonicalize_mihomo_domain)
    parsed: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines):
        if index in duplicate_indices:
            continue
        key = canonicalize_mihomo_domain(line)
        if key is not None:
            parsed.append((index, key.kind, key.target))

    suffixes = {
        value
        for _, kind, value in parsed
        if kind == "DOMAIN-SUFFIX"
    }
    redundant_suffixes = {
        suffix
        for suffix in suffixes
        if any(parent in suffixes for parent in _parent_domains(suffix))
    }
    active_suffixes = suffixes - redundant_suffixes

    removed: set[int] = set(duplicate_indices)
    stats = MinimizeStats(semantic_duplicate_count=len(duplicate_indices))
    for index, kind, value in parsed:
        if kind == "DOMAIN-SUFFIX" and value in redundant_suffixes:
            removed.add(index)
            stats.mihomo_suffix += 1
            continue

        if kind == "DOMAIN" and any(
            _suffix_covers_domain(suffix, value)
            for suffix in (value, *_parent_domains(value))
            if suffix in active_suffixes
        ):
            removed.add(index)
            stats.mihomo_domain += 1
            continue

        if kind != "DOMAIN-WILDCARD":
            continue

        fixed_suffix = _fixed_suffix(value).lstrip(".")
        candidates = [
            suffix
            for suffix in (fixed_suffix, *_parent_domains(fixed_suffix))
            if suffix in active_suffixes
        ]
        if any(glob_is_covered_by_domain(value, suffix) for suffix in candidates):
            removed.add(index)
            stats.mihomo_wildcard += 1

    # A broad wildcard also makes a narrower wildcard redundant.  Apply the
    # same language-subset relation used by DNS wildcard minimization and keep
    # the lexicographically stable representative for equivalent patterns.
    active_wildcards = [
        value
        for index, kind, value in parsed
        if kind == "DOMAIN-WILDCARD" and index not in removed
    ]
    redundant_wildcards = _redundant_wildcards(active_wildcards)
    for index, kind, value in parsed:
        if kind == "DOMAIN-WILDCARD" and value in redundant_wildcards:
            removed.add(index)
            stats.mihomo_wildcard += 1

    return [line for index, line in enumerate(lines) if index not in removed], stats


def _run_mode(mode: str, input_path: Path, output_path: Path) -> int:
    try:
        lines = read_utf8_lines(input_path)
        if mode == "dns":
            minimized, stats = minimize_dns_lines(lines)
            details = (
                f"semantic:{stats.semantic_duplicate_count} "
                f"badfilter:{stats.disabled_base} important:{stats.important_base} "
                f"parent:{stats.parent_domain} wildcard-domain:{stats.wildcard_by_domain} "
                f"wildcard-wildcard:{stats.wildcard_by_wildcard} "
                f"third-party-domain:{stats.third_party_by_domain} "
                f"third-party-wildcard:{stats.third_party_by_wildcard}"
            )
        else:
            minimized, stats = minimize_mihomo_lines(lines)
            details = (
                f"semantic:{stats.semantic_duplicate_count} "
                f"suffix:{stats.mihomo_suffix} domain:{stats.mihomo_domain} "
                f"wildcard:{stats.mihomo_wildcard}"
            )
        atomic_write_lines(output_path, minimized)
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] DNS minimizer failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"[INFO] {mode} minimizer {len(lines)} -> {len(minimized)} "
        f"(-{stats.removed}; {details})",
        file=sys.stderr,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("dns", "mihomo"))
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    return _run_mode(args.mode, args.input, args.output or args.input)


if __name__ == "__main__":
    raise SystemExit(main())
