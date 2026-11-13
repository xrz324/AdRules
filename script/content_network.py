"""Network rule parsing and minimization for content filters."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Optional, Sequence

try:
    from .content_cosmetic import find_cosmetic_marker
    from .content_models import (
        MinimizerError,
        StageStats,
        batch_domains,
        compress_domain_set,
        serialized_bytes,
        sort_unique,
    )
    from .rule_canonical import (
        GlobIndex,
        RuleCanonicalKey,
        canonicalize_adblock_rule,
        normalize_modifier,
        split_modifier_tokens,
    )
except ImportError:  # Support direct script execution.
    from content_cosmetic import find_cosmetic_marker  # type: ignore[no-redef]
    from content_models import (  # type: ignore[no-redef]
        MinimizerError,
        StageStats,
        batch_domains,
        compress_domain_set,
        serialized_bytes,
        sort_unique,
    )
    from rule_canonical import (  # type: ignore[no-redef]
        GlobIndex,
        RuleCanonicalKey,
        canonicalize_adblock_rule,
        normalize_modifier,
        split_modifier_tokens,
    )


_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
SIMPLE_HOST_RE = re.compile(rf"{_HOST_LABEL}(?:\.{_HOST_LABEL})+")
SIMPLE_URL_HOST_PATTERN_RE = re.compile(r"[A-Za-z0-9*-]+(?:\.[A-Za-z0-9*-]+)+")
MODIFIER_NAME_RE = re.compile(r"~?[A-Za-z0-9][A-Za-z0-9_-]*")


def _find_cosmetic_marker(line: str) -> Optional[tuple[int, str]]:
    return find_cosmetic_marker(line)


def _serialized_bytes(lines: Sequence[str]) -> int:
    return serialized_bytes(lines)


def _sort_unique(lines: Iterable[str]) -> list[str]:
    return sort_unique(lines)


def _normalize_simple_host(token: str) -> Optional[str]:
    if not token.isascii() or SIMPLE_HOST_RE.fullmatch(token) is None:
        return None
    return token.lower()


def _compress_domain_set(domains: Iterable[str]) -> tuple[str, ...]:
    return compress_domain_set(domains)


def _batch_domains(
    domains: Sequence[str], render, max_line_bytes: int
) -> Optional[list[str]]:
    return batch_domains(domains, render, max_line_bytes)


@dataclass(frozen=True)
class Modifier:
    raw: str
    name: str
    negated: bool
    value: Optional[str]


@dataclass(frozen=True)
class NetworkRule:
    raw: str
    base: str
    modifiers: tuple[Modifier, ...]


@dataclass(frozen=True)
class RemoveparamRule:
    network: NetworkRule
    domain_index: int
    domain_prefix: str
    domains: tuple[str, ...]


def _parse_modifier(raw: str) -> Optional[Modifier]:
    name_part, separator, value = raw.partition("=")
    if MODIFIER_NAME_RE.fullmatch(name_part) is None:
        return None
    negated = name_part.startswith("~")
    name = name_part[1:] if negated else name_part
    return Modifier(
        raw=raw,
        name=name.lower(),
        negated=negated,
        value=value if separator else None,
    )


def _parse_network_rule(line: str) -> Optional[NetworkRule]:
    # Only modifier-bearing records can be network rules.  This fast path is
    # important because content lists contain a large cosmetic/plain-domain
    # population that is visited by several minimization stages.
    if "$" not in line or line.startswith(("!", "[")):
        return None
    if _find_cosmetic_marker(line) is not None:
        return None
    return _parse_network_rule_cached(line)


@lru_cache(maxsize=262_144)
def _parse_network_rule_cached(line: str) -> Optional[NetworkRule]:
    for position, char in enumerate(line):
        if char != "$":
            continue
        raw_tokens = split_modifier_tokens(line[position + 1 :])
        if raw_tokens is None:
            continue
        modifiers = tuple(_parse_modifier(token) for token in raw_tokens)
        if any(modifier is None for modifier in modifiers):
            continue
        parsed = tuple(modifier for modifier in modifiers if modifier is not None)
        if not any(modifier.name in {"badfilter", "removeparam"} for modifier in parsed):
            continue
        return NetworkRule(raw=line, base=line[:position], modifiers=parsed)
    return None


def _parse_simple_url_host_pattern(line: str) -> Optional[NetworkRule]:
    """Parse an unanchored host-shaped URL pattern with filter options."""

    if not line or line.startswith(("!", "[", "@@")):
        return None
    base, separator, raw_options = line.partition("$")
    if (
        not separator
        or not base.isascii()
        or SIMPLE_URL_HOST_PATTERN_RE.fullmatch(base) is None
    ):
        return None

    raw_tokens = split_modifier_tokens(raw_options)
    if raw_tokens is None:
        return None
    modifiers = tuple(_parse_modifier(token) for token in raw_tokens)
    if any(modifier is None for modifier in modifiers):
        return None
    return NetworkRule(
        raw=line,
        base=base,
        modifiers=tuple(
            modifier for modifier in modifiers if modifier is not None
        ),
    )


def _render_network_rule(base: str, modifiers: Sequence[str]) -> str:
    if not modifiers:
        return base
    return f"{base}${','.join(modifiers)}"


def _modifier_key(modifier: Modifier) -> str:
    name = f"~{modifier.name}" if modifier.negated else modifier.name
    if modifier.value is None:
        return normalize_modifier(name)
    return normalize_modifier(f"{name}={modifier.value}")


def _network_rule_key(
    rule: NetworkRule, excluded_indexes: Iterable[int] = ()
) -> RuleCanonicalKey:
    excluded = set(excluded_indexes)
    modifiers = sorted(
        _modifier_key(modifier)
        for index, modifier in enumerate(rule.modifiers)
        if index not in excluded
    )
    base_key = canonicalize_adblock_rule(rule.base)
    if base_key is not None:
        return RuleCanonicalKey(
            format=base_key.format,
            kind=base_key.kind,
            target=base_key.target,
            modifiers=tuple(modifiers),
        )
    return RuleCanonicalKey(
        format="adblock",
        kind="network",
        target=rule.base,
        modifiers=tuple(modifiers),
    )


def _simple_url_host_pattern_key(
    rule: NetworkRule, excluded_indexes: Iterable[int] = ()
) -> RuleCanonicalKey:
    """Return a case-insensitive key for an eligible simple URL pattern."""

    excluded = set(excluded_indexes)
    return RuleCanonicalKey(
        format="adblock",
        kind="network",
        target=rule.base.lower(),
        modifiers=tuple(
            sorted(
                _modifier_key(modifier)
                for index, modifier in enumerate(rule.modifiers)
                if index not in excluded
            )
        ),
    )


def canonicalize_content_rule(line: str) -> Optional[RuleCanonicalKey]:
    """Return one shared key for domain and modifier-bearing network rules."""

    candidate = line.strip()
    if candidate.startswith(("||", "@@||")) and "^" in candidate:
        key = canonicalize_adblock_rule(candidate)
        if key is not None:
            return key
    if "$" not in candidate:
        return None
    parsed = _parse_network_rule(line)
    return _network_rule_key(parsed) if parsed is not None else None


def _build_badfilter_state(
    lines: Sequence[str],
) -> tuple[set[str], set[RuleCanonicalKey]]:
    return _build_badfilter_state_from_parsed(
        _parse_network_rule(line) for line in lines
    )


def _build_badfilter_state_from_parsed(
    parsed_rules: Iterable[Optional[NetworkRule]],
) -> tuple[set[str], set[RuleCanonicalKey]]:
    current: set[str] = set()
    targets: set[RuleCanonicalKey] = set()

    for parsed in parsed_rules:
        if parsed is None:
            continue
        badfilter_indexes = [
            index
            for index, modifier in enumerate(parsed.modifiers)
            if modifier.name == "badfilter"
        ]
        if not badfilter_indexes:
            continue

        current.add(parsed.raw)
        for index in badfilter_indexes:
            modifier = parsed.modifiers[index]
            if modifier.negated or modifier.value is not None:
                raise MinimizerError(f"unsupported badfilter modifier: {line}")

        targets.add(_network_rule_key(parsed, badfilter_indexes))

    return current, targets


def minimize_simple_url_host_patterns(
    lines: Sequence[str],
) -> tuple[list[str], int]:
    """Remove concrete ``$image`` patterns covered by a simple wildcard.

    Only host-shaped, unanchored patterns are eligible. The concrete pattern
    must contain no wildcard and must be fully matched by an active wildcard
    with the same sole ``image`` option. Restricting the option set avoids
    changing precedence-sensitive modifier-filter behavior.
    """

    parsed: list[tuple[int, NetworkRule]] = []
    for index, line in enumerate(lines):
        rule = _parse_simple_url_host_pattern(line)
        if rule is not None:
            parsed.append((index, rule))

    badfilter_current: set[int] = set()
    badfilter_targets: set[RuleCanonicalKey] = set()
    for index, rule in parsed:
        badfilter_indexes = [
            modifier_index
            for modifier_index, modifier in enumerate(rule.modifiers)
            if modifier.name == "badfilter"
        ]
        if not badfilter_indexes:
            continue
        badfilter_current.add(index)
        for modifier_index in badfilter_indexes:
            modifier = rule.modifiers[modifier_index]
            if modifier.negated or modifier.value is not None:
                raise MinimizerError(f"unsupported badfilter modifier: {rule.raw}")
        badfilter_targets.add(
            _simple_url_host_pattern_key(rule, badfilter_indexes)
        )

    eligible: list[tuple[int, NetworkRule]] = []
    for index, rule in parsed:
        if (
            index in badfilter_current
            or _simple_url_host_pattern_key(rule) in badfilter_targets
        ):
            continue
        modifier_keys = tuple(
            sorted(_modifier_key(modifier) for modifier in rule.modifiers)
        )
        if modifier_keys != ("image",):
            continue
        eligible.append((index, rule))

    wildcard_patterns = {
        rule.base
        for _, rule in eligible
        if rule.base.count("*") == 1
    }
    if not wildcard_patterns:
        return list(lines), 0

    normalized_wildcards = (
        pattern.lower() for pattern in sorted(wildcard_patterns)
    )
    wildcard_index = GlobIndex(normalized_wildcards)
    removed = {
        index
        for index, rule in eligible
        if "*" not in rule.base
        and wildcard_index.matches(rule.base.lower())
    }
    return (
        [line for index, line in enumerate(lines) if index not in removed],
        len(removed),
    )


def _parse_removeparam_rule(
    parsed: Optional[NetworkRule],
    badfilter_current: set[str],
    badfilter_targets: set[RuleCanonicalKey],
) -> Optional[RemoveparamRule]:
    if (
        parsed is None
        or parsed.raw in badfilter_current
        or _network_rule_key(parsed) in badfilter_targets
    ):
        return None

    removeparam = [
        modifier for modifier in parsed.modifiers if modifier.name == "removeparam"
    ]
    domain_indexes = [
        index
        for index, modifier in enumerate(parsed.modifiers)
        if modifier.name == "domain"
    ]
    if (
        len(removeparam) != 1
        or removeparam[0].negated
        or len(domain_indexes) != 1
        or any(modifier.name == "badfilter" for modifier in parsed.modifiers)
    ):
        return None

    domain_index = domain_indexes[0]
    domain_modifier = parsed.modifiers[domain_index]
    if domain_modifier.negated or domain_modifier.value is None:
        return None

    domains: list[str] = []
    for raw_domain in domain_modifier.value.split("|"):
        normalized = _normalize_simple_host(raw_domain)
        if normalized is None:
            return None
        domains.append(normalized)
    if not domains:
        return None

    equals = domain_modifier.raw.find("=")
    return RemoveparamRule(
        network=parsed,
        domain_index=domain_index,
        domain_prefix=domain_modifier.raw[: equals + 1],
        domains=tuple(domains),
    )


def _removeparam_group_key(rule: RemoveparamRule) -> tuple[object, ...]:
    template = tuple(
        (index, modifier.raw)
        for index, modifier in enumerate(rule.network.modifiers)
        if index != rule.domain_index
    )
    return (
        rule.network.base,
        rule.domain_index,
        rule.domain_prefix,
        template,
    )


def minimize_removeparam(
    lines: Sequence[str], max_line_bytes: int
) -> tuple[list[str], StageStats]:
    parsed_rules = [_parse_network_rule(line) for line in lines]
    badfilter_current, badfilter_targets = _build_badfilter_state_from_parsed(
        parsed_rules
    )
    groups: dict[tuple[object, ...], list[RemoveparamRule]] = defaultdict(list)
    passthrough: list[str] = []

    for line, parsed in zip(lines, parsed_rules):
        rule = _parse_removeparam_rule(
            parsed,
            badfilter_current,
            badfilter_targets,
        )
        if rule is None:
            passthrough.append(line)
            continue
        groups[_removeparam_group_key(rule)].append(rule)

    generated: list[str] = []
    changed_groups = 0
    oversize_groups = 0
    for rules in groups.values():
        first = rules[0]
        domains = _compress_domain_set(
            domain for rule in rules for domain in rule.domains
        )

        def render(batch: Sequence[str]) -> str:
            modifiers = [modifier.raw for modifier in first.network.modifiers]
            modifiers[first.domain_index] = f"{first.domain_prefix}{'|'.join(batch)}"
            return _render_network_rule(first.network.base, modifiers)

        outputs = _batch_domains(domains, render, max_line_bytes)
        output_rules = (
            _parse_network_rule(output) for output in outputs or ()
        )
        if outputs is None or any(
            output_rule is not None
            and _network_rule_key(output_rule) in badfilter_targets
            for output_rule in output_rules
        ):
            passthrough.extend(rule.network.raw for rule in rules)
            oversize_groups += outputs is None
            continue

        original = _sort_unique(rule.network.raw for rule in rules)
        canonical = _sort_unique(outputs)
        if original != canonical:
            changed_groups += 1
        generated.extend(canonical)

    output = _sort_unique((*passthrough, *generated))
    stats = StageStats(
        name="removeparam",
        input_lines=len(lines),
        output_lines=len(output),
        input_bytes=_serialized_bytes(lines),
        output_bytes=_serialized_bytes(output),
        eligible_lines=sum(len(group) for group in groups.values()),
        groups=len(groups),
        changed_groups=changed_groups,
        oversize_groups=oversize_groups,
    )
    return output, stats
