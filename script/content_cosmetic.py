"""Parsing and semantics-preserving minimization for cosmetic rules."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional, Sequence

try:
    from .content_models import (
        StageStats,
        batch_domains,
        compress_domain_set,
        serialized_bytes,
        sort_unique,
    )
except ImportError:  # Support direct script execution.
    from content_models import (  # type: ignore[no-redef]
        StageStats,
        batch_domains,
        compress_domain_set,
        serialized_bytes,
        sort_unique,
    )


COSMETIC_MARKERS = tuple(
    sorted(
        (
            "#@$?#", "#@?#", "#@$#", "#@%#", "#@^#", "#$?#",
            "#@#", "#?#", "#$#", "#%#", "#^#", "##",
        ),
        key=len,
        reverse=True,
    )
)
COSMETIC_MARKER_RE = re.compile(
    "|".join(re.escape(marker) for marker in COSMETIC_MARKERS)
)
_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
SIMPLE_HOST_RE = re.compile(rf"{_HOST_LABEL}(?:\.{_HOST_LABEL})+")
GLOBAL_EXACT_ID_RULE_RE = re.compile(r"^###(-?[A-Za-z_][A-Za-z0-9_-]*)$")
GLOBAL_ID_ATTRIBUTE_RULE_RE = re.compile(
    r'^##\[id(?P<operator>[\^$])="(?P<value>[A-Za-z0-9_-]+)"\]$'
)


@dataclass(frozen=True)
class CosmeticRule:
    raw: str
    marker: str
    body: str
    positives: tuple[str, ...]
    negatives: tuple[str, ...]


def find_cosmetic_marker(line: str) -> Optional[tuple[int, str]]:
    # Most network rules do not contain a marker.  Avoid invoking the regex
    # engine for that common case while keeping marker precedence unchanged.
    if "#" not in line:
        return None
    match = COSMETIC_MARKER_RE.search(line)
    if match is None:
        return None
    return match.start(), match.group(0)


def _normalize_simple_host(token: str) -> Optional[str]:
    if not token.isascii() or SIMPLE_HOST_RE.fullmatch(token) is None:
        return None
    return token.lower()


def _parse_cosmetic_rule_from_marker(
    line: str,
    marker_match: Optional[tuple[int, str]],
) -> Optional[CosmeticRule]:
    if marker_match is None:
        return None
    position, marker = marker_match
    domain_expression = line[:position]
    body = line[position + len(marker) :]
    if not domain_expression or not body:
        return None

    positives: list[str] = []
    negatives: list[str] = []
    for raw_token in domain_expression.split(","):
        if not raw_token or raw_token != raw_token.strip():
            return None
        negative = raw_token.startswith("~")
        token = raw_token[1:] if negative else raw_token
        normalized = _normalize_simple_host(token)
        if normalized is None:
            return None
        (negatives if negative else positives).append(normalized)
    if not positives:
        return None
    return CosmeticRule(
        raw=line,
        marker=marker,
        body=body,
        positives=tuple(positives),
        negatives=compress_domain_set(negatives) if negatives else (),
    )


def parse_cosmetic_rule(line: str) -> Optional[CosmeticRule]:
    return _parse_cosmetic_rule_from_marker(line, find_cosmetic_marker(line))


def _active_global_id_attribute_rules(
    lines: Sequence[str],
    markers: Optional[Sequence[Optional[tuple[int, str]]]] = None,
) -> tuple[tuple[str, str], ...]:
    candidates: dict[str, tuple[str, str]] = {}
    exception_bodies: set[str] = set()
    marker_values = markers if markers is not None else ()
    for index, line in enumerate(lines):
        # The global form is anchored at ``##[id``.  Avoid a regex attempt for
        # the overwhelmingly common network and scoped records.
        if line.startswith("##[id"):
            match = GLOBAL_ID_ATTRIBUTE_RULE_RE.fullmatch(line)
        else:
            match = None
        if match is not None:
            candidates[line[2:]] = (match.group("operator"), match.group("value"))
            continue
        marker_match = (
            marker_values[index]
            if markers is not None
            else find_cosmetic_marker(line)
        )
        if marker_match is None or marker_match[1] != "#@#":
            continue
        position, marker = marker_match
        body = line[position + len(marker) :]
        if GLOBAL_ID_ATTRIBUTE_RULE_RE.fullmatch(f"##{body}") is not None:
            exception_bodies.add(body)
    return tuple(
        rule for body, rule in sorted(candidates.items()) if body not in exception_bodies
    )


def _global_exact_id_covering_rules(
    line: str, covering_rules: Sequence[tuple[str, str]]
) -> tuple[int, ...]:
    if not line.startswith("###"):
        return ()
    match = GLOBAL_EXACT_ID_RULE_RE.fullmatch(line)
    if match is None:
        return ()
    identifier = match.group(1)
    return tuple(
        index
        for index, (operator, value) in enumerate(covering_rules)
        if (
            identifier.startswith(value)
            if operator == "^"
            else identifier.endswith(value)
        )
    )


def minimize_cosmetic(
    lines: Sequence[str], max_line_bytes: int
) -> tuple[list[str], StageStats]:
    groups: dict[tuple[str, str, tuple[str, ...]], list[CosmeticRule]] = defaultdict(list)
    passthrough: list[str] = []
    # The marker search is relatively expensive and is needed by both the
    # global-ID pass and the grouping pass.  Compute it once for this stage.
    markers = tuple(find_cosmetic_marker(line) for line in lines)
    covering_rules = _active_global_id_attribute_rules(lines, markers)
    covered_exact_ids = 0
    used_covering_rules: set[int] = set()
    for line, marker_match in zip(lines, markers):
        covering_indexes = _global_exact_id_covering_rules(line, covering_rules)
        if covering_indexes:
            covered_exact_ids += 1
            used_covering_rules.update(covering_indexes)
            continue
        if marker_match is None:
            passthrough.append(line)
            continue
        rule = _parse_cosmetic_rule_from_marker(line, marker_match)
        if rule is None:
            passthrough.append(line)
            continue
        groups[(rule.marker, rule.body, rule.negatives)].append(rule)

    generated: list[str] = []
    changed_groups = 0
    oversize_groups = 0
    for (marker, body, negatives), rules in groups.items():
        positives = compress_domain_set(
            domain for rule in rules for domain in rule.positives
        )
        negative_tokens = tuple(f"~{domain}" for domain in negatives)

        def render(batch: Sequence[str]) -> str:
            return f"{','.join((*batch, *negative_tokens))}{marker}{body}"

        outputs = batch_domains(positives, render, max_line_bytes)
        if outputs is None:
            passthrough.extend(rule.raw for rule in rules)
            oversize_groups += 1
            continue
        original = sort_unique(rule.raw for rule in rules)
        canonical = sort_unique(outputs)
        changed_groups += original != canonical
        generated.extend(canonical)

    output = sort_unique((*passthrough, *generated))
    return output, StageStats(
        name="cosmetic",
        input_lines=len(lines),
        output_lines=len(output),
        input_bytes=serialized_bytes(lines),
        output_bytes=serialized_bytes(output),
        eligible_lines=(
            sum(len(group) for group in groups.values())
            + len(covering_rules)
            + covered_exact_ids
        ),
        groups=len(groups) + len(covering_rules),
        changed_groups=changed_groups + len(used_covering_rules),
        oversize_groups=oversize_groups,
    )
