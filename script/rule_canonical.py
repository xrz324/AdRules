#!/usr/bin/env python3
"""Shared semantic keys for rule deduplication.

The pipeline keeps the original text for output, but uses these keys when two
records have the same rule semantics.  Modifier names and ordering are
canonicalized. Values remain case-sensitive except for known domain-set
modifiers, whose members are case-insensitive and order-independent.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Optional


ABP_DOMAIN_RULE_RE = re.compile(
    r"^(@@)?\|\|([A-Za-z0-9.*-]+)\^(?:\$(\S+))?$"
)
MIHOMO_DOMAIN_RULE_RE = re.compile(
    r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-WILDCARD),(.+)$"
)
SET_VALUED_DOMAIN_MODIFIERS = frozenset({"denyallow", "domain"})
OTHER_GLOB_CHAR = "\0"
# Adblock-compatible aliases which have identical request-matching semantics.
# Keep one canonical spelling so duplicate and badfilter lookups agree.
MODIFIER_ALIASES = {"3p": "third-party"}


@dataclass(frozen=True)
class RuleCanonicalKey:
    """Format-aware semantic identity for one supported rule record."""

    format: str
    kind: str
    target: str
    modifiers: tuple[str, ...] = ()


def normalize_modifier(token: str) -> str:
    """Normalize a modifier while preserving value syntax where required."""

    token = token.strip()
    if "=" not in token:
        normalized = token.lower()
        negated = normalized.startswith("~")
        name = normalized[1:] if negated else normalized
        canonical_name = MODIFIER_ALIASES.get(name, name)
        return f"~{canonical_name}" if negated else canonical_name
    name, value = token.split("=", 1)
    normalized_name = name.strip().lower()
    normalized_value = value.strip()
    if normalized_name.lstrip("~") in SET_VALUED_DOMAIN_MODIFIERS:
        members = [member.strip().lower() for member in normalized_value.split("|")]
        if members and all(members):
            normalized_value = "|".join(sorted(set(members)))
    return f"{normalized_name}={normalized_value}"


def split_modifier_tokens(text: str) -> Optional[tuple[str, ...]]:
    """Split modifiers while preserving commas inside ``/regex/`` values."""

    tokens: list[str] = []
    start = 0
    escaped = False
    in_regex = False
    value_start = False
    value_tilde_seen = False

    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if in_regex:
            if char == "/":
                in_regex = False
            continue

        if value_start:
            if char == "~" and not value_tilde_seen:
                value_tilde_seen = True
                continue
            if char == "/":
                in_regex = True
                value_start = False
                continue
            value_start = False
            value_tilde_seen = False

        if char == "=":
            value_start = True
            value_tilde_seen = False
        elif char == ",":
            token = text[start:index]
            if not token:
                return None
            tokens.append(token)
            start = index + 1

    if escaped or in_regex:
        return None

    token = text[start:]
    if not token:
        return None
    tokens.append(token)
    return tuple(tokens)


def canonical_modifiers(raw: str | None) -> Optional[tuple[str, ...]]:
    """Return modifier tokens in a deterministic, order-independent form."""

    if not raw:
        return ()
    tokens = split_modifier_tokens(raw)
    if tokens is None:
        return None
    return tuple(
        sorted(
            normalize_modifier(token)
            for token in tokens
            if token.strip()
        )
    )


@lru_cache(maxsize=262_144)
def canonicalize_adblock_rule(line: str) -> Optional[RuleCanonicalKey]:
    """Return a semantic key for an ABP domain rule or exception."""

    candidate = line.strip()
    # The canonical form only accepts anchored domain rules.  Most content
    # records are cosmetic or URL patterns, so avoid a regex fullmatch for
    # those records entirely.
    if not candidate.startswith(("||", "@@||")) or "^" not in candidate:
        return None
    match = ABP_DOMAIN_RULE_RE.fullmatch(candidate)
    if match is None:
        return None
    modifiers = canonical_modifiers(match.group(3))
    if modifiers is None:
        return None
    return RuleCanonicalKey(
        format="adblock",
        kind="exception-domain" if match.group(1) else "domain",
        target=match.group(2).lower(),
        modifiers=modifiers,
    )


def canonicalize_adblock_domain(line: str) -> Optional[RuleCanonicalKey]:
    """Return a semantic key for a blocking ABP domain rule only."""

    key = canonicalize_adblock_rule(line)
    if key is None or key.kind != "domain":
        return None
    return key


def canonicalize_mihomo_domain(line: str) -> Optional[RuleCanonicalKey]:
    """Return a semantic key for a Mihomo domain rule, if supported."""

    match = MIHOMO_DOMAIN_RULE_RE.fullmatch(line.strip())
    if match is None:
        return None
    return RuleCanonicalKey(
        format="mihomo",
        kind=match.group(1),
        target=match.group(2).strip().lower(),
    )


def split_adblock_regex_rule(line: str) -> Optional[tuple[str, str]]:
    """Split an ABP regex rule into its ``/.../`` core and modifiers."""

    if not line.startswith("/"):
        return None

    separator = -1
    search_from = 0
    while True:
        position = line.find("/$", search_from)
        if position < 0:
            break
        separator = position
        search_from = position + 2

    if separator >= 0:
        core = line[: separator + 1]
        modifiers = line[separator + 1 :]
        if re.fullmatch(r"\$[^\s]+", modifiers) is None:
            return None
    else:
        core = line
        modifiers = ""

    if len(core) < 2 or not core.endswith("/"):
        return None
    return core, modifiers


@lru_cache(maxsize=32768)
def _glob_epsilon_closure(
    pattern: str, state: frozenset[int]
) -> frozenset[int]:
    closure = set(state)
    pending = list(state)
    while pending:
        position = pending.pop()
        if (
            position < len(pattern)
            and pattern[position] == "*"
            and position + 1 not in closure
        ):
            closure.add(position + 1)
            pending.append(position + 1)
    return frozenset(closure)


@lru_cache(maxsize=65536)
def _glob_transition(
    pattern: str, state: frozenset[int], char: str
) -> frozenset[int]:
    next_state: set[int] = set()
    for position in state:
        if position >= len(pattern):
            continue
        token = pattern[position]
        if token == "*":
            next_state.add(position)
        elif token == char:
            next_state.add(position + 1)
    return _glob_epsilon_closure(pattern, frozenset(next_state))


def glob_matches(pattern: str, value: str) -> bool:
    """Return whether a literal/``*`` glob fully matches one value."""

    state = _glob_epsilon_closure(pattern, frozenset({0}))
    for char in value:
        state = _glob_transition(pattern, state, char)
        if not state:
            return False
    return len(pattern) in state


def domain_is_covered_by_glob(domain: str, pattern: str) -> bool:
    """Match an ABP hostname pattern against the domain and its suffixes."""

    labels = domain.split(".")
    return any(glob_matches(pattern, ".".join(labels[index:])) for index in range(len(labels)))


def fixed_prefix(pattern: str) -> str:
    return pattern.split("*", 1)[0]


def fixed_suffix(pattern: str) -> str:
    return pattern.rsplit("*", 1)[-1]


class _GlobTrieNode:
    """Compact trie node used only while selecting possible glob matches."""

    __slots__ = ("children", "patterns")

    def __init__(self) -> None:
        self.children: dict[str, _GlobTrieNode] = {}
        self.patterns: list[str] = []


class GlobIndex:
    """Select literal/``*`` globs by mandatory prefix and suffix.

    Two tries apply necessary literal conditions before the glob automaton,
    without changing its matching language.
    """

    __slots__ = ("_prefix_root", "_suffix_root")

    def __init__(self, patterns: Iterable[str]) -> None:
        self._prefix_root = _GlobTrieNode()
        self._suffix_root = _GlobTrieNode()
        for pattern in sorted(set(patterns)):
            self._insert(self._prefix_root, fixed_prefix(pattern), pattern)
            self._insert(
                self._suffix_root,
                reversed(fixed_suffix(pattern)),
                pattern,
            )

    @staticmethod
    def _insert(
        root: _GlobTrieNode,
        key: Iterable[str],
        pattern: str,
    ) -> None:
        node = root
        for char in key:
            node = node.children.setdefault(char, _GlobTrieNode())
        node.patterns.append(pattern)

    def _suffix_candidates(self, domain: str) -> set[str]:
        node = self._suffix_root
        candidates = set(node.patterns)
        for char in reversed(domain):
            child = node.children.get(char)
            if child is None:
                break
            node = child
            candidates.update(node.patterns)
        return candidates

    def matches(self, value: str) -> bool:
        """Return whether any indexed glob fully matches ``value``."""

        suffix_candidates = self._suffix_candidates(value)
        if not suffix_candidates:
            return False
        for pattern in self._prefix_root.patterns:
            if pattern in suffix_candidates and glob_matches(pattern, value):
                return True

        node = self._prefix_root
        for char in value:
            child = node.children.get(char)
            if child is None:
                break
            node = child
            for pattern in node.patterns:
                if pattern in suffix_candidates and glob_matches(pattern, value):
                    return True
        return False


class DomainGlobIndex(GlobIndex):
    """Extend an exact glob index with ABP hostname-suffix matching."""

    __slots__ = ()

    def covers_domain(self, domain: str) -> bool:
        """Return whether any indexed glob matches a hostname suffix."""

        suffix_candidates = self._suffix_candidates(domain)
        if not suffix_candidates:
            return False

        # An empty fixed prefix means the pattern starts with ``*``. If it can
        # match any suffix, the leading star can absorb the removed labels and
        # therefore it also matches the complete domain.
        for pattern in self._prefix_root.patterns:
            if pattern in suffix_candidates and glob_matches(pattern, domain):
                return True

        starts = [0]
        starts.extend(index + 1 for index, char in enumerate(domain) if char == ".")
        for start in starts:
            node = self._prefix_root
            for char in domain[start:]:
                child = node.children.get(char)
                if child is None:
                    break
                node = child
                for pattern in node.patterns:
                    if (
                        pattern in suffix_candidates
                        and glob_matches(pattern, domain[start:])
                    ):
                        return True
        return False


@lru_cache(maxsize=32768)
def glob_is_subset(pattern: str, covering_pattern: str) -> bool:
    """Return whether one literal/``*`` glob language is contained in another."""

    if not fixed_prefix(pattern).startswith(fixed_prefix(covering_pattern)):
        return False
    if not fixed_suffix(pattern).endswith(fixed_suffix(covering_pattern)):
        return False

    alphabet = set(pattern.replace("*", "") + covering_pattern.replace("*", ""))
    alphabet.add(OTHER_GLOB_CHAR)
    start = (
        _glob_epsilon_closure(pattern, frozenset({0})),
        _glob_epsilon_closure(covering_pattern, frozenset({0})),
    )
    pending = deque([start])
    seen = {start}

    while pending:
        subject_state, covering_state = pending.popleft()
        if len(pattern) in subject_state and len(covering_pattern) not in covering_state:
            return False
        for char in alphabet:
            next_subject = _glob_transition(pattern, subject_state, char)
            if not next_subject:
                continue
            next_covering = _glob_transition(covering_pattern, covering_state, char)
            state = (next_subject, next_covering)
            if state not in seen:
                seen.add(state)
                pending.append(state)
    return True


def _glob_is_subset_of_union(
    pattern: str, covering_patterns: Sequence[str]
) -> bool:
    alphabet = set(pattern.replace("*", ""))
    for covering_pattern in covering_patterns:
        alphabet.update(covering_pattern.replace("*", ""))
    alphabet.add(OTHER_GLOB_CHAR)

    subject_start = _glob_epsilon_closure(pattern, frozenset({0}))
    covering_start = tuple(
        _glob_epsilon_closure(covering_pattern, frozenset({0}))
        for covering_pattern in covering_patterns
    )
    start = (subject_start, covering_start)
    pending = deque([start])
    seen = {start}
    while pending:
        subject_state, covering_states = pending.popleft()
        if len(pattern) in subject_state and not any(
            len(covering_pattern) in state
            for covering_pattern, state in zip(covering_patterns, covering_states)
        ):
            return False
        for char in alphabet:
            next_subject = _glob_transition(pattern, subject_state, char)
            if not next_subject:
                continue
            next_covering = tuple(
                _glob_transition(covering_pattern, state, char)
                for covering_pattern, state in zip(covering_patterns, covering_states)
            )
            combined_state = (next_subject, next_covering)
            if combined_state not in seen:
                seen.add(combined_state)
                pending.append(combined_state)
    return True


@lru_cache(maxsize=32768)
def glob_is_covered_by_domain(pattern: str, domain: str) -> bool:
    """Return whether a domain rule covers every hostname matched by a glob."""

    return _glob_is_subset_of_union(pattern, (domain, f"*.{domain}"))


Canonicalizer = Callable[[str], Optional[RuleCanonicalKey]]


def semantic_duplicate_indices(
    lines: Sequence[str],
    canonicalizer: Canonicalizer,
    *,
    key_output: Optional[list[Optional[RuleCanonicalKey]]] = None,
) -> set[int]:
    """Find duplicate semantic records while retaining a stable raw line.

    The lexicographically smallest UTF-8 representation is retained for each
    key.  Non-parsed lines are intentionally left untouched for downstream
    format-specific handling.
    """

    representatives: dict[RuleCanonicalKey, int] = {}
    duplicates: set[int] = set()
    for index, line in enumerate(lines):
        key = canonicalizer(line)
        if key_output is not None:
            key_output.append(key)
        if key is None:
            continue

        previous = representatives.get(key)
        if previous is None:
            representatives[key] = index
            continue

        # UTF-8 byte order is identical to Unicode scalar-value order, so a
        # direct comparison avoids allocating two encoded sort keys.
        if line < lines[previous]:
            duplicates.add(previous)
            representatives[key] = index
        else:
            duplicates.add(index)
    return duplicates
