#!/usr/bin/env python3
"""Perl-compatible regex coverage matching for DNS domain snapshots.

This module owns the ABP modifier eligibility rules, conservative literal
prefix extraction, and the subprocess parallelism required by Perl regexes.
It does not parse DNS domain rules or decide how covered domains are applied.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

try:
    from rule_canonical import split_adblock_regex_rule, split_modifier_tokens
except ImportError:  # Support ``python -m script.dns_regex_coverage``.
    from .rule_canonical import (  # type: ignore[no-redef]
        split_adblock_regex_rule,
        split_modifier_tokens,
    )


MAX_REGEX_WORKERS = 4
MIN_PARALLEL_REGEX_WORK = 100_000
_OPTIONAL_DOMAIN_PREFIX = r"(\S+\.)?"
_REGEX_META_CHARS = frozenset(".^$*+?{[()|]")


class DnsRegexCoverageError(RuntimeError):
    """Raised when the Perl-compatible matcher cannot complete."""


@dataclass(frozen=True)
class RegexCoverageRule:
    pattern: str
    denyallow: tuple[str, ...] = ()


@dataclass(frozen=True)
class RegexCoverageMatch:
    covered_domains: frozenset[str]
    invalid_rule_count: int
    worker_count: int


def _modifier_info(
    modifiers: str,
) -> tuple[bool, bool, tuple[str, ...], tuple[str, ...]]:
    """Return support, badfilter state, denyallow members, and target key."""

    modifiers = modifiers.strip()
    if modifiers in {"", "$"}:
        return True, False, (), ()
    if not modifiers.startswith("$") or not modifiers[1:]:
        return False, False, (), ()

    supported = True
    badfilter = False
    denyallow: list[str] = []
    target_modifiers: list[str] = []
    raw_tokens = split_modifier_tokens(modifiers[1:])
    if raw_tokens is None:
        return False, False, (), ()
    for raw_token in raw_tokens:
        token = raw_token.strip()
        if not token:
            supported = False
            continue
        raw_name, separator, raw_value = token.partition("=")
        name = raw_name.strip().lower()
        negated = name.startswith("~")
        base_name = name[1:] if negated else name
        if base_name == "important" and not separator:
            target_modifiers.append(name)
            continue
        if base_name == "badfilter" and not negated and not separator:
            badfilter = True
            continue
        if base_name == "denyallow" and not negated and separator:
            members = [member.strip().lower() for member in raw_value.split("|")]
            if not members or not all(members):
                supported = False
            else:
                normalized_members = sorted(set(members))
                denyallow.extend(normalized_members)
                target_modifiers.append(
                    f"denyallow={'|'.join(normalized_members)}"
                )
            continue
        supported = False
    return (
        supported,
        badfilter,
        tuple(sorted(set(denyallow))),
        tuple(sorted(target_modifiers)),
    )


def parse_regex_coverage_rules(lines: Iterable[str]) -> tuple[RegexCoverageRule, ...]:
    """Return active regex rules whose modifiers have DNS coverage semantics."""

    parsed: list[
        tuple[str, bool, bool, tuple[str, ...], tuple[str, ...]]
    ] = []
    disabled: set[tuple[str, tuple[str, ...]]] = set()
    for raw_line in lines:
        line = raw_line.strip()
        parts = split_adblock_regex_rule(line)
        if parts is None:
            continue
        core, modifiers = parts
        supported, badfilter, denyallow, target_modifiers = _modifier_info(modifiers)
        parsed.append((core, supported, badfilter, denyallow, target_modifiers))
        if supported and badfilter:
            disabled.add((core, target_modifiers))

    rules: list[RegexCoverageRule] = []
    for core, supported, badfilter, denyallow, target_modifiers in parsed:
        if badfilter or not supported or (core, target_modifiers) in disabled:
            continue
        pattern = core[1:-1]
        if pattern:
            rules.append(RegexCoverageRule(pattern, denyallow))
    return tuple(rules)


def required_regex_prefix(pattern: str) -> Optional[tuple[str, bool]]:
    r"""Extract a literal prefix that every regex match must contain.

    Only start-anchored patterns are eligible. The common ``(\S+\.)?``
    prelude allows the literal to start at a hostname label boundary; without
    it the literal must start at the beginning of the complete hostname.
    Unsupported escapes and regex constructs stop extraction conservatively.
    """

    if not pattern.startswith("^"):
        return None
    position = 1
    at_label_boundary = False
    if pattern.startswith(_OPTIONAL_DOMAIN_PREFIX, position):
        position += len(_OPTIONAL_DOMAIN_PREFIX)
        at_label_boundary = True

    literal: list[str] = []
    while position < len(pattern):
        char = pattern[position]
        if char == "\\":
            if position + 1 >= len(pattern):
                break
            escaped = pattern[position + 1]
            if escaped.isalnum():
                break
            literal.append(escaped)
            position += 2
            continue
        if char in _REGEX_META_CHARS:
            break
        literal.append(char)
        position += 1

    prefix = "".join(literal).lower()
    if not prefix:
        return None
    return prefix, at_label_boundary


_PERL_MATCHER = r'''
use strict;
use warnings;
use JSON::PP qw(decode_json encode_json);

sub domain_matches_denyallow {
    my ($domain, $allow_rule) = @_;
    return 0 if !defined $allow_rule || $allow_rule eq "";

    my $a = lc($allow_rule);
    $a =~ s/^\s+|\s+$//g;
    return 0 if $a eq "";
    $a =~ s/^~//;
    return 0 if $a eq "";

    if ($a =~ /\*/) {
        my $expr = $a;
        $expr =~ s/([\\.^\$+?(){}\[\]|])/\\$1/g;
        $expr =~ s/\*/.*/g;
        return ($domain =~ /^$expr$/i) ? 1 : 0;
    }

    return 1 if $domain eq $a;
    return ($domain =~ /\.\Q$a\E$/i) ? 1 : 0;
}

my $payload = do { local $/; <STDIN> };
my $data = decode_json($payload);
my @rules;
my @domains = map { [$_, lc($_)] } @{$data->{domains} || []};
my $invalid = 0;

for my $rule (@{$data->{rules} || []}) {
    my $compiled = eval { qr/$rule->{pattern}/i };
    if ($@ || !defined $compiled) {
        $invalid++;
        next;
    }
    $rule->{compiled} = $compiled;
    push @rules, $rule;
}

my %matches;
for my $rule (@rules) {
    my $prefix = $rule->{required_prefix} || "";
    DOMAIN:
    for my $record (@domains) {
        my ($domain, $domain_lc) = @{$record};
        next DOMAIN if exists $matches{$domain};
        if ($prefix ne "") {
            if ($rule->{prefix_at_label_boundary}) {
                next DOMAIN if $domain_lc !~ /(?:^|\.)\Q$prefix\E/;
            } else {
                next DOMAIN if index($domain_lc, $prefix) != 0;
            }
        }
        my $denied = 0;
        for my $allow_rule (@{$rule->{denyallow} || []}) {
            if (domain_matches_denyallow($domain_lc, $allow_rule)) {
                $denied = 1;
                last;
            }
        }
        next DOMAIN if $denied;
        my $compiled = $rule->{compiled};
        if ($domain =~ $compiled) {
            $matches{$domain} = 1;
        }
    }
}

print encode_json({matches => [keys %matches], invalid => $invalid});
'''


def _run_perl_matcher(
    domains: Sequence[str], rules: Sequence[RegexCoverageRule]
) -> tuple[set[str], int]:
    if not rules or not domains:
        return set(), 0
    if shutil.which("perl") is None:
        raise DnsRegexCoverageError("Missing dependency for regex coverage: perl")

    payload = json.dumps(
        {
            "domains": list(domains),
            "rules": [
                {
                    "pattern": rule.pattern,
                    "denyallow": list(rule.denyallow),
                    "required_prefix": prefix[0] if prefix else "",
                    "prefix_at_label_boundary": prefix[1] if prefix else False,
                }
                for rule in rules
                for prefix in [required_regex_prefix(rule.pattern)]
            ],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    try:
        completed = subprocess.run(
            ["perl", "-e", _PERL_MATCHER],
            input=payload,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise DnsRegexCoverageError(
            f"Failed to start Perl regex coverage matcher: {exc}"
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "unknown error"
        raise DnsRegexCoverageError(
            f"Perl regex coverage matcher failed: {detail}"
        )
    try:
        result = json.loads(completed.stdout)
        matches = result.get("matches", [])
        invalid = int(result.get("invalid", 0))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DnsRegexCoverageError(
            "Perl regex coverage matcher returned invalid output"
        ) from exc
    if not isinstance(matches, list):
        raise DnsRegexCoverageError(
            "Perl regex coverage matcher returned an invalid domain set"
        )
    return {str(domain) for domain in matches}, invalid


def regex_worker_count(domain_count: int, rule_count: int) -> int:
    if domain_count * rule_count < MIN_PARALLEL_REGEX_WORK:
        return 1
    return min(
        MAX_REGEX_WORKERS,
        max(1, os.cpu_count() or 1),
        domain_count,
        max(1, rule_count),
    )


def match_regex_coverage(
    domains: Sequence[str], rules: Sequence[RegexCoverageRule]
) -> RegexCoverageMatch:
    """Match one domain snapshot with bounded Perl worker parallelism."""

    workers = regex_worker_count(len(domains), len(rules))
    if workers <= 1:
        covered, invalid = _run_perl_matcher(domains, rules)
        return RegexCoverageMatch(frozenset(covered), invalid, workers)

    rules_sharded = len(rules) > len(domains)
    if rules_sharded:
        # Compiling every regex in every process is wasteful when the rule set
        # dominates the domain snapshot. Each shard scans the full domain set;
        # matches are unioned below and invalid regex counts are additive.
        chunks = [rules[index::workers] for index in range(workers)]
        jobs = [(domains, chunk) for chunk in chunks if chunk]
    else:
        domain_chunks = [domains[index::workers] for index in range(workers)]
        jobs = [(chunk, rules) for chunk in domain_chunks if chunk]
    with ThreadPoolExecutor(
        max_workers=len(jobs),
        thread_name_prefix="dns-coverage-regex",
    ) as executor:
        results = list(
            executor.map(
                lambda job: _run_perl_matcher(*job),
                jobs,
            )
        )
    covered: set[str] = set()
    invalid_counts: list[int] = []
    for chunk_covered, chunk_invalid in results:
        covered.update(chunk_covered)
        invalid_counts.append(chunk_invalid)
    invalid_count = (
        sum(invalid_counts)
        if rules_sharded
        else (invalid_counts[0] if invalid_counts else 0)
    )
    return RegexCoverageMatch(
        frozenset(covered),
        invalid_count,
        workers,
    )
