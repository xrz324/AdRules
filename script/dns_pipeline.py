#!/usr/bin/env python3
"""Build the rule-only DNS list before probing and binary conversion.

The previous orchestration performed source loading, hosts/ABP normalisation,
compression, allow-list filtering, and semantic minimisation in one process.
This module owns that deterministic rule stage.  Pruning
and sing-box/mihomo conversion are explicit downstream stages, with conversion
implemented by ``dns_converter.py`` and the format-specific AWK helpers.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Iterable, Optional, Pattern, Sequence, Set, Tuple

try:
    from common import (
        atomic_write_lines_bundle,
        byte_sort_unique,
        read_utf8_lines,
    )
except ImportError:  # Support ``python -m script.dns_pipeline``.
    from .common import (  # type: ignore[no-redef]
        atomic_write_lines_bundle,
        byte_sort_unique,
        read_utf8_lines,
    )

try:
    from compressor import RuleValidator, compress_rules
    from dns_minimizer import MinimizeStats, minimize_dns_lines
    from remove import RemoveError, load_whitelist, rule_matches_whitelist
    from rule_canonical import (
        canonicalize_adblock_domain,
        split_adblock_regex_rule,
    )
except ImportError:  # Support ``python -m script.dns_pipeline``.
    from .compressor import RuleValidator, compress_rules  # type: ignore[no-redef]
    from .dns_minimizer import MinimizeStats, minimize_dns_lines  # type: ignore[no-redef]
    from .remove import (  # type: ignore[no-redef]
        RemoveError,
        load_whitelist,
        rule_matches_whitelist,
    )
    from .rule_canonical import (  # type: ignore[no-redef]
        canonicalize_adblock_domain,
        split_adblock_regex_rule,
    )


ROOT_DIR = Path(__file__).resolve().parents[1]
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())

IPV4_RE = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
HOSTS_PREFIX_RE = re.compile(rf"^(?:{IPV4_RE}|[0-9a-fA-F:]+)[\t ]+")
IPV4_HOST_RE = re.compile(rf"^({IPV4_RE})[\t ]+")
ABP_CANDIDATE_RE = re.compile(r"^\|\|[a-z0-9.*-]+\^?$", re.IGNORECASE)
DOMAIN_LABEL_RE = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
HOST_DOMAIN_RE = re.compile(
    rf"^(?:\*|(?:\*\.)?{DOMAIN_LABEL_RE})"
    rf"(?:\.{DOMAIN_LABEL_RE})+$",
    re.IGNORECASE,
)
HOSTS_CANDIDATE_RE = re.compile(
    rf"^(?:{IPV4_RE}|[0-9a-fA-F:]+)[\t ]+"
    rf"(?:\*|(?:\*\.)?{DOMAIN_LABEL_RE})(?:\.{DOMAIN_LABEL_RE})+$",
    re.IGNORECASE,
)
PLAIN_DOMAIN_RE = re.compile(r"^[A-Za-z0-9_*.-]+(?:\.[A-Za-z0-9_*.-]+)+$")
DOMAIN_WITH_MODIFIER_RE = re.compile(r"^\|\|.+\^(?:\$[^\s]+)?$")


class DnsPipelineError(RuntimeError):
    """Raised when the deterministic DNS rule stage cannot complete."""


@dataclass(frozen=True)
class DnsPaths:
    """Repository paths consumed and produced by the DNS rule stage."""

    root: Path
    source_rules: Path
    allowlist: Path
    upstream_dir: Path
    output: Path
    ip_cidr_output: Path

    @classmethod
    def from_root(
        cls,
        root: Path = ROOT_DIR,
        *,
        output: Optional[Path] = None,
        ip_cidr_output: Optional[Path] = None,
    ) -> "DnsPaths":
        resolved_root = Path(root).resolve()

        def resolve(value: Optional[Path], default: Path) -> Path:
            candidate = Path(value) if value is not None else default
            if not candidate.is_absolute():
                candidate = resolved_root / candidate
            return candidate.resolve()

        return cls(
            root=resolved_root,
            source_rules=resolved_root / "mod" / "rules" / "dns-rules.txt",
            allowlist=resolved_root / "mod" / "rules" / "dns-allowlist.txt",
            upstream_dir=resolved_root / "tmp" / "dns",
            output=resolve(output, Path("dns.txt")),
            ip_cidr_output=resolve(
                ip_cidr_output,
                Path("tmp") / "dns_ip_cidr_rules.txt",
            ),
        )


@dataclass(frozen=True)
class DnsBuildResult:
    """Summary of one deterministic DNS rule build."""

    paths: DnsPaths
    source_count: int
    candidate_count: int
    base_count: int
    advanced_count: int
    output_count: int
    cidr_count: int
    minimizer_stats: MinimizeStats


def _byte_sort_unique(lines: Iterable[str]) -> list[str]:
    """Return deterministic C-locale-like unique lines."""

    return byte_sort_unique(lines)


def _read_lines(path: Path) -> list[str]:
    try:
        return read_utf8_lines(path)
    except (OSError, UnicodeError, ValueError) as exc:
        raise DnsPipelineError(f"Failed to read DNS input: {path}: {exc}") from exc


def _source_lines(paths: DnsPaths) -> list[str]:
    lines: list[str] = []
    if paths.source_rules.is_file():
        lines.extend(_read_lines(paths.source_rules))

    if paths.upstream_dir.is_dir():
        for path in sorted(
            paths.upstream_dir.glob("*.txt"),
            key=lambda candidate: candidate.name.encode("utf-8"),
        ):
            if path.is_file():
                lines.extend(_read_lines(path))
    return lines


def _normalize_source_line(raw_line: str) -> str:
    """Match the old AWK hosts-line normalisation."""

    line = raw_line.strip()
    if HOSTS_PREFIX_RE.match(line):
        line = re.sub(r"[\t ]+#.*$", "", line)
        line = re.sub(r"[\t ]+", " ", line).strip()
    return line


def _iter_normalized_source_lines(lines: Iterable[str]) -> Iterable[str]:
    """Yield normalized records, expanding hosts rows with multiple aliases."""

    for raw_line in lines:
        line = _normalize_source_line(raw_line)
        if HOSTS_PREFIX_RE.match(line):
            parts = line.split()
            if len(parts) > 2:
                address = parts[0]
                yield from (f"{address} {hostname}" for hostname in parts[1:])
                continue
        yield line


def normalize_source_lines(lines: Iterable[str]) -> list[str]:
    """Normalise source records and expand hosts rows with multiple aliases."""

    return list(_iter_normalized_source_lines(lines))


def _is_ipv4_hosts_line(line: str) -> bool:
    return IPV4_HOST_RE.match(line) is not None


def _is_candidate(line: str) -> bool:
    # Select the applicable grammar before invoking its regex.  This avoids
    # trying all three fullmatches for every source record.
    if line.startswith("||"):
        return ABP_CANDIDATE_RE.fullmatch(line) is not None
    if HOSTS_PREFIX_RE.match(line) is not None:
        return HOSTS_CANDIDATE_RE.fullmatch(line) is not None
    return HOST_DOMAIN_RE.fullmatch(line) is not None


def filter_dns_candidates(lines: Iterable[str]) -> list[str]:
    """Apply the legacy candidate and blocking-host filters."""

    candidates: list[str] = []
    for line in lines:
        if _is_dns_candidate(line):
            candidates.append(line)
    return candidates


def _is_dns_candidate(line: str) -> bool:
    """Return whether a normalized source line is a base DNS candidate."""

    if line.startswith("||"):
        # The ABP grammar excludes all modifiers and marker characters, so no
        # second character scan is needed here.
        return ABP_CANDIDATE_RE.fullmatch(line) is not None

    if HOSTS_PREFIX_RE.match(line) is not None:
        if HOSTS_CANDIDATE_RE.fullmatch(line) is None:
            return False
        address = line.split(None, 1)[0]
        # The legacy filter deliberately excludes IPv6/colon-bearing records
        # from the DNS rule list even though the hosts grammar accepts them.
        if ":" in address:
            return False
        if address != "0.0.0.0" and not address.startswith("127."):
            return False
        return True

    return HOST_DOMAIN_RE.fullmatch(line) is not None


def _disabled_rule_from_line(line: str) -> Optional[str]:
    # Plain blocking rules cannot carry badfilter.  Avoid canonicalizing the
    # entire source list when only a small modifier-bearing subset qualifies.
    if "$" not in line or "badfilter" not in line.lower():
        return None
    key = canonicalize_adblock_domain(line)
    if key is None or "badfilter" not in key.modifiers:
        return None

    remaining = tuple(
        modifier for modifier in key.modifiers if modifier != "badfilter"
    )
    canonical = f"||{key.target}^"
    if remaining:
        canonical += f"${','.join(remaining)}"
    return canonical


def extract_badfilter_disabled_domain_rules(lines: Iterable[str]) -> list[str]:
    """Return canonical domain rules disabled by a domain ``badfilter``."""

    disabled: set[str] = set()
    for raw_line in lines:
        canonical = _disabled_rule_from_line(raw_line)
        if canonical is not None:
            disabled.add(canonical)

    return _byte_sort_unique(disabled)


def _disabled_key(line: str) -> str:
    if line.startswith("||"):
        return line.lower()
    if HOSTS_PREFIX_RE.match(line) is not None and _is_ipv4_hosts_line(line):
        parts = line.split()
        if len(parts) >= 2:
            return f"||{parts[1]}^".lower()
    if PLAIN_DOMAIN_RE.fullmatch(line):
        return f"||{line}^".lower()
    return line.lower()


def build_base_rules(lines: Iterable[str], disabled_rules: Iterable[str]) -> list[str]:
    """Filter unsupported records and remove domain rules disabled by badfilter."""

    disabled = set(disabled_rules)
    kept: list[str] = []
    for line in lines:
        if not _is_dns_candidate(line):
            continue
        if line.startswith("||"):
            output_rule = line.lower()
        elif line and line[0].isdigit() and _is_ipv4_hosts_line(line):
            parts = line.split()
            output_rule = f"||{parts[1].lower()}^"
        elif PLAIN_DOMAIN_RE.fullmatch(line):
            output_rule = f"||{line.lower()}^"
        else:
            output_rule = line.lower()
        if disabled and output_rule in disabled:
            continue
        kept.append(output_rule)
    return _byte_sort_unique(kept)


def _modifiers_supported(modifiers: str) -> bool:
    modifiers = modifiers.strip()
    if not modifiers:
        return True
    if not modifiers.startswith("$"):
        return False

    raw = modifiers[1:]
    if not raw:
        return False
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        name = token.split("=", 1)[0].strip()
        if name.startswith("~"):
            name = name[1:]
        if name in {"important", "badfilter"}:
            continue
        if name == "denyallow" and re.fullmatch(r"[^=]+=.+", token):
            continue
        return False
    return True


def _advanced_rule_from_line(raw_line: str) -> Optional[str]:
    line = raw_line.strip()
    if not line or line.startswith("!"):
        return None
    if not line.startswith("/") and "$" not in line:
        return None

    regex_parts = split_adblock_regex_rule(line)
    if regex_parts is not None:
        _core, modifiers = regex_parts
        return line if _modifiers_supported(modifiers) else None

    if DOMAIN_WITH_MODIFIER_RE.fullmatch(line) is None:
        return None
    caret_position = line.find("^")
    if caret_position <= 3:
        return None
    domain = line[2:caret_position]
    if re.fullmatch(r"[A-Za-z0-9.*-]+", domain) is None:
        return None
    suffix = line[caret_position + 1 :]
    modifiers = suffix if suffix.startswith("$") else ""
    if modifiers and _modifiers_supported(modifiers):
        return line
    return None


def extract_advanced_rules(lines: Iterable[str]) -> list[str]:
    """Keep regex and modifier-bearing rules for the later conversion stages."""

    advanced: list[str] = []
    for raw_line in lines:
        advanced_line = _advanced_rule_from_line(raw_line)
        if advanced_line is not None:
            advanced.append(advanced_line)
    return _byte_sort_unique(advanced)


def collapse_ipv4_networks(lines: Iterable[str]) -> list[str]:
    """Extract and collapse bare IPv4 CIDRs for Mihomo conversion."""

    networks: set[ipaddress.IPv4Network] = set()
    for raw_line in lines:
        _add_ipv4_network(networks, raw_line)

    return _collapse_ipv4_networks(networks)


def _add_ipv4_network(
    networks: Set[ipaddress.IPv4Network],
    raw_line: str,
) -> None:
    line = raw_line.split("#", 1)[0].strip()
    if "/" not in line:
        return
    try:
        network = ipaddress.ip_network(line, strict=False)
    except ValueError:
        return
    if isinstance(network, ipaddress.IPv4Network):
        networks.add(network)


def _collapse_ipv4_networks(
    networks: Set[ipaddress.IPv4Network],
) -> list[str]:

    collapsed = sorted(
        ipaddress.collapse_addresses(networks),
        key=lambda network: (int(network.network_address), network.prefixlen),
    )
    return [network.with_prefixlen for network in collapsed]


def _compress_base_rules(lines: Sequence[str]) -> list[str]:
    validator = RuleValidator(allow_ip=False)
    valid_lines, _validation_filtered = validator.validate(
        lines,
        keep_removed=False,
    )
    compressed, _compression_filtered = compress_rules(
        valid_lines,
        include_wildcards=True,
        keep_filtered=False,
    )
    return compressed


def _apply_allowlist(
    lines: Sequence[str],
    allowlist: Tuple[Set[str], list[Pattern[str]]],
) -> list[str]:
    started = perf_counter()
    plain_domains, regex_rules = allowlist

    kept: list[str] = []
    removed = 0
    for line in lines:
        if rule_matches_whitelist(line, plain_domains, regex_rules):
            removed += 1
        else:
            kept.append(line)
    LOGGER.info(
        "Allowlist filter complete %d -> %d (-%d) in %.2fs",
        len(lines),
        len(kept),
        removed,
        perf_counter() - started,
    )
    return kept


def _collect_source_metadata(
    lines: Sequence[str],
) -> tuple[list[str], list[str], list[str]]:
    """Collect badfilter, CIDR, and advanced records in one source pass."""

    disabled: set[str] = set()
    networks: set[ipaddress.IPv4Network] = set()
    advanced: list[str] = []
    for line in lines:
        disabled_rule = _disabled_rule_from_line(line)
        if disabled_rule is not None:
            disabled.add(disabled_rule)
        _add_ipv4_network(networks, line)
        advanced_rule = _advanced_rule_from_line(line)
        if advanced_rule is not None:
            advanced.append(advanced_rule)
    return (
        _byte_sort_unique(disabled),
        _collapse_ipv4_networks(networks),
        _byte_sort_unique(advanced),
    )


def build_dns(paths: DnsPaths) -> DnsBuildResult:
    """Build ``dns.txt`` rules and the IPv4 CIDR sidecar."""

    stage_started = perf_counter()
    source_lines = _source_lines(paths)
    source_count = len(source_lines)
    normalized_lines: list[str] = []
    disabled: set[str] = set()
    networks: set[ipaddress.IPv4Network] = set()
    advanced: list[str] = []
    # Normalization is already a full source pass.  Collect the metadata here
    # as records are expanded so the old second full pass is unnecessary.
    for line in _iter_normalized_source_lines(source_lines):
        normalized_lines.append(line)
        disabled_rule = _disabled_rule_from_line(line)
        if disabled_rule is not None:
            disabled.add(disabled_rule)
        _add_ipv4_network(networks, line)
        advanced_rule = _advanced_rule_from_line(line)
        if advanced_rule is not None:
            advanced.append(advanced_rule)
    normalized_count = len(normalized_lines)
    del source_lines
    disabled_rules = _byte_sort_unique(disabled)
    cidr_lines = _collapse_ipv4_networks(networks)
    advanced = _byte_sort_unique(advanced)
    base_candidates = build_base_rules(normalized_lines, disabled_rules)
    del normalized_lines
    candidate_count = len(base_candidates)
    del disabled_rules
    LOGGER.info(
        "DNS base candidates %d -> %d in %.2fs",
        normalized_count,
        len(base_candidates),
        perf_counter() - stage_started,
    )

    # Filter before compression: an allowlisted parent must not remove a
    # non-allowlisted child during parent/child minimization.
    if not paths.allowlist.is_file():
        raise DnsPipelineError(f"DNS allowlist file not found: {paths.allowlist}")
    try:
        allowlist = load_whitelist(str(paths.allowlist))
    except RemoveError as exc:
        raise DnsPipelineError(f"Failed to read DNS allowlist: {paths.allowlist}") from exc

    allowed_base = _apply_allowlist(base_candidates, allowlist)
    allowed_count = len(allowed_base)
    del base_candidates
    compression_started = perf_counter()
    compressed = _compress_base_rules(allowed_base)
    del allowed_base
    LOGGER.info(
        "DNS compression complete %d -> %d in %.2fs",
        allowed_count,
        len(compressed),
        perf_counter() - compression_started,
    )

    advanced_started = perf_counter()
    advanced = _apply_allowlist(advanced, allowlist)
    combined = _byte_sort_unique([*compressed, *advanced])
    LOGGER.info(
        "DNS advanced rules merged: advanced=%d combined=%d in %.2fs",
        len(advanced),
        len(combined),
        perf_counter() - advanced_started,
    )

    minimization_started = perf_counter()
    minimized, stats = minimize_dns_lines(combined)
    LOGGER.info(
        "DNS semantic minimization %d -> %d "
        "(-%d; badfilter:%d important:%d parent:%d "
        "wildcard:%d/%d third-party:%d/%d) in %.2fs",
        len(combined),
        len(minimized),
        stats.removed,
        stats.disabled_base,
        stats.important_base,
        stats.parent_domain,
        stats.wildcard_by_domain,
        stats.wildcard_by_wildcard,
        stats.third_party_by_domain,
        stats.third_party_by_wildcard,
        perf_counter() - minimization_started,
    )

    write_started = perf_counter()
    atomic_write_lines_bundle(
        {
            paths.ip_cidr_output: cidr_lines,
            paths.output: minimized,
        }
    )
    LOGGER.info("DNS output write complete in %.2fs", perf_counter() - write_started)
    return DnsBuildResult(
        paths=paths,
        source_count=source_count,
        candidate_count=candidate_count,
        base_count=len(compressed),
        advanced_count=len(advanced),
        output_count=len(minimized),
        cidr_count=len(cidr_lines),
        minimizer_stats=stats,
    )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT_DIR)
    parser.add_argument("--output", type=Path, default=Path("dns.txt"))
    parser.add_argument(
        "--ip-cidr-output",
        type=Path,
        default=Path("tmp/dns_ip_cidr_rules.txt"),
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        from logging_utils import configure_logging
    except ImportError:  # Support ``python -m script.dns_pipeline``.
        from .logging_utils import configure_logging  # type: ignore[no-redef]

    configure_logging()
    args = _parse_args(argv)
    try:
        paths = DnsPaths.from_root(
            args.root,
            output=args.output,
            ip_cidr_output=args.ip_cidr_output,
        )
        result = build_dns(paths)
        LOGGER.info(
            "DNS rule stage complete output=%d cidr=%d: %s",
            result.output_count,
            result.cidr_count,
            result.paths.output,
        )
    except (DnsPipelineError, OSError, UnicodeError, ValueError) as exc:
        print(f"[ERROR] DNS pipeline: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
