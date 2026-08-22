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
from typing import Iterable, Optional, Sequence

try:
    from common import atomic_write_lines, byte_sort_unique, read_utf8_lines
except ImportError:  # Support ``python -m script.dns_pipeline``.
    from .common import (  # type: ignore[no-redef]
        atomic_write_lines,
        byte_sort_unique,
        read_utf8_lines,
    )

try:
    from compressor import RuleValidator, compress_rules
    from dns_minimizer import MinimizeStats, minimize_dns_lines
    from remove import load_whitelist, rule_matches_whitelist
    from rule_canonical import (
        canonicalize_adblock_domain,
        split_adblock_regex_rule,
    )
except ImportError:  # Support ``python -m script.dns_pipeline``.
    from .compressor import RuleValidator, compress_rules  # type: ignore[no-redef]
    from .dns_minimizer import MinimizeStats, minimize_dns_lines  # type: ignore[no-redef]
    from .remove import load_whitelist, rule_matches_whitelist  # type: ignore[no-redef]
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


def normalize_source_lines(lines: Iterable[str]) -> list[str]:
    """Normalise source records and expand hosts rows with multiple aliases."""

    normalized: list[str] = []
    for raw_line in lines:
        line = _normalize_source_line(raw_line)
        if HOSTS_PREFIX_RE.match(line):
            parts = line.split()
            if len(parts) > 2:
                address = parts[0]
                normalized.extend(f"{address} {hostname}" for hostname in parts[1:])
                continue
        normalized.append(line)
    return normalized


def _is_ipv4_hosts_line(line: str) -> bool:
    return IPV4_HOST_RE.match(line) is not None


def _is_candidate(line: str) -> bool:
    return (
        ABP_CANDIDATE_RE.fullmatch(line) is not None
        or HOSTS_CANDIDATE_RE.fullmatch(line) is not None
        or HOST_DOMAIN_RE.fullmatch(line) is not None
    )


def filter_dns_candidates(lines: Iterable[str]) -> list[str]:
    """Apply the legacy candidate and blocking-host filters."""

    candidates: list[str] = []
    for line in lines:
        if not _is_candidate(line):
            continue

        if _is_ipv4_hosts_line(line):
            address = line.split(None, 1)[0]
            if address != "0.0.0.0" and not address.startswith("127."):
                continue

        if any(marker in line for marker in ("@", ":", "?", "$", "#", "!", "/")):
            continue
        candidates.append(line)
    return candidates


def extract_badfilter_disabled_domain_rules(lines: Iterable[str]) -> list[str]:
    """Return canonical domain rules disabled by a domain ``badfilter``."""

    disabled: set[str] = set()
    for raw_line in lines:
        key = canonicalize_adblock_domain(raw_line)
        if key is None or "badfilter" not in key.modifiers:
            continue

        remaining = tuple(
            modifier for modifier in key.modifiers if modifier != "badfilter"
        )
        canonical = f"||{key.target}^"
        if remaining:
            canonical += f"${','.join(remaining)}"
        disabled.add(canonical)

    return _byte_sort_unique(disabled)


def _disabled_key(line: str) -> str:
    if _is_ipv4_hosts_line(line):
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
    for line in filter_dns_candidates(lines):
        if _disabled_key(line) in disabled:
            continue
        if _is_ipv4_hosts_line(line):
            parts = line.split()
            kept.append(f"||{parts[1].lower()}^")
        elif PLAIN_DOMAIN_RE.fullmatch(line):
            kept.append(f"||{line.lower()}^")
        else:
            kept.append(line.lower())
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


def extract_advanced_rules(lines: Iterable[str]) -> list[str]:
    """Keep regex and modifier-bearing rules for the later conversion stages."""

    advanced: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("!"):
            continue

        regex_parts = split_adblock_regex_rule(line)
        if regex_parts is not None:
            _core, modifiers = regex_parts
            if _modifiers_supported(modifiers):
                advanced.append(line)
            continue

        if DOMAIN_WITH_MODIFIER_RE.fullmatch(line) is None:
            continue
        caret_position = line.find("^")
        if caret_position <= 3:
            continue
        domain = line[2:caret_position]
        if re.fullmatch(r"[A-Za-z0-9.*-]+", domain) is None:
            continue
        suffix = line[caret_position + 1 :]
        modifiers = suffix if suffix.startswith("$") else ""
        if modifiers and _modifiers_supported(modifiers):
            advanced.append(line)
    return _byte_sort_unique(advanced)


def collapse_ipv4_networks(lines: Iterable[str]) -> list[str]:
    """Extract and collapse bare IPv4 CIDRs for Mihomo conversion."""

    networks: set[ipaddress.IPv4Network] = set()
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if "/" not in line:
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network):
            networks.add(network)

    collapsed = sorted(
        ipaddress.collapse_addresses(networks),
        key=lambda network: (int(network.network_address), network.prefixlen),
    )
    return [network.with_prefixlen for network in collapsed]


def _compress_base_rules(lines: Sequence[str]) -> list[str]:
    validator = RuleValidator(allow_ip=False)
    valid_lines, _validation_filtered = validator.validate(
        list(lines),
        keep_removed=False,
    )
    compressed, _compression_filtered = compress_rules(
        valid_lines,
        include_wildcards=True,
        keep_filtered=False,
    )
    return compressed


def _apply_allowlist(lines: Sequence[str], paths: DnsPaths) -> list[str]:
    started = perf_counter()
    if not paths.allowlist.is_file():
        raise DnsPipelineError(f"DNS allowlist file not found: {paths.allowlist}")

    try:
        plain_domains, regex_rules = load_whitelist(str(paths.allowlist))
    except SystemExit as exc:
        raise DnsPipelineError(f"Failed to read DNS allowlist: {paths.allowlist}") from exc

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


def build_dns(paths: DnsPaths) -> DnsBuildResult:
    """Build ``dns.txt`` rules and the IPv4 CIDR sidecar."""

    stage_started = perf_counter()
    source_lines = _source_lines(paths)
    normalized_lines = normalize_source_lines(source_lines)
    disabled_rules = extract_badfilter_disabled_domain_rules(normalized_lines)

    cidr_lines = collapse_ipv4_networks(normalized_lines)
    base_candidates = build_base_rules(normalized_lines, disabled_rules)
    LOGGER.info(
        "DNS base candidates %d -> %d in %.2fs",
        len(normalized_lines),
        len(base_candidates),
        perf_counter() - stage_started,
    )

    # Filter before compression: an allowlisted parent must not remove a
    # non-allowlisted child during parent/child minimization.
    allowed_base = _apply_allowlist(base_candidates, paths)
    compression_started = perf_counter()
    compressed = _compress_base_rules(allowed_base)
    LOGGER.info(
        "DNS compression complete %d -> %d in %.2fs",
        len(allowed_base),
        len(compressed),
        perf_counter() - compression_started,
    )

    advanced_started = perf_counter()
    advanced = _apply_allowlist(extract_advanced_rules(normalized_lines), paths)
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
        "DNS semantic minimization %d -> %d (-%d; badfilter:%d important:%d parent:%d wildcard:%d/%d) in %.2fs",
        len(combined),
        len(minimized),
        stats.removed,
        stats.disabled_base,
        stats.important_base,
        stats.parent_domain,
        stats.wildcard_by_domain,
        stats.wildcard_by_wildcard,
        perf_counter() - minimization_started,
    )

    write_started = perf_counter()
    atomic_write_lines(paths.ip_cidr_output, cidr_lines)
    atomic_write_lines(paths.output, minimized)
    LOGGER.info("DNS output write complete in %.2fs", perf_counter() - write_started)
    return DnsBuildResult(
        paths=paths,
        source_count=len(source_lines),
        candidate_count=len(base_candidates),
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
