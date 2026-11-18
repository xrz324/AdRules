#!/usr/bin/env python3
"""Validate generated rule artifacts before they are published."""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional

try:
    from autoupdate_config import (
        DEFAULT_CONFIG_PATH,
        DEFAULT_MAX_RULE_DROP_PERCENT,
        ConfigError,
        artifact_paths,
        load_config,
    )
    from common import read_utf8_bytes
    from rule_canonical import canonicalize_adblock_domain
except ImportError:  # Support ``python -m script.validate_outputs``.
    from .autoupdate_config import (  # type: ignore[no-redef]
        DEFAULT_CONFIG_PATH,
        DEFAULT_MAX_RULE_DROP_PERCENT,
        ConfigError,
        artifact_paths,
        load_config,
    )
    from .common import read_utf8_bytes  # type: ignore[no-redef]
    from .rule_canonical import canonicalize_adblock_domain  # type: ignore[no-redef]


TOTAL_COUNT_RE = re.compile(r"^! Total count: ([0-9]+)$")
HTML_PREFIXES = ("<!doctype", "<html", "<head", "<body")
DEFAULT_MAX_DROP_PERCENT = DEFAULT_MAX_RULE_DROP_PERCENT


class ValidationError(ValueError):
    """Raised when a generated artifact is unsafe to publish."""


@dataclass(frozen=True)
class RuleFileStats:
    path: Path
    rule_count: int


def _read_utf8(path: Path) -> tuple[bytes, str]:
    try:
        raw = read_utf8_bytes(path)
    except FileNotFoundError:
        raise ValidationError(f"missing file: {path}")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"file is not UTF-8: {path}: {exc}") from exc
    if not raw:
        raise ValidationError(f"empty file: {path}")
    if not raw.endswith(b"\n"):
        raise ValidationError(f"missing final newline: {path}")
    if b"\x00" in raw:
        raise ValidationError(f"NUL byte found: {path}")

    return raw, raw.decode("utf-8")


def _is_dns_rule(line: str) -> bool:
    if canonicalize_adblock_domain(line) is not None:
        return True
    # ABP regular expressions may contain escaped slashes and modifier values
    # with additional slash-delimited replacement expressions.
    return line.startswith("/") and line.count("/") >= 2


def validate_rule_file(path: Path, kind: str) -> RuleFileStats:
    _raw, text = _read_utf8(path)
    lines = text.splitlines()
    if not lines or lines[0] != "[Adblock Plus 2.0]":
        raise ValidationError(f"invalid Adblock header: {path}")

    declared_counts = [
        int(match.group(1))
        for line in lines
        if (match := TOTAL_COUNT_RE.fullmatch(line)) is not None
    ]
    if len(declared_counts) != 1:
        raise ValidationError(f"expected exactly one total-count header: {path}")

    rule_start = 1
    while rule_start < len(lines) and lines[rule_start].startswith("!"):
        rule_start += 1
    rules = lines[rule_start:]
    if not rules:
        raise ValidationError(f"no rules generated: {path}")
    if any(not line for line in rules):
        raise ValidationError(f"blank rule found: {path}")
    if any(line.startswith("\ufeff") for line in rules):
        raise ValidationError(f"BOM found at start of rule: {path}")
    if len(set(rules)) != len(rules):
        raise ValidationError(f"duplicate rules found: {path}")
    if any(line.lstrip().lower().startswith(HTML_PREFIXES) for line in rules):
        raise ValidationError(f"HTML content found in rules: {path}")
    if declared_counts[0] != len(rules):
        raise ValidationError(
            f"count mismatch for {path}: declared={declared_counts[0]} actual={len(rules)}"
        )

    if kind == "dns":
        invalid = next((line for line in rules if not _is_dns_rule(line)), None)
        if invalid is not None:
            raise ValidationError(f"invalid DNS rule in {path}: {invalid[:160]}")
    elif kind != "adblock":
        raise ValueError(f"unsupported rule kind: {kind}")

    return RuleFileStats(path=path, rule_count=len(rules))


def validate_drop(
    current: RuleFileStats,
    baseline: Optional[RuleFileStats],
    max_drop_percent: float,
) -> None:
    if baseline is None or baseline.rule_count == 0:
        return
    if not 0 <= max_drop_percent < 100:
        raise ValidationError("max drop percent must be in [0, 100)")

    drop_percent = (
        (baseline.rule_count - current.rule_count) * 100.0 / baseline.rule_count
    )
    if drop_percent > max_drop_percent:
        raise ValidationError(
            f"rule count dropped {drop_percent:.2f}% for {current.path} "
            f"({baseline.rule_count} -> {current.rule_count}); "
            f"limit={max_drop_percent:.2f}%"
        )


def validate_binary(path: Path, magic: bytes, label: str) -> None:
    if not path.is_file():
        raise ValidationError(f"missing {label} artifact: {path}")
    raw = path.read_bytes()
    if len(raw) < 16:
        raise ValidationError(f"truncated {label} artifact: {path}")
    if not raw.startswith(magic):
        raise ValidationError(f"invalid {label} magic: {path}")


def validate_mihomo_yaml(path: Path) -> None:
    _raw, text = _read_utf8(path)
    lines = text.splitlines()
    if lines == ["payload: []"]:
        return
    if not lines or lines[0] != "payload:" or len(lines) == 1:
        raise ValidationError(f"invalid Mihomo YAML payload: {path}")
    payload = lines[1:]
    if any(not (line.startswith("  - '") and line.endswith("'")) for line in payload):
        raise ValidationError(f"invalid Mihomo YAML entry: {path}")
    if len(set(payload)) != len(payload):
        raise ValidationError(f"duplicate Mihomo YAML entries: {path}")


def _optional_baseline(path_value: str, kind: str) -> Optional[RuleFileStats]:
    if not path_value:
        return None
    return validate_rule_file(Path(path_value), kind)


def resolve_artifact_paths(
    config_path: Path,
    overrides: Mapping[str, Optional[str]],
) -> Dict[str, Path]:
    """Resolve generated artifact paths from config, with explicit CLI overrides."""
    configured = artifact_paths(load_config(config_path))
    return {
        name: Path(overrides.get(name) or configured[name])
        for name in configured
    }


def validate_artifacts(
    config_path: Path = DEFAULT_CONFIG_PATH,
    *,
    artifact_overrides: Optional[Mapping[str, Optional[str | Path]]] = None,
    baseline_adblock: Optional[Path] = None,
    baseline_dns: Optional[Path] = None,
    max_drop_percent: float = DEFAULT_MAX_DROP_PERCENT,
    root_dir: Optional[Path] = None,
) -> tuple[RuleFileStats, RuleFileStats]:
    """Validate all configured artifacts for callers embedding the pipeline.

    ``artifact_overrides`` is useful for an isolated build where the manifest
    paths are resolved relative to a temporary repository root.  The command
    line interface keeps its historical current-working-directory behavior;
    embedded callers should pass ``root_dir`` explicitly.
    """

    base = Path(root_dir).resolve() if root_dir is not None else None
    config_file = Path(config_path)
    if base is not None and not config_file.is_absolute():
        config_file = base / config_file
    overrides = {
        name: (str(value) if value is not None else None)
        for name, value in (artifact_overrides or {}).items()
    }
    paths = resolve_artifact_paths(config_file, overrides)
    if base is not None:
        paths = {
            name: path if path.is_absolute() else base / path
            for name, path in paths.items()
        }

    # Embedded callers receive the already-parsed value from RuntimeSettings.
    # Keep a deterministic constant for standalone library use; environment
    # lookup belongs exclusively to the CLI boundary below.
    drop_limit = float(max_drop_percent)
    adblock = validate_rule_file(paths["adblock"], "adblock")
    dns = validate_rule_file(paths["dns"], "dns")
    validate_drop(
        adblock,
        _optional_baseline(str(baseline_adblock or ""), "adblock"),
        drop_limit,
    )
    validate_drop(
        dns,
        _optional_baseline(str(baseline_dns or ""), "dns"),
        drop_limit,
    )
    validate_binary(paths["singbox"], b"SRS", "sing-box")
    validate_binary(paths["mihomo_mrs"], b"\x28\xb5\x2f\xfd", "Mihomo MRS")
    validate_mihomo_yaml(paths["mihomo_yaml"])
    return adblock, dns


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--adblock")
    parser.add_argument("--dns")
    parser.add_argument("--singbox")
    parser.add_argument("--mihomo-mrs")
    parser.add_argument("--mihomo-yaml")
    parser.add_argument("--baseline-adblock", default="")
    parser.add_argument("--baseline-dns", default="")
    parser.add_argument(
        "--max-drop-percent",
        type=float,
        default=os.environ.get(
            "MAX_RULE_DROP_PERCENT", str(DEFAULT_MAX_RULE_DROP_PERCENT)
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        adblock, dns = validate_artifacts(
            args.config,
            artifact_overrides={
                "adblock": args.adblock,
                "dns": args.dns,
                "singbox": args.singbox,
                "mihomo_mrs": args.mihomo_mrs,
                "mihomo_yaml": args.mihomo_yaml,
            },
            baseline_adblock=Path(args.baseline_adblock)
            if args.baseline_adblock
            else None,
            baseline_dns=Path(args.baseline_dns) if args.baseline_dns else None,
            max_drop_percent=args.max_drop_percent,
        )
    except (ConfigError, OSError, ValidationError) as exc:
        print(f"[ERROR] output validation failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"[INFO] output validation passed: "
        f"adblock={adblock.rule_count} dns={dns.rule_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
