"""Remove rules filtered by allowlist / disabled-set logic.

Inspired by Cats-Team/AdRules script/remove.py
(https://github.com/Cats-Team/AdRules, 0BSD); independently implemented.
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List, Optional, Pattern, Set, Tuple

try:
    from common import atomic_write_text, log_error, log_info, log_warn, read_utf8_text
except ImportError:  # Support ``python -m script.remove``.
    from .common import (  # type: ignore[no-redef]
        atomic_write_text,
        log_error,
        log_info,
        log_warn,
        read_utf8_text,
    )


ABP_ALLOWLIST_PATTERN = re.compile(r"^(?:@@)?\|\|([^\^]+)\^$")
ABP_BLOCK_RULE_PATTERN = re.compile(r"^\|\|([^\^]+)\^")
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)"
    r"(?:\.(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?))*$"
)


class RemoveError(RuntimeError):
    """Raised when allowlist loading or filtering cannot complete."""


def _log_info(message: str) -> None:
    """Keep the historical severity selection for allowlist diagnostics."""

    text = str(message)
    if text.startswith("Error"):
        log_error(text)
    elif text.startswith("Warning"):
        log_warn(text)
    else:
        log_info(text)

# ============================
# 核心逻辑
# ============================

def get_args():
    parser = argparse.ArgumentParser(description="Remove whitelisted domains from ABP rules.")
    parser.add_argument("--blacklist", required=True, help="Path to the ABP blocklist file (target to clean)")
    parser.add_argument("--whitelist", required=True, help="Path to the whitelist file")
    return parser.parse_args()

def is_regex(line: str) -> bool:
    """仅将由斜杠明确包围的条目识别为正则。"""
    return len(line) >= 2 and line.startswith('/') and line.endswith('/')


def normalize_domain(domain: str) -> str:
    """规范化域名以便进行大小写无关的精确匹配。"""
    normalized = domain.strip().lower().rstrip('.')
    if not normalized:
        return ''
    if normalized.isascii():
        return normalized

    try:
        return normalized.encode('idna').decode('ascii')
    except UnicodeError:
        return normalized


def is_valid_domain(domain: str) -> bool:
    """校验普通或 ABP 白名单中的精确域名。"""
    return bool(DOMAIN_PATTERN.fullmatch(domain))


def parse_whitelist_entry(line: str) -> Tuple[Optional[str], Optional[Pattern[str]]]:
    """将白名单条目解析为精确域名或已编译正则。"""
    if is_regex(line):
        pattern_text = line[1:-1]
        try:
            regex = re.compile(pattern_text, re.IGNORECASE)
        except re.error as exc:
            _log_info(f"Warning: ignoring invalid regex allowlist entry: {line} ({exc})")
            return None, None

        if regex.search('') is not None:
            _log_info(f"Warning: ignoring regex allowlist entry matching an empty string: {line}")
            return None, None
        return None, regex

    abp_match = ABP_ALLOWLIST_PATTERN.fullmatch(line)
    domain_text = abp_match.group(1) if abp_match else line
    domain = normalize_domain(domain_text)
    if not is_valid_domain(domain):
        _log_info(f"Warning: ignoring invalid domain allowlist entry: {line}")
        return None, None
    return domain, None

def load_whitelist(file_path: str) -> Tuple[Set[str], List[Pattern[str]]]:
    plain_domains: Set[str] = set()
    regex_rules: List[Pattern[str]] = []

    if not os.path.exists(file_path):
        raise RemoveError(f"allowlist file not found: {file_path}")

    try:
        for line in read_utf8_text(Path(file_path)).splitlines():
            line_content = line.strip()
            # 跳过空行和注释
            if not line_content or line_content.startswith('!') or line_content.startswith('#'):
                continue

            domain, regex_rule = parse_whitelist_entry(line_content)
            if domain is not None:
                plain_domains.add(domain)
            elif regex_rule is not None:
                regex_rules.append(regex_rule)
    except RemoveError:
        raise
    except Exception as exc:
        raise RemoveError(f"failed to read allowlist: {exc}") from exc

    _log_info(f"Allowlist loaded: plain={len(plain_domains)} regex={len(regex_rules)}")
    return plain_domains, regex_rules


def rule_matches_whitelist(
    line: str,
    plain_wl: Set[str],
    regex_wl: List[Pattern[str]],
) -> bool:
    """Return whether one ABP rule is removed by the parsed whitelist.

    Keeping this predicate separate lets pipeline stages reuse the exact
    allow-list semantics without opening a second temporary file or invoking
    the command-line adapter.
    """

    stripped = line.strip()
    match = ABP_BLOCK_RULE_PATTERN.match(stripped)
    if match is None:
        return False

    domain = normalize_domain(match.group(1))
    if domain in plain_wl:
        return True
    return any(regex.search(domain) for regex in regex_wl)

def clean_blacklist(
    blacklist_path: str,
    plain_wl: Set[str],
    regex_wl: List[Pattern[str]],
) -> None:
    if not os.path.exists(blacklist_path):
        raise RemoveError(f"blocklist file not found: {blacklist_path}")

    original_count = 0
    removed_count = 0
    kept_count = 0
    try:
        lines = read_utf8_text(Path(blacklist_path)).splitlines(keepends=True)
        kept_lines: list[str] = []
        for line in lines:
            original_count += 1
            should_remove = rule_matches_whitelist(line, plain_wl, regex_wl)
            if should_remove:
                removed_count += 1
            else:
                kept_lines.append(line)
                kept_count += 1

        atomic_write_text(Path(blacklist_path), "".join(kept_lines))
        _log_info(f"Allowlist filter complete {original_count} -> {kept_count} (-{removed_count})")

    except RemoveError:
        raise
    except Exception as exc:
        raise RemoveError(f"failed to process blocklist: {exc}") from exc

if __name__ == "__main__":
    try:
        from logging_utils import configure_logging
    except ImportError:  # Support ``python -m script.remove``.
        from .logging_utils import configure_logging  # type: ignore[no-redef]

    configure_logging()
    # 解析命令行参数
    args = get_args()

    # 1. 加载白名单
    try:
        plain_whitelist, regex_whitelist = load_whitelist(args.whitelist)
        clean_blacklist(args.blacklist, plain_whitelist, regex_whitelist)
    except RemoveError as exc:
        log_error(str(exc))
        raise SystemExit(1) from exc
