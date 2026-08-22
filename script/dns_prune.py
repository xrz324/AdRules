#!/usr/bin/env python3
"""
DNS 规则域名失活检测与清理（低依赖 / 可缓存 / 可限流）。

设计目标：
- 先用全球 DNS 并发探测，按解析器轮询分配域名；全球返回存在性信号时立即判活；
- 全球返回 NXDOMAIN/无 NS 时，再进入国内 DNS 补测；每个国内解析器都是独立业务窗口，各自维护节奏、退避和熔断冷却，并行工作且互不阻塞。全球暂时无法确认的域名保持 unknown。
- 通过缓存 + 预算（budget）避免在 GitHub Actions 中耗时过长；
- GLOBAL 默认不设请求间隔或 per-resolver 限并发（配置为 0 即无限制）；国内每个窗口一次只处理一个域名，并在自己的节奏中串行推进。

注意：
- 本脚本仅处理 ABP 风格的域名规则：以 "||" 开头且包含 "^" 的条目。
- 对 `||example.com^` / `||*.example.com^` 这类规则，A/AAAA NODATA 不代表不可拦截；有正常回包或仅有 NODATA 时仍判活。
- 仅在全球返回 NXDOMAIN/无 NS，且国内补测也给出同一失活信号时判死；解析器不可达、超时或被限流时保守记为 unknown。
- 遇到解析器不可达/超时，会降级为“本次不判死”，避免误删。

``run_prune`` 提供给上层编排使用；覆盖阶段直接传入内存中的跳过域名集合。
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    from common import atomic_write_lines, read_utf8_lines
    from dns_prune_cache import (
        cache_is_fresh,
        load_cache,
        save_cache,
        should_recheck_dead_entry,
    )
    from dns_prune_config import (
        build_probe_policy,
        parse_args,
        parse_bool,
        resolve_resolver_groups,
    )
    from dns_prune_probe import (
        ProbeExecutionSettings,
        healthcheck_group,
        run_two_round_probes,
    )
    from dns_prune_rules import (
        extract_check_domain,
        iter_check_domains,
    )
    from dns_prune_model import (
        DEFAULT_CN_BACKOFF_BASE_MS,
        DEFAULT_CN_BACKOFF_MAX_MS,
        DEFAULT_CN_COOLDOWN_MS,
        DEFAULT_CN_FAILURE_THRESHOLD,
        DEFAULT_CN_MAX_RETRIES,
        DEFAULT_CN_QUERY_DELAY_MS,
        DEFAULT_CN_SLOW_THRESHOLD_MS,
        CacheEntry,
        CacheLoadResult,
        DeadSetResult,
        ProbePlan,
    )
except ImportError:  # Support ``python -m script.dns_prune``.
    from .common import atomic_write_lines, read_utf8_lines  # type: ignore[no-redef]
    from .dns_prune_cache import (  # type: ignore[no-redef]
        cache_is_fresh,
        load_cache,
        save_cache,
        should_recheck_dead_entry,
    )
    from .dns_prune_config import (  # type: ignore[no-redef]
        build_probe_policy,
        parse_args,
        parse_bool,
        resolve_resolver_groups,
    )
    from .dns_prune_probe import (  # type: ignore[no-redef]
        ProbeExecutionSettings,
        healthcheck_group,
        run_two_round_probes,
    )
    from .dns_prune_rules import (  # type: ignore[no-redef]
        extract_check_domain,
        iter_check_domains,
    )
    from .dns_prune_model import (  # type: ignore[no-redef]
        DEFAULT_CN_BACKOFF_BASE_MS,
        DEFAULT_CN_BACKOFF_MAX_MS,
        DEFAULT_CN_COOLDOWN_MS,
        DEFAULT_CN_FAILURE_THRESHOLD,
        DEFAULT_CN_MAX_RETRIES,
        DEFAULT_CN_QUERY_DELAY_MS,
        DEFAULT_CN_SLOW_THRESHOLD_MS,
        CacheEntry,
        CacheLoadResult,
        DeadSetResult,
        ProbePlan,
    )


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _now_ts() -> int:
    return int(time.time())


def _choose_probe_targets(
    domains: Sequence[str],
    cache: Dict[str, CacheEntry],
    now_ts: int,
    budget: int,
    new_budget: int,
    recheck_budget: int,
    ttl_alive_days: int,
    ttl_dead_days: int,
    ttl_unknown_days: int,
    ttl_dead_recheck_days: int,
) -> ProbePlan:
    new_domains: List[str] = []
    dead_recheck_candidates: List[Tuple[int, str]] = []
    stale_candidates: List[Tuple[int, str]] = []
    fresh_alive_count = 0
    fresh_dead_count = 0
    fresh_unknown_count = 0

    for d in domains:
        entry = cache.get(d)
        if entry is None:
            new_domains.append(d)
            continue
        if should_recheck_dead_entry(entry, now_ts, ttl_dead_recheck_days):
            dead_recheck_candidates.append((entry.checked_at, d))
            continue
        if not cache_is_fresh(entry, now_ts, ttl_alive_days, ttl_dead_days, ttl_unknown_days):
            stale_candidates.append((entry.checked_at, d))
            continue

        if entry.status == "alive":
            fresh_alive_count += 1
        elif entry.status == "dead":
            fresh_dead_count += 1
        else:
            fresh_unknown_count += 1

    new_domains.sort()
    dead_recheck_candidates.sort(key=lambda x: (x[0], x[1]))
    stale_candidates.sort(key=lambda x: (x[0], x[1]))
    dead_recheck_domains = [d for _ts, d in dead_recheck_candidates]
    stale_domains = [d for _ts, d in stale_candidates]
    recheck_domains = dead_recheck_domains + stale_domains

    if budget <= 0:
        return ProbePlan(
            targets=new_domains + recheck_domains,
            new_count=len(new_domains),
            recheck_count=len(recheck_domains),
            dead_recheck_count=len(dead_recheck_domains),
            stale_recheck_count=len(stale_domains),
            overflow_count=0,
            new_candidate_count=len(new_domains),
            dead_recheck_candidate_count=len(dead_recheck_domains),
            stale_candidate_count=len(stale_domains),
            fresh_alive_count=fresh_alive_count,
            fresh_dead_count=fresh_dead_count,
            fresh_unknown_count=fresh_unknown_count,
        )

    resolved_new_budget = max(0, new_budget)
    resolved_recheck_budget = max(0, recheck_budget)
    if resolved_new_budget == 0 and resolved_recheck_budget == 0:
        resolved_recheck_budget = budget // 4
        resolved_new_budget = budget - resolved_recheck_budget

    if resolved_new_budget + resolved_recheck_budget > budget:
        logger.warning(
            "Probe allocation exceeds total budget; truncating (budget=%d new=%d recheck=%d)",
            budget,
            resolved_new_budget,
            resolved_recheck_budget,
        )
        overflow = resolved_new_budget + resolved_recheck_budget - budget
        if resolved_recheck_budget >= overflow:
            resolved_recheck_budget -= overflow
        else:
            overflow -= resolved_recheck_budget
            resolved_recheck_budget = 0
            resolved_new_budget = max(0, resolved_new_budget - overflow)

    targets: List[str] = []
    selected_new = new_domains[:resolved_new_budget]
    selected_recheck = recheck_domains[:resolved_recheck_budget]
    targets.extend(selected_new)
    targets.extend(selected_recheck)

    new_remaining = new_domains[len(selected_new):]
    recheck_remaining = recheck_domains[len(selected_recheck):]
    remaining_budget = max(0, budget - len(targets))
    new_quota_short = len(selected_new) < resolved_new_budget
    recheck_quota_short = len(selected_recheck) < resolved_recheck_budget

    overflow_sources: List[Tuple[str, List[str]]] = []
    if new_quota_short and not recheck_quota_short:
        overflow_sources = [("recheck", recheck_remaining), ("new", new_remaining)]
    elif recheck_quota_short and not new_quota_short:
        overflow_sources = [("new", new_remaining), ("recheck", recheck_remaining)]
    else:
        overflow_sources = [("recheck", recheck_remaining), ("new", new_remaining)]

    overflow_count = 0
    new_count = len(selected_new)
    recheck_count = len(selected_recheck)

    for source_type, source_domains in overflow_sources:
        if remaining_budget <= 0:
            break
        extra = source_domains[:remaining_budget]
        if not extra:
            continue
        targets.extend(extra)
        overflow_count += len(extra)
        remaining_budget -= len(extra)
        if source_type == "new":
            new_count += len(extra)
        else:
            recheck_count += len(extra)

    dead_recheck_set = set(dead_recheck_domains)
    scheduled_dead_recheck_count = sum(1 for d in targets if d in dead_recheck_set)
    scheduled_stale_recheck_count = recheck_count - scheduled_dead_recheck_count

    return ProbePlan(
        targets=targets,
        new_count=new_count,
        recheck_count=recheck_count,
        dead_recheck_count=scheduled_dead_recheck_count,
        stale_recheck_count=scheduled_stale_recheck_count,
        overflow_count=overflow_count,
        new_candidate_count=len(new_domains),
        dead_recheck_candidate_count=len(dead_recheck_domains),
        stale_candidate_count=len(stale_domains),
        fresh_alive_count=fresh_alive_count,
        fresh_dead_count=fresh_dead_count,
        fresh_unknown_count=fresh_unknown_count,
    )


def _build_dead_set_result(
    domains: Sequence[str],
    cache: Dict[str, CacheEntry],
    now_ts: int,
    ttl_alive_days: int,
    ttl_dead_days: int,
    ttl_unknown_days: int,
    ttl_dead_recheck_days: int,
    rechecked_domains: Set[str],
) -> DeadSetResult:
    dead: Dict[str, CacheEntry] = {}
    blocked_pending_recheck_count = 0
    for d in domains:
        entry = cache.get(d)
        if not entry or entry.status != "dead":
            continue
        if not cache_is_fresh(entry, now_ts, ttl_alive_days, ttl_dead_days, ttl_unknown_days):
            continue
        if should_recheck_dead_entry(entry, now_ts, ttl_dead_recheck_days) and d not in rechecked_domains:
            blocked_pending_recheck_count += 1
            continue
        dead[d] = entry
    return DeadSetResult(
        dead=dead,
        reusable_count=len(dead),
        blocked_pending_recheck_count=blocked_pending_recheck_count,
    )


def _merge_cache_entry(
    existing: Optional[CacheEntry],
    observed: CacheEntry,
    allow_dead: bool,
) -> Tuple[CacheEntry, bool]:
    """
    当 dead 判定被禁用时，unknown 只代表“当前环境不足以得出结论”，
    不应覆盖已有的稳定缓存状态（alive/dead）。
    """
    if allow_dead:
        return observed, False
    if existing is None:
        return observed, False
    if observed.status != "unknown":
        return observed, False
    if existing.status in {"alive", "dead"}:
        return existing, True
    return observed, False


def _normalize_skip_domains(values: Optional[Iterable[str]]) -> Set[str]:
    """Normalize an optional in-memory coverage result for probe filtering."""

    if values is None:
        return set()
    return {
        value.strip().lower().rstrip(".")
        for value in values
        if isinstance(value, str) and value.strip()
    }


def run_prune(
    args: argparse.Namespace,
    skip_domains: Optional[Iterable[str]] = (),
) -> int:
    """Run one prune transaction using parsed options.

    ``skip_domains`` is the stage boundary used by the DNS orchestrator.  It
    avoids serializing coverage results through a temporary file.
    """

    if args.print_policy_fingerprint:
        resolver_groups = resolve_resolver_groups(args, log_warnings=False)
        probe_policy = build_probe_policy(args, *resolver_groups)
        print(probe_policy.fingerprint())
        return 0

    input_path = args.input
    output_path = args.output or input_path
    cache_path = args.cache
    removed_log_path = args.removed_log

    if not os.path.exists(input_path):
        logger.error("Input file does not exist: %s", input_path)
        return 2

    if parse_bool(args.remove_nodata):
        logger.warning(
            "Ignoring --remove-nodata; only GLOBAL+CN NXDOMAIN/no-NS checks are supported"
        )
    now_ts = _now_ts()

    lines = read_utf8_lines(Path(input_path))
    check_domains = iter_check_domains(lines)
    skipped_domains = _normalize_skip_domains(skip_domains)
    if skipped_domains:
        before_count = len(check_domains)
        check_domains = [domain for domain in check_domains if domain not in skipped_domains]
        logger.info(
            "Skipped domains already covered by broader rules: %d",
            before_count - len(check_domains),
        )
    logger.info("Probe candidates: %d", len(check_domains))

    resolver_list, resolver_cn_list, resolver_global_list = resolve_resolver_groups(args)

    if not resolver_list:
        if args.require_dead_capable:
            logger.error("No resolvers configured; strict mode aborts")
            return 3
        logger.warning("No resolvers configured; skipping prune")
        return 0

    probe_policy = build_probe_policy(
        args, resolver_list, resolver_cn_list, resolver_global_list
    )

    cache_load_result = (
        load_cache(cache_path, probe_policy=probe_policy)
        if cache_path
        else CacheLoadResult(entries={}, state="disabled")
    )
    cache = cache_load_result.entries
    logger.info("Cache loaded: state=%s entries=%d", cache_load_result.state, len(cache))

    # Health-check both groups concurrently.  A health query is issued once
    # per resolver, so serializing CN checks here would make one slow provider
    # delay every otherwise independent CN window before probing even starts.
    online_resolvers_global = healthcheck_group(
        resolver_global_list,
        args.health_domain,
        args.timeout_ms,
        args.retries,
        parallel=True,
        concurrency=getattr(args, "global_concurrency", args.concurrency),
    )
    online_resolvers_cn = healthcheck_group(
        resolver_cn_list,
        args.health_domain,
        args.timeout_ms,
        args.retries,
        parallel=True,
        concurrency=getattr(args, "concurrency", len(resolver_cn_list)),
    )
    online_resolvers = list(dict.fromkeys(online_resolvers_global + online_resolvers_cn))

    logger.info(
        "Healthy resolvers: cn=%s global=%s",
        ",".join(online_resolvers_cn) or "-",
        ",".join(online_resolvers_global) or "-",
    )

    if len(online_resolvers) < max(1, args.min_online_resolvers):
        if args.require_dead_capable:
            logger.error(
                "Too few healthy resolvers (%d/%d); strict mode aborts",
                len(online_resolvers),
                max(1, args.min_online_resolvers),
            )
            return 3
        logger.warning("Too few healthy resolvers (%d); skipping prune", len(online_resolvers))
        return 0

    min_cn = max(1, int(args.min_online_resolvers_cn))
    min_global = max(1, int(args.min_online_resolvers_global))
    allow_dead = len(online_resolvers_cn) >= min_cn and len(online_resolvers_global) >= min_global
    if not allow_dead:
        logger.warning(
            "Healthy resolvers below minimum (cn=%d/%d global=%d/%d); disabling dead classification and deletion",
            len(online_resolvers_cn),
            min_cn,
            len(online_resolvers_global),
            min_global,
        )
        if args.require_dead_capable:
            logger.error("Strict mode requires dead classification; current resolver health is insufficient")
            return 4

    probe_plan = _choose_probe_targets(
        domains=check_domains,
        cache=cache,
        now_ts=now_ts,
        budget=args.budget,
        new_budget=args.new_budget,
        recheck_budget=args.recheck_budget,
        ttl_alive_days=args.ttl_alive_days,
        ttl_dead_days=args.ttl_dead_days,
        ttl_unknown_days=args.ttl_unknown_days,
        ttl_dead_recheck_days=args.ttl_dead_recheck_days,
    )

    logger.info(
        "Cache classification: new=%d fresh_alive=%d fresh_dead=%d fresh_unknown=%d dead_due_recheck=%d stale_other=%d",
        probe_plan.new_candidate_count,
        probe_plan.fresh_alive_count,
        probe_plan.fresh_dead_count,
        probe_plan.fresh_unknown_count,
        probe_plan.dead_recheck_candidate_count,
        probe_plan.stale_candidate_count,
    )
    logger.info(
        "Probe allocation: targets=%d budget=%d new=%d dead-recheck=%d stale=%d overflow=%d deferred-dead=%d",
        len(probe_plan.targets),
        args.budget,
        probe_plan.new_count,
        probe_plan.dead_recheck_count,
        probe_plan.stale_recheck_count,
        probe_plan.overflow_count,
        max(0, probe_plan.dead_recheck_candidate_count - probe_plan.dead_recheck_count),
    )

    probed_domains: Set[str] = set()
    preserved_cache_entries = 0
    if probe_plan.targets:
        observed_entries, probed_domains = run_two_round_probes(
            probe_plan.targets,
            online_resolvers_global,
            online_resolvers_cn,
            ProbeExecutionSettings(
                timeout_ms=args.timeout_ms,
                retries=args.retries,
                global_concurrency=getattr(
                    args, "global_concurrency", args.concurrency
                ),
                global_inflight_per_resolver=getattr(
                    args, "global_inflight_per_resolver", 0
                ),
                cn_inflight_per_resolver=args.inflight_per_resolver,
                cn_jitter_ms=args.jitter_ms,
                cn_query_delay_ms=getattr(
                    args, "cn_query_delay_ms", DEFAULT_CN_QUERY_DELAY_MS
                ),
                cn_backoff_base_ms=getattr(
                    args, "cn_backoff_base_ms", DEFAULT_CN_BACKOFF_BASE_MS
                ),
                cn_backoff_max_ms=getattr(
                    args, "cn_backoff_max_ms", DEFAULT_CN_BACKOFF_MAX_MS
                ),
                cn_failure_threshold=getattr(
                    args, "cn_failure_threshold", DEFAULT_CN_FAILURE_THRESHOLD
                ),
                cn_cooldown_ms=getattr(
                    args, "cn_cooldown_ms", DEFAULT_CN_COOLDOWN_MS
                ),
                cn_slow_threshold_ms=getattr(
                    args, "cn_slow_threshold_ms", DEFAULT_CN_SLOW_THRESHOLD_MS
                ),
                cn_max_retries=getattr(
                    args, "cn_max_retries", DEFAULT_CN_MAX_RETRIES
                ),
                allow_dead=allow_dead,
                min_online_cn=min_cn,
            ),
        )
        for domain, entry in observed_entries.items():
            merged_entry, preserved_existing = _merge_cache_entry(
                existing=cache.get(domain),
                observed=entry,
                allow_dead=allow_dead,
            )
            cache[domain] = merged_entry
            if preserved_existing:
                preserved_cache_entries += 1

    dead_result = _build_dead_set_result(
        domains=check_domains,
        cache=cache,
        now_ts=_now_ts(),
        ttl_alive_days=args.ttl_alive_days,
        ttl_dead_days=args.ttl_dead_days,
        ttl_unknown_days=args.ttl_unknown_days,
        ttl_dead_recheck_days=args.ttl_dead_recheck_days,
        rechecked_domains=probed_domains,
    )
    if not allow_dead:
        dead_result = DeadSetResult(dead={}, reusable_count=0, blocked_pending_recheck_count=0)
    dead = dead_result.dead

    removed_rules: List[str] = []
    removed_log_lines: List[str] = []
    kept_lines: List[str] = []
    for line in lines:
        d = extract_check_domain(line)
        if d and d in dead:
            removed_rules.append(line)
            removed_log_lines.append(f"{d}\t{dead[d].reason}\t{line}")
            continue
        kept_lines.append(line)

    logger.info("Rule cleanup: %d -> %d (-%d)", len(lines), len(kept_lines), len(removed_rules))
    logger.info(
        "Dead-cache reuse: reusable=%d blocked_pending_recheck=%d",
        dead_result.reusable_count,
        dead_result.blocked_pending_recheck_count,
    )
    if preserved_cache_entries > 0:
        logger.info("Degraded-mode cache protection: preserved=%d", preserved_cache_entries)
    logger.info("Inactive domains eligible for removal: %d", len(dead))

    if args.dry_run:
        return 0

    atomic_write_lines(Path(output_path), kept_lines)

    if removed_log_path:
        atomic_write_lines(Path(removed_log_path), removed_log_lines)

    if cache_path:
        save_cache(cache_path, cache, active_domains=check_domains, probe_policy=probe_policy)

    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        from logging_utils import configure_logging
    except ImportError:  # Support ``python -m script.dns_prune``.
        from .logging_utils import configure_logging  # type: ignore[no-redef]

    configure_logging()
    return run_prune(parse_args(argv, environment=os.environ))


if __name__ == "__main__":
    raise SystemExit(main())
