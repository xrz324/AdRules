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

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

try:
    from common import atomic_write_text_bundle, read_utf8_lines
    from dns_prune_cache import (
        cache_is_fresh,
        load_cache,
        render_cache,
        should_recheck_dead_entry,
    )
    from inactive_domain_cache import select_reusable_inactive_domains
    from inactive_domain_model import InactiveDomainSelection
    from dns_prune_config import (
        build_probe_policy,
        parse_args,
        request_from_args,
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
        CacheEntry,
        CacheLoadResult,
        DnsPolicyMode,
        ProbePlan,
        ProbePolicy,
        PruneExecutionResult,
        PruneRequest,
    )
except ImportError:  # Support ``python -m script.dns_prune``.
    from .common import atomic_write_text_bundle, read_utf8_lines  # type: ignore[no-redef]
    from .dns_prune_cache import (  # type: ignore[no-redef]
        cache_is_fresh,
        load_cache,
        render_cache,
        should_recheck_dead_entry,
    )
    from .inactive_domain_cache import (  # type: ignore[no-redef]
        select_reusable_inactive_domains,
    )
    from .inactive_domain_model import InactiveDomainSelection  # type: ignore[no-redef]
    from .dns_prune_config import (  # type: ignore[no-redef]
        build_probe_policy,
        parse_args,
        request_from_args,
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
        CacheEntry,
        CacheLoadResult,
        DnsPolicyMode,
        ProbePlan,
        ProbePolicy,
        PruneExecutionResult,
        PruneRequest,
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


def _filter_dead_rules(
    lines: Sequence[str],
    dead: Dict[str, CacheEntry],
) -> Tuple[List[str], List[str], List[str]]:
    """Split rules using an already validated inactive-domain set."""

    removed_rules: List[str] = []
    removed_log_lines: List[str] = []
    kept_lines: List[str] = []
    for line in lines:
        domain = extract_check_domain(line)
        if domain and domain in dead:
            removed_rules.append(line)
            removed_log_lines.append(f"{domain}\t{dead[domain].reason}\t{line}")
            continue
        kept_lines.append(line)
    return kept_lines, removed_rules, removed_log_lines


@dataclass
class PruneSnapshot:
    """Validated input, compatible cache, and resolver policy for one run."""

    input_path: Path
    output_path: Path
    cache_path: Optional[Path]
    removed_log_path: Optional[Path]
    lines: List[str]
    check_domains: List[str]
    resolver_list: List[str]
    resolver_cn_list: List[str]
    resolver_global_list: List[str]
    probe_policy: ProbePolicy
    cache: Dict[str, CacheEntry]
    started_at: int


@dataclass(frozen=True)
class ProbeOutcome:
    """State produced by a probe strategy before shared rule cleanup."""

    allow_dead: bool
    rechecked_domains: Set[str]
    degraded_reason: str = ""
    preserved_cache_entries: int = 0
    write_cache: bool = True


@dataclass(frozen=True)
class ResolverHealth:
    """Healthy resolver groups and the classification capability they provide."""

    global_resolvers: Tuple[str, ...]
    cn_resolvers: Tuple[str, ...]
    allow_dead: bool
    min_online_cn: int
    degraded_reason: str = ""


def _prepare_prune_snapshot(
    request: PruneRequest,
    skip_domains: Optional[Iterable[str]],
    *,
    log_resolver_warnings: bool,
) -> Union[PruneSnapshot, PruneExecutionResult]:
    """Read and normalize all state shared by every prune strategy."""

    io = request.io
    input_path = io.input
    if input_path is None or not input_path.is_file():
        logger.error("Input file does not exist: %s", input_path)
        return PruneExecutionResult(2, "failed", "input file does not exist")

    lines = read_utf8_lines(Path(input_path))
    check_domains = iter_check_domains(lines)
    skipped_domains = _normalize_skip_domains(skip_domains)
    if skipped_domains:
        before_count = len(check_domains)
        check_domains = [
            domain for domain in check_domains if domain not in skipped_domains
        ]
        logger.info(
            "Skipped domains already covered by broader rules: %d",
            before_count - len(check_domains),
        )
    logger.info("Prune candidates: %d", len(check_domains))

    resolver_groups = resolve_resolver_groups(
        request,
        log_warnings=log_resolver_warnings,
    )
    probe_policy = build_probe_policy(request, *resolver_groups)
    cache_path = io.cache_file
    cache_load_result = (
        load_cache(cache_path, probe_policy=probe_policy)
        if cache_path
        else CacheLoadResult(entries={}, state="disabled")
    )
    cache = cache_load_result.entries
    logger.info(
        "Cache loaded: state=%s entries=%d",
        cache_load_result.state,
        len(cache),
    )
    return PruneSnapshot(
        input_path=input_path,
        output_path=io.output or input_path,
        cache_path=cache_path,
        removed_log_path=io.removed_log,
        lines=lines,
        check_domains=check_domains,
        resolver_list=resolver_groups[0],
        resolver_cn_list=resolver_groups[1],
        resolver_global_list=resolver_groups[2],
        probe_policy=probe_policy,
        cache=cache,
        started_at=_now_ts(),
    )


def _evaluate_resolver_health(
    snapshot: PruneSnapshot,
    request: PruneRequest,
) -> Union[ResolverHealth, PruneExecutionResult]:
    """Health-check resolver groups and enforce the configured quorum policy."""

    execution = request.execution
    resolver_policy = request.resolvers
    probe = request.probe
    query = probe.query
    if not snapshot.resolver_list:
        if execution.require_dead_capable:
            logger.error("No resolvers configured; strict mode aborts")
            return PruneExecutionResult(3, "failed", "no resolvers configured")
        logger.warning("No resolvers configured; skipping prune")
        return PruneExecutionResult(0, "degraded", "no resolvers configured")

    online_global = healthcheck_group(
        snapshot.resolver_global_list,
        resolver_policy.health_domain,
        query.timeout_ms,
        query.retries,
        parallel=True,
        concurrency=probe.global_probe.concurrency,
    )
    online_cn = healthcheck_group(
        snapshot.resolver_cn_list,
        resolver_policy.health_domain,
        query.timeout_ms,
        query.retries,
        parallel=True,
        concurrency=probe.cn_probe.concurrency,
    )
    online_resolvers = list(dict.fromkeys(online_global + online_cn))
    logger.info(
        "Healthy resolvers: cn=%s global=%s",
        ",".join(online_cn) or "-",
        ",".join(online_global) or "-",
    )

    required_resolvers = max(1, resolver_policy.min_online_resolvers)
    if len(online_resolvers) < required_resolvers:
        if execution.require_dead_capable:
            logger.error(
                "Too few healthy resolvers (%d/%d); strict mode aborts",
                len(online_resolvers),
                required_resolvers,
            )
            return PruneExecutionResult(3, "failed", "too few healthy resolvers")
        logger.warning(
            "Too few healthy resolvers (%d); skipping prune",
            len(online_resolvers),
        )
        return PruneExecutionResult(
            0,
            "degraded",
            "too few healthy resolvers; prune skipped",
        )

    min_cn = max(1, resolver_policy.min_online_resolvers_cn)
    min_global = max(1, resolver_policy.min_online_resolvers_global)
    allow_dead = len(online_cn) >= min_cn and len(online_global) >= min_global
    degraded_reason = ""
    if not allow_dead:
        logger.warning(
            "Healthy resolvers below minimum (cn=%d/%d global=%d/%d); "
            "disabling dead classification and deletion",
            len(online_cn),
            min_cn,
            len(online_global),
            min_global,
        )
        if execution.require_dead_capable:
            logger.error(
                "Strict mode requires dead classification; current resolver "
                "health is insufficient"
            )
            return PruneExecutionResult(
                4,
                "failed",
                "resolver health cannot support dead classification",
            )
        degraded_reason = "resolver health cannot support dead classification"

    return ResolverHealth(
        global_resolvers=tuple(online_global),
        cn_resolvers=tuple(online_cn),
        allow_dead=allow_dead,
        min_online_cn=min_cn,
        degraded_reason=degraded_reason,
    )


def _plan_probe_targets(
    snapshot: PruneSnapshot,
    request: PruneRequest,
) -> ProbePlan:
    """Build and report the cache-aware probe allocation for one run."""

    budget = request.probe.budget
    cache_ttl = request.cache_ttl
    plan = _choose_probe_targets(
        domains=snapshot.check_domains,
        cache=snapshot.cache,
        now_ts=snapshot.started_at,
        budget=budget.budget,
        new_budget=budget.new_budget,
        recheck_budget=budget.recheck_budget,
        ttl_alive_days=cache_ttl.ttl_alive_days,
        ttl_dead_days=cache_ttl.ttl_dead_days,
        ttl_unknown_days=cache_ttl.ttl_unknown_days,
        ttl_dead_recheck_days=cache_ttl.ttl_dead_recheck_days,
    )
    logger.info(
        "Cache classification: new=%d fresh_alive=%d fresh_dead=%d "
        "fresh_unknown=%d dead_due_recheck=%d stale_other=%d",
        plan.new_candidate_count,
        plan.fresh_alive_count,
        plan.fresh_dead_count,
        plan.fresh_unknown_count,
        plan.dead_recheck_candidate_count,
        plan.stale_candidate_count,
    )
    logger.info(
        "Probe allocation: targets=%d budget=%d new=%d dead-recheck=%d "
        "stale=%d overflow=%d deferred-dead=%d",
        len(plan.targets),
        budget.budget,
        plan.new_count,
        plan.dead_recheck_count,
        plan.stale_recheck_count,
        plan.overflow_count,
        max(0, plan.dead_recheck_candidate_count - plan.dead_recheck_count),
    )
    return plan


def _execute_probe_plan(
    snapshot: PruneSnapshot,
    request: PruneRequest,
    health: ResolverHealth,
    plan: ProbePlan,
) -> ProbeOutcome:
    """Execute one allocation and merge observations into the loaded cache."""

    probed_domains: Set[str] = set()
    preserved_cache_entries = 0
    if plan.targets:
        probe = request.probe
        observed_entries, probed_domains = run_two_round_probes(
            plan.targets,
            health.global_resolvers,
            health.cn_resolvers,
            ProbeExecutionSettings(
                query=probe.query,
                global_probe=probe.global_probe,
                cn_probe=probe.cn_probe,
                allow_dead=health.allow_dead,
                min_online_cn=health.min_online_cn,
            ),
        )
        for domain, entry in observed_entries.items():
            merged_entry, preserved_existing = _merge_cache_entry(
                existing=snapshot.cache.get(domain),
                observed=entry,
                allow_dead=health.allow_dead,
            )
            snapshot.cache[domain] = merged_entry
            if preserved_existing:
                preserved_cache_entries += 1

    return ProbeOutcome(
        allow_dead=health.allow_dead,
        rechecked_domains=probed_domains,
        degraded_reason=health.degraded_reason,
        preserved_cache_entries=preserved_cache_entries,
    )


def _run_probe_strategy(
    snapshot: PruneSnapshot,
    request: PruneRequest,
) -> Union[ProbeOutcome, PruneExecutionResult]:
    """Apply health policy, plan cache work, and execute the resulting probes."""

    health = _evaluate_resolver_health(snapshot, request)
    if isinstance(health, PruneExecutionResult):
        return health
    plan = _plan_probe_targets(snapshot, request)
    return _execute_probe_plan(snapshot, request, health, plan)


def _commit_prune(
    snapshot: PruneSnapshot,
    request: PruneRequest,
    outcome: ProbeOutcome,
) -> PruneExecutionResult:
    """Apply one strategy outcome and atomically publish its artifacts."""

    cache_ttl = request.cache_ttl
    inactive_result = select_reusable_inactive_domains(
        snapshot.cache,
        active_domains=snapshot.check_domains,
        ttl_policy=cache_ttl,
        now_ts=_now_ts(),
        rechecked_domains=outcome.rechecked_domains,
    )
    if not outcome.allow_dead:
        inactive_result = InactiveDomainSelection(
            inactive={},
            reusable_count=0,
            blocked_pending_recheck_count=0,
            cache_state=inactive_result.cache_state,
        )
    kept_lines, removed_rules, removed_log_lines = _filter_dead_rules(
        snapshot.lines,
        inactive_result.inactive,
    )
    logger.info(
        "Rule cleanup: %d -> %d (-%d)",
        len(snapshot.lines),
        len(kept_lines),
        len(removed_rules),
    )
    logger.info(
        "Dead-cache reuse: reusable=%d blocked_pending_recheck=%d",
        inactive_result.reusable_count,
        inactive_result.blocked_pending_recheck_count,
    )
    if outcome.preserved_cache_entries > 0:
        logger.info(
            "Degraded-mode cache protection: preserved=%d",
            outcome.preserved_cache_entries,
        )
    logger.info(
        "Inactive domains eligible for removal: %d",
        len(inactive_result.inactive),
    )

    status = "degraded" if outcome.degraded_reason else "success"
    if request.execution.dry_run:
        return PruneExecutionResult(0, status, outcome.degraded_reason)

    output_targets = {
        snapshot.output_path: "\n".join(kept_lines)
        + ("\n" if kept_lines else "")
    }
    if snapshot.removed_log_path:
        output_targets[snapshot.removed_log_path] = "\n".join(
            removed_log_lines
        ) + ("\n" if removed_log_lines else "")
    if outcome.write_cache and snapshot.cache_path:
        output_targets[snapshot.cache_path] = render_cache(
            snapshot.cache,
            active_domains=snapshot.check_domains,
            probe_policy=snapshot.probe_policy,
        )
    atomic_write_text_bundle(output_targets)
    return PruneExecutionResult(0, status, outcome.degraded_reason)


def run_prune_detailed(
    request: PruneRequest,
    skip_domains: Optional[Iterable[str]] = (),
    *,
    mode: DnsPolicyMode = DnsPolicyMode.PROBE,
) -> PruneExecutionResult:
    """Run one prune transaction using a validated request.

    ``skip_domains`` is the stage boundary used by the DNS orchestrator.  It
    avoids serializing coverage results through a temporary file.
    """

    if request.execution.print_policy_fingerprint:
        resolver_groups = resolve_resolver_groups(request, log_warnings=False)
        if not resolver_groups[1] or not resolver_groups[2]:
            logger.error(
                "DNS prune policy requires non-empty CN and GLOBAL resolver groups"
            )
            return PruneExecutionResult(
                2,
                "failed",
                "resolver groups are incomplete",
            )
        probe_policy = build_probe_policy(request, *resolver_groups)
        print(probe_policy.fingerprint())
        return PruneExecutionResult(0, "success")

    if mode is DnsPolicyMode.COVERAGE_ONLY:
        raise ValueError("coverage-only mode does not run a prune transaction")

    if request.execution.remove_nodata and mode is DnsPolicyMode.PROBE:
        logger.warning(
            "Ignoring --remove-nodata; only GLOBAL+CN NXDOMAIN/no-NS checks are supported"
        )

    prepared = _prepare_prune_snapshot(
        request,
        skip_domains,
        log_resolver_warnings=mode is DnsPolicyMode.PROBE,
    )
    if isinstance(prepared, PruneExecutionResult):
        return prepared

    if mode is DnsPolicyMode.CACHE_ONLY:
        outcome: Union[ProbeOutcome, PruneExecutionResult] = ProbeOutcome(
            allow_dead=True,
            rechecked_domains=set(),
            write_cache=False,
        )
    else:
        outcome = _run_probe_strategy(prepared, request)
    if isinstance(outcome, PruneExecutionResult):
        return outcome
    return _commit_prune(prepared, request, outcome)


def run_prune(
    request: PruneRequest,
    skip_domains: Optional[Iterable[str]] = (),
) -> int:
    """Run pruning and retain the historical integer return-code API."""

    return run_prune_detailed(request, skip_domains=skip_domains).exit_code


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        from logging_utils import configure_logging
    except ImportError:  # Support ``python -m script.dns_prune``.
        from .logging_utils import configure_logging  # type: ignore[no-redef]

    configure_logging()
    args = parse_args(argv, environment=os.environ)
    return run_prune(request_from_args(args))


if __name__ == "__main__":
    raise SystemExit(main())
