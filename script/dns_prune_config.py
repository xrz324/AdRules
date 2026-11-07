"""CLI and resolver policy configuration for DNS pruning."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple

try:
    from .dns_prune_model import (
        DEFAULT_BUDGET,
        DEFAULT_CN_BACKOFF_BASE_MS,
        DEFAULT_CN_BACKOFF_MAX_MS,
        DEFAULT_CN_COOLDOWN_MS,
        DEFAULT_CN_FAILURE_THRESHOLD,
        DEFAULT_CN_MAX_RETRIES,
        DEFAULT_CN_QUERY_DELAY_MS,
        DEFAULT_CN_SLOW_THRESHOLD_MS,
        DEFAULT_CONCURRENCY,
        DEFAULT_GLOBAL_CONCURRENCY,
        DEFAULT_GLOBAL_INFLIGHT_PER_RESOLVER,
        DEFAULT_INFLIGHT_PER_RESOLVER,
        DEFAULT_JITTER_MS,
        DEFAULT_MIN_ONLINE_RESOLVERS,
        DEFAULT_MIN_ONLINE_RESOLVERS_CN,
        DEFAULT_MIN_ONLINE_RESOLVERS_GLOBAL,
        DEFAULT_NEW_BUDGET,
        DEFAULT_RECHECK_BUDGET,
        DEFAULT_RESOLVERS_CN,
        DEFAULT_RESOLVERS_GLOBAL,
        DEFAULT_RETRIES,
        DEFAULT_TIMEOUT_MS,
        DEFAULT_TTL_ALIVE_DAYS,
        DEFAULT_TTL_DEAD_DAYS,
        DEFAULT_TTL_DEAD_RECHECK_DAYS,
        DEFAULT_TTL_UNKNOWN_DAYS,
        PROBE_POLICY_VERSION,
        CnProbeSettings,
        DnsQuerySettings,
        GlobalProbeSettings,
        ProbeBudget,
        ProbeSettings,
        ProbePolicy,
        PruneExecutionPolicy,
        PruneIO,
        PruneRequest,
        ResolverPolicy,
    )
    from .inactive_domain_model import CacheReusePolicy, CacheTtlPolicy
except ImportError:  # Support direct script execution.
    from dns_prune_model import (  # type: ignore[no-redef]
        DEFAULT_BUDGET,
        DEFAULT_CN_BACKOFF_BASE_MS,
        DEFAULT_CN_BACKOFF_MAX_MS,
        DEFAULT_CN_COOLDOWN_MS,
        DEFAULT_CN_FAILURE_THRESHOLD,
        DEFAULT_CN_MAX_RETRIES,
        DEFAULT_CN_QUERY_DELAY_MS,
        DEFAULT_CN_SLOW_THRESHOLD_MS,
        DEFAULT_CONCURRENCY,
        DEFAULT_GLOBAL_CONCURRENCY,
        DEFAULT_GLOBAL_INFLIGHT_PER_RESOLVER,
        DEFAULT_INFLIGHT_PER_RESOLVER,
        DEFAULT_JITTER_MS,
        DEFAULT_MIN_ONLINE_RESOLVERS,
        DEFAULT_MIN_ONLINE_RESOLVERS_CN,
        DEFAULT_MIN_ONLINE_RESOLVERS_GLOBAL,
        DEFAULT_NEW_BUDGET,
        DEFAULT_RECHECK_BUDGET,
        DEFAULT_RESOLVERS_CN,
        DEFAULT_RESOLVERS_GLOBAL,
        DEFAULT_RETRIES,
        DEFAULT_TIMEOUT_MS,
        DEFAULT_TTL_ALIVE_DAYS,
        DEFAULT_TTL_DEAD_DAYS,
        DEFAULT_TTL_DEAD_RECHECK_DAYS,
        DEFAULT_TTL_UNKNOWN_DAYS,
        PROBE_POLICY_VERSION,
        CnProbeSettings,
        DnsQuerySettings,
        GlobalProbeSettings,
        ProbeBudget,
        ProbeSettings,
        ProbePolicy,
        PruneExecutionPolicy,
        PruneIO,
        PruneRequest,
        ResolverPolicy,
    )
    from inactive_domain_model import CacheReusePolicy, CacheTtlPolicy


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

def parse_bool(value: str) -> bool:
    v = (value or "").strip().lower()
    return v in {"1", "true", "yes", "y", "on"}


def _env_value(
    environment: Mapping[str, str], name: str, default: str = ""
) -> str:
    """Read one policy value from the explicit runtime environment."""

    value = environment.get(name, default)
    return str(value).strip() or default


def _env_value_preserve_empty(
    environment: Mapping[str, str], name: str, default: str = ""
) -> str:
    """Use a default only when the variable is absent, not when it is empty."""

    if name not in environment:
        return default
    return str(environment.get(name, "")).strip()


def _env_int_default(
    name: str, default: int, environment: Mapping[str, str]
) -> str:
    """Return a non-empty environment value for an integer CLI default."""

    return _env_value(environment, name, str(default))


def _parse_resolvers_csv(value: str) -> List[str]:
    return [r.strip() for r in str(value).split(",") if r.strip()]


def _dedupe_resolvers(items: Sequence[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _request_defaults(environment: Mapping[str, str]) -> Dict[str, object]:
    """Return the shared environment-derived defaults for all adapters."""

    return {
        "input": None,
        "output": None,
        "cache": _env_value(
            environment, "DNS_PRUNE_CACHE_FILE", "dns_prune_cache.json"
        ),
        "removed_log": _env_value(
            environment,
            "DNS_PRUNE_REMOVED_LOG",
            "tmp/dns_prune_removed_rules.txt",
        ),
        "dry_run": False,
        "print_policy_fingerprint": False,
        "require_dead_capable": parse_bool(
            _env_value(environment, "STRICT_DNS_PRUNE", "false")
        ),
        "resolvers_cn": _env_value_preserve_empty(
            environment, "DNS_PRUNE_RESOLVERS_CN", ",".join(DEFAULT_RESOLVERS_CN)
        ),
        "resolvers_global": _env_value_preserve_empty(
            environment,
            "DNS_PRUNE_RESOLVERS_GLOBAL",
            ",".join(DEFAULT_RESOLVERS_GLOBAL),
        ),
        "health_domain": _env_value(
            environment, "DNS_PRUNE_HEALTH_DOMAIN", "example.com"
        ),
        "min_online_resolvers": _env_int_default(
            "DNS_PRUNE_MIN_ONLINE_RESOLVERS",
            DEFAULT_MIN_ONLINE_RESOLVERS,
            environment,
        ),
        "min_online_resolvers_cn": _env_int_default(
            "DNS_PRUNE_MIN_ONLINE_RESOLVERS_CN",
            DEFAULT_MIN_ONLINE_RESOLVERS_CN,
            environment,
        ),
        "min_online_resolvers_global": _env_int_default(
            "DNS_PRUNE_MIN_ONLINE_RESOLVERS_GLOBAL",
            DEFAULT_MIN_ONLINE_RESOLVERS_GLOBAL,
            environment,
        ),
        "budget": _env_int_default("DNS_PRUNE_BUDGET", DEFAULT_BUDGET, environment),
        "new_budget": _env_int_default(
            "DNS_PRUNE_NEW_BUDGET", DEFAULT_NEW_BUDGET, environment
        ),
        "recheck_budget": _env_int_default(
            "DNS_PRUNE_RECHECK_BUDGET", DEFAULT_RECHECK_BUDGET, environment
        ),
        "concurrency": _env_int_default(
            "DNS_PRUNE_CONCURRENCY", DEFAULT_CONCURRENCY, environment
        ),
        "global_concurrency": _env_int_default(
            "DNS_PRUNE_GLOBAL_CONCURRENCY", DEFAULT_GLOBAL_CONCURRENCY, environment
        ),
        "inflight_per_resolver": _env_int_default(
            "DNS_PRUNE_INFLIGHT_PER_RESOLVER",
            DEFAULT_INFLIGHT_PER_RESOLVER,
            environment,
        ),
        "timeout_ms": _env_int_default(
            "DNS_PRUNE_TIMEOUT_MS", DEFAULT_TIMEOUT_MS, environment
        ),
        "retries": _env_int_default("DNS_PRUNE_RETRIES", DEFAULT_RETRIES, environment),
        "jitter_ms": _env_int_default(
            "DNS_PRUNE_JITTER_MS", DEFAULT_JITTER_MS, environment
        ),
        "cn_query_delay_ms": _env_int_default(
            "DNS_PRUNE_CN_QUERY_DELAY_MS", DEFAULT_CN_QUERY_DELAY_MS, environment
        ),
        "cn_backoff_base_ms": _env_int_default(
            "DNS_PRUNE_CN_BACKOFF_BASE_MS", DEFAULT_CN_BACKOFF_BASE_MS, environment
        ),
        "cn_backoff_max_ms": _env_int_default(
            "DNS_PRUNE_CN_BACKOFF_MAX_MS", DEFAULT_CN_BACKOFF_MAX_MS, environment
        ),
        "cn_failure_threshold": _env_int_default(
            "DNS_PRUNE_CN_FAILURE_THRESHOLD",
            DEFAULT_CN_FAILURE_THRESHOLD,
            environment,
        ),
        "cn_cooldown_ms": _env_int_default(
            "DNS_PRUNE_CN_COOLDOWN_MS", DEFAULT_CN_COOLDOWN_MS, environment
        ),
        "cn_slow_threshold_ms": _env_int_default(
            "DNS_PRUNE_CN_SLOW_THRESHOLD_MS", DEFAULT_CN_SLOW_THRESHOLD_MS, environment
        ),
        "cn_max_retries": _env_int_default(
            "DNS_PRUNE_CN_MAX_RETRIES", DEFAULT_CN_MAX_RETRIES, environment
        ),
        "global_inflight_per_resolver": _env_int_default(
            "DNS_PRUNE_GLOBAL_INFLIGHT_PER_RESOLVER",
            DEFAULT_GLOBAL_INFLIGHT_PER_RESOLVER,
            environment,
        ),
        "remove_nodata": _env_value(
            environment, "DNS_PRUNE_REMOVE_NODATA", "false"
        ),
        "ttl_alive_days": _env_int_default(
            "DNS_PRUNE_TTL_ALIVE_DAYS", DEFAULT_TTL_ALIVE_DAYS, environment
        ),
        "ttl_dead_days": _env_int_default(
            "DNS_PRUNE_TTL_DEAD_DAYS", DEFAULT_TTL_DEAD_DAYS, environment
        ),
        "ttl_unknown_days": _env_int_default(
            "DNS_PRUNE_TTL_UNKNOWN_DAYS", DEFAULT_TTL_UNKNOWN_DAYS, environment
        ),
        "ttl_dead_recheck_days": _env_int_default(
            "DNS_PRUNE_TTL_DEAD_RECHECK_DAYS",
            DEFAULT_TTL_DEAD_RECHECK_DAYS,
            environment,
        ),
    }


def _optional_path(value: object) -> Optional[Path]:
    text = str(value or "").strip()
    return Path(text) if text else None


def _request_from_values(values: Mapping[str, object]) -> PruneRequest:
    return PruneRequest(
        io=PruneIO(
            input=_optional_path(values.get("input")),
            output=_optional_path(values.get("output")),
            cache_file=_optional_path(values.get("cache")),
            removed_log=_optional_path(values.get("removed_log")),
        ),
        execution=PruneExecutionPolicy(
            dry_run=bool(values["dry_run"]),
            print_policy_fingerprint=bool(values["print_policy_fingerprint"]),
            require_dead_capable=bool(values["require_dead_capable"]),
            remove_nodata=parse_bool(str(values["remove_nodata"])),
        ),
        resolvers=ResolverPolicy(
            resolvers_cn=tuple(
                _dedupe_resolvers(_parse_resolvers_csv(str(values["resolvers_cn"])))
            ),
            resolvers_global=tuple(
                _dedupe_resolvers(
                    _parse_resolvers_csv(str(values["resolvers_global"]))
                )
            ),
            health_domain=str(values["health_domain"]).strip().lower(),
            min_online_resolvers=int(values["min_online_resolvers"]),
            min_online_resolvers_cn=int(values["min_online_resolvers_cn"]),
            min_online_resolvers_global=int(values["min_online_resolvers_global"]),
        ),
        probe=ProbeSettings(
            budget=ProbeBudget(
                budget=int(values["budget"]),
                new_budget=int(values["new_budget"]),
                recheck_budget=int(values["recheck_budget"]),
            ),
            query=DnsQuerySettings(
                timeout_ms=int(values["timeout_ms"]),
                retries=int(values["retries"]),
            ),
            global_probe=GlobalProbeSettings(
                concurrency=int(values["global_concurrency"]),
                inflight_per_resolver=int(
                    values["global_inflight_per_resolver"]
                ),
            ),
            cn_probe=CnProbeSettings(
                concurrency=int(values["concurrency"]),
                inflight_per_resolver=int(values["inflight_per_resolver"]),
                jitter_ms=int(values["jitter_ms"]),
                query_delay_ms=int(values["cn_query_delay_ms"]),
                backoff_base_ms=int(values["cn_backoff_base_ms"]),
                backoff_max_ms=int(values["cn_backoff_max_ms"]),
                failure_threshold=int(values["cn_failure_threshold"]),
                cooldown_ms=int(values["cn_cooldown_ms"]),
                slow_threshold_ms=int(values["cn_slow_threshold_ms"]),
                max_retries=int(values["cn_max_retries"]),
            ),
        ),
        cache_ttl=CacheTtlPolicy(
            ttl_alive_days=int(values["ttl_alive_days"]),
            ttl_dead_days=int(values["ttl_dead_days"]),
            ttl_unknown_days=int(values["ttl_unknown_days"]),
            ttl_dead_recheck_days=int(values["ttl_dead_recheck_days"]),
        ),
    )


def request_from_args(args: argparse.Namespace) -> PruneRequest:
    """Convert the CLI namespace at the adapter boundary."""

    return _request_from_values(vars(args))


def build_prune_request(
    *,
    environment: Mapping[str, str],
    input_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    cache_path: Optional[Path] = None,
    removed_log_path: Optional[Path] = None,
    require_dead_capable: Optional[bool] = None,
) -> PruneRequest:
    """Build a typed request for an in-process caller without CLI round-tripping."""

    values = _request_defaults(environment)
    values["input"] = input_path
    if output_path is not None:
        values["output"] = output_path
    if cache_path is not None:
        values["cache"] = cache_path
    if removed_log_path is not None:
        values["removed_log"] = removed_log_path
    if require_dead_capable is not None:
        values["require_dead_capable"] = require_dead_capable
    return _request_from_values(values)


def parse_args(
    argv: Optional[Sequence[str]] = None,
    *,
    environment: Mapping[str, str],
) -> argparse.Namespace:
    defaults = _request_defaults(environment)
    parser = argparse.ArgumentParser(
        description="Prune inactive domains in DNS ABP rules."
    )
    parser.add_argument("--input", help="Path to dns rules file")
    parser.add_argument("--output", help="Output path (default: in-place)")
    parser.add_argument(
        "--cache",
        default=defaults["cache"],
        help="Cache file path (json)",
    )
    parser.add_argument(
        "--removed-log",
        default=defaults["removed_log"],
        help="Write removed rules to file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write output/cache",
    )
    parser.add_argument(
        "--print-policy-fingerprint",
        action="store_true",
        help="Print the cache-compatible probe policy fingerprint and exit",
    )
    parser.add_argument(
        "--require-dead-capable",
        dest="require_dead_capable",
        action="store_true",
        default=defaults["require_dead_capable"],
        help="Fail when resolver availability is insufficient for dead classification and deletion",
    )
    parser.add_argument(
        "--no-require-dead-capable",
        dest="require_dead_capable",
        action="store_false",
        help="Override STRICT_DNS_PRUNE and allow a degraded probe run",
    )

    parser.add_argument(
        "--resolvers-cn",
        default=defaults["resolvers_cn"],
        help="Comma-separated CN resolvers",
    )
    parser.add_argument(
        "--resolvers-global",
        default=defaults["resolvers_global"],
        help="Comma-separated GLOBAL resolvers",
    )
    parser.add_argument(
        "--health-domain",
        default=defaults["health_domain"],
        help="Resolver health check domain",
    )
    parser.add_argument(
        "--min-online-resolvers",
        type=int,
        default=defaults["min_online_resolvers"],
        help="Minimum online resolvers to enable pruning",
    )
    parser.add_argument(
        "--min-online-resolvers-cn",
        type=int,
        default=defaults["min_online_resolvers_cn"],
        help="Minimum online CN resolvers to enable dead classification and deletion (default: 2)",
    )
    parser.add_argument(
        "--min-online-resolvers-global",
        type=int,
        default=defaults["min_online_resolvers_global"],
        help="Minimum online global resolvers to enable dead classification and deletion (default: 2)",
    )

    parser.add_argument(
        "--budget",
        type=int,
        default=defaults["budget"],
        help="Max domains to probe this run (0=unlimited)",
    )
    parser.add_argument(
        "--new-budget",
        type=int,
        default=defaults["new_budget"],
        help="Budget reserved for never-probed domains (0=auto)",
    )
    parser.add_argument(
        "--recheck-budget",
        type=int,
        default=defaults["recheck_budget"],
        help="Budget reserved for expired cache rechecks (0=auto)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=defaults["concurrency"],
        help="Fallback worker threads for probe stages",
    )
    parser.add_argument(
        "--global-concurrency",
        type=int,
        default=defaults["global_concurrency"],
        help="GLOBAL worker threads (0=one worker per target, capped for safety)",
    )
    parser.add_argument(
        "--inflight-per-resolver",
        type=int,
        default=defaults["inflight_per_resolver"],
        help="Per-window in-flight cap for CN resolver queries (normally one)",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=defaults["timeout_ms"],
        help="Per DNS query timeout in ms",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=defaults["retries"],
        help="Retry times on timeout/error",
    )
    parser.add_argument(
        "--jitter-ms",
        type=int,
        default=defaults["jitter_ms"],
        help="Random jitter before query (ms)",
    )
    parser.add_argument(
        "--cn-query-delay-ms",
        type=int,
        default=defaults["cn_query_delay_ms"],
        help="Base delay between queries in each independent CN window (ms)",
    )
    parser.add_argument(
        "--cn-backoff-base-ms",
        type=int,
        default=defaults["cn_backoff_base_ms"],
        help="Base exponential backoff after a slow/failed query in one CN window (ms)",
    )
    parser.add_argument(
        "--cn-backoff-max-ms",
        type=int,
        default=defaults["cn_backoff_max_ms"],
        help="Maximum additional backoff for one CN window (ms; 0=unlimited)",
    )
    parser.add_argument(
        "--cn-failure-threshold",
        type=int,
        default=defaults["cn_failure_threshold"],
        help="Consecutive slow/failed probes before pausing one CN window",
    )
    parser.add_argument(
        "--cn-cooldown-ms",
        type=int,
        default=defaults["cn_cooldown_ms"],
        help="Cooldown before a paused CN window accepts work again (ms)",
    )
    parser.add_argument(
        "--cn-slow-threshold-ms",
        type=int,
        default=defaults["cn_slow_threshold_ms"],
        help="Latency counted as extremely slow for CN health tracking (ms)",
    )
    parser.add_argument(
        "--cn-max-retries",
        type=int,
        default=defaults["cn_max_retries"],
        help="Maximum retries for timeout/slow observations in the CN queue",
    )
    parser.add_argument(
        "--global-inflight-per-resolver",
        type=int,
        default=defaults["global_inflight_per_resolver"],
        help="GLOBAL per-resolver in-flight cap (0=unlimited)",
    )
    parser.add_argument(
        "--remove-nodata",
        type=str,
        default=defaults["remove_nodata"],
        help="Deprecated; only the GLOBAL+CN NXDOMAIN/no-NS combination is accepted",
    )

    parser.add_argument(
        "--ttl-alive-days",
        type=int,
        default=defaults["ttl_alive_days"],
    )
    parser.add_argument(
        "--ttl-dead-days",
        type=int,
        default=defaults["ttl_dead_days"],
    )
    parser.add_argument(
        "--ttl-unknown-days",
        type=int,
        default=defaults["ttl_unknown_days"],
    )
    parser.add_argument(
        "--ttl-dead-recheck-days",
        type=int,
        default=defaults["ttl_dead_recheck_days"],
        help="Recheck dead cache after N days even if dead TTL has not expired (0=disable)",
    )

    args = parser.parse_args(argv)
    if not args.print_policy_fingerprint and not args.input:
        parser.error("--input is required unless --print-policy-fingerprint is used")
    return args


def build_probe_policy(
    request: PruneRequest,
    resolver_list: Sequence[str],
    resolver_cn_list: Sequence[str],
    resolver_global_list: Sequence[str],
) -> ProbePolicy:
    resolvers = request.resolvers
    probe = request.probe
    query = probe.query
    cn_probe = probe.cn_probe
    global_probe = probe.global_probe
    return ProbePolicy(
        version=PROBE_POLICY_VERSION,
        resolvers=tuple(resolver_list),
        resolvers_cn=tuple(resolver_cn_list),
        resolvers_global=tuple(resolver_global_list),
        health_domain=resolvers.health_domain,
        min_online_resolvers=max(1, resolvers.min_online_resolvers),
        min_online_resolvers_cn=max(1, resolvers.min_online_resolvers_cn),
        min_online_resolvers_global=max(1, resolvers.min_online_resolvers_global),
        timeout_ms=query.timeout_ms,
        retries=query.retries,
        cn_query_delay_ms=max(
            0,
            cn_probe.query_delay_ms,
        ),
        cn_backoff_base_ms=max(
            0,
            cn_probe.backoff_base_ms,
        ),
        cn_backoff_max_ms=max(
            0,
            cn_probe.backoff_max_ms,
        ),
        cn_failure_threshold=max(
            1,
            cn_probe.failure_threshold,
        ),
        cn_cooldown_ms=max(
            0,
            cn_probe.cooldown_ms,
        ),
        cn_slow_threshold_ms=max(
            0,
            cn_probe.slow_threshold_ms,
        ),
        cn_max_retries=max(
            0,
            cn_probe.max_retries,
        ),
        global_inflight_per_resolver=max(
            0,
            global_probe.inflight_per_resolver,
        ),
    )


def resolve_resolver_groups(
    request: PruneRequest,
    log_warnings: bool = True,
) -> Tuple[List[str], List[str], List[str]]:
    """Normalize resolver lists exactly once for probing and fingerprinting."""
    resolver_cn_list = _dedupe_resolvers(request.resolvers.resolvers_cn)
    resolver_global_list = _dedupe_resolvers(request.resolvers.resolvers_global)
    resolver_list = _dedupe_resolvers(resolver_global_list + resolver_cn_list)

    cn_set = set(resolver_cn_list)
    global_set = set(resolver_global_list)
    overlap = cn_set & global_set
    if overlap:
        if log_warnings:
            logger.warning(
                "Resolver appears in both CN and GLOBAL groups; using GLOBAL: %s",
                ",".join(sorted(overlap)),
            )
        resolver_cn_list = [r for r in resolver_cn_list if r not in overlap]
        cn_set = set(resolver_cn_list)

    if log_warnings and (not resolver_cn_list or not resolver_global_list):
        logger.warning(
            "Resolver groups are incomplete (cn=%d global=%d); configure both groups explicitly",
            len(resolver_cn_list),
            len(resolver_global_list),
        )

    return resolver_list, resolver_cn_list, resolver_global_list


def build_cache_reuse_policy(
    environment: Mapping[str, str],
) -> CacheReusePolicy:
    """Resolve the DNS compatibility and TTL policy for cache-only consumers."""

    request = build_prune_request(
        environment=environment,
    )
    return cache_reuse_policy_from_request(request)


def cache_reuse_policy_from_request(request: PruneRequest) -> CacheReusePolicy:
    """Adapt one already-resolved DNS request to the generic cache contract."""

    resolver_groups = resolve_resolver_groups(request, log_warnings=False)
    return CacheReusePolicy(
        compatibility=build_probe_policy(request, *resolver_groups).to_dict(),
        ttl=request.cache_ttl,
    )
