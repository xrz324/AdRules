"""CLI and resolver policy configuration for DNS pruning."""

from __future__ import annotations

import argparse
import logging
from typing import List, Mapping, Optional, Sequence, Set, Tuple

try:
    from .dns_prune_model import (
        DEFAULT_CN_BACKOFF_BASE_MS,
        DEFAULT_CN_BACKOFF_MAX_MS,
        DEFAULT_CN_COOLDOWN_MS,
        DEFAULT_CN_FAILURE_THRESHOLD,
        DEFAULT_CN_MAX_RETRIES,
        DEFAULT_CN_QUERY_DELAY_MS,
        DEFAULT_CN_SLOW_THRESHOLD_MS,
        DEFAULT_RESOLVERS_CN,
        DEFAULT_RESOLVERS_GLOBAL,
        PROBE_POLICY_VERSION,
        ProbePolicy,
    )
except ImportError:  # Support direct script execution.
    from dns_prune_model import (  # type: ignore[no-redef]
        DEFAULT_CN_BACKOFF_BASE_MS,
        DEFAULT_CN_BACKOFF_MAX_MS,
        DEFAULT_CN_COOLDOWN_MS,
        DEFAULT_CN_FAILURE_THRESHOLD,
        DEFAULT_CN_MAX_RETRIES,
        DEFAULT_CN_QUERY_DELAY_MS,
        DEFAULT_CN_SLOW_THRESHOLD_MS,
        DEFAULT_RESOLVERS_CN,
        DEFAULT_RESOLVERS_GLOBAL,
        PROBE_POLICY_VERSION,
        ProbePolicy,
    )


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


def parse_args(
    argv: Optional[Sequence[str]] = None,
    *,
    environment: Mapping[str, str],
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prune inactive domains in DNS ABP rules."
    )
    parser.add_argument("--input", help="Path to dns rules file")
    parser.add_argument("--output", help="Output path (default: in-place)")
    parser.add_argument(
        "--cache",
        default=_env_value(environment, "DNS_PRUNE_CACHE_FILE"),
        help="Cache file path (json)",
    )
    parser.add_argument(
        "--removed-log",
        default=_env_value(environment, "DNS_PRUNE_REMOVED_LOG"),
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
        default=parse_bool(_env_value(environment, "STRICT_DNS_PRUNE", "false")),
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
        default=_env_value_preserve_empty(
            environment, "DNS_PRUNE_RESOLVERS_CN", ",".join(DEFAULT_RESOLVERS_CN)
        ),
        help="Comma-separated CN resolvers",
    )
    parser.add_argument(
        "--resolvers-global",
        default=_env_value_preserve_empty(
            environment,
            "DNS_PRUNE_RESOLVERS_GLOBAL",
            ",".join(DEFAULT_RESOLVERS_GLOBAL),
        ),
        help="Comma-separated GLOBAL resolvers",
    )
    parser.add_argument(
        "--health-domain",
        default=_env_value(environment, "DNS_PRUNE_HEALTH_DOMAIN", "example.com"),
        help="Resolver health check domain",
    )
    parser.add_argument(
        "--min-online-resolvers",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_MIN_ONLINE_RESOLVERS", 2, environment
        ),
        help="Minimum online resolvers to enable pruning",
    )
    parser.add_argument(
        "--min-online-resolvers-cn",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_MIN_ONLINE_RESOLVERS_CN", 2, environment
        ),
        help="Minimum online CN resolvers to enable dead classification and deletion (default: 2)",
    )
    parser.add_argument(
        "--min-online-resolvers-global",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_MIN_ONLINE_RESOLVERS_GLOBAL", 2, environment
        ),
        help="Minimum online global resolvers to enable dead classification and deletion (default: 2)",
    )

    parser.add_argument(
        "--budget",
        type=int,
        default=_env_int_default("DNS_PRUNE_BUDGET", 5000, environment),
        help="Max domains to probe this run (0=unlimited)",
    )
    parser.add_argument(
        "--new-budget",
        type=int,
        default=_env_int_default("DNS_PRUNE_NEW_BUDGET", 0, environment),
        help="Budget reserved for never-probed domains (0=auto)",
    )
    parser.add_argument(
        "--recheck-budget",
        type=int,
        default=_env_int_default("DNS_PRUNE_RECHECK_BUDGET", 0, environment),
        help="Budget reserved for expired cache rechecks (0=auto)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=_env_int_default("DNS_PRUNE_CONCURRENCY", 128, environment),
        help="Fallback worker threads for probe stages",
    )
    parser.add_argument(
        "--global-concurrency",
        type=int,
        default=_env_int_default("DNS_PRUNE_GLOBAL_CONCURRENCY", 0, environment),
        help="GLOBAL worker threads (0=one worker per target, capped for safety)",
    )
    parser.add_argument(
        "--inflight-per-resolver",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_INFLIGHT_PER_RESOLVER", 1, environment
        ),
        help="Per-window in-flight cap for CN resolver queries (normally one)",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=_env_int_default("DNS_PRUNE_TIMEOUT_MS", 800, environment),
        help="Per DNS query timeout in ms",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=_env_int_default("DNS_PRUNE_RETRIES", 1, environment),
        help="Retry times on timeout/error",
    )
    parser.add_argument(
        "--jitter-ms",
        type=int,
        default=_env_int_default("DNS_PRUNE_JITTER_MS", 10, environment),
        help="Random jitter before query (ms)",
    )
    parser.add_argument(
        "--cn-query-delay-ms",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_CN_QUERY_DELAY_MS", DEFAULT_CN_QUERY_DELAY_MS, environment
        ),
        help="Base delay between queries in each independent CN window (ms)",
    )
    parser.add_argument(
        "--cn-backoff-base-ms",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_CN_BACKOFF_BASE_MS", DEFAULT_CN_BACKOFF_BASE_MS, environment
        ),
        help="Base exponential backoff after a slow/failed query in one CN window (ms)",
    )
    parser.add_argument(
        "--cn-backoff-max-ms",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_CN_BACKOFF_MAX_MS", DEFAULT_CN_BACKOFF_MAX_MS, environment
        ),
        help="Maximum additional backoff for one CN window (ms; 0=unlimited)",
    )
    parser.add_argument(
        "--cn-failure-threshold",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_CN_FAILURE_THRESHOLD",
            DEFAULT_CN_FAILURE_THRESHOLD,
            environment,
        ),
        help="Consecutive slow/failed probes before pausing one CN window",
    )
    parser.add_argument(
        "--cn-cooldown-ms",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_CN_COOLDOWN_MS", DEFAULT_CN_COOLDOWN_MS, environment
        ),
        help="Cooldown before a paused CN window accepts work again (ms)",
    )
    parser.add_argument(
        "--cn-slow-threshold-ms",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_CN_SLOW_THRESHOLD_MS", DEFAULT_CN_SLOW_THRESHOLD_MS, environment
        ),
        help="Latency counted as extremely slow for CN health tracking (ms)",
    )
    parser.add_argument(
        "--cn-max-retries",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_CN_MAX_RETRIES", DEFAULT_CN_MAX_RETRIES, environment
        ),
        help="Maximum retries for timeout/slow observations in the CN queue",
    )
    parser.add_argument(
        "--global-inflight-per-resolver",
        type=int,
        default=_env_int_default("DNS_PRUNE_GLOBAL_INFLIGHT_PER_RESOLVER", 0, environment),
        help="GLOBAL per-resolver in-flight cap (0=unlimited)",
    )
    parser.add_argument(
        "--remove-nodata",
        type=str,
        default=_env_value(environment, "DNS_PRUNE_REMOVE_NODATA", "false"),
        help="Deprecated; only the GLOBAL+CN NXDOMAIN/no-NS combination is accepted",
    )

    parser.add_argument(
        "--ttl-alive-days",
        type=int,
        default=_env_int_default("DNS_PRUNE_TTL_ALIVE_DAYS", 14, environment),
    )
    parser.add_argument(
        "--ttl-dead-days",
        type=int,
        default=_env_int_default("DNS_PRUNE_TTL_DEAD_DAYS", 30, environment),
    )
    parser.add_argument(
        "--ttl-unknown-days",
        type=int,
        default=_env_int_default("DNS_PRUNE_TTL_UNKNOWN_DAYS", 1, environment),
    )
    parser.add_argument(
        "--ttl-dead-recheck-days",
        type=int,
        default=_env_int_default(
            "DNS_PRUNE_TTL_DEAD_RECHECK_DAYS", 7, environment
        ),
        help="Recheck dead cache after N days even if dead TTL has not expired (0=disable)",
    )

    args = parser.parse_args(argv)
    if not args.print_policy_fingerprint and not args.input:
        parser.error("--input is required unless --print-policy-fingerprint is used")
    return args


def build_probe_policy(
    args: argparse.Namespace,
    resolver_list: Sequence[str],
    resolver_cn_list: Sequence[str],
    resolver_global_list: Sequence[str],
) -> ProbePolicy:
    return ProbePolicy(
        version=PROBE_POLICY_VERSION,
        resolvers=tuple(resolver_list),
        resolvers_cn=tuple(resolver_cn_list),
        resolvers_global=tuple(resolver_global_list),
        health_domain=str(args.health_domain).strip().lower(),
        min_online_resolvers=max(1, int(args.min_online_resolvers)),
        min_online_resolvers_cn=max(1, int(args.min_online_resolvers_cn)),
        min_online_resolvers_global=max(1, int(args.min_online_resolvers_global)),
        timeout_ms=int(args.timeout_ms),
        retries=int(args.retries),
        cn_query_delay_ms=max(
            0,
            int(getattr(args, "cn_query_delay_ms", DEFAULT_CN_QUERY_DELAY_MS)),
        ),
        cn_backoff_base_ms=max(
            0,
            int(getattr(args, "cn_backoff_base_ms", DEFAULT_CN_BACKOFF_BASE_MS)),
        ),
        cn_backoff_max_ms=max(
            0,
            int(getattr(args, "cn_backoff_max_ms", DEFAULT_CN_BACKOFF_MAX_MS)),
        ),
        cn_failure_threshold=max(
            1,
            int(
                getattr(
                    args,
                    "cn_failure_threshold",
                    DEFAULT_CN_FAILURE_THRESHOLD,
                )
            ),
        ),
        cn_cooldown_ms=max(
            0,
            int(getattr(args, "cn_cooldown_ms", DEFAULT_CN_COOLDOWN_MS)),
        ),
        cn_slow_threshold_ms=max(
            0,
            int(getattr(args, "cn_slow_threshold_ms", DEFAULT_CN_SLOW_THRESHOLD_MS)),
        ),
        cn_max_retries=max(
            0,
            int(getattr(args, "cn_max_retries", DEFAULT_CN_MAX_RETRIES)),
        ),
        global_inflight_per_resolver=max(
            0,
            int(getattr(args, "global_inflight_per_resolver", 0)),
        ),
    )


def resolve_resolver_groups(
    args: argparse.Namespace,
    log_warnings: bool = True,
) -> Tuple[List[str], List[str], List[str]]:
    """Normalize resolver lists exactly once for probing and fingerprinting."""
    resolver_cn_list = _dedupe_resolvers(_parse_resolvers_csv(args.resolvers_cn))
    resolver_global_list = _dedupe_resolvers(_parse_resolvers_csv(args.resolvers_global))
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
