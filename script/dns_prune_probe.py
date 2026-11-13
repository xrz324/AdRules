"""Resolver probing and two-stage classification for DNS pruning."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import (
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)

try:
    from .dns_prune_model import (
        CacheEntry,
        CnProbeSettings,
        DnsQuerySettings,
        GlobalProbeSettings,
        ResolverProbe,
    )
    from .dns_prune_resolver import QTYPE_A, QTYPE_AAAA, query_with_retries
    from .dns_prune_scheduler import (
        CnWindowSettings,
        EXISTENCE_SIGNAL_STATUSES,
        INACTIVE_SIGNAL_STATUSES,
        ProbeResolver,
        join_reasons,
        run_cn_windows,
    )
except ImportError:  # Support direct script execution.
    from dns_prune_model import (  # type: ignore[no-redef]
        CacheEntry,
        CnProbeSettings,
        DnsQuerySettings,
        GlobalProbeSettings,
        ResolverProbe,
    )
    from dns_prune_resolver import QTYPE_A, QTYPE_AAAA, query_with_retries  # type: ignore[no-redef]
    from dns_prune_scheduler import (  # type: ignore[no-redef]
        CnWindowSettings,
        EXISTENCE_SIGNAL_STATUSES,
        INACTIVE_SIGNAL_STATUSES,
        ProbeResolver,
        join_reasons,
        run_cn_windows,
    )


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
T = TypeVar("T")


def now_ts() -> int:
    return int(time.time())


def _rotate_list(items: Sequence[T], start: int) -> List[T]:
    if not items:
        return []
    size = len(items)
    offset = start % size
    return list(items[offset:]) + list(items[:offset])


@dataclass(frozen=True)
class ProbeExecutionSettings:
    query: DnsQuerySettings
    global_probe: GlobalProbeSettings
    cn_probe: CnProbeSettings
    allow_dead: bool
    min_online_cn: int = 1


def healthcheck_resolver(
    resolver: str,
    health_domain: str,
    timeout_ms: int,
    retries: int,
    retry_backoff_ms: int = 30,
    *,
    query_resolver: Callable[..., object] = query_with_retries,
) -> bool:
    semaphore = threading.BoundedSemaphore(1)
    kind, _ = query_resolver(
        resolver=resolver,
        domain=health_domain,
        qtype=QTYPE_A,
        timeout_ms=timeout_ms,
        retries=retries,
        jitter_ms=0,
        semaphore=semaphore,
        retry_backoff_ms=retry_backoff_ms,
    )
    return kind == "answer"


def probe_single_resolver(
    resolver: str,
    domain: str,
    semaphores: Mapping[str, Optional[threading.BoundedSemaphore]],
    timeout_ms: int,
    retries: int,
    jitter_ms: int,
    retry_backoff_ms: int = 30,
    *,
    query_resolver: Callable[..., object] = query_with_retries,
) -> Tuple[str, str]:
    """
    Returns: (status, reason_fragment)
    - status: alive | nxdomain | no-ns | nodata | error | mixed
    """
    sem = semaphores[resolver]
    kind_a, reply_a = query_resolver(
        resolver=resolver,
        domain=domain,
        qtype=QTYPE_A,
        timeout_ms=timeout_ms,
        retries=retries,
        jitter_ms=jitter_ms,
        semaphore=sem,
        retry_backoff_ms=retry_backoff_ms,
    )

    if kind_a == "answer":
        return "alive", f"{resolver}:A"
    if kind_a == "error":
        return "error", f"{resolver}:A:error"
    if kind_a == "nxdomain":
        return "nxdomain", f"{resolver}:nxdomain"

    # kind_a == nodata，尝试 AAAA，避免误判为仅 IPv6 域名
    kind_aaaa, reply_aaaa = query_resolver(
        resolver=resolver,
        domain=domain,
        qtype=QTYPE_AAAA,
        timeout_ms=timeout_ms,
        retries=retries,
        jitter_ms=jitter_ms,
        semaphore=sem,
        retry_backoff_ms=retry_backoff_ms,
    )
    if kind_aaaa == "answer":
        return "alive", f"{resolver}:AAAA"
    if kind_aaaa == "error":
        return "error", f"{resolver}:AAAA:error"
    if kind_aaaa == "nxdomain":
        return "mixed", f"{resolver}:mixed-a-nodata-aaaa-nxdomain"
    if (
        kind_aaaa == "nodata"
        and reply_a is not None
        and reply_aaaa is not None
        and getattr(reply_a, "nscount", None) == 0
        and getattr(reply_aaaa, "nscount", None) == 0
    ):
        return "no-ns", f"{resolver}:no-ns"
    return "nodata", f"{resolver}:nodata"


def timed_probe_resolver(
    resolver: str,
    domain: str,
    semaphores: Mapping[str, Optional[threading.BoundedSemaphore]],
    timeout_ms: int,
    retries: int,
    jitter_ms: int,
    retry_backoff_ms: int = 30,
) -> ResolverProbe:
    """Run one resolver probe and retain latency for CN health decisions."""

    started = time.monotonic()
    try:
        status, reason = probe_single_resolver(
            resolver=resolver,
            domain=domain,
            semaphores=semaphores,
            timeout_ms=timeout_ms,
            retries=retries,
            jitter_ms=jitter_ms,
            retry_backoff_ms=retry_backoff_ms,
        )
    except Exception as exc:  # noqa: BLE001 - one bad resolver must not abort a run.
        status = "error"
        reason = f"{resolver}:exception:{type(exc).__name__}"
    elapsed_ms = max(0.0, (time.monotonic() - started) * 1000.0)
    return ResolverProbe(
        resolver=resolver,
        status=status,
        reason=reason,
        elapsed_ms=elapsed_ms,
    )


def _balanced_assignments(
    domains: Sequence[str],
    resolvers: Sequence[str],
    start: int = 0,
) -> List[Tuple[str, str]]:
    """Assign at most one domain per resolver in deterministic round-robin order."""

    if not domains or not resolvers:
        return []
    rotated = _rotate_list(resolvers, start)
    return [
        (domain, rotated[index % len(rotated)])
        for index, domain in enumerate(domains)
    ]


def _global_worker_count(configured: int, target_count: int) -> int:
    """Resolve GLOBAL worker count while preventing an accidental thread storm."""

    if target_count <= 0:
        return 1
    if configured <= 0:
        # ``0`` means unlimited from the policy perspective.  A finite safety
        # ceiling protects a runner when a malformed input contains millions
        # of domains while still removing any per-provider rate limit.
        return min(target_count, 512)
    return min(target_count, max(1, configured))


def run_global_round(
    domains: Sequence[str],
    resolvers: Sequence[str],
    timeout_ms: int,
    retries: int,
    global_concurrency: int,
    global_inflight_per_resolver: int,
    *,
    probe_resolver: ProbeResolver = timed_probe_resolver,
) -> Dict[str, ResolverProbe]:
    """Probe every target once through a balanced GLOBAL resolver round."""

    if not domains:
        return {}

    if not resolvers:
        return {
            domain: ResolverProbe(
                resolver="",
                status="error",
                reason="no-global-resolvers",
                elapsed_ms=0.0,
            )
            for domain in domains
        }

    assignments = _balanced_assignments(domains, resolvers)
    if global_inflight_per_resolver > 0:
        semaphores: Dict[str, Optional[threading.BoundedSemaphore]] = {
            resolver: threading.BoundedSemaphore(global_inflight_per_resolver)
            for resolver in resolvers
        }
    else:
        # No semaphore is the important distinction from the CN stage.
        semaphores = {resolver: None for resolver in resolvers}

    observations: Dict[str, ResolverProbe] = {}
    workers = _global_worker_count(global_concurrency, len(assignments))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                probe_resolver,
                resolver,
                domain,
                semaphores,
                timeout_ms,
                retries,
                0,  # GLOBAL has no pacing jitter.
                0,  # GLOBAL retries are also not paced.
            ): domain
            for domain, resolver in assignments
        }
        for future in as_completed(futures):
            domain = futures[future]
            try:
                observation = future.result()
                if not isinstance(observation, ResolverProbe):
                    raise TypeError("resolver probe returned an invalid observation")
                observations[domain] = observation
            except Exception as exc:  # pragma: no cover - defensive executor guard.
                observations[domain] = ResolverProbe(
                    resolver="",
                    status="error",
                    reason=f"global-exception:{type(exc).__name__}",
                    elapsed_ms=0.0,
                )

    counts: Dict[str, int] = {}
    for observation in observations.values():
        counts[observation.resolver] = counts.get(observation.resolver, 0) + 1
    logger.info(
        "GLOBAL probe round complete: domains=%d workers=%d allocation=%s",
        len(domains),
        workers,
        ",".join(f"{resolver}:{counts.get(resolver, 0)}" for resolver in resolvers),
    )
    return observations


def healthcheck_group(
    resolvers: Sequence[str],
    health_domain: str,
    timeout_ms: int,
    retries: int,
    *,
    parallel: bool = True,
    query_delay_ms: int = 0,
    concurrency: int = 0,
) -> List[str]:
    """Return resolvers that answer the health query for this run.

    Health checks are one request per resolver.  Production invokes this
    helper concurrently for both groups: a CN provider's health check must
    not make otherwise healthy provider windows wait for it.  ``parallel``
    remains an explicit argument for embedders that need deterministic
    serial checks in a test or diagnostic harness.
    """

    unique = list(dict.fromkeys(resolvers))
    if not unique:
        return []
    health_retries = 1 if int(retries) > 0 else 0
    online: List[str] = []
    if parallel:
        online_set: Set[str] = set()
        workers = _global_worker_count(concurrency, len(unique))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    healthcheck_resolver,
                    resolver,
                    health_domain,
                    timeout_ms,
                    health_retries,
                    0,
                ): resolver
                for resolver in unique
            }
            for future in as_completed(futures):
                resolver = futures[future]
                try:
                    healthy = bool(future.result())
                except Exception:  # pragma: no cover - defensive executor guard.
                    healthy = False
                if healthy:
                    online_set.add(resolver)
                else:
                    logger.warning("Resolver unavailable; temporarily disabled: %s", resolver)
        # Preserve configured order even though futures complete out of order;
        # this keeps balancing stable across runs.
        return [resolver for resolver in unique if resolver in online_set]

    for index, resolver in enumerate(unique):
        if index > 0 and query_delay_ms > 0:
            time.sleep(max(0, int(query_delay_ms)) / 1000.0)
        try:
            healthy = healthcheck_resolver(
                resolver,
                health_domain,
                timeout_ms,
                retries=health_retries,
                retry_backoff_ms=max(30, int(query_delay_ms)),
            )
        except Exception:  # pragma: no cover - network boundary guard.
            healthy = False
        if healthy:
            online.append(resolver)
        else:
            logger.warning("Resolver unavailable; temporarily disabled: %s", resolver)
    return online

def run_two_round_probes(
    targets: Sequence[str],
    online_resolvers_global: Sequence[str],
    online_resolvers_cn: Sequence[str],
    settings: ProbeExecutionSettings,
    *,
    probe_resolver: ProbeResolver = timed_probe_resolver,
) -> Tuple[Dict[str, CacheEntry], Set[str]]:
    """Execute GLOBAL first, then CN only for unresolved GLOBAL signals."""

    query = settings.query
    global_probe = settings.global_probe

    if not targets:
        return {}, set()

    global_observations = run_global_round(
        domains=targets,
        resolvers=online_resolvers_global,
        timeout_ms=query.timeout_ms,
        retries=query.retries,
        global_concurrency=global_probe.concurrency,
        global_inflight_per_resolver=global_probe.inflight_per_resolver,
        probe_resolver=probe_resolver,
    )

    final: Dict[str, CacheEntry] = {}
    candidates: List[str] = []
    probed_domains: Set[str] = set(targets)
    global_alive_count = 0
    for domain in targets:
        observation = global_observations.get(domain)
        if observation is not None and observation.status in EXISTENCE_SIGNAL_STATUSES:
            final[domain] = CacheEntry(
                status="alive",
                checked_at=now_ts(),
                reason=observation.reason,
            )
            global_alive_count += 1
        elif observation is not None and observation.status in INACTIVE_SIGNAL_STATUSES:
            # Normally only an explicit inactive signal enters the
            # rate-limited CN stage.  A per-domain timeout/error is a resolver
            # quality problem, not evidence that the domain is inactive.
            candidates.append(domain)
        elif (
            observation is not None
            and observation.status == "error"
            and not online_resolvers_global
        ):
            # If the whole GLOBAL group is unavailable, CN may still provide
            # a safe alive signal.  ``allow_dead`` remains false because the
            # GLOBAL minimum is not satisfied, so CN errors/NX cannot delete.
            candidates.append(domain)
        else:
            final[domain] = CacheEntry(
                status="unknown",
                checked_at=now_ts(),
                reason=join_reasons(
                    observation.reason if observation else "global:unknown",
                    "global-no-confirmation",
                ),
            )

    logger.info(
        "GLOBAL classification complete: alive=%d cn-follow-up=%d",
        global_alive_count,
        len(candidates),
    )

    if candidates:
        cn_results, cn_attempted = run_cn_windows(
            candidates,
            global_observations,
            online_resolvers_cn,
            CnWindowSettings(
                query=query,
                probe=settings.cn_probe,
                allow_dead=settings.allow_dead,
                min_online_cn=settings.min_online_cn,
            ),
            probe_resolver=probe_resolver,
            now_ts=now_ts,
        )
        final.update(cn_results)
        probed_domains.update(cn_attempted)
        for domain in candidates:
            final.setdefault(
                domain,
                CacheEntry(
                    status="unknown",
                    checked_at=now_ts(),
                    reason=join_reasons(
                        global_observations.get(domain).reason
                        if global_observations.get(domain)
                        else "global:unknown",
                        "cn-no-result",
                    ),
                ),
            )

    return final, probed_domains
