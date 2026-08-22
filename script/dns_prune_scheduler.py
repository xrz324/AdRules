"""Concurrent CN resolver window scheduling for DNS pruning."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from queue import Empty, Queue
from typing import Callable, Dict, Mapping, Optional, Protocol, Sequence, Set, Tuple

try:
    from .dns_prune_model import CacheEntry, CnWindowState, ResolverProbe
except ImportError:  # Support direct script execution.
    from dns_prune_model import CacheEntry, CnWindowState, ResolverProbe  # type: ignore[no-redef]


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

EXISTENCE_SIGNAL_STATUSES = frozenset({"alive", "nodata", "mixed"})
INACTIVE_SIGNAL_STATUSES = frozenset({"nxdomain", "no-ns"})


class ProbeResolver(Protocol):
    def __call__(
        self,
        resolver: str,
        domain: str,
        semaphores: Mapping[str, Optional[threading.BoundedSemaphore]],
        timeout_ms: int,
        retries: int,
        jitter_ms: int,
        retry_backoff_ms: int = 30,
    ) -> ResolverProbe: ...


WaitForWindow = Callable[[threading.Event, str, float, str], bool]


@dataclass(frozen=True)
class CnWindowSettings:
    timeout_ms: int
    retries: int
    inflight_per_resolver: int
    jitter_ms: int
    query_delay_ms: int
    backoff_base_ms: int
    backoff_max_ms: int
    failure_threshold: int
    cooldown_ms: int
    slow_threshold_ms: int
    max_retries: int
    allow_dead: bool
    min_online_cn: int = 1


def join_reasons(*parts: Optional[str]) -> str:
    return ";".join(part for part in parts if part)[:400] or "unknown"


def cn_window_delay_seconds(
    failure_streak: int,
    query_delay_ms: int,
    backoff_base_ms: int,
    backoff_max_ms: int,
) -> float:
    """Return one window's own pacing delay after a probe."""

    delay_ms = max(0, int(query_delay_ms))
    if failure_streak > 0 and backoff_base_ms > 0:
        exponent = min(20, max(0, int(failure_streak) - 1))
        additional = int(backoff_base_ms) * (2**exponent)
        if backoff_max_ms > 0:
            additional = min(additional, int(backoff_max_ms))
        delay_ms += max(0, additional)
    return delay_ms / 1000.0


def wait_for_cn_window(
    stop_event: threading.Event,
    resolver: str,
    delay_seconds: float,
    reason: str,
) -> bool:
    """Wait without blocking other resolver windows; return if interrupted."""

    if delay_seconds <= 0:
        return stop_event.is_set()
    logger.debug(
        "CN window=%s wait=%.3fs reason=%s",
        resolver,
        delay_seconds,
        reason,
    )
    return stop_event.wait(delay_seconds)


def run_cn_windows(
    candidates: Sequence[str],
    global_observations: Mapping[str, ResolverProbe],
    resolvers: Sequence[str],
    settings: CnWindowSettings,
    *,
    probe_resolver: ProbeResolver,
    wait_for_window: WaitForWindow = wait_for_cn_window,
    now_ts: Callable[[], int] = lambda: int(time.time()),
) -> Tuple[Dict[str, CacheEntry], Set[str]]:
    """Run one independent, paced work window per CN resolver.

    A window owns its queue consumption, delay/backoff and circuit-breaker
    state.  It requeues an unreliable domain for another window, pauses only
    itself after consecutive failures, and reopens after its cooldown.  The
    initial slices and handoff queue provide load balancing; there is no round
    barrier or global sleep that can stall healthy windows.
    """

    timeout_ms = settings.timeout_ms
    retries = settings.retries
    inflight_per_resolver = settings.inflight_per_resolver
    jitter_ms = settings.jitter_ms
    query_delay_ms = settings.query_delay_ms
    backoff_base_ms = settings.backoff_base_ms
    backoff_max_ms = settings.backoff_max_ms
    failure_threshold = settings.failure_threshold
    cooldown_ms = settings.cooldown_ms
    slow_threshold_ms = settings.slow_threshold_ms
    max_retries = settings.max_retries
    allow_dead = settings.allow_dead
    min_online_cn = settings.min_online_cn

    unique_resolvers = list(dict.fromkeys(resolvers))
    unique_candidates = list(dict.fromkeys(candidates))
    if not unique_candidates:
        return {}, set()
    if not unique_resolvers:
        return {
            domain: CacheEntry(
                status="unknown",
                checked_at=now_ts(),
                reason=join_reasons(
                    global_observations.get(domain).reason
                    if global_observations.get(domain)
                    else "global:unknown",
                    "cn-no-healthy-resolvers",
                ),
            )
            for domain in unique_candidates
        }, set()

    # Give every window a deterministic, balanced initial slice. Retries and
    # work released by a paused window go to handoff_queue and can be accepted
    # by whichever other window is ready. This preserves the initial N-way
    # load balance without introducing a round barrier.
    window_queues: Dict[str, Queue[str]] = {
        resolver: Queue() for resolver in unique_resolvers
    }
    for index, domain in enumerate(unique_candidates):
        resolver = unique_resolvers[index % len(unique_resolvers)]
        window_queues[resolver].put(domain)
    logger.info(
        "CN probe allocation: candidates=%d windows=%d allocation=%s inflight=%d delay=%dms backoff=%d..%dms retries=%d",
        len(unique_candidates),
        len(unique_resolvers),
        ",".join(
            f"{resolver}:{window_queues[resolver].qsize()}"
            for resolver in unique_resolvers
        ),
        max(1, int(inflight_per_resolver)),
        max(0, int(query_delay_ms)),
        max(0, int(backoff_base_ms)),
        max(0, int(backoff_max_ms)),
        max(0, int(max_retries)),
    )
    handoff_queue: Queue[str] = Queue()

    stop_event = threading.Event()
    state_lock = threading.Lock()
    results: Dict[str, CacheEntry] = {}
    retry_counts: Dict[str, int] = {domain: 0 for domain in unique_candidates}
    attempted: Set[str] = set()
    remaining = len(unique_candidates)
    all_done = threading.Event()
    accepting_windows: Set[str] = set(unique_resolvers)
    states = {resolver: CnWindowState(resolver) for resolver in unique_resolvers}
    threshold = max(1, int(failure_threshold))
    required_cn = max(1, int(min_online_cn))
    retry_limit = max(0, int(max_retries))
    slow_limit = max(0, int(slow_threshold_ms))
    sem_limit = max(1, int(inflight_per_resolver))

    def _schedule_retry(domain: str) -> bool:
        with state_lock:
            count = retry_counts.get(domain, 0)
            if count >= retry_limit:
                return False
            retry_counts[domain] = count + 1
            return True

    def _release_window_queue(resolver: str) -> None:
        """Hand a paused window's not-yet-started work to healthy windows."""

        queue = window_queues[resolver]
        while True:
            try:
                domain = queue.get_nowait()
            except Empty:
                return
            queue.task_done()
            handoff_queue.put(domain)

    def _take_window_task(
        resolver: str,
    ) -> Tuple[Optional[str], Optional[Queue[str]]]:
        """Take work for a window, allowing idle windows to steal backlog.

        A worker always prefers its own balanced slice.  If that slice is
        empty, it consumes retries/handoffs; finally it may steal queued work
        from a window that has already started (or is paused).  The last step
        prevents a slow window's pacing delay from holding its backlog while
        healthy windows sit idle, without changing each window's own state.
        """

        own_queue = window_queues[resolver]
        try:
            return own_queue.get_nowait(), own_queue
        except Empty:
            pass

        try:
            return handoff_queue.get_nowait(), handoff_queue
        except Empty:
            pass

        with state_lock:
            current_healthy = states[resolver].failure_streak == 0
            stealable = [
                other
                for other in unique_resolvers
                if other != resolver
                and current_healthy
                and (states[other].active or other not in accepting_windows)
            ]
        for other in stealable:
            queue = window_queues[other]
            try:
                return queue.get_nowait(), queue
            except Empty:
                continue
        return None, None

    def _worker(resolver: str) -> None:
        nonlocal remaining
        state = states[resolver]
        semaphores: Dict[str, Optional[threading.BoundedSemaphore]] = {
            resolver: threading.BoundedSemaphore(sem_limit)
        }
        while not stop_event.is_set():
            domain, source_queue = _take_window_task(resolver)
            if domain is None or source_queue is None:
                if all_done.is_set():
                    return
                # Polling is deliberately short: it only handles the idle
                # handoff path and does not impose a shared pacing interval.
                stop_event.wait(0.01)
                continue
            with state_lock:
                states[resolver].active = True

            should_retry = False
            health_failure = False
            entry: Optional[CacheEntry] = None
            global_observation = global_observations.get(domain)
            try:
                with state_lock:
                    attempted.add(domain)
                observation = probe_resolver(
                    resolver=resolver,
                    domain=domain,
                    semaphores=semaphores,
                    timeout_ms=timeout_ms,
                    retries=retries,
                    jitter_ms=max(0, int(jitter_ms)),
                    retry_backoff_ms=max(0, int(backoff_base_ms)),
                )
                if not isinstance(observation, ResolverProbe):
                    raise TypeError("resolver probe returned an invalid observation")
                is_slow = slow_limit > 0 and observation.elapsed_ms >= slow_limit
                health_failure = observation.status == "error" or is_slow
                with state_lock:
                    if health_failure:
                        state.failure_streak += 1
                    else:
                        state.failure_streak = 0

                unreliable = observation.status == "error" or (
                    is_slow and observation.status not in EXISTENCE_SIGNAL_STATUSES
                )
                if observation.status in EXISTENCE_SIGNAL_STATUSES:
                    # A positive answer is safe even when the window is slow;
                    # the window health state is handled below.
                    entry = CacheEntry(
                        status="alive",
                        checked_at=now_ts(),
                        reason=join_reasons(
                            global_observation.reason
                            if global_observation
                            else "global:unknown",
                            observation.reason,
                        ),
                    )
                elif observation.status in INACTIVE_SIGNAL_STATUSES and not unreliable:
                    with state_lock:
                        dead_capable = (
                            allow_dead and len(accepting_windows) >= required_cn
                        )
                    if (
                        dead_capable
                        and global_observation is not None
                        and global_observation.status in INACTIVE_SIGNAL_STATUSES
                    ):
                        entry = CacheEntry(
                            status="dead",
                            checked_at=now_ts(),
                            reason=join_reasons(
                                global_observation.reason,
                                observation.reason,
                            ),
                        )
                    else:
                        entry = CacheEntry(
                            status="unknown",
                            checked_at=now_ts(),
                            reason=join_reasons(
                                global_observation.reason
                                if global_observation
                                else "global:unknown",
                                observation.reason,
                                "dead-disabled:need-global+cn-inactive",
                            ),
                        )
                elif unreliable:
                    should_retry = _schedule_retry(domain)
                    if not should_retry:
                        entry = CacheEntry(
                            status="unknown",
                            checked_at=now_ts(),
                            reason=join_reasons(
                                global_observation.reason
                                if global_observation
                                else "global:unknown",
                                observation.reason,
                                "cn-retry-exhausted",
                            ),
                        )
                else:
                    entry = CacheEntry(
                        status="unknown",
                        checked_at=now_ts(),
                        reason=join_reasons(
                            global_observation.reason
                            if global_observation
                            else "global:unknown",
                            observation.reason,
                        ),
                    )
            except Exception as exc:  # noqa: BLE001 - isolate one window/task.
                health_failure = True
                with state_lock:
                    state.failure_streak += 1
                should_retry = _schedule_retry(domain)
                if not should_retry:
                    entry = CacheEntry(
                        status="unknown",
                        checked_at=now_ts(),
                        reason=join_reasons(
                            global_observation.reason
                            if global_observation
                            else "global:unknown",
                            f"{resolver}:exception:{type(exc).__name__}",
                            "cn-retry-exhausted",
                        ),
                    )
            finally:
                if source_queue is None:  # pragma: no cover - defensive guard.
                    source_queue = handoff_queue
                source_queue.task_done()
                with state_lock:
                    if not should_retry:
                        # Keep the coordinator progressing even if a future
                        # branch forgets to construct a terminal entry.
                        if entry is None:
                            entry = CacheEntry(
                                status="unknown",
                                checked_at=now_ts(),
                                reason=join_reasons(
                                    global_observation.reason
                                    if global_observation
                                    else "global:unknown",
                                    f"{resolver}:no-terminal-result",
                                ),
                            )
                        results[domain] = entry
                        remaining -= 1
                        if remaining <= 0:
                            all_done.set()
                if should_retry:
                    handoff_queue.put(domain)

            if stop_event.is_set():
                return

            if health_failure and state.failure_streak >= threshold:
                with state_lock:
                    accepting_windows.discard(resolver)
                    state.pause_count += 1
                _release_window_queue(resolver)
                logger.warning(
                    "CN window=%s failed or was slow %d times; pausing for %dms",
                    resolver,
                    threshold,
                    max(0, int(cooldown_ms)),
                )
                interrupted = wait_for_window(
                    stop_event,
                    resolver,
                    max(0, int(cooldown_ms)) / 1000.0,
                    "cooldown",
                )
                if interrupted:
                    return
                with state_lock:
                    accepting_windows.add(resolver)
                    # Half-open after cooldown: one failure reopens quickly,
                    # while a healthy result below resets the streak to zero.
                    state.failure_streak = max(0, threshold - 1)
                logger.info("CN window=%s cooldown complete; reopened", resolver)
                continue

            delay = cn_window_delay_seconds(
                state.failure_streak if health_failure else 0,
                query_delay_ms,
                backoff_base_ms,
                backoff_max_ms,
            )
            if wait_for_window(
                stop_event,
                resolver,
                delay,
                "backoff" if health_failure else "pace",
            ):
                return

    with ThreadPoolExecutor(
        max_workers=len(unique_resolvers),
        thread_name_prefix="dns-prune-cn",
    ) as executor:
        futures = [executor.submit(_worker, resolver) for resolver in unique_resolvers]
        # There is no global round barrier. ``all_done`` tracks logical
        # domains; once every domain has a terminal result, wake windows that
        # happen to be in pacing/cooldown waits and let them exit promptly.
        all_done.wait()
        stop_event.set()
        for queue in window_queues.values():
            queue.join()
        handoff_queue.join()
        for future in futures:
            try:
                future.result()
            except Exception as exc:  # pragma: no cover - worker guard.
                logger.warning("CN window worker failed: %s", exc)

    logger.info(
        "CN probe windows complete: candidates=%d resolved=%d paused=%s accepting=%s",
        len(unique_candidates),
        len(results),
        ",".join(
            f"{resolver}:{states[resolver].pause_count}"
            for resolver in unique_resolvers
            if states[resolver].pause_count
        )
        or "-",
        ",".join(sorted(accepting_windows)) or "-",
    )
    return results, attempted

