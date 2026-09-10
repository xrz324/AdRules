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
    from .dns_prune_model import (
        CacheEntry,
        CnProbeSettings,
        DnsQuerySettings,
        ResolverProbe,
    )
except ImportError:  # Support direct script execution.
    from dns_prune_model import (  # type: ignore[no-redef]
        CacheEntry,
        CnProbeSettings,
        DnsQuerySettings,
        ResolverProbe,
    )


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
    query: DnsQuerySettings
    probe: CnProbeSettings
    allow_dead: bool
    min_online_cn: int = 1


@dataclass
class CnWindowState:
    resolver: str
    failure_streak: int = 0
    pause_count: int = 0
    active: bool = False


@dataclass(frozen=True)
class CnProbeDecision:
    """Classification of one CN observation, independent of scheduling."""

    entry: Optional[CacheEntry]
    retryable: bool
    health_failure: bool


@dataclass(frozen=True)
class CnRunSnapshot:
    """Immutable coordinator state returned after all windows stop."""

    results: Dict[str, CacheEntry]
    attempted: Set[str]
    worker_errors: Tuple[Tuple[str, BaseException], ...]
    pause_counts: Dict[str, int]
    accepting_windows: Set[str]


class CnTaskBroker:
    """Own CN work queues and keep task movement out of worker logic."""

    def __init__(self, resolvers: Sequence[str], candidates: Sequence[str]) -> None:
        self.resolvers = tuple(resolvers)
        self.window_queues: Dict[str, Queue[str]] = {
            resolver: Queue() for resolver in self.resolvers
        }
        self.handoff_queue: Queue[str] = Queue()
        for index, domain in enumerate(candidates):
            resolver = self.resolvers[index % len(self.resolvers)]
            self.window_queues[resolver].put(domain)

    def release_window(self, resolver: str) -> None:
        """Move a paused window's not-yet-started work to handoff."""

        queue = self.window_queues[resolver]
        while True:
            try:
                domain = queue.get_nowait()
            except Empty:
                return
            queue.task_done()
            self.handoff_queue.put(domain)

    def take(
        self,
        resolver: str,
        *,
        state_snapshot: Mapping[str, Tuple[int, bool]],
        accepting_windows: Set[str],
    ) -> Tuple[Optional[str], Optional[Queue[str]]]:
        """Prefer local work, then handoff, then stealable paused work."""

        own_queue = self.window_queues[resolver]
        try:
            return own_queue.get_nowait(), own_queue
        except Empty:
            pass

        try:
            return self.handoff_queue.get_nowait(), self.handoff_queue
        except Empty:
            pass

        current_healthy = state_snapshot[resolver][0] == 0
        if not current_healthy:
            return None, None
        stealable = [
            other
            for other in self.resolvers
            if other != resolver
            and (
                state_snapshot[other][1]
                or other not in accepting_windows
            )
        ]
        for other in stealable:
            queue = self.window_queues[other]
            try:
                return queue.get_nowait(), queue
            except Empty:
                continue
        return None, None


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


def classify_cn_observation(
    observation: ResolverProbe,
    global_observation: Optional[ResolverProbe],
    *,
    slow_limit_ms: int,
    dead_capable: bool,
    checked_at: int,
) -> CnProbeDecision:
    """Convert resolver observations into a cache result or retry decision."""

    is_slow = slow_limit_ms > 0 and observation.elapsed_ms >= slow_limit_ms
    health_failure = observation.status == "error" or is_slow
    unreliable = observation.status == "error" or (
        is_slow and observation.status not in EXISTENCE_SIGNAL_STATUSES
    )
    global_reason = (
        global_observation.reason if global_observation else "global:unknown"
    )

    if observation.status in EXISTENCE_SIGNAL_STATUSES:
        entry = CacheEntry(
            status="alive",
            checked_at=checked_at,
            reason=join_reasons(global_reason, observation.reason),
        )
    elif observation.status in INACTIVE_SIGNAL_STATUSES and not unreliable:
        if (
            dead_capable
            and global_observation is not None
            and global_observation.status in INACTIVE_SIGNAL_STATUSES
        ):
            entry = CacheEntry(
                status="dead",
                checked_at=checked_at,
                reason=join_reasons(global_observation.reason, observation.reason),
            )
        else:
            entry = CacheEntry(
                status="unknown",
                checked_at=checked_at,
                reason=join_reasons(
                    global_reason,
                    observation.reason,
                    "dead-disabled:need-global+cn-inactive",
                ),
            )
    elif unreliable:
        entry = None
    else:
        entry = CacheEntry(
            status="unknown",
            checked_at=checked_at,
            reason=join_reasons(global_reason, observation.reason),
        )
    return CnProbeDecision(
        entry=entry,
        retryable=unreliable,
        health_failure=health_failure,
    )


class CnRunState:
    """Own all mutable, synchronized state shared by CN window workers."""

    def __init__(
        self,
        resolvers: Sequence[str],
        candidates: Sequence[str],
        retry_limit: int,
    ) -> None:
        self.stop_event = threading.Event()
        self.all_done = threading.Event()
        self.worker_failure = threading.Event()
        self._lock = threading.Lock()
        self._results: Dict[str, CacheEntry] = {}
        self._retry_counts = {domain: 0 for domain in candidates}
        self._attempted: Set[str] = set()
        self._remaining = len(candidates)
        self._worker_errors: list[tuple[str, BaseException]] = []
        self._accepting_windows: Set[str] = set(resolvers)
        self._windows = {
            resolver: CnWindowState(resolver) for resolver in resolvers
        }
        self._retry_limit = max(0, int(retry_limit))

    def broker_snapshot(
        self,
    ) -> Tuple[Dict[str, Tuple[int, bool]], Set[str]]:
        with self._lock:
            windows = {
                resolver: (state.failure_streak, state.active)
                for resolver, state in self._windows.items()
            }
            return windows, set(self._accepting_windows)

    def mark_active(self, resolver: str) -> None:
        with self._lock:
            self._windows[resolver].active = True

    def mark_attempted(self, domain: str) -> None:
        with self._lock:
            self._attempted.add(domain)

    def record_health(self, resolver: str, failed: bool) -> int:
        with self._lock:
            state = self._windows[resolver]
            state.failure_streak = state.failure_streak + 1 if failed else 0
            return state.failure_streak

    def failure_streak(self, resolver: str) -> int:
        with self._lock:
            return self._windows[resolver].failure_streak

    def reserve_retry(self, domain: str) -> bool:
        with self._lock:
            count = self._retry_counts.get(domain, 0)
            if count >= self._retry_limit:
                return False
            self._retry_counts[domain] = count + 1
            return True

    def can_classify_dead(self, *, allowed: bool, required_windows: int) -> bool:
        with self._lock:
            return allowed and len(self._accepting_windows) >= required_windows

    def complete(self, domain: str, entry: CacheEntry) -> None:
        with self._lock:
            self._results[domain] = entry
            self._remaining -= 1
            if self._remaining <= 0:
                self.all_done.set()

    def pause(self, resolver: str) -> None:
        with self._lock:
            self._accepting_windows.discard(resolver)
            self._windows[resolver].pause_count += 1

    def reopen(self, resolver: str, failure_threshold: int) -> None:
        with self._lock:
            self._accepting_windows.add(resolver)
            self._windows[resolver].failure_streak = max(
                0,
                failure_threshold - 1,
            )

    def record_worker_failure(self, resolver: str, exc: BaseException) -> None:
        with self._lock:
            self._worker_errors.append((resolver, exc))
            if resolver in self._windows:
                self._windows[resolver].active = False
        self.worker_failure.set()
        self.stop_event.set()
        self.all_done.set()

    def result_snapshot(self) -> CnRunSnapshot:
        with self._lock:
            pause_counts = {
                resolver: state.pause_count
                for resolver, state in self._windows.items()
            }
            return CnRunSnapshot(
                results=dict(self._results),
                attempted=set(self._attempted),
                worker_errors=tuple(self._worker_errors),
                pause_counts=pause_counts,
                accepting_windows=set(self._accepting_windows),
            )


class CnCoordinator:
    """Own task movement and synchronized run state as one transaction boundary."""

    def __init__(
        self,
        resolvers: Sequence[str],
        candidates: Sequence[str],
        retry_limit: int,
    ) -> None:
        self._broker = CnTaskBroker(resolvers, candidates)
        self._state = CnRunState(resolvers, candidates, retry_limit)

    @property
    def stop_event(self) -> threading.Event:
        return self._state.stop_event

    @property
    def all_done(self) -> threading.Event:
        return self._state.all_done

    @property
    def worker_failed(self) -> bool:
        return self._state.worker_failure.is_set()

    def allocation(self, resolver: str) -> int:
        return self._broker.window_queues[resolver].qsize()

    def take(self, resolver: str) -> Tuple[Optional[str], Optional[Queue[str]]]:
        state_snapshot, accepting_windows = self._state.broker_snapshot()
        return self._broker.take(
            resolver,
            state_snapshot=state_snapshot,
            accepting_windows=accepting_windows,
        )

    def mark_active(self, resolver: str) -> None:
        self._state.mark_active(resolver)

    def mark_attempted(self, domain: str) -> None:
        self._state.mark_attempted(domain)

    def record_health(self, resolver: str, failed: bool) -> int:
        return self._state.record_health(resolver, failed)

    def failure_streak(self, resolver: str) -> int:
        return self._state.failure_streak(resolver)

    def reserve_retry(self, domain: str) -> bool:
        return self._state.reserve_retry(domain)

    def can_classify_dead(self, *, allowed: bool, required_windows: int) -> bool:
        return self._state.can_classify_dead(
            allowed=allowed,
            required_windows=required_windows,
        )

    def settle(
        self,
        source_queue: Queue[str],
        domain: str,
        *,
        retry: bool,
        entry: Optional[CacheEntry],
    ) -> None:
        """Acknowledge exactly one task, then either requeue or complete it."""

        source_queue.task_done()
        if retry:
            self._broker.handoff_queue.put(domain)
            return
        if entry is None:
            raise ValueError("terminal CN task requires a cache entry")
        self._state.complete(domain, entry)

    def pause_and_release(self, resolver: str) -> None:
        self._state.pause(resolver)
        self._broker.release_window(resolver)

    def reopen(self, resolver: str, failure_threshold: int) -> None:
        self._state.reopen(resolver, failure_threshold)

    def record_worker_failure(self, resolver: str, exc: BaseException) -> None:
        self._state.record_worker_failure(resolver, exc)

    def stop(self) -> None:
        self._state.stop_event.set()

    def join_queues(self) -> None:
        for queue in self._broker.window_queues.values():
            queue.join()
        self._broker.handoff_queue.join()

    def snapshot(self) -> CnRunSnapshot:
        return self._state.result_snapshot()


class CnWindowWorker:
    """Probe and pace one resolver window using brokered work."""

    def __init__(
        self,
        resolver: str,
        global_observations: Mapping[str, ResolverProbe],
        coordinator: CnCoordinator,
        settings: CnWindowSettings,
        probe_resolver: ProbeResolver,
        wait_for_window: WaitForWindow,
        now_ts: Callable[[], int],
    ) -> None:
        self.resolver = resolver
        self.global_observations = global_observations
        self.coordinator = coordinator
        self.settings = settings
        self.probe_resolver = probe_resolver
        self.wait_for_window = wait_for_window
        self.now_ts = now_ts
        self.failure_threshold = max(1, int(settings.probe.failure_threshold))
        self.required_cn = max(1, int(settings.min_online_cn))
        self.slow_limit = max(0, int(settings.probe.slow_threshold_ms))
        self.semaphores: Dict[
            str, Optional[threading.BoundedSemaphore]
        ] = {
            resolver: threading.BoundedSemaphore(
                max(1, int(settings.probe.inflight_per_resolver))
            )
        }

    def run_guarded(self) -> None:
        try:
            self.run()
        except BaseException as exc:  # noqa: BLE001 - wake coordinator first.
            self.coordinator.record_worker_failure(self.resolver, exc)

    def run(self) -> None:
        while not self.coordinator.stop_event.is_set():
            domain, source_queue = self.coordinator.take(self.resolver)
            if domain is None or source_queue is None:
                if self.coordinator.all_done.is_set():
                    return
                self.coordinator.stop_event.wait(0.01)
                continue

            self.coordinator.mark_active(self.resolver)
            entry, should_retry, health_failure = self._probe_domain(domain)
            self.coordinator.settle(
                source_queue,
                domain,
                retry=should_retry,
                entry=entry or (None if should_retry else self._fallback_entry(domain)),
            )

            if self.coordinator.stop_event.is_set():
                return
            paused, interrupted = self._pause_if_unhealthy(health_failure)
            if interrupted:
                return
            if paused:
                continue
            if self._wait_after_probe(health_failure):
                return

    def _probe_domain(
        self,
        domain: str,
    ) -> Tuple[Optional[CacheEntry], bool, bool]:
        global_observation = self.global_observations.get(domain)
        self.coordinator.mark_attempted(domain)
        try:
            observation = self.probe_resolver(
                resolver=self.resolver,
                domain=domain,
                semaphores=self.semaphores,
                timeout_ms=self.settings.query.timeout_ms,
                retries=self.settings.query.retries,
                jitter_ms=max(0, int(self.settings.probe.jitter_ms)),
                retry_backoff_ms=max(
                    0,
                    int(self.settings.probe.backoff_base_ms),
                ),
            )
            if not isinstance(observation, ResolverProbe):
                raise TypeError("resolver probe returned an invalid observation")
            decision = classify_cn_observation(
                observation,
                global_observation,
                slow_limit_ms=self.slow_limit,
                dead_capable=self.coordinator.can_classify_dead(
                    allowed=self.settings.allow_dead,
                    required_windows=self.required_cn,
                ),
                checked_at=self.now_ts(),
            )
            self.coordinator.record_health(
                self.resolver,
                decision.health_failure,
            )
            if decision.retryable:
                should_retry = self.coordinator.reserve_retry(domain)
                if should_retry:
                    return None, True, decision.health_failure
                return (
                    self._retry_exhausted_entry(
                        global_observation,
                        observation.reason,
                    ),
                    False,
                    decision.health_failure,
                )
            return decision.entry, False, decision.health_failure
        except Exception as exc:  # noqa: BLE001 - isolate one window/task.
            self.coordinator.record_health(self.resolver, True)
            if self.coordinator.reserve_retry(domain):
                return None, True, True
            return (
                self._retry_exhausted_entry(
                    global_observation,
                    f"{self.resolver}:exception:{type(exc).__name__}",
                ),
                False,
                True,
            )

    def _retry_exhausted_entry(
        self,
        global_observation: Optional[ResolverProbe],
        reason: str,
    ) -> CacheEntry:
        return CacheEntry(
            status="unknown",
            checked_at=self.now_ts(),
            reason=join_reasons(
                global_observation.reason
                if global_observation
                else "global:unknown",
                reason,
                "cn-retry-exhausted",
            ),
        )

    def _fallback_entry(self, domain: str) -> CacheEntry:
        global_observation = self.global_observations.get(domain)
        return CacheEntry(
            status="unknown",
            checked_at=self.now_ts(),
            reason=join_reasons(
                global_observation.reason
                if global_observation
                else "global:unknown",
                f"{self.resolver}:no-terminal-result",
            ),
        )

    def _pause_if_unhealthy(
        self,
        health_failure: bool,
    ) -> Tuple[bool, bool]:
        if not health_failure:
            return False, False
        if self.coordinator.failure_streak(self.resolver) < self.failure_threshold:
            return False, False

        self.coordinator.pause_and_release(self.resolver)
        logger.warning(
            "CN window=%s failed or was slow %d times; pausing for %dms",
            self.resolver,
            self.failure_threshold,
            max(0, int(self.settings.probe.cooldown_ms)),
        )
        if self._wait(
            max(0, int(self.settings.probe.cooldown_ms)) / 1000.0,
            "cooldown",
        ):
            return True, True
        self.coordinator.reopen(self.resolver, self.failure_threshold)
        logger.info("CN window=%s cooldown complete; reopened", self.resolver)
        return True, False

    def _wait_after_probe(self, health_failure: bool) -> bool:
        failure_streak = (
            self.coordinator.failure_streak(self.resolver)
            if health_failure
            else 0
        )
        delay = cn_window_delay_seconds(
            failure_streak,
            self.settings.probe.query_delay_ms,
            self.settings.probe.backoff_base_ms,
            self.settings.probe.backoff_max_ms,
        )
        return self._wait(delay, "backoff" if health_failure else "pace")

    def _wait(self, delay_seconds: float, reason: str) -> bool:
        try:
            return self.wait_for_window(
                self.coordinator.stop_event,
                self.resolver,
                delay_seconds,
                reason,
            )
        except Exception as exc:  # noqa: BLE001 - isolate pacing hooks.
            logger.warning(
                "CN window=%s %s wait failed: %s",
                self.resolver,
                reason,
                exc,
            )
            return False


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
    """Run one independent, paced work window per CN resolver."""

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

    coordinator = CnCoordinator(
        unique_resolvers,
        unique_candidates,
        settings.probe.max_retries,
    )
    logger.info(
        "CN probe allocation: candidates=%d windows=%d allocation=%s "
        "inflight=%d delay=%dms backoff=%d..%dms retries=%d",
        len(unique_candidates),
        len(unique_resolvers),
        ",".join(
            f"{resolver}:{coordinator.allocation(resolver)}"
            for resolver in unique_resolvers
        ),
        max(1, int(settings.probe.inflight_per_resolver)),
        max(0, int(settings.probe.query_delay_ms)),
        max(0, int(settings.probe.backoff_base_ms)),
        max(0, int(settings.probe.backoff_max_ms)),
        max(0, int(settings.probe.max_retries)),
    )
    workers = [
        CnWindowWorker(
            resolver,
            global_observations,
            coordinator,
            settings,
            probe_resolver,
            wait_for_window,
            now_ts,
        )
        for resolver in unique_resolvers
    ]

    with ThreadPoolExecutor(
        max_workers=len(unique_resolvers),
        thread_name_prefix="dns-prune-cn",
    ) as executor:
        futures = [executor.submit(worker.run_guarded) for worker in workers]
        coordinator.all_done.wait()
        coordinator.stop()
        if not coordinator.worker_failed:
            coordinator.join_queues()
        for future in futures:
            try:
                future.result()
            except BaseException as exc:  # pragma: no cover - guarded worker.
                coordinator.record_worker_failure("unknown", exc)

    snapshot = coordinator.snapshot()
    if snapshot.worker_errors:
        resolver, exc = snapshot.worker_errors[0]
        raise RuntimeError(
            f"CN window worker failed for {resolver}: {type(exc).__name__}"
        ) from exc

    logger.info(
        "CN probe windows complete: candidates=%d resolved=%d paused=%s accepting=%s",
        len(unique_candidates),
        len(snapshot.results),
        ",".join(
            f"{resolver}:{snapshot.pause_counts[resolver]}"
            for resolver in unique_resolvers
            if snapshot.pause_counts[resolver]
        )
        or "-",
        ",".join(sorted(snapshot.accepting_windows)) or "-",
    )
    return snapshot.results, snapshot.attempted
