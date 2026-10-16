from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock


ROOT_DIR = Path(__file__).resolve().parents[1]
from script.dns_prune_model import (
    CnProbeSettings,
    DnsQuerySettings,
    DnsReply,
    GlobalProbeSettings,
    PROBE_POLICY_VERSION,
    ProbePolicy,
    ResolverProbe,
)
from script.dns_prune_probe import (
    ProbeExecutionSettings,
    probe_single_resolver,
    run_two_round_probes,
)
from script.dns_prune_rules import iter_check_domains
from script.dns_prune_scheduler import (
    CnWindowSettings,
    cn_window_delay_seconds,
    run_cn_windows,
)


class DnsPruneTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ProbePolicy(
            version=PROBE_POLICY_VERSION,
            resolvers=("8.8.8.8", "223.5.5.5"),
            resolvers_cn=("223.5.5.5",),
            resolvers_global=("8.8.8.8",),
            health_domain="example.com",
            min_online_resolvers=2,
            min_online_resolvers_cn=1,
            min_online_resolvers_global=1,
            timeout_ms=800,
            retries=0,
        )

    @staticmethod
    def cn_settings(**overrides: object) -> CnWindowSettings:
        values = {
            "timeout_ms": 800,
            "retries": 0,
            "concurrency": 64,
            "inflight_per_resolver": 1,
            "jitter_ms": 0,
            "query_delay_ms": 0,
            "backoff_base_ms": 0,
            "backoff_max_ms": 0,
            "failure_threshold": 3,
            "cooldown_ms": 0,
            "slow_threshold_ms": 1000,
            "max_retries": 0,
            "allow_dead": True,
            "min_online_cn": 1,
        }
        values.update(overrides)
        query = DnsQuerySettings(
            timeout_ms=int(values.pop("timeout_ms")),
            retries=int(values.pop("retries")),
        )
        allow_dead = bool(values.pop("allow_dead"))
        min_online_cn = int(values.pop("min_online_cn"))
        return CnWindowSettings(
            query=query,
            probe=CnProbeSettings(**values),  # type: ignore[arg-type]
            allow_dead=allow_dead,
            min_online_cn=min_online_cn,
        )

    @classmethod
    def probe_settings(cls, **overrides: object) -> ProbeExecutionSettings:
        cn = cls.cn_settings(**overrides)
        return ProbeExecutionSettings(
            query=cn.query,
            global_probe=GlobalProbeSettings(
                concurrency=0,
                inflight_per_resolver=0,
            ),
            cn_probe=cn.probe,
            allow_dead=cn.allow_dead,
            min_online_cn=cn.min_online_cn,
        )

    def test_fingerprint_is_stable_and_change_sensitive(self) -> None:
        first = self.policy.fingerprint()
        second = replace(self.policy).fingerprint()
        changed = replace(self.policy, timeout_ms=801).fingerprint()

        self.assertRegex(first, re.compile(r"^[0-9a-f]{64}$"))
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)

    def test_probe_candidates_are_deduplicated_by_domain(self) -> None:
        domains = iter_check_domains(
            [
                "||ads.example^",
                "||ADS.EXAMPLE^$important",
                "||*.ads.example^",
                "||tracker.example^",
            ]
        )

        self.assertEqual(["ads.example", "tracker.example"], domains)

    def test_global_round_balances_and_only_inactive_enters_cn(self) -> None:
        domains = [f"d{index}.example" for index in range(8)]
        calls: list[tuple[str, str]] = []

        def fake_probe(
            resolver: str,
            domain: str,
            *_args: object,
            **_kwargs: object,
        ) -> ResolverProbe:
            calls.append((resolver, domain))
            if resolver.startswith("g"):
                status = "alive" if int(domain[1]) % 2 == 0 else "nxdomain"
                return ResolverProbe(resolver, status, f"{resolver}:{status}", 1.0)
            return ResolverProbe(resolver, "nxdomain", f"{resolver}:nxdomain", 1.0)

        observed, _probed = run_two_round_probes(
            domains,
            ["g1", "g2", "g3", "g4"],
            ["c1", "c2"],
            self.probe_settings(),
            probe_resolver=fake_probe,
        )

        global_calls = [
            (resolver, domain)
            for resolver, domain in calls
            if resolver.startswith("g")
        ]
        cn_calls = [(resolver, domain) for resolver, domain in calls if resolver.startswith("c")]
        self.assertEqual(8, len(global_calls))
        self.assertEqual(
            [2, 2, 2, 2],
            [
                sum(1 for resolver_name, _ in global_calls if resolver_name == resolver)
                for resolver in ["g1", "g2", "g3", "g4"]
            ],
        )
        self.assertEqual(
            {"d1.example", "d3.example", "d5.example", "d7.example"},
            {domain for _, domain in cn_calls},
        )
        self.assertEqual(4, sum(entry.status == "alive" for entry in observed.values()))
        self.assertEqual(4, sum(entry.status == "dead" for entry in observed.values()))

    def test_failed_cn_window_pauses_without_blocking_healthy_windows(self) -> None:
        candidates = [f"d{index}.example" for index in range(7)]
        global_observations = {
            domain: ResolverProbe("g1", "nxdomain", "g1:nxdomain", 1.0)
            for domain in candidates
        }
        calls: list[tuple[str, str]] = []

        def fake_probe(
            resolver: str,
            domain: str,
            *_args: object,
            **_kwargs: object,
        ) -> ResolverProbe:
            calls.append((resolver, domain))
            if resolver == "c1":
                return ResolverProbe(resolver, "error", "c1:timeout", 900.0)
            return ResolverProbe(resolver, "nxdomain", f"{resolver}:nxdomain", 1.0)

        results, _attempted = run_cn_windows(
            candidates,
            global_observations,
            ["c1", "c2", "c3"],
            self.cn_settings(
                failure_threshold=2,
                cooldown_ms=100,
                slow_threshold_ms=800,
                max_retries=2,
            ),
            probe_resolver=fake_probe,
        )

        c1_calls = [domain for resolver, domain in calls if resolver == "c1"]
        healthy_calls = {
            domain for resolver, domain in calls if resolver in {"c2", "c3"}
        }
        self.assertEqual(2, len(c1_calls))
        self.assertEqual(set(candidates), healthy_calls)
        self.assertTrue(all(entry.status == "dead" for entry in results.values()))

    def test_idle_cn_window_steals_backlog_from_slow_window(self) -> None:
        candidates = [f"d{index}.example" for index in range(4)]
        global_observations = {
            domain: ResolverProbe("g1", "nxdomain", "g1:nxdomain", 1.0)
            for domain in candidates
        }
        healthy_progress = threading.Event()
        slow_window_released: list[bool] = []
        healthy_domains: list[str] = []

        def fake_probe(
            resolver: str,
            domain: str,
            *_args: object,
            **_kwargs: object,
        ) -> ResolverProbe:
            if resolver == "c1":
                slow_window_released.append(healthy_progress.wait(0.5))
            else:
                healthy_domains.append(domain)
                if len(healthy_domains) >= 3:
                    healthy_progress.set()
            return ResolverProbe(resolver, "nxdomain", f"{resolver}:nxdomain", 1.0)

        results, _attempted = run_cn_windows(
            candidates,
            global_observations,
            ["c1", "c2"],
            self.cn_settings(),
            probe_resolver=fake_probe,
        )

        self.assertEqual([True], slow_window_released)
        self.assertEqual(3, len(healthy_domains))
        self.assertTrue(all(entry.status == "dead" for entry in results.values()))

    def test_paused_cn_window_reopens_after_cooldown(self) -> None:
        domain = "retry.example"
        global_observations = {
            domain: ResolverProbe("g1", "nxdomain", "g1:nxdomain", 1.0)
        }
        probe_calls: list[str] = []

        def fake_probe(
            resolver: str,
            domain: str,
            *_args: object,
            **_kwargs: object,
        ) -> ResolverProbe:
            self.assertEqual("retry.example", domain)
            probe_calls.append(resolver)
            if len(probe_calls) == 1:
                return ResolverProbe(resolver, "error", "c1:timeout", 900.0)
            return ResolverProbe(resolver, "nxdomain", "c1:nxdomain", 1.0)

        waits: list[tuple[str, str]] = []

        def fake_wait(
            _stop_event: object,
            resolver: str,
            _delay_seconds: float,
            reason: str,
        ) -> bool:
            waits.append((resolver, reason))
            return False

        results, _attempted = run_cn_windows(
            [domain],
            global_observations,
            ["c1"],
            self.cn_settings(
                failure_threshold=1,
                cooldown_ms=100,
                slow_threshold_ms=800,
                max_retries=1,
            ),
            probe_resolver=fake_probe,
            wait_for_window=fake_wait,
        )

        self.assertEqual(["c1", "c1"], probe_calls)
        self.assertIn(("c1", "cooldown"), waits)
        self.assertEqual("dead", results[domain].status)

    def test_wait_hook_failure_does_not_leave_retry_window_hanging(self) -> None:
        domain = "wait-failure.example"
        global_observations = {
            domain: ResolverProbe("g1", "nxdomain", "g1:nxdomain", 1.0)
        }
        calls: list[str] = []

        def fake_probe(
            resolver: str,
            domain: str,
            *_args: object,
            **_kwargs: object,
        ) -> ResolverProbe:
            calls.append(domain)
            return ResolverProbe(resolver, "error", "timeout", 900.0)

        def broken_wait(*_args: object, **_kwargs: object) -> bool:
            raise RuntimeError("clock hook failed")

        results, _attempted = run_cn_windows(
            [domain],
            global_observations,
            ["c1"],
            self.cn_settings(
                failure_threshold=99,
                max_retries=1,
                slow_threshold_ms=800,
            ),
            probe_resolver=fake_probe,
            wait_for_window=broken_wait,
        )

        self.assertEqual([domain, domain], calls)
        self.assertEqual("unknown", results[domain].status)

    def test_cn_window_delay_adds_exponential_capped_backoff(self) -> None:
        self.assertEqual(0.25, cn_window_delay_seconds(0, 250, 500, 1200))
        self.assertEqual(0.75, cn_window_delay_seconds(1, 250, 500, 1200))
        self.assertEqual(1.25, cn_window_delay_seconds(2, 250, 500, 1200))
        self.assertEqual(1.45, cn_window_delay_seconds(3, 250, 500, 1200))
        self.assertEqual(1.45, cn_window_delay_seconds(4, 250, 500, 1200))

    def test_slow_positive_cn_reply_keeps_alive_result(self) -> None:
        global_observations = {
            "slow.example": ResolverProbe("g1", "nxdomain", "g1:nxdomain", 1.0)
        }

        results, _attempted = run_cn_windows(
            ["slow.example"],
            global_observations,
            ["c1"],
            self.cn_settings(failure_threshold=1),
            probe_resolver=lambda *_args, **_kwargs: ResolverProbe(
                "c1", "alive", "c1:A", 5000.0
            ),
        )

        self.assertEqual("alive", results["slow.example"].status)

    def test_no_ns_is_an_inactive_signal_but_nodata_is_alive(self) -> None:
        no_ns = ("nodata", DnsReply(rcode=0, ancount=0, nscount=0))
        status, _reason = probe_single_resolver(
            "resolver",
            "example.com",
            {"resolver": None},
            800,
            0,
            0,
            query_resolver=Mock(side_effect=[no_ns, no_ns]),
        )
        self.assertEqual("no-ns", status)

        nodata = ("nodata", DnsReply(rcode=0, ancount=0, nscount=1))
        status, _reason = probe_single_resolver(
            "resolver",
            "example.com",
            {"resolver": None},
            800,
            0,
            0,
            query_resolver=Mock(side_effect=[nodata, nodata]),
        )
        self.assertEqual("nodata", status)

    def test_cli_fingerprint_needs_no_input_or_network(self) -> None:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("DNS_PRUNE_") and key != "STRICT_DNS_PRUNE"
        }
        environment.update(
            {
                "DNS_PRUNE_RESOLVERS_CN": "192.0.2.1",
                "DNS_PRUNE_RESOLVERS_GLOBAL": "198.51.100.1",
            }
        )
        command = [
            sys.executable,
            "-m",
            "script.dns_prune",
            "--print-policy-fingerprint",
        ]

        first = subprocess.run(
            command,
            cwd=ROOT_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        environment["DNS_PRUNE_TIMEOUT_MS"] = "801"
        changed = subprocess.run(
            command,
            cwd=ROOT_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )

        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, changed.returncode, changed.stderr)
        self.assertEqual("", first.stderr)
        self.assertRegex(first.stdout.strip(), re.compile(r"^[0-9a-f]{64}$"))
        self.assertNotEqual(first.stdout, changed.stdout)

    def test_cli_fingerprint_rejects_incomplete_resolver_groups(self) -> None:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("DNS_PRUNE_") and key != "STRICT_DNS_PRUNE"
        }
        environment.update(
            {
                "DNS_PRUNE_RESOLVERS_CN": "",
                "DNS_PRUNE_RESOLVERS_GLOBAL": "198.51.100.1",
            }
        )

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "script.dns_prune",
                "--print-policy-fingerprint",
            ],
            cwd=ROOT_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )

        self.assertEqual(2, completed.returncode)
        self.assertIn("requires non-empty CN and GLOBAL", completed.stderr)


if __name__ == "__main__":
    unittest.main()
