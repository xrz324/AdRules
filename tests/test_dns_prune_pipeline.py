from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from script import dns_prune_pipeline
from script.autoupdate_config import DEFAULT_CONFIG_PATH, environment_values, load_config
from script.dns_prune_cache import render_cache
from script.dns_prune_config import (
    build_probe_policy,
    build_prune_request,
    parse_args,
    request_from_args,
    resolve_resolver_groups,
)
from script.dns_prune import run_prune, run_prune_detailed
from script.dns_prune_pipeline import (
    DnsPrunePipelineError,
    DnsPrunePaths,
    run_dns_policy,
)
from script.dns_prune_model import (
    CacheEntry,
    DnsPolicyMode,
    PruneExecutionResult,
    PruneRequest,
)


class DnsPrunePipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "tmp").mkdir()
        self.rules = self.root / "dns.txt"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_model_defaults_match_autoupdate_dns_policy(self) -> None:
        configured = environment_values(load_config(DEFAULT_CONFIG_PATH))
        request = build_prune_request(environment={}, input_path=self.rules)

        self.assertEqual(
            int(configured["DNS_PRUNE_BUDGET"]),
            request.probe.budget.budget,
        )
        self.assertEqual(
            int(configured["DNS_PRUNE_GLOBAL_CONCURRENCY"]),
            request.probe.global_probe.concurrency,
        )
        self.assertEqual(
            int(configured["DNS_PRUNE_TTL_ALIVE_DAYS"]),
            request.cache_ttl.ttl_alive_days,
        )
        self.assertEqual(
            configured["DNS_PRUNE_RESOLVERS_CN"].split(","),
            list(request.resolvers.resolvers_cn),
        )
        self.assertEqual(Path("dns_prune_cache.json"), request.io.cache_file)

    def test_paths_use_root_relative_runtime_defaults(self) -> None:
        paths = DnsPrunePaths.from_root(
            self.root,
            environment={"DNS_PRUNE_CACHE_FILE": "", "DNS_PRUNE_REMOVED_LOG": ""},
        )

        self.assertEqual(self.root / "dns.txt", paths.input_file)
        self.assertEqual(self.root / "dns_prune_cache.json", paths.cache_file)
        self.assertEqual(
            self.root / "tmp/dns_prune_removed_rules.txt",
            paths.removed_log,
        )

    def test_strict_environment_does_not_enable_fingerprint_mode(self) -> None:
        args = parse_args(
            ["--input", "dns.txt"],
            environment={"STRICT_DNS_PRUNE": "true"},
        )

        self.assertFalse(args.print_policy_fingerprint)
        self.assertTrue(args.require_dead_capable)

    def test_cli_and_in_process_adapters_produce_equivalent_request(self) -> None:
        environment = {
            "DNS_PRUNE_RESOLVERS_CN": "c1,c2,c1",
            "DNS_PRUNE_RESOLVERS_GLOBAL": "g1,g2",
            "DNS_PRUNE_TIMEOUT_MS": "901",
            "DNS_PRUNE_TTL_UNKNOWN_DAYS": "3",
            "STRICT_DNS_PRUNE": "true",
        }
        input_path = self.root / "dns.txt"
        cli = request_from_args(
            parse_args(
                ["--input", str(input_path)],
                environment=environment,
            )
        )
        in_process = build_prune_request(
            environment=environment,
            input_path=input_path,
        )

        self.assertIsInstance(in_process, PruneRequest)
        self.assertEqual(cli, in_process)
        self.assertEqual(("c1", "c2"), in_process.resolvers.resolvers_cn)
        self.assertEqual(901, in_process.probe.query.timeout_ms)
        self.assertEqual(3, in_process.cache_ttl.ttl_unknown_days)
        self.assertTrue(in_process.execution.require_dead_capable)

    def test_detailed_prune_reports_non_strict_missing_resolvers_as_degraded(self) -> None:
        self.rules.write_text("||keep.example^\n", encoding="utf-8", newline="\n")
        request = build_prune_request(
            environment={
                "DNS_PRUNE_RESOLVERS_CN": "",
                "DNS_PRUNE_RESOLVERS_GLOBAL": "",
            },
            input_path=self.rules,
            require_dead_capable=False,
        )

        result = run_prune_detailed(request)

        self.assertEqual(0, result.exit_code)
        self.assertEqual("degraded", result.status)
        self.assertEqual(0, run_prune(request))

    def test_pipeline_passes_typed_request_without_cli_round_trip(self) -> None:
        self.rules.write_text("||keep.example^\n", encoding="utf-8", newline="\n")
        captured: list[PruneRequest] = []

        def fake_prune(
            request: PruneRequest,
            skip_domains: object = (),
            *,
            mode: DnsPolicyMode,
        ) -> PruneExecutionResult:
            captured.append(request)
            self.assertEqual(set(), set(skip_domains))
            self.assertIs(DnsPolicyMode.PROBE, mode)
            return PruneExecutionResult(0, "success")

        with patch(
            "script.dns_prune_pipeline.run_prune_detailed",
            side_effect=fake_prune,
        ):
            run_dns_policy(
                self.root,
                input_file=self.rules,
                mode=DnsPolicyMode.PROBE,
                require_dead_capable=False,
                environment={"DNS_PRUNE_TIMEOUT_MS": "777"},
            )

        self.assertEqual(1, len(captured))
        self.assertIsInstance(captured[0], PruneRequest)
        self.assertEqual(self.rules, captured[0].io.input)
        self.assertEqual(777, captured[0].probe.query.timeout_ms)
        self.assertFalse(captured[0].execution.require_dead_capable)

    def test_coverage_is_passed_in_memory_and_applied_after_prune(self) -> None:
        self.rules.write_text(
            "\n".join(
                [
                    "||*.example.com^",
                    "||sub.example.com^",
                    "||keep.example^",
                ]
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        captured: list[set[str]] = []

        def fake_prune(
            _args: object,
            skip_domains: object = (),
            *,
            mode: DnsPolicyMode,
        ) -> PruneExecutionResult:
            captured.append(set(skip_domains))
            self.assertIs(DnsPolicyMode.PROBE, mode)
            return PruneExecutionResult(0, "success")

        with patch(
            "script.dns_prune_pipeline.run_prune_detailed",
            side_effect=fake_prune,
        ), patch(
            "script.dns_prune_pipeline.analyze_coverage",
            wraps=dns_prune_pipeline.analyze_coverage,
        ) as analyze:
            result = run_dns_policy(
                self.root,
                input_file=self.rules,
                mode=DnsPolicyMode.PROBE,
                require_dead_capable=False,
                environment={},
            )

        self.assertEqual([{"sub.example.com"}], captured)
        self.assertEqual(1, analyze.call_count)
        self.assertEqual(3, result.before_rule_count)
        self.assertEqual(1, result.covered_domain_count)
        self.assertEqual(2, result.final_rule_count)
        self.assertEqual(
            ["||*.example.com^", "||keep.example^"],
            self.rules.read_text(encoding="utf-8").splitlines(),
        )

    def test_coverage_is_recalculated_when_prune_removes_wildcard(self) -> None:
        self.rules.write_text(
            "||*.example.com^\n||sub.example.com^\n",
            encoding="utf-8",
            newline="\n",
        )

        def fake_prune(
            _args: object,
            skip_domains: object = (),
            *,
            mode: DnsPolicyMode,
        ) -> PruneExecutionResult:
            del skip_domains
            self.assertIs(DnsPolicyMode.PROBE, mode)
            self.rules.write_text(
                "||sub.example.com^\n",
                encoding="utf-8",
                newline="\n",
            )
            return PruneExecutionResult(0, "success")

        with patch(
            "script.dns_prune_pipeline.run_prune_detailed",
            side_effect=fake_prune,
        ), patch(
            "script.dns_prune_pipeline.analyze_coverage",
            wraps=dns_prune_pipeline.analyze_coverage,
        ) as analyze:
            result = run_dns_policy(
                self.root,
                input_file=self.rules,
                mode=DnsPolicyMode.PROBE,
                require_dead_capable=False,
                environment={},
            )

        self.assertEqual(2, analyze.call_count)
        self.assertEqual(1, result.final_rule_count)
        self.assertEqual(0, result.covered_domain_count)
        self.assertEqual(0, len(result.coverage.covered_domains))
        self.assertEqual(
            ["||sub.example.com^"],
            self.rules.read_text(encoding="utf-8").splitlines(),
        )

    def test_prune_failure_preserves_snapshot(self) -> None:
        original = "||*.example.com^\n||sub.example.com^\n"
        self.rules.write_text(original, encoding="utf-8", newline="\n")

        with patch(
            "script.dns_prune_pipeline.run_prune_detailed",
            return_value=PruneExecutionResult(4, "failed", "fixture"),
        ):
            with self.assertRaises(DnsPrunePipelineError) as context:
                run_dns_policy(
                    self.root,
                    input_file=self.rules,
                    mode=DnsPolicyMode.PROBE,
                    require_dead_capable=False,
                    environment={},
                )

        self.assertEqual(4, context.exception.exit_code)
        self.assertEqual(original, self.rules.read_text(encoding="utf-8"))

    def test_degraded_prune_status_is_preserved_for_orchestration(self) -> None:
        self.rules.write_text("||keep.example^\n", encoding="utf-8", newline="\n")

        with patch(
            "script.dns_prune_pipeline.run_prune_detailed",
            return_value=PruneExecutionResult(
                0,
                "degraded",
                "too few healthy resolvers; prune skipped",
            ),
        ):
            result = run_dns_policy(
                self.root,
                input_file=self.rules,
                mode=DnsPolicyMode.PROBE,
                require_dead_capable=False,
                environment={},
            )

        self.assertEqual("degraded", result.prune_status)
        self.assertIn("too few healthy resolvers", result.prune_reason)

    def test_coverage_only_api_applies_without_probe_stage(self) -> None:
        self.rules.write_text(
            "||*.example.com^\n||sub.example.com^\n||keep.example^\n",
            encoding="utf-8",
            newline="\n",
        )

        result = run_dns_policy(
            self.root,
            input_file=self.rules,
            mode=DnsPolicyMode.COVERAGE_ONLY,
            require_dead_capable=False,
            environment={},
        )

        self.assertEqual(1, result.covered_domain_count)
        self.assertEqual(2, result.final_rule_count)
        self.assertEqual(
            ["||*.example.com^", "||keep.example^"],
            self.rules.read_text(encoding="utf-8").splitlines(),
        )

    def test_cache_mode_reuses_fresh_dead_cache_without_dns_io(self) -> None:
        self.rules.write_text(
            "||inactive.example^\n||due.example^\n||alive.example^\n||new.example^\n",
            encoding="utf-8",
            newline="\n",
        )
        cache_path = self.root / "cache.json"
        removed_log = self.root / "removed.log"
        request = build_prune_request(
            environment={},
            input_path=self.rules,
            cache_path=cache_path,
            removed_log_path=removed_log,
            require_dead_capable=False,
        )
        resolver_groups = resolve_resolver_groups(request, log_warnings=False)
        cache_path.write_text(
            render_cache(
                {
                    "inactive.example": CacheEntry(
                        status="dead",
                        checked_at=int(time.time()),
                        reason="cached-nxdomain",
                    ),
                    "alive.example": CacheEntry(
                        status="alive",
                        checked_at=int(time.time()),
                        reason="cached-resolved",
                    ),
                    "due.example": CacheEntry(
                        status="dead",
                        checked_at=int(time.time()) - 8 * 86400,
                        reason="cached-nxdomain",
                    ),
                },
                probe_policy=build_probe_policy(request, *resolver_groups),
            ),
            encoding="utf-8",
            newline="\n",
        )
        original_cache = cache_path.read_text(encoding="utf-8")

        with patch("script.dns_prune.healthcheck_group") as healthcheck, patch(
            "script.dns_prune.run_two_round_probes"
        ) as probes:
            result = run_dns_policy(
                self.root,
                input_file=self.rules,
                mode=DnsPolicyMode.CACHE_ONLY,
                cache_file=cache_path,
                removed_log=removed_log,
                require_dead_capable=True,
                environment={},
            )

        self.assertEqual("success", result.prune_status)
        self.assertEqual(
            ["||due.example^", "||alive.example^", "||new.example^"],
            self.rules.read_text(encoding="utf-8").splitlines(),
        )
        self.assertIn(
            "inactive.example\tcached-nxdomain",
            removed_log.read_text(encoding="utf-8"),
        )
        self.assertEqual(original_cache, cache_path.read_text(encoding="utf-8"))
        healthcheck.assert_not_called()
        probes.assert_not_called()

    def test_unified_policy_routes_to_prune_or_coverage(self) -> None:
        with patch(
            "script.dns_prune_pipeline._run_dns_prune",
            return_value="prune-result",
        ) as prune, patch(
            "script.dns_prune_pipeline._run_dns_coverage",
            return_value="coverage-result",
        ) as coverage:
            self.assertEqual(
                "prune-result",
                run_dns_policy(
                    self.root,
                    input_file=self.rules,
                    mode=DnsPolicyMode.PROBE,
                    cache_file=self.root / "cache.json",
                    removed_log=self.root / "removed.log",
                    require_dead_capable=False,
                    environment={"DNS_PRUNE_ENABLED": "true"},
                ),
            )
            prune.assert_called_once()
            coverage.assert_not_called()
            prune.reset_mock()
            self.assertEqual(
                "coverage-result",
                run_dns_policy(
                    self.root,
                    input_file=self.rules,
                    mode=DnsPolicyMode.COVERAGE_ONLY,
                    require_dead_capable=False,
                    environment={},
                ),
            )
            coverage.assert_called_once()
            prune.assert_not_called()


if __name__ == "__main__":
    unittest.main()
