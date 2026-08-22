from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from script import dns_prune_pipeline
from script.dns_prune_pipeline import (
    DnsPrunePipelineError,
    DnsPrunePaths,
    run_dns_policy,
)
from script.dns_prune_config import parse_args


class DnsPrunePipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "tmp").mkdir()
        self.rules = self.root / "dns.txt"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

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

        def fake_prune(_args: object, skip_domains: object = ()) -> int:
            captured.append(set(skip_domains))
            return 0

        with patch(
            "script.dns_prune_pipeline.run_prune",
            side_effect=fake_prune,
        ), patch(
            "script.dns_prune_pipeline.analyze_coverage",
            wraps=dns_prune_pipeline.analyze_coverage,
        ) as analyze:
            result = run_dns_policy(
                self.root,
                input_file=self.rules,
                prune_enabled=True,
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

        def fake_prune(_args: object, skip_domains: object = ()) -> int:
            del skip_domains
            self.rules.write_text(
                "||sub.example.com^\n",
                encoding="utf-8",
                newline="\n",
            )
            return 0

        with patch(
            "script.dns_prune_pipeline.run_prune",
            side_effect=fake_prune,
        ), patch(
            "script.dns_prune_pipeline.analyze_coverage",
            wraps=dns_prune_pipeline.analyze_coverage,
        ) as analyze:
            result = run_dns_policy(
                self.root,
                input_file=self.rules,
                prune_enabled=True,
                require_dead_capable=False,
                environment={},
            )

        self.assertEqual(2, analyze.call_count)
        self.assertEqual(1, result.final_rule_count)
        self.assertEqual(
            ["||sub.example.com^"],
            self.rules.read_text(encoding="utf-8").splitlines(),
        )

    def test_prune_failure_preserves_snapshot(self) -> None:
        original = "||*.example.com^\n||sub.example.com^\n"
        self.rules.write_text(original, encoding="utf-8", newline="\n")

        with patch("script.dns_prune_pipeline.run_prune", return_value=4):
            with self.assertRaises(DnsPrunePipelineError) as context:
                run_dns_policy(
                    self.root,
                    input_file=self.rules,
                    prune_enabled=True,
                    require_dead_capable=False,
                    environment={},
                )

        self.assertEqual(4, context.exception.exit_code)
        self.assertEqual(original, self.rules.read_text(encoding="utf-8"))

    def test_coverage_only_api_applies_without_probe_stage(self) -> None:
        self.rules.write_text(
            "||*.example.com^\n||sub.example.com^\n||keep.example^\n",
            encoding="utf-8",
            newline="\n",
        )

        result = run_dns_policy(
            self.root,
            input_file=self.rules,
            prune_enabled=False,
            require_dead_capable=False,
            environment={},
        )

        self.assertEqual(1, result.covered_domain_count)
        self.assertEqual(2, result.final_rule_count)
        self.assertEqual(
            ["||*.example.com^", "||keep.example^"],
            self.rules.read_text(encoding="utf-8").splitlines(),
        )

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
                    prune_enabled=True,
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
                    prune_enabled=False,
                    require_dead_capable=False,
                    environment={},
                ),
            )
            coverage.assert_called_once()
            prune.assert_not_called()


if __name__ == "__main__":
    unittest.main()
