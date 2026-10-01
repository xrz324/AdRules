from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from script.content_inactive import cleanup_content_with_cache
from script.dns_prune_cache import render_cache
from script.dns_prune_config import (
    build_cache_reuse_policy,
    build_prune_request,
    build_probe_policy,
    resolve_resolver_groups,
)
from script.dns_prune_model import CacheEntry


class ContentInactiveCleanupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.output = self.root / "adblock.txt"
        self.cache = self.root / "dns_prune_cache.json"
        self.environment = {}
        self.now_ts = 2_000_000_000
        self.policy = build_cache_reuse_policy(self.environment)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_compatible_cache(self, entries: dict[str, CacheEntry]) -> None:
        request = build_prune_request(
            environment=self.environment,
            input_path=self.root / "dns.txt",
        )
        groups = resolve_resolver_groups(request, log_warnings=False)
        policy = build_probe_policy(request, *groups)
        self.cache.write_text(
            render_cache(entries, probe_policy=policy),
            encoding="utf-8",
            newline="\n",
        )

    def test_removes_only_exact_plain_blocking_domain_rules(self) -> None:
        self.output.write_text(
            "\n".join(
                (
                    "[Adblock Plus 2.0]",
                    "! Total count: 7",
                    "! Fixture",
                    "||dead.example^",
                    "||dead.example^$third-party",
                    "@@||exception.example^",
                    "||*.wild.example^",
                    "/dead-pattern/",
                    "example.com##.sponsor",
                    "||alive.example^",
                )
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self.write_compatible_cache(
            {
                "dead.example": CacheEntry("dead", self.now_ts - 3600, "nxdomain"),
                "alive.example": CacheEntry("alive", self.now_ts - 3600, "ok"),
            }
        )
        cache_before = self.cache.read_bytes()

        result = cleanup_content_with_cache(
            self.output,
            cache_file=self.cache,
            policy=self.policy,
            now_ts=self.now_ts,
        )

        self.assertEqual(7, result.before_rule_count)
        self.assertEqual(6, result.after_rule_count)
        self.assertEqual(1, result.removed_rule_count)
        self.assertEqual(1, result.reusable_dead_count)
        self.assertEqual("loaded", result.cache_state)
        output = self.output.read_text(encoding="utf-8")
        self.assertIn("! Total count: 6\n", output)
        self.assertNotIn("||dead.example^\n", output)
        self.assertIn("||dead.example^$third-party\n", output)
        self.assertIn("@@||exception.example^\n", output)
        self.assertIn("||*.wild.example^\n", output)
        self.assertIn("/dead-pattern/\n", output)
        self.assertEqual(cache_before, self.cache.read_bytes())

    def test_pending_recheck_and_stale_entries_are_not_reused(self) -> None:
        self.output.write_text(
            "[Adblock Plus 2.0]\n! Total count: 3\n"
            "||pending.example^\n||stale.example^\n||reusable.example^\n",
            encoding="utf-8",
            newline="\n",
        )
        self.write_compatible_cache(
            {
                "pending.example": CacheEntry(
                    "dead", self.now_ts - 8 * 86400, "nxdomain"
                ),
                "stale.example": CacheEntry(
                    "dead", self.now_ts - 15 * 86400, "nxdomain"
                ),
                "reusable.example": CacheEntry("dead", self.now_ts - 3600, "nxdomain"),
            }
        )

        result = cleanup_content_with_cache(
            self.output,
            cache_file=self.cache,
            policy=self.policy,
            now_ts=self.now_ts,
        )

        self.assertEqual(1, result.removed_rule_count)
        output = self.output.read_text(encoding="utf-8")
        self.assertIn("||pending.example^\n", output)
        self.assertIn("||stale.example^\n", output)
        self.assertNotIn("||reusable.example^\n", output)

    def test_cache_miss_leaves_artifact_unchanged(self) -> None:
        original = "[Adblock Plus 2.0]\n! Total count: 1\n||stable.example^\n"
        self.output.write_text(original, encoding="utf-8", newline="\n")

        result = cleanup_content_with_cache(
            self.output,
            cache_file=self.cache,
            policy=self.policy,
            now_ts=self.now_ts,
        )

        self.assertEqual(0, result.removed_rule_count)
        self.assertEqual("miss", result.cache_state)
        self.assertEqual(original, self.output.read_text(encoding="utf-8"))

    def test_policy_mismatch_is_a_conservative_cache_miss(self) -> None:
        original = "[Adblock Plus 2.0]\n! Total count: 1\n||dead.example^\n"
        self.output.write_text(original, encoding="utf-8", newline="\n")
        self.write_compatible_cache(
            {
                "dead.example": CacheEntry("dead", self.now_ts - 3600, "nxdomain")
            }
        )

        result = cleanup_content_with_cache(
            self.output,
            cache_file=self.cache,
            policy=build_cache_reuse_policy({"DNS_PRUNE_TIMEOUT_MS": "801"}),
            now_ts=self.now_ts,
        )

        self.assertEqual(0, result.removed_rule_count)
        self.assertEqual("policy-mismatch", result.cache_state)
        self.assertEqual(original, self.output.read_text(encoding="utf-8"))

    def test_dns_prune_disabled_skips_content_cleanup(self) -> None:
        original = "[Adblock Plus 2.0]\n! Total count: 1\n||dead.example^\n"
        self.output.write_text(original, encoding="utf-8", newline="\n")
        self.write_compatible_cache(
            {
                "dead.example": CacheEntry("dead", self.now_ts - 3600, "nxdomain")
            }
        )

        result = cleanup_content_with_cache(
            self.output,
            cache_file=self.cache,
            policy=self.policy,
            enabled=False,
            now_ts=self.now_ts,
        )

        self.assertEqual(0, result.removed_rule_count)
        self.assertEqual("disabled", result.cache_state)
        self.assertEqual(original, self.output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
