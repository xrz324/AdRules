from __future__ import annotations

import unittest
from unittest.mock import patch

from script.dns_regex_coverage import (
    RegexCoverageRule,
    match_regex_coverage,
    required_regex_prefix,
)


class DnsRegexCoverageTest(unittest.TestCase):
    def test_required_regex_prefix_is_conservative(self) -> None:
        self.assertEqual(
            ("analytics", True),
            required_regex_prefix(r"^(\S+\.)?analytics(\-|\.)"),
        )
        self.assertEqual(
            ("101.198.192.33", False),
            required_regex_prefix(r"^101\.198\.192\.33$"),
        )
        self.assertEqual(
            ("https://example.com", False),
            required_regex_prefix(r"^https:\/\/example\.com"),
        )
        self.assertIsNone(required_regex_prefix(r"^(ads|track)\.example$"))
        self.assertIsNone(required_regex_prefix(r"analytics\.example"))

    def test_parallel_chunks_preserve_matches_and_invalid_count(self) -> None:
        domains = ("ads.example", "tracker.example", "allowed.example")
        rules = (
            RegexCoverageRule(r"^ads\.example$"),
            RegexCoverageRule(r"^tracker\.example$"),
            RegexCoverageRule(r"^.+\.example$", ("allowed.example",)),
            RegexCoverageRule(r"[unterminated"),
        )

        with patch(
            "script.dns_regex_coverage.MIN_PARALLEL_REGEX_WORK",
            1,
        ), patch("script.dns_regex_coverage.os.cpu_count", return_value=4):
            result = match_regex_coverage(domains, rules)

        self.assertEqual(
            {"ads.example", "tracker.example"},
            set(result.covered_domains),
        )
        self.assertEqual(1, result.invalid_rule_count)
        self.assertEqual(3, result.worker_count)


if __name__ == "__main__":
    unittest.main()
