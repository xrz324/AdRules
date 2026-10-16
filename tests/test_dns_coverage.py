from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from script.dns_coverage import (
    analyze_coverage,
    apply_coverage,
    parse_coverage_snapshot,
)
from script.rule_canonical import canonicalize_adblock_domain


class DnsCoverageTest(unittest.TestCase):
    def test_snapshot_canonicalizes_each_input_once(self) -> None:
        lines = (
            "||plain.example^",
            "||*.wildcard.example^",
            "/^ads\\.example$/",
            "! comment",
        )

        with patch(
            "script.dns_coverage.canonicalize_adblock_domain",
            wraps=canonicalize_adblock_domain,
        ) as canonicalize:
            snapshot = parse_coverage_snapshot(lines)

        self.assertEqual(len(lines), canonicalize.call_count)
        self.assertEqual(("plain.example",), snapshot.domains)
        self.assertEqual(("wildcard.example",), snapshot.suffixes)
        self.assertEqual(1, len(snapshot.regex_rules))

    def test_suffix_and_glob_coverage(self) -> None:
        result = analyze_coverage(
            [
                "||example.com^",
                "||sub.example.com^",
                "||*.example.com^",
                "||ad-*.amazonaws.com^",
                "||ad-foo.amazonaws.com^",
                "||sub.ad-foo.amazonaws.com^",
                "||other.amazonaws.com^",
            ]
        )

        self.assertEqual(
            [
                "ad-foo.amazonaws.com",
                "sub.ad-foo.amazonaws.com",
                "sub.example.com",
            ],
            list(result.covered_domains),
        )
        self.assertEqual(1, result.stats.suffix)
        self.assertEqual(2, result.stats.wildcard)

    def test_badfilter_disables_matching_coverage_rule(self) -> None:
        result = analyze_coverage(
            [
                "||example.com^",
                "||sub.example.com^",
                "||*.example.com^",
                "||*.example.com^$badfilter",
            ]
        )

        self.assertEqual([], list(result.covered_domains))

    def test_repeated_badfilter_still_disables_wildcard(self) -> None:
        result = analyze_coverage(
            [
                "||sub.example.com^",
                "||*.example.com^",
                "||*.example.com^$badfilter,badfilter",
            ]
        )

        self.assertEqual([], list(result.covered_domains))

    def test_regex_and_denyallow_coverage(self) -> None:
        result = analyze_coverage(
            [
                "||ads.foo.example^",
                "||allowed.example^",
                "||blocked.allowed.example^",
                "/^.+\\.example/$denyallow=allowed.example",
            ]
        )

        self.assertEqual(
            ["ads.foo.example"],
            list(result.covered_domains),
        )
        self.assertEqual(1, result.stats.regex)

    def test_regex_multi_value_denyallow_excludes_each_domain(self) -> None:
        result = analyze_coverage(
            [
                "||ads.foo.example^",
                "||blocked.allowed.example^",
                "||also.other.example^",
                "/^.+\\.example$/$denyallow=allowed.example|other.example",
            ]
        )

        self.assertEqual(
            ["ads.foo.example"],
            list(result.covered_domains),
        )

    def test_regex_badfilter_matches_exact_modifier_set(self) -> None:
        result = analyze_coverage(
            [
                "||ads.example^",
                "/^ads\\.example$/$important",
                "/^ads\\.example$/$badfilter",
            ]
        )

        self.assertEqual(["ads.example"], list(result.covered_domains))

    def test_regex_badfilter_normalizes_denyallow_set(self) -> None:
        result = analyze_coverage(
            [
                "||ads.example^",
                "/^ads\\.example$/$denyallow=allowed.example|other.example",
                "/^ads\\.example$/$denyallow=OTHER.example|ALLOWED.example,badfilter",
            ]
        )

        self.assertEqual([], list(result.covered_domains))

    def test_regex_badfilter_and_invalid_pattern_are_ignored(self) -> None:
        result = analyze_coverage(
            [
                "||ads.example^",
                "/^ads\\.example$/",
                "/^ads\\.example$/$badfilter",
                "/[unterminated/",
            ]
        )

        self.assertEqual([], list(result.covered_domains))
        self.assertEqual(1, result.stats.invalid_regex)

    def test_apply_removes_only_exact_plain_rules(self) -> None:
        lines = [
            "||covered.example^",
            "||covered.example^$important",
            "||other.example^",
        ]
        self.assertEqual(
            ["||covered.example^$important", "||other.example^"],
            apply_coverage(lines, ["covered.example"]),
        )

    def test_cli_outputs_covered_domains_and_cleans_temp_files(self) -> None:
        # Keep a small filesystem assertion here without invoking the CLI's
        # subprocess entry point; the shell adapter covers that boundary.
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "rules.txt"
            path.write_text("||root.example^\n", encoding="utf-8", newline="\n")
            self.assertEqual([], list(analyze_coverage(path.read_text().splitlines()).covered_domains))
            self.assertEqual([], list(path.parent.glob("*.tmp*")))


if __name__ == "__main__":
    unittest.main()
