#!/usr/bin/env python3

from __future__ import annotations

import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
from script import content_minimizer as minimizer


class ContentMinimizerTest(unittest.TestCase):
    def minimize(self, *lines: str, max_line_bytes: int = 4096) -> list[str]:
        return list(
            minimizer.minimize_lines(
                list(lines), max_line_bytes=max_line_bytes
            ).lines
        )

    def test_minimization_reports_stage_progress_at_info_level(self) -> None:
        with self.assertLogs(minimizer.LOGGER, level="INFO") as captured:
            minimizer.minimize_lines(("||example.com^", "##.advert"))

        output = "\n".join(captured.output)
        self.assertIn("Content semantic deduplication", output)
        self.assertIn("Content URL-pattern minimization", output)
        self.assertIn("Content domain minimization", output)
        self.assertIn("Content cosmetic minimization", output)
        self.assertIn("Content removeparam minimization", output)

    def test_longest_cosmetic_marker_wins(self) -> None:
        extended_exception = minimizer._parse_cosmetic_rule(
            "a.example#@?#div:has-text(ad)"
        )
        style_extended = minimizer._parse_cosmetic_rule(
            "a.example#$?#div { display: none }"
        )

        self.assertIsNotNone(extended_exception)
        self.assertIsNotNone(style_extended)
        self.assertEqual(extended_exception.marker, "#@?#")
        self.assertEqual(style_extended.marker, "#$?#")
        self.assertEqual(
            self.minimize(
                "a.example#@?#div:has-text(ad)",
                "b.example#@?#div:has-text(ad)",
            ),
            ["a.example,b.example#@?#div:has-text(ad)"],
        )

    def test_global_and_scoped_cosmetic_rules_stay_separate(self) -> None:
        result = self.minimize(
            "##.advert",
            "a.example##.advert",
            "b.example##.advert",
            "@@||a.example^$generichide",
            "@@||b.example^$elemhide",
        )

        self.assertEqual(
            result,
            sorted(
                (
                    "##.advert",
                    "a.example,b.example##.advert",
                    "@@||a.example^$generichide",
                    "@@||b.example^$elemhide",
                ),
                key=lambda line: line.encode(),
            ),
        )

    def test_global_id_attribute_rules_cover_exact_global_ids(self) -> None:
        result = minimizer.minimize_lines(
            (
                '##[id^="ad-"]',
                '##[id$="-ad"]',
                "###ad-banner",
                "###footer-ad",
                "###ad-display-ad",
            )
        )

        self.assertEqual(
            ('##[id$="-ad"]', '##[id^="ad-"]'),
            result.lines,
        )
        self.assertEqual(3, result.cosmetic.saved_lines)

    def test_global_id_coverage_keeps_non_equivalent_cosmetic_rules(self) -> None:
        lines = (
            '##[id^="ad-"]',
            "###Ad-banner",
            "###ad-banner > img",
            "###ad-banner:style(display: none !important)",
            "example.com###ad-banner",
            "*###ad-banner",
        )

        result = minimizer.minimize_lines(lines)

        self.assertEqual(
            sorted(lines, key=lambda line: line.encode()),
            list(result.lines),
        )
        self.assertEqual(0, result.cosmetic.saved_lines)

    def test_exact_id_exception_does_not_disable_attribute_coverage(self) -> None:
        result = minimizer.minimize_lines(
            (
                '##[id^="ad-"]',
                "###ad-banner",
                "example.com#@##ad-banner",
            )
        )

        self.assertNotIn("###ad-banner", result.lines)
        self.assertIn("example.com#@##ad-banner", result.lines)
        self.assertEqual(1, result.cosmetic.saved_lines)

    def test_id_attribute_exception_disables_only_its_covering_rule(self) -> None:
        lines = (
            '##[id^="ad-"]',
            '##[id$="-ad"]',
            'example.com#@#[id^="ad-"]',
            "###ad-banner",
            "###footer-ad",
        )

        result = minimizer.minimize_lines(lines)

        self.assertIn("###ad-banner", result.lines)
        self.assertNotIn("###footer-ad", result.lines)
        self.assertIn('example.com#@#[id^="ad-"]', result.lines)
        self.assertEqual(1, result.cosmetic.saved_lines)

    def test_negative_sets_are_normalized_but_not_crossed(self) -> None:
        result = self.minimize(
            "a.example,~skip.example##.advert",
            "b.example,~child.skip.example,~skip.example##.advert",
            "c.example,~other.example##.advert",
        )

        self.assertEqual(
            result,
            sorted(
                (
                    "a.example,b.example,~skip.example##.advert",
                    "c.example,~other.example##.advert",
                ),
                key=lambda line: line.encode(),
            ),
        )

    def test_positive_domains_are_deduplicated_and_parent_compressed(self) -> None:
        result = self.minimize(
            "parent.example,child.parent.example,parent.example##.advert",
            "deep.child.parent.example##.advert",
        )

        self.assertEqual(result, ["parent.example##.advert"])

    def test_special_scopes_are_passed_through(self) -> None:
        lines = (
            "##.advert",
            "*##.advert",
            "amazon.*##.advert",
            "пример.рф##.advert",
            "localhost##.advert",
            "a.example##.advert",
            "b.example##.advert",
        )

        result = self.minimize(*lines)

        self.assertIn("##.advert", result)
        self.assertIn("*##.advert", result)
        self.assertIn("amazon.*##.advert", result)
        self.assertIn("пример.рф##.advert", result)
        self.assertIn("localhost##.advert", result)
        self.assertIn("a.example,b.example##.advert", result)

    def test_cosmetic_output_is_batched_by_total_utf8_length(self) -> None:
        lines = tuple(f"d{index:02d}.example##.advert" for index in range(12))

        result = self.minimize(*lines, max_line_bytes=48)

        self.assertGreater(len(result), 1)
        self.assertTrue(all(len(line.encode()) <= 48 for line in result))
        domains = {
            domain
            for line in result
            for domain in line.split("##", 1)[0].split(",")
        }
        self.assertEqual(domains, {f"d{index:02d}.example" for index in range(12)})

    def test_scriptlet_body_is_kept_byte_for_byte(self) -> None:
        adguard_body = "//scriptlet('set-constant', 'a,b', 'x')"
        ublock_body = "+js(set, value, 'a,b')"

        result = self.minimize(
            f"a.example#%#{adguard_body}",
            f"b.example#%#{adguard_body}",
            f"a.example##{ublock_body}",
            f"b.example##{ublock_body}",
        )

        self.assertIn(f"a.example,b.example#%#{adguard_body}", result)
        self.assertIn(f"a.example,b.example##{ublock_body}", result)

    def test_removeparam_regex_comma_and_domain_union(self) -> None:
        result = self.minimize(
            "||tracker.example^$removeparam=/foo,bar/,domain=a.example,third-party",
            "||tracker.example^$removeparam=/foo,bar/,domain=b.example,third-party",
        )

        self.assertEqual(
            result,
            [
                "||tracker.example^$removeparam=/foo,bar/,domain=a.example|b.example,third-party"
            ],
        )

    def test_removeparam_domains_are_parent_compressed_and_batched(self) -> None:
        lines = tuple(
            f"||tracker.example^$removeparam=utm_source,domain=d{index:02d}.example"
            for index in range(10)
        ) + (
            "||tracker.example^$removeparam=utm_source,domain=child.d00.example",
        )

        result = self.minimize(*lines, max_line_bytes=96)

        self.assertGreater(len(result), 1)
        self.assertTrue(all(len(line.encode()) <= 96 for line in result))
        combined = "|".join(
            line.split("domain=", 1)[1].split(",", 1)[0] for line in result
        )
        domains = set(combined.split("|"))
        self.assertEqual(domains, {f"d{index:02d}.example" for index in range(10)})

    def test_badfilter_target_is_removed_without_rewriting_other_rules(self) -> None:
        target = (
            "||tracker.example^$removeparam=utm_source,"
            "domain=a.example,third-party"
        )
        badfilter = (
            "||tracker.example^$third-party,domain=a.example,"
            "removeparam=utm_source,badfilter"
        )
        other = (
            "||tracker.example^$removeparam=utm_source,"
            "domain=b.example,third-party"
        )

        result = self.minimize(target, badfilter, other)

        self.assertEqual(result, sorted((badfilter, other), key=lambda line: line.encode()))

    def test_semantic_network_duplicates_ignore_case_and_modifier_order(self) -> None:
        lines = (
            "||Example.com^$removeparam=utm,domain=a.example,third-party",
            "||example.com^$third-party,domain=a.example,removeparam=utm",
            "@@||Example.com^$generichide",
            "@@||example.com^$generichide",
        )

        result = self.minimize(*lines)

        self.assertEqual(
            result,
            [
                "@@||Example.com^$generichide",
                "||Example.com^$removeparam=utm,domain=a.example,third-party",
            ],
        )

    def test_badfilter_target_matching_is_case_insensitive(self) -> None:
        result = self.minimize(
            "||example.com^$removeparam=utm,domain=a.example",
            "||Example.COM^$domain=a.example,removeparam=utm,badfilter",
        )

        self.assertEqual(
            [
                "||Example.COM^$domain=a.example,removeparam=utm,badfilter",
            ],
            result,
        )

    def test_domain_dominance_removes_plain_and_narrow_wildcards(self) -> None:
        result = self.minimize(
            "||pixel.example^",
            "||pixel.example^$important",
            "||track.*^",
            "||track.*.roku.example^",
        )

        self.assertEqual(
            [
                "||pixel.example^$important",
                "||track.*^",
            ],
            result,
        )

    def test_third_party_alias_and_plain_domain_coverage(self) -> None:
        result = minimizer.minimize_lines(
            (
                "||stat.4u.pl^",
                "||stat.4u.pl^$3p",
                "||other.example^$3p",
                "||other.example^$third-party",
            )
        )

        self.assertEqual(
            ("||other.example^$3p", "||stat.4u.pl^"),
            result.lines,
        )
        self.assertEqual(1, result.semantic_duplicate_count)
        self.assertEqual(1, result.domain_redundancy_count)

    def test_unanchored_image_wildcard_covers_concrete_host_patterns(self) -> None:
        result = minimizer.minimize_lines(
            (
                "*.marketingcloudqaops.com$image",
                "5078.sfap-qa1.marketingcloudqaops.com$image",
                "10002.ftp-qa1.marketingcloudqaops.com$IMAGE",
            )
        )

        self.assertEqual(
            ("*.marketingcloudqaops.com$image",),
            result.lines,
        )
        self.assertEqual(2, result.url_pattern_redundancy_count)

    def test_unanchored_image_wildcard_keeps_non_equivalent_rules(self) -> None:
        lines = (
            "*.marketingcloudqaops.com$image",
            "5078.sfap-qa1.marketingcloudqaops.net$image",
            "5078.sfap-qa1.marketingcloudqaops.com$script",
            "@@*.marketingcloudqaops.com$image",
            "https://5078.sfap-qa1.marketingcloudqaops.com/pixel$image",
            "foo.*.marketingcloudqaops.com$image",
            "foo.*.*.complex.example$image",
            "foo.a.b.complex.example$image",
        )

        result = minimizer.minimize_lines(lines)

        self.assertEqual(
            sorted(lines, key=lambda line: line.encode()),
            list(result.lines),
        )
        self.assertEqual(0, result.url_pattern_redundancy_count)

    def test_badfilter_disables_unanchored_image_wildcard_coverage(self) -> None:
        lines = (
            "*.marketingcloudqaops.com$image",
            "*.MarketingCloudQAOps.com$image,badfilter",
            "5078.sfap-qa1.marketingcloudqaops.com$image",
        )

        result = minimizer.minimize_lines(lines)

        self.assertEqual(
            sorted(lines, key=lambda line: line.encode()),
            list(result.lines),
        )
        self.assertEqual(0, result.url_pattern_redundancy_count)

    def test_badfilter_matches_reordered_set_valued_modifier(self) -> None:
        result = self.minimize(
            "||example.com^$removeparam=utm,domain=a.example|b.example",
            "||EXAMPLE.com^$domain=B.example|A.example,removeparam=utm,badfilter",
        )

        self.assertEqual(
            [
                "||EXAMPLE.com^$domain=B.example|A.example,removeparam=utm,badfilter"
            ],
            result,
        )

    def test_candidate_output_that_is_badfilter_target_is_not_emitted(self) -> None:
        first = (
            "||tracker.example^$removeparam=utm_source,"
            "domain=a.example,third-party"
        )
        second = (
            "||tracker.example^$removeparam=utm_source,"
            "domain=b.example,third-party"
        )
        badfilter = (
            "||tracker.example^$third-party,domain=a.example|b.example,"
            "removeparam=utm_source,badfilter"
        )

        result = self.minimize(first, second, badfilter)

        self.assertEqual(result, sorted((first, second, badfilter), key=lambda line: line.encode()))

    def test_removeparam_different_value_or_modifier_order_does_not_merge(self) -> None:
        lines = (
            "||tracker.example^$removeparam=one,domain=a.example,third-party",
            "||tracker.example^$removeparam=two,domain=b.example,third-party",
            "||tracker.example^$third-party,removeparam=one,domain=c.example",
        )

        self.assertEqual(self.minimize(*lines), sorted(lines, key=lambda line: line.encode()))

    def test_removeparam_special_or_negative_domains_are_passed_through(self) -> None:
        lines = (
            "$removeparam=utm,domain=amazon.*",
            "$removeparam=utm,domain=~a.example|b.example",
            "$removeparam=utm,domain=localhost",
            "$removeparam=utm,domain=пример.рф",
        )

        self.assertEqual(self.minimize(*lines), sorted(lines, key=lambda line: line.encode()))

    def test_minimization_is_idempotent(self) -> None:
        lines = (
            "##.advert",
            "a.example##.advert",
            "b.example##.advert",
            "a.example,~skip.example#@#.advert",
            "b.example,~skip.example#@#.advert",
            "a.example#%#//scriptlet('set', 'a,b')",
            "b.example#%#//scriptlet('set', 'a,b')",
            "||tracker.example^$removeparam=/foo,bar/,domain=a.example",
            "||tracker.example^$removeparam=/foo,bar/,domain=b.example",
        )

        first = minimizer.minimize_lines(lines, max_line_bytes=96)
        second = minimizer.minimize_lines(first.lines, max_line_bytes=96)

        self.assertEqual(first.lines, second.lines)


if __name__ == "__main__":
    unittest.main()
