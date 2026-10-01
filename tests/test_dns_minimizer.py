import unittest
from unittest.mock import patch

from script.dns_minimizer import (
    glob_is_subset,
    minimize_dns_lines,
    minimize_mihomo_lines,
)
from script.rule_canonical import (
    DomainGlobIndex,
    GlobIndex,
    domain_is_covered_by_glob,
    glob_matches,
)


class GlobLanguageTest(unittest.TestCase):
    def test_exact_glob_index_does_not_apply_domain_suffix_semantics(self):
        index = GlobIndex(("email.*", "*.marketingcloudqaops.com"))

        self.assertTrue(index.matches("email.example"))
        self.assertTrue(index.matches("5078.marketingcloudqaops.com"))
        self.assertFalse(index.matches("sub.email.example"))
        self.assertFalse(index.matches("marketingcloudqaops.com"))

    def test_proven_subset_examples(self):
        self.assertTrue(glob_is_subset("ad-*.amazonaws.com", "ad-*.com"))
        self.assertTrue(
            glob_is_subset(
                "ads*-normal-*.zijieapi.com",
                "ads*-normal*.zijieapi.com",
            )
        )
        self.assertTrue(
            glob_is_subset(
                "ad-host-backup-*.*.aliyuncs.com",
                "ad-host-backup-*.aliyuncs.com",
            )
        )

    def test_non_subset_counterexamples(self):
        self.assertFalse(glob_is_subset("ad-*.com", "ad-*.amazonaws.com"))
        self.assertFalse(glob_is_subset("*.com", "ad-*.com"))
        self.assertFalse(glob_is_subset("a*.example.com", "b*.example.com"))
        self.assertFalse(glob_is_subset("a*x*c", "a*b*c"))

    def test_equivalent_consecutive_stars(self):
        self.assertTrue(glob_is_subset("a**b.example", "a*b.example"))
        self.assertTrue(glob_is_subset("a*b.example", "a**b.example"))

    def test_domain_glob_index_matches_reference_semantics(self):
        patterns = (
            "ad.*",
            "*.example.com",
            "track.*.roku.example",
            "*metric*",
            "ads*",
            "foo.*.bar",
            "a**b.example",
            "*",
        )
        domains = (
            "ad.example",
            "sub.ad.example",
            "deep.sub.example.com",
            "track.us.roku.example",
            "telemetry.test",
            "prefixmetricvalue.invalid",
            "x.foo.one.bar",
            "a.long.b.example",
            "unrelated.test",
        )
        index = DomainGlobIndex(patterns)

        for domain in domains:
            with self.subTest(domain=domain):
                self.assertEqual(
                    any(
                        domain_is_covered_by_glob(domain, pattern)
                        for pattern in patterns
                    ),
                    index.covers_domain(domain),
                )

    def test_domain_glob_index_skips_unrelated_automata(self):
        patterns = tuple(
            f"ad{index}.*.suffix{index}.test" for index in range(500)
        )
        index = DomainGlobIndex((*patterns, "track.*"))

        with patch(
            "script.rule_canonical.glob_matches",
            wraps=glob_matches,
        ) as matcher:
            self.assertFalse(index.covers_domain("unrelated.example"))
            self.assertEqual(0, matcher.call_count)

            self.assertTrue(
                index.covers_domain("x.ad42.value.suffix42.test")
            )
            self.assertEqual(1, matcher.call_count)


class DnsMinimizerTest(unittest.TestCase):
    def minimize(self, lines):
        return minimize_dns_lines(lines)[0]

    def test_badfilter_removes_only_its_exact_base(self):
        lines = [
            "||disabled.example^",
            "||disabled.example^$badfilter",
            "||child.disabled.example^",
            "||priority.example^",
            "||priority.example^$important",
            "||priority.example^$important,badfilter",
        ]

        result = self.minimize(lines)

        self.assertNotIn("||disabled.example^", result)
        self.assertIn("||disabled.example^$badfilter", result)
        self.assertIn("||child.disabled.example^", result)
        self.assertIn("||priority.example^", result)
        self.assertNotIn("||priority.example^$important", result)
        self.assertIn("||priority.example^$important,badfilter", result)

    def test_active_important_replaces_only_plain_same_target(self):
        lines = [
            "||example.com^",
            "||example.com^$important",
            "||example.com^$dnsrewrite=0.0.0.0",
        ]

        result = self.minimize(lines)

        self.assertNotIn("||example.com^", result)
        self.assertIn("||example.com^$important", result)
        self.assertIn("||example.com^$dnsrewrite=0.0.0.0", result)

    def test_domain_and_wildcard_coverage(self):
        lines = [
            "||mmstat.com^",
            "||*.mmstat.com^",
            "||ad-*.com^",
            "||ad-*.amazonaws.com^",
            "||ads*-normal*.zijieapi.com^",
            "||ads*-normal-*.zijieapi.com^",
            "||unrelated*.example.net^",
        ]

        result = self.minimize(lines)

        self.assertIn("||mmstat.com^", result)
        self.assertNotIn("||*.mmstat.com^", result)
        self.assertIn("||ad-*.com^", result)
        self.assertNotIn("||ad-*.amazonaws.com^", result)
        self.assertIn("||ads*-normal*.zijieapi.com^", result)
        self.assertNotIn("||ads*-normal-*.zijieapi.com^", result)
        self.assertIn("||unrelated*.example.net^", result)

    def test_disabled_cover_is_not_used(self):
        lines = [
            "||parent.example^",
            "||parent.example^$badfilter",
            "||ad*.parent.example^",
            "||wide*.example^",
            "||wide*.example^$badfilter",
            "||wide-narrow*.example^",
        ]

        result = self.minimize(lines)

        self.assertIn("||ad*.parent.example^", result)
        self.assertIn("||wide-narrow*.example^", result)

    def test_result_is_deterministic_and_idempotent(self):
        lines = [
            "||a**b.example^",
            "||a*b.example^",
            "||keep.example^",
            "||keep.example^$important",
        ]

        first = self.minimize(lines)
        second = self.minimize(first)

        self.assertEqual(first, second)
        self.assertEqual(
            len([line for line in first if line.startswith("||a")]),
            1,
        )

    def test_semantic_duplicates_ignore_domain_case_and_modifier_order(self):
        lines = [
            "||Example.com^$important,denyallow=foo.example",
            "||example.com^$denyallow=foo.example,IMPORTANT",
            "||keep.example^",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(
            [
                "||Example.com^$important,denyallow=foo.example",
                "||keep.example^",
            ],
            minimized,
        )
        self.assertEqual(stats.semantic_duplicate_count, 1)

    def test_semantic_duplicates_normalize_set_valued_modifiers(self):
        lines = [
            "||example.com^$denyallow=A.example|b.example,important",
            "||EXAMPLE.com^$IMPORTANT,denyallow=b.example|a.example",
            "||scoped.example^$domain=B.example|a.example",
            "||scoped.example^$domain=a.example|b.example",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(
            [
                "||EXAMPLE.com^$IMPORTANT,denyallow=b.example|a.example",
                "||scoped.example^$domain=B.example|a.example",
            ],
            minimized,
        )
        self.assertEqual(stats.semantic_duplicate_count, 2)

    def test_semantic_duplicates_normalize_third_party_aliases(self):
        lines = [
            "||Example.com^$3p",
            "||example.com^$third-party",
            "||other.example^",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(
            ["||Example.com^$3p", "||other.example^"],
            minimized,
        )
        self.assertEqual(stats.semantic_duplicate_count, 1)

    def test_badfilter_matches_third_party_aliases(self):
        lines = [
            "||alias.example^$3p",
            "||alias.example^$third-party,badfilter",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(["||alias.example^$third-party,badfilter"], minimized)
        self.assertEqual(stats.disabled_base, 1)

    def test_plain_rule_covers_same_domain_third_party_rule(self):
        lines = [
            "||stat.4u.pl^",
            "||stat.4u.pl^$third-party",
            "||keep.example^$third-party",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(
            ["||keep.example^$third-party", "||stat.4u.pl^"],
            sorted(minimized),
        )
        self.assertEqual(stats.third_party_by_domain, 1)

    def test_plain_wildcard_covers_concrete_third_party_rule(self):
        lines = [
            "||ads.*^",
            "||ads.avocet.io^$3p",
            "||keep.example^$3p",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(
            ["||ads.*^", "||keep.example^$3p"],
            minimized,
        )
        self.assertEqual(stats.third_party_by_wildcard, 1)

    def test_plain_wildcard_covers_same_wildcard_third_party_rule(self):
        lines = [
            "||ads.*^",
            "||ads.*^$3p",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(["||ads.*^"], minimized)
        self.assertEqual(stats.third_party_by_wildcard, 1)

    def test_plain_parent_covers_subdomain_third_party_rule(self):
        lines = [
            "||example.com^",
            "||sub.example.com^$3p",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(["||example.com^"], minimized)
        self.assertEqual(stats.third_party_by_domain, 1)

    def test_plain_domain_covers_third_party_wildcard_rule(self):
        lines = [
            "||example.com^",
            "||ads*.example.com^$3p",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(["||example.com^"], minimized)
        self.assertEqual(stats.third_party_by_domain, 1)

    def test_plain_wildcard_covers_third_party_wildcard_rule(self):
        lines = [
            "||ads.*^",
            "||ads.foo.*^$3p",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(["||ads.*^"], minimized)
        self.assertEqual(stats.third_party_by_wildcard, 1)

    def test_disabled_plain_cover_does_not_remove_third_party_rule(self):
        lines = [
            "||stat.example^",
            "||stat.example^$badfilter",
            "||stat.example^$3p",
        ]

        minimized, _stats = minimize_dns_lines(lines)

        self.assertEqual(
            [
                "||stat.example^$3p",
                "||stat.example^$badfilter",
            ],
            sorted(minimized),
        )

    def test_plain_rule_does_not_cover_third_party_redirect_rule(self):
        lines = [
            "||redirect.example^",
            "||redirect.example^$3p,redirect=noop.txt",
        ]

        minimized, stats = minimize_dns_lines(lines)

        self.assertEqual(lines, minimized)
        self.assertEqual(stats.third_party_by_domain, 0)


class MihomoMinimizerTest(unittest.TestCase):
    def test_semantic_duplicates_ignore_domain_case(self):
        lines = [
            "DOMAIN-SUFFIX,Example.COM",
            "DOMAIN-SUFFIX,example.com",
            "DOMAIN,Exact.COM",
            "DOMAIN,exact.com",
        ]

        minimized, stats = minimize_mihomo_lines(lines)

        self.assertEqual(
            ["DOMAIN-SUFFIX,Example.COM", "DOMAIN,Exact.COM"],
            minimized,
        )
        self.assertEqual(stats.semantic_duplicate_count, 2)

    def test_mrs_and_yaml_are_minimized_as_one_rule_set(self):
        lines = [
            "DOMAIN-SUFFIX,example.com",
            "DOMAIN-SUFFIX,sub.example.com",
            "DOMAIN,exact.example.com",
            "DOMAIN,other.test",
            "DOMAIN-WILDCARD,*.example.com",
            "DOMAIN-WILDCARD,ad*.example.com",
            "DOMAIN-WILDCARD,*.unrelated.test",
            "DOMAIN-REGEX,^ads\\.",
        ]

        minimized, stats = minimize_mihomo_lines(lines)

        self.assertIn("DOMAIN-SUFFIX,example.com", minimized)
        self.assertNotIn("DOMAIN-SUFFIX,sub.example.com", minimized)
        self.assertNotIn("DOMAIN,exact.example.com", minimized)
        self.assertNotIn("DOMAIN-WILDCARD,*.example.com", minimized)
        self.assertNotIn("DOMAIN-WILDCARD,ad*.example.com", minimized)
        self.assertIn("DOMAIN,other.test", minimized)
        self.assertIn("DOMAIN-WILDCARD,*.unrelated.test", minimized)
        self.assertIn("DOMAIN-REGEX,^ads\\.", minimized)
        self.assertEqual(stats.mihomo_suffix, 1)
        self.assertEqual(stats.mihomo_domain, 1)
        self.assertEqual(stats.mihomo_wildcard, 2)
        self.assertEqual(minimize_mihomo_lines(minimized)[0], minimized)

    def test_wildcard_subset_is_removed_without_domain_suffix(self):
        lines = [
            "DOMAIN-WILDCARD,*.foo.test",
            "DOMAIN-WILDCARD,ad*.foo.test",
            "DOMAIN-WILDCARD,ad-banner*.foo.test",
            "DOMAIN-WILDCARD,*.other.test",
        ]

        minimized, stats = minimize_mihomo_lines(lines)

        self.assertIn("DOMAIN-WILDCARD,*.foo.test", minimized)
        self.assertNotIn("DOMAIN-WILDCARD,ad*.foo.test", minimized)
        self.assertNotIn("DOMAIN-WILDCARD,ad-banner*.foo.test", minimized)
        self.assertIn("DOMAIN-WILDCARD,*.other.test", minimized)
        self.assertEqual(stats.mihomo_wildcard, 2)


if __name__ == "__main__":
    unittest.main()
