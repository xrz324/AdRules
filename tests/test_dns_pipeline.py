from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from script.dns_pipeline import (
    DnsPipelineError,
    DnsPaths,
    build_base_rules,
    build_dns,
    collapse_ipv4_networks,
    extract_advanced_rules,
    extract_badfilter_disabled_domain_rules,
    normalize_source_lines,
)


class DnsPipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "mod/rules").mkdir(parents=True)
        (self.root / "tmp/dns").mkdir(parents=True)
        (self.root / "mod/rules/dns-allowlist.txt").write_text(
            "# allowlist\n",
            encoding="utf-8",
            newline="\n",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_badfilter_and_advanced_rule_boundaries(self) -> None:
        disabled = extract_badfilter_disabled_domain_rules(
            [
                "||Example.COM^$badfilter,important",
                "||badfilter.example^",
                "||other.example^$client=desktop",
            ]
        )
        self.assertEqual(["||example.com^$important"], disabled)

        advanced = extract_advanced_rules(
            [
                "||plain.example^",
                "||important.example^$important",
                "||deny.example^$denyallow=allowed.example",
                "||empty-deny.example^$denyallow=",
                "||unsupported.example^$client=desktop",
                "/^ads\\.[^.]+\\.example$/",
                "/^ads\\.example$/ $important",
            ]
        )
        self.assertEqual(
            [
                "/^ads\\.[^.]+\\.example$/",
                "||deny.example^$denyallow=allowed.example",
                "||important.example^$important",
            ],
            advanced,
        )

    def test_base_filter_normalizes_hosts_and_drops_non_blocking_redirects(self) -> None:
        rules = build_base_rules(
            normalize_source_lines(
                [
                    "  0.0.0.0 Ads.Example.com ads2.example.com # comment  ",
                    "127.0.0.1 local.example.com",
                    "1.2.3.4 redirect.example.com",
                    " Plain.Example.com ",
                    "||Already.example^",
                    "||already.example^",
                ]
            ),
            [],
        )
        self.assertEqual(
            [
                "||ads.example.com^",
                "||ads2.example.com^",
                "||already.example^",
                "||local.example.com^",
                "||plain.example.com^",
            ],
            rules,
        )

    def test_ipv4_networks_are_collapsed_and_invalid_entries_ignored(self) -> None:
        self.assertEqual(
            ["192.0.2.0/24", "198.51.100.0/24"],
            collapse_ipv4_networks(
                [
                    "192.0.2.1/24",
                    "192.0.2.0/24",
                    "192.0.2.0/33",
                    "2001:db8::/32",
                    "198.51.100.9/24 # comment",
                ]
            ),
        )

    def test_build_dns_preserves_prune_order_and_writes_sidecar(self) -> None:
        (self.root / "mod/rules/dns-rules.txt").write_text(
            "\n".join(
                [
                    "||example.com^",
                    "||example.com^$badfilter",
                    "||sub.example.com^",
                    "||cover.example^",
                    "||child.cover.example^",
                    "0.0.0.0 ads.example.com # comment",
                    "1.2.3.4 redirect.example.com",
                    "||important.example^$important",
                    "||unsupported.example^$client=desktop",
                    "/^192\\.0\\.2\\.1$/",
                    "192.0.2.1/24",
                ]
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        (self.root / "tmp/dns/source.txt").write_text(
            "||sub.example.com^\n||extra.example^\n",
            encoding="utf-8",
            newline="\n",
        )

        paths = DnsPaths.from_root(self.root)
        result = build_dns(paths)
        output = paths.output.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.output_count, len(output))
        self.assertIn("||example.com^$badfilter", output)
        self.assertIn("||sub.example.com^", output)
        self.assertIn("||cover.example^", output)
        self.assertNotIn("||child.cover.example^", output)
        self.assertIn("||important.example^$important", output)
        self.assertIn("/^192\\.0\\.2\\.1$/", output)
        self.assertNotIn("||unsupported.example^$client=desktop", output)
        self.assertNotIn("||redirect.example.com^", output)
        self.assertEqual(
            "192.0.2.0/24\n",
            paths.ip_cidr_output.read_text(encoding="utf-8"),
        )

    def test_allowlist_runs_before_parent_compression_and_covers_advanced(self) -> None:
        (self.root / "mod/rules/dns-rules.txt").write_text(
            "\n".join(
                [
                    "||example.com^",
                    "||child.example.com^",
                    "||allow-advanced.example^$important",
                    "||keep.example^",
                ]
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        (self.root / "mod/rules/dns-allowlist.txt").write_text(
            "example.com\nallow-advanced.example\n",
            encoding="utf-8",
            newline="\n",
        )

        paths = DnsPaths.from_root(self.root)
        build_dns(paths)
        output = paths.output.read_text(encoding="utf-8").splitlines()

        self.assertNotIn("||example.com^", output)
        self.assertIn("||child.example.com^", output)
        self.assertNotIn("||allow-advanced.example^$important", output)
        self.assertIn("||keep.example^", output)

    def test_missing_allowlist_fails_before_replacing_output(self) -> None:
        source = self.root / "mod/rules/dns-rules.txt"
        source.write_text("||example.com^\n", encoding="utf-8", newline="\n")
        paths = DnsPaths.from_root(self.root)
        paths.output.write_text("previous\n", encoding="utf-8", newline="\n")
        paths.allowlist.unlink()

        with self.assertRaises(DnsPipelineError):
            build_dns(paths)
        self.assertEqual("previous\n", paths.output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
