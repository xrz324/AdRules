from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from script.dns_output import DnsOutputError, finalize_dns_output, render_dns_output


class DnsOutputTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_render_adds_title_count_and_update_headers(self) -> None:
        rendered = render_dns_output(
            ["\ufeff[Adblock Plus 2.0]", "! Title: Fixture", ""],
            ["||ads.example^", "||tracker.example^"],
            datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        )

        self.assertEqual(
            "[Adblock Plus 2.0]\n"
            "! Title: Fixture\n"
            "! Total count: 2\n"
            "! Update: 2026-01-02 11:04:05(GMT+8)\n"
            "||ads.example^\n"
            "||tracker.example^\n",
            rendered,
        )

    def test_finalize_is_atomic_and_keeps_rule_count_body(self) -> None:
        title = self.root / "mod/title/dns-title.txt"
        title.parent.mkdir(parents=True)
        title.write_text(
            "[Adblock Plus 2.0]\n! Fixture\n",
            encoding="utf-8",
            newline="\n",
        )
        rules = self.root / "tmp/dns.txt"
        rules.parent.mkdir(parents=True)
        rules.write_text("||ads.example^\n", encoding="utf-8", newline="\n")
        output = self.root / "generated/dns.txt"

        result = finalize_dns_output(
            rules,
            title_file=title,
            output_file=output,
            timestamp=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        )

        self.assertEqual(output, result.output_file)
        self.assertEqual(1, result.rule_count)
        self.assertIn("! Total count: 1\n", output.read_text(encoding="utf-8"))
        self.assertFalse(
            any(
                path.name.startswith(".dns.txt.")
                for path in output.parent.iterdir()
            )
        )

    def test_rejects_carriage_returns_without_replacing_existing_output(self) -> None:
        rules = self.root / "dns.txt"
        rules.write_bytes(b"||ads.example^\r\n")
        output = self.root / "published.txt"
        output.write_text("old\n", encoding="utf-8", newline="\n")

        with self.assertRaises(DnsOutputError):
            finalize_dns_output(rules, output_file=output)

        self.assertEqual("old\n", output.read_text(encoding="utf-8"))

    def test_finalize_preserves_timestamp_when_rules_are_unchanged(self) -> None:
        rules = self.root / "rules.txt"
        output = self.root / "dns.txt"
        rules.write_text("||stable.example^\n", encoding="utf-8", newline="\n")

        finalize_dns_output(
            rules,
            output_file=output,
            timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        before = output.read_bytes()
        finalize_dns_output(
            rules,
            output_file=output,
            timestamp=datetime(2026, 1, 3, tzinfo=timezone.utc),
        )

        self.assertEqual(before, output.read_bytes())
        self.assertIn(b"! Update: 2026-01-02 08:00:00(GMT+8)", before)

    def test_finalize_restores_previous_output_after_input_was_overwritten(self) -> None:
        rules = self.root / "dns.txt"
        baseline = self.root / "tmp/baseline/dns.txt"
        baseline.parent.mkdir(parents=True)
        baseline.write_text(
            "! Total count: 1\n"
            "! Update: 2026-01-02 08:00:00(GMT+8)\n"
            "||stable.example^\n",
            encoding="utf-8",
            newline="\n",
        )
        rules.write_text("||stable.example^\n", encoding="utf-8", newline="\n")

        finalize_dns_output(
            rules,
            output_file=rules,
            previous_output_file=baseline,
            timestamp=datetime(2026, 1, 3, tzinfo=timezone.utc),
        )

        self.assertEqual(baseline.read_bytes(), rules.read_bytes())


if __name__ == "__main__":
    unittest.main()
