from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
from script.content_pipeline import (
    ContentPaths,
    ContentPipelineError,
    apply_remove_list,
    build_content,
    filter_rule_lines,
    prune_covered_content_domains,
)


class ContentPipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.paths = ContentPaths.from_root(self.root)
        self.paths.rules_file.parent.mkdir(parents=True)
        self.paths.title_file.parent.mkdir(parents=True)
        self.paths.content_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def test_filter_keeps_only_supported_cosmetic_prefixes(self) -> None:
        lines = (
            "",
            "  ! comment",
            "[Adblock Plus 2.0]",
            "  # unsupported comment",
            "  ##.global",
            "  #@?#div:has-text(ad)",
            "||network.example^",
        )

        self.assertEqual(
            ["  ##.global", "  #@?#div:has-text(ad)", "||network.example^"],
            filter_rule_lines(lines),
        )

    def test_remove_list_is_exact_and_optional(self) -> None:
        remove_file = self.root / "remove.txt"
        self.write(remove_file, "exact\n")

        self.assertEqual(
            ["exactly", "other"],
            apply_remove_list(("exact", "exactly", "other"), remove_file),
        )
        self.assertEqual(
            ["exact", "other"],
            apply_remove_list(("exact", "other"), self.root / "missing.txt"),
        )

    def test_parent_prune_respects_exact_badfilter(self) -> None:
        lines = (
            "||example.com^",
            "||example.com^$badfilter",
            "||child.example.com^",
            "||active.test^",
            "||child.active.test^",
            "||active.test^$badfilter,important",
            "||child.active.test^$important",
        )

        self.assertEqual(
            [
                "||example.com^$badfilter",
                "||child.example.com^",
                "||active.test^",
                "||active.test^$badfilter,important",
                "||child.active.test^$important",
            ],
            prune_covered_content_domains(lines),
        )

    def test_wildcard_prune_covers_domains_and_parent_suffixes(self) -> None:
        lines = (
            "||track.*^",
            "||track.example^",
            "||sub.track.test^",
            "||nottrack.example^",
            "||track.example^$important",
        )

        self.assertEqual(
            [
                "||track.*^",
                "||nottrack.example^",
                "||track.example^$important",
            ],
            prune_covered_content_domains(lines),
        )

    def test_disabled_wildcard_does_not_cover_domains(self) -> None:
        lines = (
            "||track.*^",
            "||track.*^$badfilter",
            "||track.example^",
        )

        self.assertEqual(
            ("||track.*^$badfilter", "||track.example^"),
            tuple(prune_covered_content_domains(lines)),
        )

    def test_build_uses_sources_minimizer_and_atomic_output(self) -> None:
        self.write(
            self.paths.rules_file,
            "\n".join(
                (
                    "! comment",
                    "||parent.example^",
                    "||child.parent.example^",
                    "||remove.example^",
                    "##.sponsor",
                )
            )
            + "\n",
        )
        self.write(self.paths.remove_file, "||remove.example^\n")
        self.write(
            self.paths.content_dir / "b.txt",
            "b.example##.sponsor\n@@||exception.example^$generichide\n",
        )
        self.write(self.paths.content_dir / "a.txt", "a.example##.sponsor\n")
        self.write(self.paths.title_file, "[Adblock Plus 2.0]\n! Fixture\n")

        result = build_content(
            self.root,
            timestamp=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
            output_file=Path("generated/adblock.txt"),
        )

        self.assertEqual(self.root / "generated/adblock.txt", result.output_file)
        self.assertEqual(4, result.rule_count)
        self.assertEqual(7, result.remove_list_input_count)
        output = result.output_file.read_text(encoding="utf-8")
        self.assertIn("! Version: 2026-01-02 11:04:05(GMT+8)\n", output)
        self.assertIn("! Total count: 4\n", output)
        self.assertIn("||parent.example^\n", output)
        self.assertNotIn("||child.parent.example^\n", output)
        self.assertIn("a.example,b.example##.sponsor\n", output)
        self.assertIn("@@||exception.example^$generichide\n", output)
        self.assertFalse(
            any(
                path.name.startswith(".adblock.txt.")
                for path in self.root.iterdir()
            )
        )

    def test_build_prunes_concrete_unanchored_image_patterns(self) -> None:
        self.write(
            self.paths.rules_file,
            "*.marketingcloudqaops.com$image\n",
        )
        self.write(
            self.paths.content_dir / "source.txt",
            "5078.sfap-qa1.marketingcloudqaops.com$image\n",
        )
        self.write(self.paths.title_file, "[Adblock Plus 2.0]\n")

        result = build_content(self.root)

        output = result.output_file.read_text(encoding="utf-8")
        self.assertIn("*.marketingcloudqaops.com$image\n", output)
        self.assertNotIn(
            "5078.sfap-qa1.marketingcloudqaops.com$image\n",
            output,
        )
        self.assertEqual(1, result.minimized.url_pattern_redundancy_count)

    def test_build_preserves_timestamp_when_rules_are_unchanged(self) -> None:
        self.write(self.paths.rules_file, "||stable.example^\n")
        self.write(self.paths.title_file, "[Adblock Plus 2.0]\n")
        first_timestamp = datetime(2026, 1, 2, tzinfo=timezone.utc)
        second_timestamp = datetime(2026, 1, 3, tzinfo=timezone.utc)

        build_content(self.root, timestamp=first_timestamp)
        before = self.paths.output_file.read_bytes()
        build_content(self.root, timestamp=second_timestamp)

        self.assertEqual(before, self.paths.output_file.read_bytes())
        self.assertIn(b"! Version: 2026-01-02 08:00:00(GMT+8)", before)

    def test_build_prunes_exact_ids_covered_by_global_attribute_rule(self) -> None:
        self.write(
            self.paths.rules_file,
            '##[id^="ad-"]\n',
        )
        self.write(
            self.paths.content_dir / "source.txt",
            "###ad-banner\nexample.com###ad-banner\n",
        )
        self.write(self.paths.title_file, "[Adblock Plus 2.0]\n")

        result = build_content(self.root)

        output = result.output_file.read_text(encoding="utf-8")
        self.assertIn('##[id^="ad-"]\n', output)
        self.assertNotIn("\n###ad-banner\n", output)
        self.assertIn("example.com###ad-banner\n", output)
        self.assertEqual(1, result.minimized.cosmetic.saved_lines)

    def test_missing_title_is_reported_before_writing_output(self) -> None:
        self.write(self.paths.rules_file, "||example.test^\n")

        with self.assertRaises(ContentPipelineError):
            build_content(self.root)
        self.assertFalse(self.paths.output_file.exists())

    def test_invalid_source_encoding_does_not_replace_existing_output(self) -> None:
        self.write(self.paths.rules_file, "||old.example^\n")
        self.write(self.paths.title_file, "[Adblock Plus 2.0]\n")
        self.write(self.paths.output_file, "old output\n")
        (self.paths.content_dir / "broken.txt").write_bytes(b"\xff\n")

        with self.assertRaises(ContentPipelineError):
            build_content(self.root)
        self.assertEqual(
            "old output\n",
            self.paths.output_file.read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
