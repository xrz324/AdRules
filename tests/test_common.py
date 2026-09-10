from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import script.common as common


class AtomicWriteBundleTest(unittest.TestCase):
    def test_metadata_comparison_ignores_only_selected_line_values(self) -> None:
        existing = "header\n! Version: old\nbody\n"
        generated = "header\n! Version: new\nbody\n"

        self.assertTrue(
            common.text_matches_ignoring_prefixed_lines(
                existing,
                generated,
                ("! Version: ",),
            )
        )
        self.assertFalse(
            common.text_matches_ignoring_prefixed_lines(
                existing,
                generated.replace("body", "changed"),
                ("! Version: ",),
            )
        )

    def test_replacement_failure_restores_all_previous_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.txt"
            second = root / "second.txt"
            first.write_text("old first\n", encoding="utf-8")
            second.write_text("old second\n", encoding="utf-8")

            original_replace = common.os.replace

            def fail_second(source: str | bytes, target: str | bytes) -> None:
                source_path = Path(source)
                target_path = Path(target)
                if target_path == second and source_path.suffix == ".tmp":
                    raise OSError("injected replace failure")
                original_replace(source, target)

            with patch.object(common.os, "replace", side_effect=fail_second):
                with self.assertRaises(OSError):
                    common.atomic_write_text_bundle(
                        {first: "new first\n", second: "new second\n"}
                    )

            self.assertEqual("old first\n", first.read_text(encoding="utf-8"))
            self.assertEqual("old second\n", second.read_text(encoding="utf-8"))
            self.assertEqual([], list(root.glob(".*.tmp")))
            self.assertEqual([], list(root.glob(".*.bak")))


if __name__ == "__main__":
    unittest.main()
