from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from script.dns_cache_report import compare_cache, snapshot_cache
from script.dns_prune_cache import load_cache


class DnsCacheReportTest(unittest.TestCase):
    def test_snapshot_and_compare_report_inactive_entry_delta(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "before.json"
            after = root / "after.json"
            snapshot = root / "snapshot.json"
            before.write_text(
                json.dumps(
                    {
                        "domains": {
                            "keep.example": {"status": "dead"},
                            "old.example": {"status": "dead"},
                            "alive.example": {"status": "alive"},
                        }
                    }
                ),
                encoding="utf-8",
            )
            after.write_text(
                json.dumps(
                    {
                        "domains": {
                            "keep.example": {"status": "dead"},
                            "new.example": {"status": "dead"},
                            "unknown.example": {"status": "unknown"},
                        }
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(2, snapshot_cache(before, snapshot))
            self.assertEqual(
                {
                    "inactive_entries": 2,
                    "inactive_added": 1,
                    "inactive_removed": 1,
                },
                compare_cache(snapshot, after),
            )

    def test_invalid_or_missing_cache_is_treated_as_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = root / "invalid.json"
            invalid.write_text("not json", encoding="utf-8")

            self.assertEqual(0, snapshot_cache(invalid, root / "snapshot.json"))
            self.assertEqual(
                {
                    "inactive_entries": 0,
                    "inactive_added": 0,
                    "inactive_removed": 0,
                },
                compare_cache(root / "missing.json", invalid),
            )

    def test_valid_json_scalar_is_a_recoverable_cache_miss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scalar.json"
            path.write_text("[]", encoding="utf-8")

            result = load_cache(path)

            self.assertEqual({}, result.entries)
            self.assertEqual("invalid", result.state)


if __name__ == "__main__":
    unittest.main()
