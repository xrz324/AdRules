from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
from script.autoupdate_config import DEFAULT_CONFIG_PATH
from script.validate_outputs import (
    DEFAULT_MAX_DROP_PERCENT,
    RuleFileStats,
    ValidationError,
    _optional_baseline,
    resolve_artifact_paths,
    validate_binary,
    validate_drop,
    validate_mihomo_yaml,
    validate_rule_file,
    validate_artifacts,
)


class ValidateOutputsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_rules(self, name: str, rules: list[str], declared: int | None = None) -> Path:
        path = self.root / name
        count = len(rules) if declared is None else declared
        path.write_text(
            "\n".join(
                [
                    "[Adblock Plus 2.0]",
                    "! Title: Test",
                    f"! Total count: {count}",
                    *rules,
                    "",
                ]
            ),
            encoding="utf-8",
            newline="\n",
        )
        return path

    def test_validates_rule_count_and_dns_shape(self) -> None:
        path = self.write_rules(
            "dns.txt",
            ["/^ads\\./", "||ads.example^", "||tracker.example^$important"],
        )
        stats = validate_rule_file(path, "dns")
        self.assertEqual(3, stats.rule_count)

    def test_rejects_mismatched_count_and_duplicates(self) -> None:
        mismatch = self.write_rules("mismatch.txt", ["||ads.example^"], declared=2)
        duplicate = self.write_rules(
            "duplicate.txt", ["||ads.example^", "||ads.example^"]
        )

        with self.assertRaises(ValidationError):
            validate_rule_file(mismatch, "dns")
        with self.assertRaises(ValidationError):
            validate_rule_file(duplicate, "dns")

    def test_rejects_bom_at_start_of_rule(self) -> None:
        path = self.write_rules("adblock.txt", ["\ufeff! Upstream metadata"])

        with self.assertRaises(ValidationError):
            validate_rule_file(path, "adblock")
        with self.assertRaises(ValidationError):
            _optional_baseline(str(path), "adblock")

    def test_rejects_abnormal_rule_drop(self) -> None:
        baseline = RuleFileStats(self.root / "old.txt", 100)
        current = RuleFileStats(self.root / "new.txt", 59)

        with self.assertRaises(ValidationError):
            validate_drop(current, baseline, DEFAULT_MAX_DROP_PERCENT)
        validate_drop(
            RuleFileStats(self.root / "safe.txt", 60),
            baseline,
            DEFAULT_MAX_DROP_PERCENT,
        )

    def test_validates_proxy_artifacts(self) -> None:
        singbox = self.root / "rules.srs"
        singbox.write_bytes(b"SRS\x02" + b"x" * 16)
        mrs = self.root / "rules.mrs"
        mrs.write_bytes(b"\x28\xb5\x2f\xfd" + b"x" * 16)
        yaml = self.root / "rules.yaml"
        yaml.write_text("payload:\n  - 'DOMAIN,ads.example'\n", encoding="utf-8")

        validate_binary(singbox, b"SRS", "sing-box")
        validate_binary(mrs, b"\x28\xb5\x2f\xfd", "Mihomo MRS")
        validate_mihomo_yaml(yaml)

    def test_resolves_artifact_paths_from_config_with_cli_overrides(self) -> None:
        raw_config = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
        raw_config["artifacts"][0]["path"] = "out/adblock.rules"
        config_path = self.root / "autoupdate.json"
        config_path.write_text(json.dumps(raw_config), encoding="utf-8", newline="\n")

        paths = resolve_artifact_paths(config_path, {"dns": "override-dns.txt"})

        self.assertEqual(Path("out/adblock.rules"), paths["adblock"])
        self.assertEqual(Path("override-dns.txt"), paths["dns"])

    def test_embedded_validation_resolves_manifest_against_explicit_root(self) -> None:
        config_path = self.root / "autoupdate.json"
        raw_config = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
        config_path.write_text(json.dumps(raw_config), encoding="utf-8", newline="\n")

        artifacts = {
            "adblock": self.root / "adblock.txt",
            "dns": self.root / "dns.txt",
            "singbox": self.root / "rules.srs",
            "mihomo_mrs": self.root / "rules.mrs",
            "mihomo_yaml": self.root / "rules.yaml",
        }
        for name in ("adblock", "dns"):
            self.write_rules(artifacts[name].name, [f"||{name}.example^"])
        artifacts["singbox"].write_bytes(b"SRS\x02" + b"x" * 16)
        artifacts["mihomo_mrs"].write_bytes(b"\x28\xb5\x2f\xfd" + b"x" * 16)
        artifacts["mihomo_yaml"].write_text(
            "payload: []\n",
            encoding="utf-8",
            newline="\n",
        )

        adblock, dns = validate_artifacts(
            Path("autoupdate.json"),
            artifact_overrides=artifacts,
            root_dir=self.root,
        )

        self.assertEqual(1, adblock.rule_count)
        self.assertEqual(1, dns.rule_count)


if __name__ == "__main__":
    unittest.main()
