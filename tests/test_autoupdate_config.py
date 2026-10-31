from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
from script.autoupdate_config import (
    DEFAULT_CONFIG_PATH,
    ConfigError,
    RuntimeSettings,
    artifact_paths,
    environment_values,
    load_config,
    pipeline_path,
    pipeline_paths,
    runtime_settings,
    runtime_path,
    write_github_env,
    write_github_output,
)


class AutoupdateConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.raw_config = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_config(self, raw: object) -> Path:
        path = self.root / "autoupdate.json"
        path.write_text(json.dumps(raw), encoding="utf-8", newline="\n")
        return path

    @staticmethod
    def read_assignments(path: Path) -> dict[str, str]:
        return {
            key: value
            for key, value in (
                line.split("=", 1)
                for line in path.read_text(encoding="utf-8").splitlines()
            )
        }

    def test_repository_config_exports_runtime_paths_and_artifacts(self) -> None:
        config = load_config()
        environment = environment_values(config)
        artifacts = artifact_paths(config)

        self.assertNotIn("DNS_PRUNE_RESOLVERS", environment)
        self.assertEqual(
            "223.5.5.5,223.6.6.6,114.114.114.114,119.29.29.29",
            environment["DNS_PRUNE_RESOLVERS_CN"],
        )
        self.assertEqual(
            "8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1",
            environment["DNS_PRUNE_RESOLVERS_GLOBAL"],
        )
        self.assertEqual("500", environment["DNS_PRUNE_CN_QUERY_DELAY_MS"])
        self.assertEqual("500", environment["DNS_PRUNE_CN_BACKOFF_BASE_MS"])
        self.assertEqual("8000", environment["DNS_PRUNE_CN_BACKOFF_MAX_MS"])
        self.assertEqual("3", environment["DNS_PRUNE_CN_FAILURE_THRESHOLD"])
        self.assertEqual("10000", environment["DNS_PRUNE_CN_COOLDOWN_MS"])
        self.assertEqual("4000", environment["DNS_PRUNE_CN_SLOW_THRESHOLD_MS"])
        self.assertEqual("dns_prune_cache.json", environment["DNS_PRUNE_CACHE_FILE"])
        self.assertEqual(
            "tmp/dns_prune_removed_rules.txt",
            environment["DNS_PRUNE_REMOVED_LOG"],
        )
        self.assertEqual("download_failed.log", environment["DOWNLOAD_FAILED_LOG"])
        self.assertEqual("adblock.txt", artifacts["adblock"])
        self.assertEqual("adrules-mihomo.yaml", artifacts["mihomo_yaml"])
        self.assertEqual(
            "download_failed.log",
            runtime_path(config, "download_failed_log"),
        )
        paths = pipeline_paths(config)
        self.assertEqual("config/upstream.json", paths["upstream_config"])
        self.assertEqual("config/converter.json", pipeline_path(config, "converter_config"))
        self.assertEqual("tmp/baseline", paths["baseline_dir"])

    def test_github_exports_are_derived_from_the_same_config(self) -> None:
        config = load_config()
        github_env = self.root / "github-env"
        github_output = self.root / "github-output"

        write_github_env(config, github_env)
        write_github_output(config, github_output)

        environment = self.read_assignments(github_env)
        outputs = self.read_assignments(github_output)
        self.assertEqual(
            environment["DNS_PRUNE_CACHE_FILE"],
            outputs["dns_prune_cache_file"],
        )
        self.assertEqual("dns.txt", outputs["artifact_dns_path"])
        self.assertEqual("config/upstream.json", outputs["upstream_config_path"])
        self.assertEqual("config/converter.json", outputs["converter_config_path"])
        self.assertEqual("1", outputs["config_version"])

    def test_rejects_unsafe_runtime_paths(self) -> None:
        raw = copy.deepcopy(self.raw_config)
        raw["runtime"]["dns_prune_cache"] = "../cache.json"

        with self.assertRaises(ConfigError):
            load_config(self.write_config(raw))

    def test_rejects_unsafe_pipeline_paths(self) -> None:
        raw = copy.deepcopy(self.raw_config)
        raw["paths"]["converter_config"] = "../converter.json"

        with self.assertRaises(ConfigError):
            load_config(self.write_config(raw))

    def test_rejects_null_pipeline_paths(self) -> None:
        raw = copy.deepcopy(self.raw_config)
        raw["paths"] = None

        with self.assertRaises(ConfigError):
            load_config(self.write_config(raw))

    def test_rejects_unknown_config_version(self) -> None:
        raw = copy.deepcopy(self.raw_config)
        raw["version"] = 2

        with self.assertRaises(ConfigError):
            load_config(self.write_config(raw))

    def test_rejects_runtime_environment_duplicates(self) -> None:
        raw = copy.deepcopy(self.raw_config)
        raw["environment"]["DNS_PRUNE_CACHE_FILE"] = "other-cache.json"

        with self.assertRaises(ConfigError):
            load_config(self.write_config(raw))

    def test_rejects_duplicate_artifact_names(self) -> None:
        raw = copy.deepcopy(self.raw_config)
        raw["artifacts"][1]["name"] = "adblock"

        with self.assertRaises(ConfigError):
            load_config(self.write_config(raw))

    def test_rejects_duplicate_artifact_paths(self) -> None:
        raw = copy.deepcopy(self.raw_config)
        raw["artifacts"][1]["path"] = raw["artifacts"][0]["path"]

        with self.assertRaises(ConfigError):
            load_config(self.write_config(raw))

    def test_runtime_settings_are_typed_and_repository_values_win(self) -> None:
        config = load_config()
        settings = runtime_settings(
            config,
            {
                **os.environ,
                "DNS_PRUNE_ENABLED": "false",
                "MAX_RULE_DROP_PERCENT": "3",
                "SECRET_TOKEN": "do-not-forward",
            },
        )

        self.assertIsInstance(settings, RuntimeSettings)
        self.assertTrue(settings.dns_prune_enabled)
        self.assertEqual(40.0, settings.max_rule_drop_percent)
        self.assertEqual("true", settings.environment["DNS_PRUNE_ENABLED"])
        self.assertNotIn("SECRET_TOKEN", settings.dns_environment)
        self.assertNotIn("SECRET_TOKEN", settings.upstream_environment)
        self.assertNotIn("SECRET_TOKEN", settings.converter_environment)
        with self.assertRaises(TypeError):
            settings.environment["NEW_SETTING"] = "value"  # type: ignore[index]

    def test_runtime_settings_reject_invalid_policy_values_at_boundary(self) -> None:
        raw = copy.deepcopy(self.raw_config)
        raw["environment"]["DNS_PRUNE_ENABLED"] = "sometimes"
        config = load_config(self.write_config(raw))
        with self.assertRaises(ConfigError):
            runtime_settings(config, {})

        raw = copy.deepcopy(self.raw_config)
        raw["environment"]["MAX_RULE_DROP_PERCENT"] = "100"
        config = load_config(self.write_config(raw))
        with self.assertRaises(ConfigError):
            runtime_settings(config, {})


if __name__ == "__main__":
    unittest.main()
