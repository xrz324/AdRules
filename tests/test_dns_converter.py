from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
from script.dns_converter import (
    ConverterConfigError,
    DnsConverterError,
    extract_mihomo_asset_url,
    load_converter_config,
    resolve_converter_settings,
    run_conversion,
)
from script.dns_converter_io import publish_artifacts


class DnsConverterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "tmp/tools").mkdir(parents=True)
        (self.root / "config").mkdir(exist_ok=True)
        (self.root / "config/converter.json").write_text(
            (ROOT_DIR / "config/converter.json").read_text(encoding="utf-8"),
            encoding="utf-8",
            newline="\n",
        )
        self.dns_file = self.root / "dns.txt"
        self.cidr_file = self.root / "tmp/dns_ip_cidr_rules.txt"
        self.dns_file.write_text(
            "\n".join(
                (
                    "! title",
                    "||example.com^",
                    "||sub.example.com^",
                    "||ad.*^",
                    "||*.wild.example^",
                    "||metric.*^$denyallow=allow.*",
                    "/^192\\.0\\.2\\.1$/",
                    "||payload.example^$denyallow=allow.example",
                )
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self.cidr_file.write_text("192.0.2.0/24\n", encoding="utf-8", newline="\n")
        self._write_stub_tools()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_stub_tools(self) -> None:
        singbox = self.root / "tmp/tools/sing-box"
        singbox.write_text(
            """#!/bin/bash
set -euo pipefail
input="$3"
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    output="$2"
    break
  fi
  shift
done
cp "$input" "${SINGBOX_CAPTURE:-/dev/null}"
printf 'sing-box fixture\\n' > "$output"
printf 'INFO[0000] parsed rules: 8/8\\n' >&2
""",
            encoding="utf-8",
            newline="\n",
        )
        mihomo = self.root / "tmp/tools/mihomo"
        mihomo.write_text(
            """#!/bin/bash
set -euo pipefail
[[ "${1:-}" == "convert-ruleset" ]]
if [[ -n "${MIHOMO_CAPTURE:-}" ]]; then
  cp "$4" "$MIHOMO_CAPTURE"
fi
printf 'mihomo fixture\\n' > "${!#}"
printf 'INFO[0000] parsed rules: 2/2\\n' >&2
""",
            encoding="utf-8",
            newline="\n",
        )
        singbox.chmod(0o755)
        mihomo.chmod(0o755)

    def test_asset_selection_preserves_preference_scores(self) -> None:
        release = {
            "assets": [
                {
                    "name": "mihomo-linux-amd64-v1-v1.0.0.gz",
                    "browser_download_url": "https://example.invalid/v1.gz",
                },
                {
                    "name": "mihomo-linux-amd64-v2-v1.0.0.gz",
                    "browser_download_url": "https://example.invalid/v2.gz",
                },
                {
                    "name": "mihomo-linux-amd64-compatible-v1.0.0.gz",
                    "browser_download_url": "https://example.invalid/compatible.gz",
                },
            ]
        }
        self.assertEqual(
            "https://example.invalid/v2.gz",
            extract_mihomo_asset_url(release, "v2"),
        )
        self.assertEqual(
            "https://example.invalid/v1.gz",
            extract_mihomo_asset_url(release, "v1"),
        )

    def test_local_binaries_are_used_and_outputs_are_atomic(self) -> None:
        capture = self.root / "singbox-input.txt"
        mihomo_capture = self.root / "mihomo-domain-input.txt"
        old_singbox = self.root / "adrules-singbox.srs"
        old_mrs = self.root / "adrules-mihomo.mrs"
        old_yaml = self.root / "adrules-mihomo.yaml"

        def downloader(url: str, output: Path) -> bool:
            raise AssertionError(f"unexpected download: {url} -> {output}")

        with self.assertLogs("adrules", level="INFO") as logs:
            result = run_conversion(
                self.root,
                dns_input=self.dns_file,
                ip_cidr_input=self.cidr_file,
                awk_dir=ROOT_DIR / "script",
                downloader=downloader,
                strict=True,
                environment={
                    **os.environ,
                    "MIHOMO_CAPTURE": str(mihomo_capture),
                    "SINGBOX_CAPTURE": str(capture),
                },
            )

        self.assertTrue(result.success)
        self.assertIn("INFO:adrules:parsed rules: 8/8", logs.output)
        self.assertIn("INFO:adrules:parsed rules: 2/2", logs.output)
        self.assertEqual("sing-box fixture\n", old_singbox.read_text(encoding="utf-8"))
        self.assertEqual("mihomo fixture\n", old_mrs.read_text(encoding="utf-8"))
        yaml = old_yaml.read_text(encoding="utf-8")
        self.assertIn("AND,((DOMAIN-SUFFIX,payload.example)", yaml)
        self.assertIn("DOMAIN-WILDCARD,ad.*", yaml)
        self.assertIn("DOMAIN-WILDCARD,*.ad.*", yaml)
        self.assertNotIn("DOMAIN-REGEX,(^|\\.)ad\\..*$", yaml)
        self.assertIn(
            "OR,((DOMAIN-WILDCARD,metric.*),(DOMAIN-WILDCARD,*.metric.*))",
            yaml,
        )
        self.assertIn(
            "OR,((DOMAIN-WILDCARD,allow.*),(DOMAIN-WILDCARD,*.allow.*))",
            yaml,
        )
        self.assertIn("IP-CIDR,192.0.2.1/32", yaml)
        self.assertIn(
            ".wild.example",
            mihomo_capture.read_text(encoding="utf-8").splitlines(),
        )
        self.assertNotIn(
            "*.wild.example",
            mihomo_capture.read_text(encoding="utf-8").splitlines(),
        )
        self.assertTrue(capture.is_file())
        self.assertIn("||sub.example.com^", capture.read_text(encoding="utf-8"))
        self.assertFalse((self.root / "tmp/mihomo_classical.txt").exists())
        self.assertFalse((self.root / "tmp/singbox_dns.txt").exists())

    def test_strict_modifier_failure_keeps_existing_mihomo_artifacts(self) -> None:
        self.dns_file.write_text(
            "||keep.example^\n||unsupported.example^$client=desktop\n",
            encoding="utf-8",
            newline="\n",
        )
        old_mrs = self.root / "adrules-mihomo.mrs"
        old_yaml = self.root / "adrules-mihomo.yaml"
        old_mrs.write_text("old mrs\n", encoding="utf-8", newline="\n")
        old_yaml.write_text("old yaml\n", encoding="utf-8", newline="\n")

        with self.assertRaises(DnsConverterError):
            run_conversion(
                self.root,
                dns_input=self.dns_file,
                ip_cidr_input=self.cidr_file,
                awk_dir=ROOT_DIR / "script",
                strict=True,
                strict_mihomo_modifiers=True,
                environment={},
            )

        self.assertEqual("old mrs\n", old_mrs.read_text(encoding="utf-8"))
        self.assertEqual("old yaml\n", old_yaml.read_text(encoding="utf-8"))
        self.assertFalse((self.root / "tmp/mihomo_classical.txt").exists())

    def test_config_validation_rejects_missing_template(self) -> None:
        config = self.root / "config/bad.json"
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "singbox": {
                        "version": "1.0",
                        "download_url": "https://example.invalid/tool.tar.gz",
                    },
                    "mihomo": {
                        "channel": "stable",
                        "version": "",
                        "api_base": "https://example.invalid/api",
                    },
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(ConverterConfigError):
            load_converter_config(config)

    def test_settings_resolver_uses_only_explicit_environment(self) -> None:
        config = load_converter_config(self.root / "config/converter.json")
        with patch.dict(
            os.environ,
            {
                "SINGBOX_VERSION": "99.0",
                "STRICT_DNS_CONVERTER": "true",
            },
        ):
            settings = resolve_converter_settings(config, {})

        self.assertEqual(config.singbox.version, settings.singbox.version)
        self.assertFalse(settings.strict)

        overridden = resolve_converter_settings(
            config,
            {
                "SINGBOX_VERSION": "v2.0",
                "MIHOMO_CHANNEL": "preview",
                "STRICT_DNS_CONVERTER": "yes",
            },
        )
        self.assertEqual("2.0", overridden.singbox.version)
        self.assertEqual("preview", overridden.mihomo.channel)
        self.assertTrue(overridden.strict)

    def test_group_publication_rolls_back_all_existing_artifacts(self) -> None:
        source_mrs = self.root / "tmp/new.mrs"
        source_yaml = self.root / "tmp/new.yaml"
        output_mrs = self.root / "adrules-mihomo.mrs"
        output_yaml = self.root / "adrules-mihomo.yaml"
        source_mrs.write_text("new mrs\n", encoding="utf-8", newline="\n")
        source_yaml.write_text("new yaml\n", encoding="utf-8", newline="\n")
        output_mrs.write_text("old mrs\n", encoding="utf-8", newline="\n")
        output_yaml.write_text("old yaml\n", encoding="utf-8", newline="\n")
        real_replace = os.replace

        def fail_second_publish(source: object, destination: object) -> None:
            if Path(source) == source_yaml and Path(destination) == output_yaml:
                raise OSError("fixture publish failure")
            real_replace(source, destination)

        with patch(
            "script.dns_converter_io.os.replace", side_effect=fail_second_publish
        ):
            with self.assertRaises(OSError):
                publish_artifacts(
                    (
                        (source_mrs, output_mrs),
                        (source_yaml, output_yaml),
                    )
                )

        self.assertEqual("old mrs\n", output_mrs.read_text(encoding="utf-8"))
        self.assertEqual("old yaml\n", output_yaml.read_text(encoding="utf-8"))
        self.assertEqual([], list(self.root.glob(".*.bak")))


if __name__ == "__main__":
    unittest.main()
