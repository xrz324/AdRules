from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import script.publish_pipeline as publish_pipeline
from script.publish_pipeline import PublishPipelineError, stage_artifacts


class PublishPipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "config").mkdir()
        (self.root / "config/autoupdate.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "environment": {},
                    "runtime": {
                        "dns_prune_cache": "dns_prune_cache.json",
                        "dns_prune_log": "tmp/dns-prune.log",
                        "download_failed_log": "download_failed.log",
                    },
                    "artifacts": [
                        {
                            "name": "adblock",
                            "path": "adblock.txt",
                            "kind": "adblock",
                            "required": True,
                        },
                        {
                            "name": "dns",
                            "path": "dns.txt",
                            "kind": "dns",
                            "required": True,
                        },
                        {
                            "name": "singbox",
                            "path": "rules.srs",
                            "kind": "binary",
                            "required": False,
                        },
                        {
                            "name": "mihomo_mrs",
                            "path": "rules.mrs",
                            "kind": "binary",
                            "required": False,
                        },
                        {
                            "name": "mihomo_yaml",
                            "path": "rules.yaml",
                            "kind": "yaml",
                            "required": False,
                        },
                    ],
                }
            ),
            encoding="utf-8",
            newline="\n",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _git(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ("git", *arguments),
            cwd=self.root,
            check=check,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    def _init_repository(self, *, optional_files: bool = True) -> None:
        for path in ("adblock.txt", "dns.txt"):
            (self.root / path).write_text(
                f"old {path}\n", encoding="utf-8", newline="\n"
            )
        if optional_files:
            for path in ("rules.srs", "rules.mrs", "rules.yaml"):
                (self.root / path).write_text(
                    f"old {path}\n", encoding="utf-8", newline="\n"
                )
        (self.root / "download_failed.log").write_text(
            "old failure\n", encoding="utf-8", newline="\n"
        )
        self._git("init", "-q")
        self._git("config", "user.name", "test")
        self._git("config", "user.email", "test@example.com")
        self._git("add", ".")
        self._git("commit", "-qm", "baseline")

    def test_stages_manifest_outputs_and_removes_obsolete_files(self) -> None:
        self._init_repository()
        for path in ("adblock.txt", "dns.txt", "rules.srs"):
            (self.root / path).write_text(
                f"new {path}\n", encoding="utf-8", newline="\n"
            )
        (self.root / "rules.mrs").unlink()

        result = stage_artifacts(
            self.root,
            config_path=Path("config/autoupdate.json"),
        )

        self.assertEqual(
            {Path("adblock.txt"), Path("dns.txt"), Path("rules.srs"), Path("rules.yaml")},
            set(result.staged),
        )
        self.assertEqual(
            {Path("rules.mrs"), Path("download_failed.log")},
            set(result.removed),
        )
        self.assertEqual((), result.skipped)
        staged = self._git("diff", "--cached", "--name-status").stdout.splitlines()
        self.assertIn("M\tadblock.txt", staged)
        self.assertIn("M\tdns.txt", staged)
        self.assertIn("M\trules.srs", staged)
        self.assertIn("D\trules.mrs", staged)
        self.assertIn("D\tdownload_failed.log", staged)

    def test_required_output_is_preflighted_before_index_mutation(self) -> None:
        self._init_repository()
        (self.root / "dns.txt").unlink()

        with self.assertRaises(PublishPipelineError) as context:
            stage_artifacts(self.root)

        self.assertIn("missing required output: dns.txt", str(context.exception))
        self.assertEqual(0, self._git("diff", "--cached", "--quiet").returncode)

    def test_untracked_optional_output_is_skipped(self) -> None:
        self._init_repository(optional_files=False)

        result = stage_artifacts(self.root)

        self.assertEqual(
            {Path("rules.srs"), Path("rules.mrs"), Path("rules.yaml")},
            set(result.skipped),
        )
        self.assertEqual({Path("download_failed.log")}, set(result.removed))

    def test_staging_failure_restores_the_original_index(self) -> None:
        self._init_repository()
        (self.root / "adblock.txt").write_text(
            "new adblock\n", encoding="utf-8", newline="\n"
        )
        (self.root / "dns.txt").write_text(
            "new dns\n", encoding="utf-8", newline="\n"
        )
        original_git = publish_pipeline._git

        def fail_on_dns(
            root_dir: Path,
            arguments: tuple[str, ...],
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            if arguments == ("add", "--", "dns.txt"):
                raise PublishPipelineError("injected staging failure")
            return original_git(root_dir, arguments, **kwargs)

        with patch.object(publish_pipeline, "_git", side_effect=fail_on_dns):
            with self.assertRaises(PublishPipelineError):
                stage_artifacts(self.root)

        self.assertEqual(0, self._git("diff", "--cached", "--quiet").returncode)

    def test_unrelated_pre_staged_file_is_rejected(self) -> None:
        self._init_repository()
        unrelated = self.root / "unrelated.txt"
        unrelated.write_text("do not publish\n", encoding="utf-8", newline="\n")
        self._git("add", "--", unrelated.name)

        with self.assertRaisesRegex(PublishPipelineError, "unrelated.txt"):
            stage_artifacts(self.root)

        self.assertIn(
            "unrelated.txt",
            self._git("diff", "--cached", "--name-only").stdout,
        )


if __name__ == "__main__":
    unittest.main()
