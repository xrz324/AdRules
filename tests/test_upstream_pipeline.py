from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
from script.upstream_pipeline import (
    UPSTREAM_CONFIG_PATH,
    UpstreamConfigError,
    UpstreamPipelineError,
    get_download_filename,
    load_upstream_config,
    normalize_download_bytes,
    run_upstream,
)


class UpstreamPipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_repository_sources_are_loaded_from_independent_config(self) -> None:
        config = load_upstream_config()

        self.assertEqual(UPSTREAM_CONFIG_PATH.name, "upstream.json")
        self.assertEqual(8, config.max_workers)
        self.assertEqual(12, len(config.content))
        self.assertEqual(12, len(config.dns))
        self.assertEqual(
            "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt",
            config.content[0].url,
        )
        self.assertEqual("someonewhocares", config.dns[-1].name)

    def test_run_uses_catalogue_when_sources_are_not_overridden(self) -> None:
        config_dir = self.root / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "upstream.json").write_text(
            """{
              "version": 1,
              "max_workers": 1,
              "content": [{"name": "content", "url": "https://example.test/shared"}],
              "dns": [{"name": "dns", "url": "https://example.test/dns"}]
            }
            """,
            encoding="utf-8",
            newline="\n",
        )
        calls: list[str] = []

        def fake_downloader(url: str, output: Path) -> bool:
            calls.append(url)
            output.write_bytes(b"||configured.example^\n")
            return True

        result = run_upstream(
            self.root,
            downloader=fake_downloader,
            strict=True,
            environment={},
        )

        self.assertEqual(
            ["https://example.test/shared", "https://example.test/dns"],
            calls,
        )
        self.assertEqual(2, result.succeeded)

    def test_rejects_invalid_upstream_source_config(self) -> None:
        config_path = self.root / "upstream.json"
        config_path.write_text(
            """{
              "version": 1,
              "content": [{"name": "bad", "url": "file:///rules.txt"}],
              "dns": ["https://example.test/dns"]
            }
            """,
            encoding="utf-8",
            newline="\n",
        )

        with self.assertRaises(UpstreamConfigError):
            load_upstream_config(config_path)

    def test_filename_and_normalization_match_shell_contract(self) -> None:
        self.assertTrue(
            get_download_filename("https://example.test/SMAdHosts").endswith(
                "_SMAdHosts.txt"
            )
        )
        self.assertTrue(
            get_download_filename("https://example.test/list?format=hosts").endswith(
                "_list.txt"
            )
        )
        self.assertEqual(
            b"! Title\n||example.test^\n",
            normalize_download_bytes(
                b"\xef\xbb\xbf! Title\r\n||example.test^\r\n"
            ),
        )

    def test_groups_reuse_mirror_and_leave_no_intermediates(self) -> None:
        shared = "https://example.test/shared"
        content_only = "https://example.test/content"
        calls: list[str] = []

        def fake_downloader(url: str, output: Path) -> bool:
            calls.append(url)
            output.write_bytes(b"\xef\xbb\xbf||shared.example^\r\n")
            return True

        result = run_upstream(
            self.root,
            content_sources=(shared, content_only),
            dns_sources=(shared,),
            downloader=fake_downloader,
            max_workers=1,
            strict=True,
            environment={},
        )

        # The DNS copy is served from tmp/content and does not invoke the
        # downloader a second time.
        self.assertEqual([shared, content_only], calls)
        self.assertEqual(3, result.attempted)
        self.assertEqual(1, result.mirrored)
        self.assertEqual(3, result.succeeded)
        filename = get_download_filename(shared)
        expected = b"! url: " + shared.encode() + b"\n||shared.example^\n"
        self.assertEqual(
            expected,
            (self.root / "tmp/content" / filename).read_bytes(),
        )
        self.assertEqual(
            expected,
            (self.root / "tmp/dns" / filename).read_bytes(),
        )
        self.assertEqual(b"", (self.root / "download_failed.log").read_bytes())
        self.assertEqual([], list(self.root.rglob("*.tmp")))
        self.assertEqual([], list(self.root.rglob("*.normalized")))

    def test_failure_log_is_deterministic_and_non_strict_runs_continue(self) -> None:
        first = "https://example.test/first"
        failed = "https://example.test/failed"
        third = "https://example.test/third"

        def fake_downloader(url: str, output: Path) -> bool:
            if url == failed:
                return False
            output.write_bytes(b"||ok.example^\n")
            return True

        result = run_upstream(
            self.root,
            content_sources=(first, failed, third),
            dns_sources=(),
            downloader=fake_downloader,
            max_workers=1,
            strict=False,
            environment={},
        )

        self.assertEqual((failed,), result.failed_urls)
        self.assertEqual(
            failed + "\n",
            (self.root / "download_failed.log").read_text(encoding="utf-8"),
        )
        self.assertEqual([], list(self.root.rglob("*.tmp")))
        self.assertEqual([], list(self.root.rglob("*.normalized")))
        self.assertTrue(
            (self.root / "tmp/content" / get_download_filename(first)).is_file()
        )
        self.assertTrue(
            (self.root / "tmp/content" / get_download_filename(third)).is_file()
        )

    def test_strict_failure_raises_after_writing_failure_log(self) -> None:
        failed = "https://example.test/failed"

        def fake_downloader(_url: str, _output: Path) -> bool:
            return False

        with self.assertRaises(UpstreamPipelineError):
            run_upstream(
                self.root,
                content_sources=(failed,),
                dns_sources=(),
                downloader=fake_downloader,
                max_workers=1,
                strict=True,
                environment={},
            )
        self.assertEqual(
            failed + "\n",
            (self.root / "download_failed.log").read_text(encoding="utf-8"),
        )

    def test_runtime_paths_honor_explicit_environment_override(self) -> None:
        run_upstream(
            self.root,
            content_sources=(),
            dns_sources=(),
            max_workers=1,
            strict=True,
            environment={"DOWNLOAD_FAILED_LOG": "logs/upstream-failed.log"},
        )
        self.assertTrue((self.root / "logs/upstream-failed.log").is_file())


if __name__ == "__main__":
    unittest.main()
