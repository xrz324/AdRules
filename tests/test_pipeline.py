from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]

from script.autoupdate_config import DEFAULT_CONFIG_PATH  # noqa: E402
from script.dns_coverage import CoverageResult, CoverageStats  # noqa: E402
from script.dns_prune_pipeline import (  # noqa: E402
    DnsCoveragePipelineResult,
    DnsPrunePipelineResult,
)
from script.dns_prune_model import DnsPolicyMode  # noqa: E402
from script.pipeline import (  # noqa: E402
    Pipeline,
    PipelineContext,
    PipelineError,
    PipelineServices,
    StageInvocation,
    UpdateMode,
    create_context,
)


class PipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "config").mkdir()
        shutil.copyfile(
            DEFAULT_CONFIG_PATH,
            self.root / "config" / "autoupdate.json",
        )
        for name, content in {
            "adblock.txt": "adblock baseline\n",
            "dns.txt": "dns baseline\n",
        }.items():
            (self.root / name).write_text(content, encoding="utf-8", newline="\n")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def context(self) -> PipelineContext:
        return create_context(
            self.root / "config" / "autoupdate.json",
            root_dir=self.root,
        )

    def test_context_injects_config_and_resolves_all_paths(self) -> None:
        context = self.context()

        self.assertTrue(context.settings.dns_prune_enabled)
        self.assertEqual("true", context.settings.environment["DNS_PRUNE_ENABLED"])
        self.assertEqual(
            "dns_prune_cache.json",
            context.settings.environment["DNS_PRUNE_CACHE_FILE"],
        )
        self.assertEqual(self.root / "adblock.txt", context.artifacts.adblock)
        self.assertEqual(
            self.root / "dns_prune_cache.json",
            context.runtime.dns_prune_cache,
        )
        self.assertEqual(
            self.root / "config" / "upstream.json",
            context.upstream_config_path,
        )
        self.assertEqual(
            self.root / "config" / "converter.json",
            context.converter_config_path,
        )
        self.assertEqual(
            self.root / "mod/title/dns-title.txt",
            context.dns_title_path,
        )

    def test_stage_plan_contains_only_python_api_boundaries(self) -> None:
        pipeline = Pipeline(self.context())

        self.assertEqual(
            [
                "upstream",
                "content",
                "dns-rules",
                "dns-coverage/prune",
                "content-inactive-cleanup",
                "dns-output",
                "dns-converter",
                "validate",
            ],
            [stage.name for stage in pipeline.stage_plan()],
        )
        self.assertTrue(
            all(
                "bash" not in stage.api and "update_" not in stage.api
                for stage in pipeline.stage_plan()
            )
        )
        self.assertIn(
            "dns_prune_pipeline.execute_dns_policy",
            [stage.api for stage in pipeline.stage_plan()],
        )

    def test_quick_revision_options_skip_upstream_and_dns_probe(self) -> None:
        captured: dict[str, object] = {}
        calls: list[str] = []

        def policy(request: object) -> None:
            calls.append("policy")
            captured["policy"] = request

        services = PipelineServices(
            run_upstream=lambda *args, **kwargs: calls.append("upstream"),
            build_content=lambda *args, **kwargs: calls.append("content"),
            cleanup_content_inactive=lambda *args, **kwargs: calls.append("content-inactive"),
            build_dns=lambda *args, **kwargs: calls.append("dns-rules"),
            run_dns_policy=policy,
            finalize_dns_output=lambda *args, **kwargs: calls.append("output"),
            run_conversion=lambda *args, **kwargs: calls.append("converter"),
            validate_artifacts=lambda *args, **kwargs: calls.append("validate"),
        )
        pipeline = Pipeline(
            self.context(),
            services=services,
            skip_upstream=True,
            update_mode=UpdateMode.QUICK,
        )

        self.assertNotIn(
            "upstream",
            [stage.name for stage in pipeline.stage_plan()],
        )
        pipeline.build()
        self.assertEqual(
            ["content", "dns-rules", "policy", "content-inactive", "output", "converter", "validate"],
            calls,
        )
        self.assertIs(DnsPolicyMode.CACHE_ONLY, captured["policy"].mode)

    def test_custom_artifact_paths_are_passed_to_every_stage(self) -> None:
        raw_config = json.loads(
            (self.root / "config" / "autoupdate.json").read_text(encoding="utf-8")
        )
        custom_paths = {
            "adblock": "generated/adblock.txt",
            "dns": "generated/dns.txt",
            "singbox": "generated/rules.srs",
            "mihomo_mrs": "generated/rules.mrs",
            "mihomo_yaml": "generated/rules.yaml",
        }
        for item in raw_config["artifacts"]:
            item["path"] = custom_paths[item["name"]]
        raw_config["paths"] = {
            "upstream_config": "settings/upstream.json",
            "converter_config": "settings/converter.json",
            "dns_title": "settings/dns-title.txt",
            "dns_ip_cidr": "generated/dns-cidr.txt",
            "baseline_dir": "generated/baseline",
        }
        raw_config["environment"]["DNS_PRUNE_ENABLED"] = "false"
        (self.root / "config" / "autoupdate.json").write_text(
            json.dumps(raw_config), encoding="utf-8", newline="\n"
        )
        for path in custom_paths.values():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"baseline {path}\n", encoding="utf-8", newline="\n")

        captured: dict[str, Any] = {}

        def upstream(request: object) -> None:
            captured["upstream"] = request

        def content(root: Path, **kwargs: object) -> None:
            captured["content"] = (root, kwargs)

        def dns(paths: object) -> None:
            captured["dns"] = paths

        def policy(request: object) -> None:
            captured["policy"] = request

        def output(input_file: Path, **kwargs: object) -> None:
            captured["output"] = (input_file, kwargs)

        def conversion(request: object) -> None:
            captured["conversion"] = request

        def validate(config_path: Path, **kwargs: object) -> None:
            captured["validate"] = (config_path, kwargs)

        def content_inactive(output_file: Path, **kwargs: object) -> None:
            captured["content_inactive"] = (output_file, kwargs)

        services = PipelineServices(
            run_upstream=upstream,
            build_content=content,
            cleanup_content_inactive=content_inactive,
            build_dns=dns,
            run_dns_policy=policy,
            finalize_dns_output=output,
            run_conversion=conversion,
            validate_artifacts=validate,
        )
        # Construct the context after changing the isolated configuration.
        pipeline = Pipeline(
            create_context(self.root / "config" / "autoupdate.json", self.root),
            services=services,
        )
        pipeline.build()

        self.assertEqual(
            self.root / "settings/upstream.json",
            captured["upstream"].config_path,
        )
        self.assertEqual(
            self.root / "settings/converter.json",
            captured["conversion"].config_path,
        )
        self.assertEqual(
            self.root / "settings/dns-title.txt",
            captured["output"][1]["title_file"],
        )
        self.assertEqual(
            self.root / "generated/dns-cidr.txt",
            captured["conversion"].ip_cidr_input,
        )
        self.assertEqual(
            self.root / "generated/adblock.txt",
            captured["content"][1]["output_file"],
        )
        self.assertEqual(
            self.root / "generated/adblock.txt",
            captured["content_inactive"][0],
        )
        self.assertEqual(
            self.root / "dns_prune_cache.json",
            captured["content_inactive"][1]["cache_file"],
        )
        self.assertIsNotNone(captured["content"][1]["timestamp"])
        self.assertEqual(
            captured["content"][1]["timestamp"],
            captured["output"][1]["timestamp"],
        )
        self.assertEqual(
            self.root / "generated/dns.txt",
            captured["policy"].input_file,
        )
        self.assertEqual(self.root / "generated/dns.txt", captured["output"][0])
        self.assertEqual(
            self.root / "generated/rules.srs",
            captured["conversion"].singbox_output,
        )
        self.assertEqual(
            self.root / "generated/rules.mrs",
            captured["conversion"].mihomo_mrs_output,
        )
        self.assertEqual(
            self.root / "generated/rules.yaml",
            captured["conversion"].mihomo_yaml_output,
        )
        validate_kwargs = captured["validate"][1]
        self.assertEqual(self.root, validate_kwargs["root_dir"])
        self.assertEqual(
            self.root / "generated/rules.yaml",
            validate_kwargs["artifact_overrides"]["mihomo_yaml"],
        )

    def test_prepare_baseline_uses_configured_artifacts(self) -> None:
        pipeline = Pipeline(self.context())

        pipeline.prepare_baseline()

        self.assertEqual(
            "adblock baseline\n",
            (self.root / "tmp/baseline/adblock.txt").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            "dns baseline\n",
            (self.root / "tmp/baseline/dns.txt").read_text(encoding="utf-8"),
        )

    def test_policy_receives_runtime_cache_and_scoped_environment(self) -> None:
        captured: dict[str, Any] = {}

        def policy(request: object) -> None:
            captured["request"] = request

        services = PipelineServices(
            run_upstream=lambda *args, **kwargs: None,
            build_content=lambda *args, **kwargs: None,
            cleanup_content_inactive=lambda *args, **kwargs: None,
            build_dns=lambda *args, **kwargs: None,
            run_dns_policy=policy,
            finalize_dns_output=lambda *args, **kwargs: None,
            run_conversion=lambda *args, **kwargs: None,
            validate_artifacts=lambda *args, **kwargs: None,
        )

        Pipeline(self.context(), services=services)._run_dns_policy()

        request = captured["request"]
        self.assertEqual(self.root / "dns.txt", request.input_file)
        self.assertIs(DnsPolicyMode.PROBE, request.mode)
        self.assertTrue(request.require_dead_capable is False)
        self.assertEqual(self.root / "dns_prune_cache.json", request.cache_file)
        self.assertEqual(
            self.root / "tmp/dns_prune_removed_rules.txt",
            request.removed_log,
        )
        self.assertEqual("true", request.environment["DNS_PRUNE_ENABLED"])
        self.assertNotIn("GITHUB_TOKEN", request.environment)

    def test_unified_policy_service_receives_explicit_policy_and_paths(self) -> None:
        captured: dict[str, Any] = {}

        def policy(request: object) -> None:
            captured["request"] = request

        services = PipelineServices(
            run_upstream=lambda *args, **kwargs: None,
            build_content=lambda *args, **kwargs: None,
            cleanup_content_inactive=lambda *args, **kwargs: None,
            build_dns=lambda *args, **kwargs: None,
            run_dns_policy=policy,
            finalize_dns_output=lambda *args, **kwargs: None,
            run_conversion=lambda *args, **kwargs: None,
            validate_artifacts=lambda *args, **kwargs: None,
        )

        Pipeline(self.context(), services=services)._run_dns_policy()

        request = captured["request"]
        self.assertIs(DnsPolicyMode.PROBE, request.mode)
        self.assertEqual(self.root / "dns.txt", request.input_file)
        self.assertEqual(self.root / "dns_prune_cache.json", request.cache_file)
        self.assertEqual(
            self.root / "tmp/dns_prune_removed_rules.txt",
            request.removed_log,
        )
        self.assertEqual("true", request.environment["DNS_PRUNE_ENABLED"])

    def test_build_stops_after_failed_python_stage_and_cleans_sidecar(self) -> None:
        calls: list[str] = []

        def upstream(*args: object, **kwargs: object) -> None:
            calls.append("upstream")

        def content(*args: object, **kwargs: object) -> None:
            calls.append("content")
            raise RuntimeError("fixture failure")

        services = PipelineServices(
            run_upstream=upstream,
            build_content=content,
            cleanup_content_inactive=lambda *args, **kwargs: calls.append("content-inactive"),
            build_dns=lambda *args, **kwargs: calls.append("dns-rules"),
            run_dns_policy=lambda *args, **kwargs: calls.append("policy"),
            finalize_dns_output=lambda *args, **kwargs: calls.append("output"),
            run_conversion=lambda *args, **kwargs: calls.append("converter"),
            validate_artifacts=lambda *args, **kwargs: calls.append("validate"),
        )
        sidecar = self.root / "tmp/dns_ip_cidr_rules.txt"
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        sidecar.write_text("generated\n", encoding="utf-8", newline="\n")

        with self.assertRaises(PipelineError):
            Pipeline(self.context(), services=services).build()

        self.assertEqual(["upstream", "content"], calls)
        self.assertFalse(sidecar.exists())
        self.assertTrue((self.root / "tmp/baseline/adblock.txt").is_file())

    def test_stage_logs_have_clear_boundaries_and_key_result(self) -> None:
        class ContentResult:
            rule_count = 42
            source_line_count = 100

        services = PipelineServices(
            run_upstream=lambda *args, **kwargs: None,
            build_content=lambda *args, **kwargs: ContentResult(),
            cleanup_content_inactive=lambda *args, **kwargs: None,
            build_dns=lambda *args, **kwargs: None,
            run_dns_policy=lambda *args, **kwargs: None,
            finalize_dns_output=lambda *args, **kwargs: None,
            run_conversion=lambda *args, **kwargs: None,
            validate_artifacts=lambda *args, **kwargs: None,
        )
        output = io.StringIO()

        with contextlib.redirect_stderr(output):
            result = Pipeline(self.context(), services=services).run_stage(
                StageInvocation("content", "content_pipeline.build_content")
            )

        self.assertIsInstance(result, ContentResult)
        log = output.getvalue()
        self.assertIn(
            "[PIPELINE] START content | content_pipeline.build_content",
            log,
        )
        self.assertRegex(
            log,
            r"\[PIPELINE\] DONE content \| [0-9.]+s \| "
            r"rules=42 source-lines=100",
        )
        self.assertNotIn("::group::", log)

    def test_actions_group_and_summary_identify_failed_stage(self) -> None:
        summary_path = self.root / "github-step-summary.md"

        def failing_content(*args: object, **kwargs: object) -> None:
            raise RuntimeError("fixture failure")

        services = PipelineServices(
            run_upstream=lambda *args, **kwargs: None,
            build_content=failing_content,
            cleanup_content_inactive=lambda *args, **kwargs: None,
            build_dns=lambda *args, **kwargs: None,
            run_dns_policy=lambda *args, **kwargs: None,
            finalize_dns_output=lambda *args, **kwargs: None,
            run_conversion=lambda *args, **kwargs: None,
            validate_artifacts=lambda *args, **kwargs: None,
        )
        output = io.StringIO()

        with patch.dict(
            os.environ,
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_STEP_SUMMARY": str(summary_path),
            },
        ):
            pipeline = Pipeline(
                create_context(
                    self.root / "config" / "autoupdate.json",
                    root_dir=self.root,
                ),
                services=services,
            )
            with contextlib.redirect_stderr(output):
                with self.assertRaises(PipelineError):
                    pipeline.build()

        log = output.getvalue()
        self.assertIn("::group::[PIPELINE] upstream", log)
        self.assertIn("::group::[PIPELINE] content", log)
        self.assertIn("::error title=Pipeline stage failed::content:", log)
        self.assertIn("::endgroup::", log)
        self.assertNotIn("| stage=", log)
        summary = summary_path.read_text(encoding="utf-8")
        self.assertIn("## Rule pipeline", summary)
        self.assertIn("| `content` | FAILED |", summary)
        self.assertIn("stage content failed: fixture failure", summary)
        self.assertNotIn("**Result:**", summary)
        self.assertIn("skipped=6", log)

    def test_partial_stage_result_is_reported_as_warning(self) -> None:
        class UpstreamResult:
            attempted = 3
            succeeded = 2
            mirrored = 1
            failed_urls = ("https://example.test/failed",)

        services = PipelineServices(
            run_upstream=lambda *args, **kwargs: UpstreamResult(),
            build_content=lambda *args, **kwargs: None,
            cleanup_content_inactive=lambda *args, **kwargs: None,
            build_dns=lambda *args, **kwargs: None,
            run_dns_policy=lambda *args, **kwargs: None,
            finalize_dns_output=lambda *args, **kwargs: None,
            run_conversion=lambda *args, **kwargs: None,
            validate_artifacts=lambda *args, **kwargs: None,
        )
        output = io.StringIO()

        with contextlib.redirect_stderr(output):
            Pipeline(self.context(), services=services).run_stage(
                StageInvocation(
                    "upstream",
                    "upstream_pipeline.execute_upstream_stage",
                )
            )

        self.assertIn("status=warning", output.getvalue())
        self.assertIn("downloaded=2/3 mirrored=1 failed=1", output.getvalue())

    def test_coverage_only_policy_summary_does_not_require_prune_fields(self) -> None:
        policy_result = DnsCoveragePipelineResult(
            before_rule_count=12,
            covered_domain_count=3,
            final_rule_count=9,
            coverage=CoverageResult((), CoverageStats()),
        )
        services = PipelineServices(
            run_upstream=lambda *args, **kwargs: None,
            build_content=lambda *args, **kwargs: None,
            cleanup_content_inactive=lambda *args, **kwargs: None,
            build_dns=lambda *args, **kwargs: None,
            run_dns_policy=lambda *args, **kwargs: policy_result,
            finalize_dns_output=lambda *args, **kwargs: None,
            run_conversion=lambda *args, **kwargs: None,
            validate_artifacts=lambda *args, **kwargs: None,
        )
        output = io.StringIO()

        with contextlib.redirect_stderr(output):
            Pipeline(
                self.context(),
                services=services,
                update_mode=UpdateMode.QUICK,
            ).run_stage(
                StageInvocation(
                    "dns-coverage/prune",
                    "dns_prune_pipeline.execute_dns_policy",
                )
            )

        self.assertIn("rules=12->9 covered=3 pruned=0", output.getvalue())

    def test_degraded_dns_prune_is_reported_as_warning(self) -> None:
        policy_result = DnsPrunePipelineResult(
            before_rule_count=12,
            covered_domain_count=0,
            after_prune_rule_count=12,
            final_rule_count=12,
            coverage=CoverageResult((), CoverageStats()),
            prune_status="degraded",
            prune_reason="too few healthy resolvers; prune skipped",
        )
        services = PipelineServices(
            run_upstream=lambda *args, **kwargs: None,
            build_content=lambda *args, **kwargs: None,
            cleanup_content_inactive=lambda *args, **kwargs: None,
            build_dns=lambda *args, **kwargs: None,
            run_dns_policy=lambda *args, **kwargs: policy_result,
            finalize_dns_output=lambda *args, **kwargs: None,
            run_conversion=lambda *args, **kwargs: None,
            validate_artifacts=lambda *args, **kwargs: None,
        )
        output = io.StringIO()

        with contextlib.redirect_stderr(output):
            Pipeline(self.context(), services=services).run_stage(
                StageInvocation(
                    "dns-coverage/prune",
                    "dns_prune_pipeline.execute_dns_policy",
                )
            )

        self.assertIn("status=warning", output.getvalue())
        self.assertIn("too few healthy resolvers", output.getvalue())


if __name__ == "__main__":
    unittest.main()
