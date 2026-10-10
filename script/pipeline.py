#!/usr/bin/env python3
"""Run the GitHub Actions rule-generation stages through Python APIs."""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from time import monotonic
from typing import (
    Any,
    Callable,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

try:
    from autoupdate_config import (
        DEFAULT_CONFIG_PATH,
        ConfigError,
        RuntimeSettings,
        artifact_paths,
        load_config,
        pipeline_paths,
        runtime_settings,
    )
    from content_pipeline import ContentBuildResult, build_content
    from content_inactive import (
        ContentInactiveCleanupResult,
        cleanup_content_with_cache,
    )
    from common import now_gmt8
    from dns_converter import (
        ConversionResult,
        execute_conversion_request,
    )
    from dns_converter_model import ConversionRequest
    from dns_output import DnsOutputResult, finalize_dns_output
    from dns_pipeline import DnsBuildResult, DnsPaths, build_dns
    from dns_prune_pipeline import DnsPolicyResult, DnsPolicyStageRequest, execute_dns_policy
    from dns_prune_config import cache_reuse_policy_from_request, build_prune_request
    from inactive_domain_model import CacheReusePolicy
    from pipeline_adapters import (
        run_content,
        run_content_inactive_cleanup,
        run_dns_converter,
        run_dns_output,
        run_dns_policy,
        run_dns_rules,
        run_upstream,
        run_validation,
    )
    from pipeline_stages import StageInvocation, StageSpec, build_stage_specs
    from dns_prune_model import PruneRequest
    from logging_utils import configure_logging
    from pipeline_reporting import (
        PipelineReporter,
        StageReport,
        format_duration,
        one_line,
    )
    from upstream_pipeline import (
        UpstreamBuildResult,
        UpstreamStageRequest,
        execute_upstream_stage,
    )
    from validate_outputs import RuleFileStats, validate_artifacts
except ImportError:  # Support ``python -m script.pipeline``.
    from .autoupdate_config import (  # type: ignore[no-redef]
        DEFAULT_CONFIG_PATH,
        ConfigError,
        RuntimeSettings,
        artifact_paths,
        load_config,
        pipeline_paths,
        runtime_settings,
    )
    from .content_pipeline import ContentBuildResult, build_content  # type: ignore[no-redef]
    from .content_inactive import (  # type: ignore[no-redef]
        ContentInactiveCleanupResult,
        cleanup_content_with_cache,
    )
    from .common import now_gmt8  # type: ignore[no-redef]
    from .dns_converter import (  # type: ignore[no-redef]
        ConversionResult,
        execute_conversion_request,
    )
    from .dns_converter_model import ConversionRequest  # type: ignore[no-redef]
    from .dns_output import DnsOutputResult, finalize_dns_output  # type: ignore[no-redef]
    from .dns_pipeline import DnsBuildResult, DnsPaths, build_dns  # type: ignore[no-redef]
    from .dns_prune_pipeline import (  # type: ignore[no-redef]
        DnsPolicyResult,
        DnsPolicyStageRequest,
        execute_dns_policy,
    )
    from .dns_prune_config import (  # type: ignore[no-redef]
        cache_reuse_policy_from_request,
        build_prune_request,
    )
    from .inactive_domain_model import CacheReusePolicy  # type: ignore[no-redef]
    from .pipeline_adapters import (  # type: ignore[no-redef]
        run_content,
        run_content_inactive_cleanup,
        run_dns_converter,
        run_dns_output,
        run_dns_policy,
        run_dns_rules,
        run_upstream,
        run_validation,
    )
    from .pipeline_stages import (  # type: ignore[no-redef]
        StageInvocation,
        StageSpec,
        build_stage_specs,
    )
    from .dns_prune_model import PruneRequest  # type: ignore[no-redef]
    from .logging_utils import configure_logging  # type: ignore[no-redef]
    from .pipeline_reporting import (  # type: ignore[no-redef]
        PipelineReporter,
        StageReport,
        format_duration,
        one_line,
    )
    from .upstream_pipeline import (  # type: ignore[no-redef]
        UpstreamBuildResult,
        UpstreamStageRequest,
        execute_upstream_stage,
    )
    from .validate_outputs import RuleFileStats, validate_artifacts  # type: ignore[no-redef]


ROOT_DIR = Path(__file__).resolve().parents[1]
BASELINE_ARTIFACTS = ("adblock", "dns")


class PipelineError(RuntimeError):
    """Raised when a pipeline stage cannot complete successfully."""


class UpdateMode(str, Enum):
    """Application-level update plans selected by the trigger adapter."""

    FULL = "full"
    QUICK = "quick"


@dataclass(frozen=True)
class PipelinePaths:
    """Resolved repository paths shared by all build stages.

    The values originate in ``config/autoupdate.json``.  Keeping them in one
    immutable object prevents individual stage adapters from re-deriving
    paths from the process working directory or from separate defaults.
    """

    baseline_dir: Path
    upstream_config: Path
    converter_config: Path
    dns_title: Path
    dns_ip_cidr: Path

    @classmethod
    def from_config(
        cls,
        root_dir: Path,
        config: Mapping[str, object],
    ) -> "PipelinePaths":
        root = Path(root_dir).resolve()
        configured = pipeline_paths(config)
        return cls(
            baseline_dir=_resolve_root_path(root, configured["baseline_dir"]),
            upstream_config=_resolve_root_path(
                root, configured["upstream_config"]
            ),
            converter_config=_resolve_root_path(
                root, configured["converter_config"]
            ),
            dns_title=_resolve_root_path(root, configured["dns_title"]),
            dns_ip_cidr=_resolve_root_path(root, configured["dns_ip_cidr"]),
        )


@dataclass(frozen=True)
class PipelineArtifacts:
    """Typed output artifact paths required by the build."""

    adblock: Path
    dns: Path
    singbox: Path
    mihomo_mrs: Path
    mihomo_yaml: Path

    @classmethod
    def from_config(
        cls,
        root_dir: Path,
        config: Mapping[str, object],
    ) -> "PipelineArtifacts":
        root = Path(root_dir).resolve()
        configured = artifact_paths(config)
        return cls(
            adblock=_resolve_root_path(root, configured["adblock"]),
            dns=_resolve_root_path(root, configured["dns"]),
            singbox=_resolve_root_path(root, configured["singbox"]),
            mihomo_mrs=_resolve_root_path(root, configured["mihomo_mrs"]),
            mihomo_yaml=_resolve_root_path(root, configured["mihomo_yaml"]),
        )

    def as_mapping(self) -> Mapping[str, Path]:
        return {
            "adblock": self.adblock,
            "dns": self.dns,
            "singbox": self.singbox,
            "mihomo_mrs": self.mihomo_mrs,
            "mihomo_yaml": self.mihomo_yaml,
        }


@dataclass(frozen=True)
class PipelineRuntimePaths:
    """Typed transient paths shared by pipeline stages."""

    dns_prune_cache: Path
    dns_prune_log: Path
    download_failed_log: Path

    @classmethod
    def from_config(
        cls,
        root_dir: Path,
        config: Mapping[str, object],
    ) -> "PipelineRuntimePaths":
        root = Path(root_dir).resolve()
        raw = config.get("runtime", {})
        if not isinstance(raw, Mapping):
            raise ConfigError("normalized config has invalid runtime")
        return cls(
            dns_prune_cache=_resolve_root_path(root, str(raw["dns_prune_cache"])),
            dns_prune_log=_resolve_root_path(root, str(raw["dns_prune_log"])),
            download_failed_log=_resolve_root_path(
                root,
                str(raw["download_failed_log"]),
            ),
        )


@dataclass(frozen=True)
class PipelineContext:
    """Immutable configuration, settings, and paths for one build."""

    root_dir: Path
    config_path: Path
    settings: RuntimeSettings
    artifacts: PipelineArtifacts
    paths: PipelinePaths
    runtime: PipelineRuntimePaths
    cache_policy: CacheReusePolicy
    dns_prune_request: PruneRequest

    @property
    def baseline_dir(self) -> Path:
        """Convenience view for callers that only need the baseline path."""

        return self.paths.baseline_dir

    @property
    def upstream_config_path(self) -> Path:
        return self.paths.upstream_config

    @property
    def converter_config_path(self) -> Path:
        return self.paths.converter_config

    @property
    def dns_title_path(self) -> Path:
        return self.paths.dns_title

    @property
    def dns_ip_cidr_path(self) -> Path:
        return self.paths.dns_ip_cidr


class UpstreamService(Protocol):
    def __call__(
        self,
        request: UpstreamStageRequest,
    ) -> UpstreamBuildResult: ...


class ContentService(Protocol):
    def __call__(
        self,
        root_dir: Path,
        *,
        timestamp: Optional[datetime],
        output_file: Path,
    ) -> ContentBuildResult: ...


class ContentInactiveCleanupService(Protocol):
    def __call__(
        self,
        output_file: Path,
        *,
        cache_file: Path,
        policy: CacheReusePolicy,
        enabled: bool,
    ) -> ContentInactiveCleanupResult: ...


class DnsRulesService(Protocol):
    def __call__(self, paths: DnsPaths) -> DnsBuildResult: ...


class DnsPolicyService(Protocol):
    def __call__(
        self,
        request: DnsPolicyStageRequest,
    ) -> DnsPolicyResult: ...


class DnsOutputService(Protocol):
    def __call__(
        self,
        input_file: Path,
        *,
        title_file: Path,
        output_file: Path,
        previous_output_file: Path,
        timestamp: Optional[datetime],
    ) -> DnsOutputResult: ...


class ConversionService(Protocol):
    def __call__(
        self,
        request: ConversionRequest,
    ) -> ConversionResult: ...


class ValidationService(Protocol):
    def __call__(
        self,
        config_path: Path,
        *,
        artifact_overrides: Mapping[str, Path],
        baseline_adblock: Path,
        baseline_dns: Path,
        max_drop_percent: float,
        root_dir: Path,
    ) -> tuple[RuleFileStats, RuleFileStats]: ...


@dataclass(frozen=True)
class PipelineServices:
    """Injectable stage functions used by the Actions orchestrator."""

    run_upstream: UpstreamService
    build_content: ContentService
    build_dns: DnsRulesService
    run_dns_policy: DnsPolicyService
    finalize_dns_output: DnsOutputService
    run_conversion: ConversionService
    validate_artifacts: ValidationService
    cleanup_content_inactive: ContentInactiveCleanupService = (
        cleanup_content_with_cache
    )


def _default_services() -> PipelineServices:
    # Resolve globals at construction time so tests can patch a stage before
    # creating a Pipeline without mutating a process-wide singleton.
    return PipelineServices(
        run_upstream=execute_upstream_stage,
        build_content=build_content,
        cleanup_content_inactive=cleanup_content_with_cache,
        build_dns=build_dns,
        run_dns_policy=execute_dns_policy,
        finalize_dns_output=finalize_dns_output,
        run_conversion=execute_conversion_request,
        validate_artifacts=validate_artifacts,
    )


class StageRunner:
    """Execute and report one stage without owning pipeline ordering."""

    def __init__(
        self,
        stage_supplier: Callable[[], Tuple[StageSpec[Any], ...]],
        reporter: PipelineReporter,
        reports: list[StageReport],
    ) -> None:
        self._stage_supplier = stage_supplier
        self._reporter = reporter
        self._reports = reports

    def run(self, stage: StageInvocation) -> Any:
        spec = next(
            (
                candidate
                for candidate in self._stage_supplier()
                if candidate.invocation.name == stage.name
            ),
            None,
        )
        if spec is None:
            raise PipelineError(f"unknown pipeline stage: {stage.name}")
        stage = spec.invocation
        started = monotonic()
        self._reporter.stage_start(stage.name, stage.api)
        try:
            result = spec.run()
        except PipelineError as exc:
            report = self._record(stage, "failed", started, one_line(exc))
            self._reporter.stage_failure(report, exc)
            raise
        except Exception as exc:  # noqa: BLE001 - stage boundary translation.
            wrapped = PipelineError(f"stage {stage.name} failed: {exc}")
            report = self._record(stage, "failed", started, one_line(wrapped))
            self._reporter.stage_failure(report, wrapped)
            raise wrapped from exc
        except BaseException as exc:
            # Preserve process-control exceptions while still closing the
            # Actions group and recording an accurate failed stage.
            report = self._record(stage, "failed", started, one_line(exc))
            self._reporter.stage_failure(report, exc)
            raise
        else:
            report = self._record(
                stage,
                spec.status(result),
                started,
                spec.summarize(result),
            )
            self._reporter.stage_done(report)
            return result
        finally:
            self._reporter.stage_end()

    def _record(
        self,
        stage: StageInvocation,
        status: str,
        started: float,
        summary: str = "",
    ) -> StageReport:
        report = StageReport(
            name=stage.name,
            api=stage.api,
            status=status,
            duration_seconds=max(0.0, monotonic() - started),
            summary=summary,
        )
        self._reports.append(report)
        return report


def _resolve_config_path(config_path: Path, root_dir: Path) -> Path:
    configured = Path(config_path)
    if configured.is_absolute():
        return configured.resolve()
    return (Path(root_dir).resolve() / configured).resolve()


def _resolve_root_path(root: Path, value: str | Path) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    return candidate.resolve()


def _display_path(root: Path, path: Path) -> str:
    """Prefer concise repository-relative paths in human-facing logs."""

    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _empty_summary(result: object) -> str:
    del result
    return ""


def _upstream_summary(result: Optional[UpstreamBuildResult]) -> str:
    if result is None:
        return ""
    return (
        f"downloaded={result.succeeded}/{result.attempted} "
        f"mirrored={result.mirrored} "
        f"failed={len(result.failed_urls)}"
    )


def _content_summary(result: Optional[ContentBuildResult]) -> str:
    if result is None:
        return ""
    return f"rules={result.rule_count} source-lines={result.source_line_count}"


def _content_inactive_summary(
    result: Optional[ContentInactiveCleanupResult],
) -> str:
    if result is None:
        return ""
    return (
        f"rules={result.before_rule_count}->{result.after_rule_count} "
        f"removed={result.removed_rule_count} cache={result.cache_state}"
    )


def _dns_rules_summary(result: Optional[DnsBuildResult]) -> str:
    if result is None:
        return ""
    return f"rules={result.output_count} cidr={result.cidr_count}"


def _dns_policy_summary(result: Optional[DnsPolicyResult]) -> str:
    if result is None:
        return ""
    summary = (
        f"rules={result.before_rule_count}->{result.final_rule_count} "
        f"covered={result.covered_domain_count} "
        f"pruned={result.pruned_rule_count}"
    )
    if result.prune_reason:
        summary += f" reason={one_line(result.prune_reason)}"
    return summary


def _dns_output_summary(result: Optional[DnsOutputResult]) -> str:
    if result is None:
        return ""
    return f"rules={result.rule_count}"


def _conversion_summary(result: Optional[ConversionResult]) -> str:
    if result is None:
        return ""
    return (
        f"sing-box={'ok' if result.singbox_success else 'failed'} "
        f"mihomo={'ok' if result.mihomo_success else 'failed'}"
    )


def _validation_summary(result: Optional[tuple[RuleFileStats, RuleFileStats]]) -> str:
    if not isinstance(result, tuple) or len(result) != 2:
        return ""
    return f"adblock={result[0].rule_count} dns={result[1].rule_count}"


def _success_status(result: object) -> str:
    del result
    return "success"


def _upstream_status(result: Optional[UpstreamBuildResult]) -> str:
    return "warning" if result is not None and result.failed_urls else "success"


def _conversion_status(result: Optional[ConversionResult]) -> str:
    return "warning" if result is not None and result.failed else "success"


def _dns_policy_status(result: Optional[DnsPolicyResult]) -> str:
    return (
        "warning"
        if result is not None and result.prune_status == "degraded"
        else "success"
    )


def create_context(
    config_path: Path = DEFAULT_CONFIG_PATH,
    root_dir: Path = ROOT_DIR,
) -> PipelineContext:
    """Load one normalized config and derive every stage path."""

    root = Path(root_dir).resolve()
    resolved_config = _resolve_config_path(config_path, root)
    config = load_config(resolved_config)

    settings = runtime_settings(config, os.environ)

    configured_artifacts = PipelineArtifacts.from_config(root, config)
    paths = PipelinePaths.from_config(root, config)
    runtime = PipelineRuntimePaths.from_config(root, config)
    dns_prune_request = build_prune_request(
        environment=settings.dns_environment,
        input_path=configured_artifacts.dns,
        cache_path=runtime.dns_prune_cache,
        removed_log_path=runtime.dns_prune_log,
        require_dead_capable=settings.strict_dns_prune,
    )
    return PipelineContext(
        root_dir=root,
        config_path=resolved_config,
        settings=settings,
        artifacts=configured_artifacts,
        paths=paths,
        runtime=runtime,
        cache_policy=cache_reuse_policy_from_request(dns_prune_request),
        dns_prune_request=dns_prune_request,
    )


class Pipeline:
    """Execute the ordered Python stage APIs for one repository snapshot."""

    def __init__(
        self,
        context: PipelineContext,
        services: Optional[PipelineServices] = None,
        *,
        skip_upstream: bool = False,
        update_mode: UpdateMode = UpdateMode.FULL,
        reporter: Optional[PipelineReporter] = None,
    ) -> None:
        self.context = context
        self.services = services or _default_services()
        self.skip_upstream = skip_upstream
        self.update_mode = update_mode
        self.reporter = reporter or PipelineReporter(
            context.root_dir,
            context.settings.reporting_environment,
        )
        self._stage_reports: list[StageReport] = []
        self._baseline_report: Optional[StageReport] = None
        self._build_timestamp: Optional[datetime] = None
        self._stage_specs: Optional[Tuple[StageSpec[Any], ...]] = None
        self._stage_runner = StageRunner(
            self.stage_specs,
            self.reporter,
            self._stage_reports,
        )

    def stage_specs(self) -> Tuple[StageSpec[Any], ...]:
        """Return the ordered stage graph for this build."""

        if self._stage_specs is not None:
            return self._stage_specs
        handlers = {
            "upstream": lambda: run_upstream(self.context, self.services),
            "content": lambda: run_content(
                self.context, self.services, self._build_timestamp
            ),
            "dns-rules": lambda: run_dns_rules(self.context, self.services),
            "dns-coverage/prune": lambda: run_dns_policy(
                self.context, self.services, self.update_mode
            ),
            "content-inactive-cleanup": lambda: run_content_inactive_cleanup(
                self.context, self.services
            ),
            "dns-output": lambda: run_dns_output(
                self.context, self.services, self._build_timestamp
            ),
            "dns-converter": lambda: run_dns_converter(self.context, self.services),
            "validate": lambda: run_validation(self.context, self.services),
        }
        summaries = {
            "upstream": _upstream_summary,
            "content": _content_summary,
            "dns-rules": _dns_rules_summary,
            "dns-coverage/prune": _dns_policy_summary,
            "content-inactive-cleanup": _content_inactive_summary,
            "dns-output": _dns_output_summary,
            "dns-converter": _conversion_summary,
            "validate": _validation_summary,
        }
        statuses = {
            "upstream": _upstream_status,
            "content": _success_status,
            "dns-rules": _success_status,
            "dns-coverage/prune": _dns_policy_status,
            "content-inactive-cleanup": _success_status,
            "dns-output": _success_status,
            "dns-converter": _conversion_status,
            "validate": _success_status,
        }
        self._stage_specs = build_stage_specs(
            skip_upstream=self.skip_upstream,
            handlers=handlers,
            summaries=summaries,
            statuses=statuses,
        )
        return self._stage_specs

    def stage_plan(self) -> Tuple[StageInvocation, ...]:
        return tuple(spec.invocation for spec in self.stage_specs())

    @property
    def execution_reported(self) -> bool:
        """Whether a build has emitted a baseline or stage result."""

        return bool(self._stage_reports or self._baseline_report)

    def prepare_baseline(self) -> None:
        """Snapshot required published artifacts before any build stage runs."""

        started = monotonic()
        print(
            "[PIPELINE] START baseline | "
            f"adblock={_display_path(self.context.root_dir, self.context.artifacts.adblock)} "
            f"dns={_display_path(self.context.root_dir, self.context.artifacts.dns)}",
            file=sys.stderr,
            flush=True,
        )
        try:
            self.context.baseline_dir.mkdir(parents=True, exist_ok=True)
            for name in BASELINE_ARTIFACTS:
                source = getattr(self.context.artifacts, name)
                if not source.is_file():
                    raise PipelineError(f"missing baseline artifact: {source}")
                target = self.context.baseline_dir / f"{name}.txt"
                shutil.copyfile(source, target)
        except BaseException as exc:
            duration = format_duration(monotonic() - started)
            message = one_line(exc)
            self._baseline_report = StageReport(
                name="baseline",
                api="pipeline.prepare_baseline",
                status="failed",
                duration_seconds=max(0.0, monotonic() - started),
                summary=message,
            )
            print(
                f"[PIPELINE] FAIL baseline | {duration} | {message}",
                file=sys.stderr,
                flush=True,
            )
            raise
        self._baseline_report = StageReport(
            name="baseline",
            api="pipeline.prepare_baseline",
            status="success",
            duration_seconds=max(0.0, monotonic() - started),
            summary="snapshots=2",
        )
        print(
            f"[PIPELINE] DONE baseline | "
            f"{format_duration(self._baseline_report.duration_seconds)} | snapshots=2",
            file=sys.stderr,
            flush=True,
        )

    def _run_upstream(self) -> UpstreamBuildResult:
        return run_upstream(self.context, self.services)

    def _run_content(self) -> ContentBuildResult:
        return run_content(self.context, self.services, self._build_timestamp)

    def _run_dns_rules(self) -> DnsBuildResult:
        return run_dns_rules(self.context, self.services)

    def _run_dns_policy(self) -> DnsPolicyResult:
        return run_dns_policy(self.context, self.services, self.update_mode)

    def _run_dns_output(self) -> DnsOutputResult:
        return run_dns_output(self.context, self.services, self._build_timestamp)

    def _run_content_inactive_cleanup(self) -> ContentInactiveCleanupResult:
        return run_content_inactive_cleanup(self.context, self.services)

    def _run_dns_converter(self) -> ConversionResult:
        return run_dns_converter(self.context, self.services)

    def _run_validation(self) -> tuple[RuleFileStats, RuleFileStats]:
        return run_validation(self.context, self.services)

    def run_stage(
        self,
        stage: StageInvocation,
    ) -> Any:
        return self._stage_runner.run(stage)

    def _cleanup_generated_files(self) -> None:
        try:
            self.context.dns_ip_cidr_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(
                "[WARN] unable to remove DNS sidecar "
                f"{self.context.dns_ip_cidr_path}: {exc}",
                file=sys.stderr,
            )

    def build(self) -> None:
        self._stage_reports.clear()
        self._baseline_report = None
        stages = self.stage_specs()
        build_started = monotonic()
        self._build_timestamp = now_gmt8()
        print(
            f"[PIPELINE] START build | stages={len(stages)} "
            f"config={_display_path(self.context.root_dir, self.context.config_path)}",
            file=sys.stderr,
            flush=True,
        )
        build_error: Optional[BaseException] = None
        try:
            self.prepare_baseline()
            for spec in stages:
                self.run_stage(spec.invocation)
        except BaseException as exc:
            build_error = exc
            raise
        finally:
            self._cleanup_generated_files()
            elapsed = format_duration(monotonic() - build_started)
            passed = sum(
                report.status == "success" for report in self._stage_reports
            )
            warnings = sum(
                report.status == "warning" for report in self._stage_reports
            )
            failed = sum(
                report.status == "failed" for report in self._stage_reports
            )
            if self._baseline_report is not None:
                failed += int(self._baseline_report.status == "failed")
            skipped = max(0, len(stages) - len(self._stage_reports))
            if build_error is None:
                print(
                    f"[PIPELINE] DONE build | {elapsed} | "
                    f"passed={passed} warnings={warnings} failed={failed} "
                    f"skipped={skipped}",
                    file=sys.stderr,
                    flush=True,
                )
            else:
                print(
                    f"[PIPELINE] FAIL build | {elapsed} | "
                    f"passed={passed} warnings={warnings} failed={failed} "
                    f"skipped={skipped}",
                    file=sys.stderr,
                    flush=True,
                )
            self.reporter.write_summary(
                self._baseline_report,
                self._stage_reports,
            )

    def print_plan(self) -> None:
        try:
            baseline = self.context.baseline_dir.relative_to(self.context.root_dir)
            baseline_display = baseline.as_posix()
        except ValueError:
            baseline_display = str(self.context.baseline_dir)
        print(
            "prepare-baseline: copy configured adblock/dns artifacts to "
            f"{baseline_display}"
        )
        for stage in self.stage_plan():
            print(f"{stage.name}: {stage.api}")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "plan"))
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Show stage diagnostic logs (INFO); by default print only the concise summary"
        ),
    )
    parser.add_argument(
        "--skip-upstream",
        action="store_true",
        help="reuse existing tmp/content and tmp/dns sources without downloading",
    )
    parser.add_argument(
        "--update-mode",
        choices=tuple(mode.value for mode in UpdateMode),
        default=UpdateMode.FULL.value,
        help="select the full or quick application update plan",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    pipeline: Optional[Pipeline] = None
    try:
        if args.command == "build":
            # Stage APIs are intentionally quiet at INFO here.  Their
            # warnings/errors remain visible inside the current Actions group;
            # the pipeline itself emits the concise START/DONE summary lines.
            configure_logging(
                level=logging.INFO if args.verbose else logging.WARNING
            )
        pipeline = Pipeline(
            create_context(args.config),
            skip_upstream=args.skip_upstream,
            update_mode=UpdateMode(args.update_mode),
        )
        if args.command == "plan":
            pipeline.print_plan()
        else:
            pipeline.build()
    except (ConfigError, OSError, PipelineError) as exc:
        # ``build`` already emits a stage-level and an overall FAIL record.
        # Avoid repeating the same exception as a fourth log line; retain a
        # direct error for configuration/startup failures before execution.
        execution_reported = pipeline is not None and pipeline.execution_reported
        if args.command != "build" or not execution_reported:
            print(f"[ERROR] pipeline: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
