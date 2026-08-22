#!/usr/bin/env python3
"""Run the GitHub Actions rule-generation stages through Python APIs."""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from time import monotonic
from typing import Callable, Mapping, Optional, Sequence, Tuple, cast

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
    from common import now_gmt8
    from dns_converter import ConversionResult, run_conversion
    from dns_output import DnsOutputResult, finalize_dns_output
    from dns_pipeline import DnsBuildResult, DnsPaths, build_dns
    from dns_prune_pipeline import (
        DnsCoveragePipelineResult,
        DnsPolicyResult,
        DnsPrunePipelineResult,
        run_dns_policy,
    )
    from logging_utils import configure_logging
    from pipeline_reporting import (
        PipelineReporter,
        StageReport,
        format_duration,
        one_line,
    )
    from upstream_pipeline import UpstreamBuildResult, run_upstream
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
    from .common import now_gmt8  # type: ignore[no-redef]
    from .dns_converter import ConversionResult, run_conversion  # type: ignore[no-redef]
    from .dns_output import DnsOutputResult, finalize_dns_output  # type: ignore[no-redef]
    from .dns_pipeline import DnsBuildResult, DnsPaths, build_dns  # type: ignore[no-redef]
    from .dns_prune_pipeline import (  # type: ignore[no-redef]
        DnsCoveragePipelineResult,
        DnsPolicyResult,
        DnsPrunePipelineResult,
        run_dns_policy,
    )
    from .logging_utils import configure_logging  # type: ignore[no-redef]
    from .pipeline_reporting import (  # type: ignore[no-redef]
        PipelineReporter,
        StageReport,
        format_duration,
        one_line,
    )
    from .upstream_pipeline import UpstreamBuildResult, run_upstream  # type: ignore[no-redef]
    from .validate_outputs import RuleFileStats, validate_artifacts  # type: ignore[no-redef]


ROOT_DIR = Path(__file__).resolve().parents[1]
BASELINE_ARTIFACTS = ("adblock", "dns")


class PipelineError(RuntimeError):
    """Raised when a pipeline stage cannot complete successfully."""


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
class PipelineContext:
    """Immutable configuration, settings, and paths for one build."""

    root_dir: Path
    config_path: Path
    settings: RuntimeSettings
    artifacts: Mapping[str, Path]
    paths: PipelinePaths
    config: Mapping[str, object] = field(default_factory=dict)
    runtime: Mapping[str, Path] = field(default_factory=dict)

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


@dataclass(frozen=True)
class StageInvocation:
    """A named Python API stage used for ordering and plan display."""

    name: str
    api: str


StageResult = (
    UpstreamBuildResult
    | ContentBuildResult
    | DnsBuildResult
    | DnsPolicyResult
    | DnsOutputResult
    | ConversionResult
    | tuple[RuleFileStats, RuleFileStats]
    | None
)
StageFunction = Callable[..., StageResult]
StageSummary = Callable[[StageResult], str]
StageStatus = Callable[[StageResult], str]


@dataclass(frozen=True)
class StageSpec:
    """One stage's execution and reporting contract."""

    invocation: StageInvocation
    run: Callable[[], StageResult]
    summarize: StageSummary
    status: StageStatus


@dataclass(frozen=True)
class PipelineServices:
    """Injectable stage functions used by the Actions orchestrator."""

    run_upstream: StageFunction
    build_content: StageFunction
    build_dns: StageFunction
    run_dns_policy: StageFunction
    finalize_dns_output: StageFunction
    run_conversion: StageFunction
    validate_artifacts: StageFunction


def _default_services() -> PipelineServices:
    # Resolve globals at construction time so tests can patch a stage before
    # creating a Pipeline without mutating a process-wide singleton.
    return PipelineServices(
        run_upstream=run_upstream,
        build_content=build_content,
        build_dns=build_dns,
        run_dns_policy=run_dns_policy,
        finalize_dns_output=finalize_dns_output,
        run_conversion=run_conversion,
        validate_artifacts=validate_artifacts,
    )


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


def _empty_summary(result: StageResult) -> str:
    del result
    return ""


def _upstream_summary(result: StageResult) -> str:
    if result is None:
        return ""
    upstream = cast(UpstreamBuildResult, result)
    return (
        f"downloaded={upstream.succeeded}/{upstream.attempted} "
        f"mirrored={upstream.mirrored} "
        f"failed={len(upstream.failed_urls)}"
    )


def _content_summary(result: StageResult) -> str:
    if result is None:
        return ""
    content = cast(ContentBuildResult, result)
    return f"rules={content.rule_count} source-lines={content.source_line_count}"


def _dns_rules_summary(result: StageResult) -> str:
    if result is None:
        return ""
    dns = cast(DnsBuildResult, result)
    return f"rules={dns.output_count} cidr={dns.cidr_count}"


def _dns_policy_summary(result: StageResult) -> str:
    if result is None:
        return ""
    if isinstance(result, DnsCoveragePipelineResult):
        return (
            f"rules={result.before_rule_count}->{result.final_rule_count} "
            f"covered={result.covered_domain_count} pruned=0"
        )
    policy = cast(DnsPrunePipelineResult, result)
    return (
        f"rules={policy.before_rule_count}->{policy.final_rule_count} "
        f"covered={policy.covered_domain_count} "
        f"pruned={max(0, policy.before_rule_count - policy.after_prune_rule_count)}"
    )


def _dns_output_summary(result: StageResult) -> str:
    if result is None:
        return ""
    output = cast(DnsOutputResult, result)
    return f"rules={output.rule_count}"


def _conversion_summary(result: StageResult) -> str:
    if result is None:
        return ""
    return (
        f"sing-box={'ok' if cast(ConversionResult, result).singbox_success else 'failed'} "
        f"mihomo={'ok' if cast(ConversionResult, result).mihomo_success else 'failed'}"
    )


def _validation_summary(result: StageResult) -> str:
    if not isinstance(result, tuple) or len(result) != 2:
        return ""
    return f"adblock={result[0].rule_count} dns={result[1].rule_count}"


def _success_status(result: StageResult) -> str:
    del result
    return "success"


def _upstream_status(result: StageResult) -> str:
    upstream = cast(Optional[UpstreamBuildResult], result)
    return "warning" if upstream is not None and upstream.failed_urls else "success"


def _conversion_status(result: StageResult) -> str:
    conversion = cast(Optional[ConversionResult], result)
    return "warning" if conversion is not None and conversion.failed else "success"


def create_context(
    config_path: Path = DEFAULT_CONFIG_PATH,
    root_dir: Path = ROOT_DIR,
) -> PipelineContext:
    """Load one normalized config and derive every stage path."""

    root = Path(root_dir).resolve()
    resolved_config = _resolve_config_path(config_path, root)
    config = load_config(resolved_config)

    settings = runtime_settings(config, os.environ)

    configured_artifacts = {
        name: _resolve_root_path(root, path)
        for name, path in artifact_paths(config).items()
    }
    paths = PipelinePaths.from_config(root, config)
    raw_runtime = config.get("runtime", {})
    if not isinstance(raw_runtime, Mapping):
        raise ConfigError("normalized config has invalid runtime")
    runtime = {
        str(name): _resolve_root_path(root, str(path))
        for name, path in raw_runtime.items()
    }
    return PipelineContext(
        root_dir=root,
        config_path=resolved_config,
        settings=settings,
        artifacts=configured_artifacts,
        paths=paths,
        config=config,
        runtime=runtime,
    )


class Pipeline:
    """Execute the ordered Python stage APIs for one repository snapshot."""

    def __init__(
        self,
        context: PipelineContext,
        services: Optional[PipelineServices] = None,
        *,
        skip_upstream: bool = False,
        skip_dns_probe: bool = False,
        reporter: Optional[PipelineReporter] = None,
    ) -> None:
        self.context = context
        self.services = services or _default_services()
        self.skip_upstream = skip_upstream
        self.skip_dns_probe = skip_dns_probe
        self.reporter = reporter or PipelineReporter(
            context.root_dir,
            context.settings.environment,
        )
        self._stage_reports: list[StageReport] = []
        self._baseline_report: Optional[StageReport] = None
        self._build_timestamp: Optional[datetime] = None

    def stage_specs(self) -> Tuple[StageSpec, ...]:
        """Return the single registry for stage execution and reporting."""

        stages = [
            StageSpec(
                StageInvocation("content", "content_pipeline.build_content"),
                self._run_content,
                _content_summary,
                _success_status,
            ),
            StageSpec(
                StageInvocation("dns-rules", "dns_pipeline.build_dns"),
                self._run_dns_rules,
                _dns_rules_summary,
                _success_status,
            ),
            StageSpec(
                StageInvocation(
                    "dns-coverage/prune",
                    "dns_prune_pipeline.run_dns_policy",
                ),
                self._run_dns_policy,
                _dns_policy_summary,
                _success_status,
            ),
            StageSpec(
                StageInvocation("dns-output", "dns_output.finalize_dns_output"),
                self._run_dns_output,
                _dns_output_summary,
                _success_status,
            ),
            StageSpec(
                StageInvocation("dns-converter", "dns_converter.run_conversion"),
                self._run_dns_converter,
                _conversion_summary,
                _conversion_status,
            ),
            StageSpec(
                StageInvocation("validate", "validate_outputs.validate_artifacts"),
                self._run_validation,
                _validation_summary,
                _success_status,
            ),
        ]
        if not self.skip_upstream:
            stages.insert(
                0,
                StageSpec(
                    StageInvocation("upstream", "upstream_pipeline.run_upstream"),
                    self._run_upstream,
                    _upstream_summary,
                    _upstream_status,
                ),
            )
        return tuple(stages)

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
            f"adblock={_display_path(self.context.root_dir, self.context.artifacts['adblock'])} "
            f"dns={_display_path(self.context.root_dir, self.context.artifacts['dns'])}",
            file=sys.stderr,
            flush=True,
        )
        try:
            self.context.baseline_dir.mkdir(parents=True, exist_ok=True)
            for name in BASELINE_ARTIFACTS:
                source = self.context.artifacts[name]
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

    def _run_upstream(self) -> StageResult:
        failed_log = self.context.runtime["download_failed_log"]
        return self.services.run_upstream(
            self.context.root_dir,
            config_path=self.context.upstream_config_path,
            failed_log=failed_log,
            strict=self.context.settings.strict_upstream_download,
            environment=self.context.settings.environment,
        )

    def _run_content(self) -> StageResult:
        return self.services.build_content(
            self.context.root_dir,
            timestamp=self._build_timestamp,
            output_file=self.context.artifacts["adblock"],
        )

    def _run_dns_rules(self) -> StageResult:
        paths = DnsPaths.from_root(
            self.context.root_dir,
            output=self.context.artifacts["dns"],
            ip_cidr_output=self.context.dns_ip_cidr_path,
        )
        return self.services.build_dns(paths)

    def _run_dns_policy(self) -> StageResult:
        common = {
            "root_dir": self.context.root_dir,
            "input_file": self.context.artifacts["dns"],
        }
        cache_file = self.context.runtime["dns_prune_cache"]
        removed_log = self.context.runtime["dns_prune_log"]
        return self.services.run_dns_policy(
            **common,
            prune_enabled=(
                False
                if self.skip_dns_probe
                else self.context.settings.dns_prune_enabled
            ),
            cache_file=cache_file,
            removed_log=removed_log,
            require_dead_capable=self.context.settings.strict_dns_prune,
            environment=self.context.settings.environment,
        )

    def _run_dns_output(self) -> StageResult:
        return self.services.finalize_dns_output(
            self.context.artifacts["dns"],
            title_file=self.context.dns_title_path,
            output_file=self.context.artifacts["dns"],
            timestamp=self._build_timestamp,
        )

    def _run_dns_converter(self) -> StageResult:
        return self.services.run_conversion(
            self.context.root_dir,
            dns_input=self.context.artifacts["dns"],
            ip_cidr_input=self.context.dns_ip_cidr_path,
            config_path=self.context.converter_config_path,
            singbox_output=self.context.artifacts["singbox"],
            mihomo_mrs_output=self.context.artifacts["mihomo_mrs"],
            mihomo_yaml_output=self.context.artifacts["mihomo_yaml"],
            strict=self.context.settings.strict_dns_converter,
            strict_mihomo_modifiers=self.context.settings.strict_mihomo_modifiers,
            environment=self.context.settings.environment,
        )

    def _run_validation(self) -> StageResult:
        return self.services.validate_artifacts(
            self.context.config_path,
            artifact_overrides={
                name: path for name, path in self.context.artifacts.items()
            },
            baseline_adblock=self.context.baseline_dir / "adblock.txt",
            baseline_dns=self.context.baseline_dir / "dns.txt",
            max_drop_percent=self.context.settings.max_rule_drop_percent,
            root_dir=self.context.root_dir,
        )

    def _record_stage(
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
        self._stage_reports.append(report)
        return report

    def run_stage(
        self,
        stage: StageInvocation,
    ) -> StageResult:
        spec = next(
            (
                candidate
                for candidate in self.stage_specs()
                if candidate.invocation.name == stage.name
            ),
            None,
        )
        if spec is None:
            raise PipelineError(f"unknown pipeline stage: {stage.name}")
        stage = spec.invocation
        started = monotonic()
        self.reporter.stage_start(stage.name, stage.api)
        try:
            result = spec.run()
        except PipelineError as exc:
            report = self._record_stage(stage, "failed", started, one_line(exc))
            self.reporter.stage_failure(report, exc)
            raise
        except Exception as exc:  # noqa: BLE001 - stage boundary translation.
            wrapped = PipelineError(f"stage {stage.name} failed: {exc}")
            report = self._record_stage(
                stage,
                "failed",
                started,
                one_line(wrapped),
            )
            self.reporter.stage_failure(report, wrapped)
            raise wrapped from exc
        except BaseException as exc:
            # Preserve process-control exceptions while still closing the
            # Actions group and recording an accurate failed stage.
            report = self._record_stage(stage, "failed", started, one_line(exc))
            self.reporter.stage_failure(report, exc)
            raise
        else:
            report = self._record_stage(
                stage,
                spec.status(result),
                started,
                spec.summarize(result),
            )
            self.reporter.stage_done(report)
            return result
        finally:
            self.reporter.stage_end()

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
        "--skip-dns-probe",
        action="store_true",
        help="apply DNS coverage cleanup without inactive-domain probing",
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
            skip_dns_probe=args.skip_dns_probe,
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
