"""Stage request adapters for the top-level rule pipeline.

Each function translates the shared pipeline context into one stage's narrow
request.  Execution and reporting remain outside this module.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from pipeline import PipelineContext, PipelineServices, UpdateMode

try:
    from dns_prune_model import DnsPolicyMode
    from dns_prune_pipeline import DnsPrunePaths, DnsPolicyStageRequest
    from dns_pipeline import DnsPaths
    from dns_converter_model import ConversionRequest
    from upstream_pipeline import UpstreamStageRequest
except ImportError:  # Support ``python -m script.pipeline_adapters``.
    from .dns_prune_model import DnsPolicyMode  # type: ignore[no-redef]
    from .dns_prune_pipeline import (  # type: ignore[no-redef]
        DnsPrunePaths,
        DnsPolicyStageRequest,
    )
    from .dns_pipeline import DnsPaths  # type: ignore[no-redef]
    from .dns_converter_model import ConversionRequest  # type: ignore[no-redef]
    from .upstream_pipeline import UpstreamStageRequest  # type: ignore[no-redef]


def run_upstream(context: "PipelineContext", services: "PipelineServices") -> object:
    request = UpstreamStageRequest(
        root_dir=context.root_dir,
        environment=context.settings.upstream_environment,
        config_path=context.upstream_config_path,
        failed_log=context.runtime.download_failed_log,
        strict=context.settings.strict_upstream_download,
    )
    return services.run_upstream(request)


def run_content(
    context: "PipelineContext",
    services: "PipelineServices",
    timestamp: Optional[datetime],
) -> object:
    return services.build_content(
        context.root_dir,
        timestamp=timestamp,
        output_file=context.artifacts.adblock,
    )


def run_dns_rules(context: "PipelineContext", services: "PipelineServices") -> object:
    paths = DnsPaths.from_root(
        context.root_dir,
        output=context.artifacts.dns,
        ip_cidr_output=context.dns_ip_cidr_path,
    )
    return services.build_dns(paths)


def run_dns_policy(
    context: "PipelineContext",
    services: "PipelineServices",
    update_mode: "UpdateMode",
) -> object:
    mode = (
        DnsPolicyMode.COVERAGE_ONLY
        if not context.settings.dns_prune_enabled
        else DnsPolicyMode.CACHE_ONLY
        if update_mode.value == "quick"
        else DnsPolicyMode.PROBE
    )
    paths = DnsPrunePaths.from_root(
        context.root_dir,
        input_file=context.artifacts.dns,
        cache_file=context.runtime.dns_prune_cache,
        removed_log=context.runtime.dns_prune_log,
        environment=context.settings.dns_environment,
    )
    request = DnsPolicyStageRequest(
        root_dir=context.root_dir,
        input_file=context.artifacts.dns,
        mode=mode,
        cache_file=context.runtime.dns_prune_cache,
        removed_log=context.runtime.dns_prune_log,
        require_dead_capable=context.settings.strict_dns_prune,
        environment=context.settings.dns_environment,
        prune_request=context.dns_prune_request,
        paths=paths,
    )
    return services.run_dns_policy(request)


def run_content_inactive_cleanup(
    context: "PipelineContext", services: "PipelineServices"
) -> object:
    return services.cleanup_content_inactive(
        context.artifacts.adblock,
        cache_file=context.runtime.dns_prune_cache,
        policy=context.cache_policy,
        enabled=context.settings.dns_prune_enabled,
    )


def run_dns_output(
    context: "PipelineContext",
    services: "PipelineServices",
    timestamp: Optional[datetime],
) -> object:
    return services.finalize_dns_output(
        context.artifacts.dns,
        title_file=context.dns_title_path,
        output_file=context.artifacts.dns,
        previous_output_file=context.baseline_dir / "dns.txt",
        timestamp=timestamp,
    )


def run_dns_converter(context: "PipelineContext", services: "PipelineServices") -> object:
    request = ConversionRequest(
        root_dir=context.root_dir,
        environment=context.settings.converter_environment,
        dns_input=context.artifacts.dns,
        ip_cidr_input=context.dns_ip_cidr_path,
        config_path=context.converter_config_path,
        singbox_output=context.artifacts.singbox,
        mihomo_mrs_output=context.artifacts.mihomo_mrs,
        mihomo_yaml_output=context.artifacts.mihomo_yaml,
        strict=context.settings.strict_dns_converter,
        strict_mihomo_modifiers=context.settings.strict_mihomo_modifiers,
    )
    return services.run_conversion(request)


def run_validation(context: "PipelineContext", services: "PipelineServices") -> object:
    return services.validate_artifacts(
        context.config_path,
        artifact_overrides=context.artifacts.as_mapping(),
        baseline_adblock=context.baseline_dir / "adblock.txt",
        baseline_dns=context.baseline_dir / "dns.txt",
        max_drop_percent=context.settings.max_rule_drop_percent,
        root_dir=context.root_dir,
    )
