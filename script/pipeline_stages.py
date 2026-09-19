"""Stage registration primitives for the rule-generation pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Generic, Mapping, Tuple, TypeVar


@dataclass(frozen=True)
class StageInvocation:
    """A named Python API stage used for ordering and plan display."""

    name: str
    api: str


StageValue = TypeVar("StageValue")


@dataclass(frozen=True)
class StageSpec(Generic[StageValue]):
    """One stage's execution and reporting contract."""

    invocation: StageInvocation
    run: Callable[[], StageValue]
    summarize: Callable[[StageValue], str]
    status: Callable[[StageValue], str]


def build_stage_specs(
    *,
    skip_upstream: bool,
    handlers: Mapping[str, Callable[[], Any]],
    summaries: Mapping[str, Callable[[Any], str]],
    statuses: Mapping[str, Callable[[Any], str]],
) -> Tuple[StageSpec[Any], ...]:
    """Build the ordered stage graph from injected stage handlers.

    The registry owns ordering and public API names; the pipeline owns only
    request construction and service composition.
    """

    definitions = [
        ("content", "content_pipeline.build_content"),
        ("dns-rules", "dns_pipeline.build_dns"),
        ("dns-coverage/prune", "dns_prune_pipeline.execute_dns_policy"),
        ("content-inactive-cleanup", "content_inactive.cleanup_content_with_cache"),
        ("dns-output", "dns_output.finalize_dns_output"),
        ("dns-converter", "dns_converter.execute_conversion_request"),
        ("validate", "validate_outputs.validate_artifacts"),
    ]
    if not skip_upstream:
        definitions.insert(0, ("upstream", "upstream_pipeline.execute_upstream_stage"))
    try:
        return tuple(
            StageSpec(
                StageInvocation(name, api),
                handlers[name],
                summaries[name],
                statuses[name],
            )
            for name, api in definitions
        )
    except KeyError as exc:
        raise ValueError(f"stage registry is missing handler: {exc.args[0]}") from exc

