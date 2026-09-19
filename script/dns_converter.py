#!/usr/bin/env python3
"""Convert the generated DNS list to sing-box and Mihomo rule sets.

This module is the stable converter facade.  Configuration, rule preparation,
tool acquisition, and rollback-capable publication live in focused internal
modules; callers continue to use ``run_conversion`` or this file's CLI.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Optional

try:
    from dns_converter_config import (
        DEFAULT_CONFIG_NAME,
        load_converter_config,
        resolve_converter_settings,
    )
    from dns_converter_io import (
        atomic_write_text,
        log_error,
        log_info,
        log_warn,
        publish_artifacts,
        read_lines,
        remove,
        run_binary,
        temporary_output,
    )
    from dns_converter_model import (
        ConversionContext,
        ConversionRequest,
        ConversionResult,
        ConversionStageError,
        ConverterConfigError,
        ConverterPaths,
        DnsConverterError,
        Downloader,
        ROOT_DIR,
        resolve_path,
    )
    from dns_converter_rules import (
        generate_mihomo_classical_rules,
        generate_singbox_input,
        minimize_mihomo_rules,
        prepare_mihomo_payload,
        validate_mihomo_classical_rules,
    )
    from dns_converter_tools import (
        download_file,
        extract_mihomo_asset_url,
        get_mihomo_binary,
        get_singbox_binary,
        resolve_mihomo_download_url,
    )
except ImportError:  # Support ``python -m script.dns_converter``.
    from .dns_converter_config import (  # type: ignore[no-redef]
        DEFAULT_CONFIG_NAME,
        load_converter_config,
        resolve_converter_settings,
    )
    from .dns_converter_io import (  # type: ignore[no-redef]
        atomic_write_text,
        log_error,
        log_info,
        log_warn,
        publish_artifacts,
        read_lines,
        remove,
        run_binary,
        temporary_output,
    )
    from .dns_converter_model import (  # type: ignore[no-redef]
        ConversionContext,
        ConversionRequest,
        ConversionResult,
        ConversionStageError,
        ConverterConfigError,
        ConverterPaths,
        DnsConverterError,
        Downloader,
        ROOT_DIR,
        resolve_path,
    )
    from .dns_converter_rules import (  # type: ignore[no-redef]
        generate_mihomo_classical_rules,
        generate_singbox_input,
        minimize_mihomo_rules,
        prepare_mihomo_payload,
        validate_mihomo_classical_rules,
    )
    from .dns_converter_tools import (  # type: ignore[no-redef]
        download_file,
        extract_mihomo_asset_url,
        get_mihomo_binary,
        get_singbox_binary,
        resolve_mihomo_download_url,
    )


def _process_singbox(context: ConversionContext, *, downloader: Downloader) -> None:
    paths = context.paths
    try:
        lines = generate_singbox_input(
            paths,
            environment=context.environment,
        )
    except ConversionStageError:
        log_warn("sing-box preprocessing failed")
        raise
    if not lines:
        raise ConversionStageError("sing-box preprocessing produced no rules; skipping conversion")

    binary = get_singbox_binary(
        paths,
        context.settings.singbox,
        downloader=downloader,
    )
    temporary = temporary_output(paths.singbox_output)
    try:
        run_binary(
            (
                str(binary),
                "rule-set",
                "convert",
                str(paths.singbox_input_file),
                "-t",
                "adguard",
                "--output",
                str(temporary),
            ),
            cwd=paths.root_dir,
            label="sing-box",
            environment=context.environment,
            normalize_stderr=True,
        )
        if not temporary.is_file():
            raise ConversionStageError("sing-box produced no output file")
        publish_artifacts(((temporary, paths.singbox_output),))
    finally:
        remove(temporary)
    log_info("sing-box conversion complete")


def _report_invalid_mihomo_rules(lines: Sequence[str], invalid: Sequence[str]) -> None:
    log_error("Detected rules with unsupported Mihomo classical syntax; examples:")
    invalid_set = set(invalid)
    shown = 0
    for index, line in enumerate(lines, start=1):
        if line not in invalid_set:
            continue
        print(f"{index}:{line}", file=sys.stderr)
        shown += 1
        if shown >= 10:
            break


def _process_mihomo(context: ConversionContext, *, downloader: Downloader) -> None:
    paths = context.paths
    try:
        generate_mihomo_classical_rules(
            paths,
            environment=context.environment,
        )
    except ConversionStageError:
        log_warn("Mihomo classical rule generation failed")
        raise
    minimize_mihomo_rules(paths.mihomo_rule_file)
    classical_lines = read_lines(paths.mihomo_rule_file)
    if not classical_lines:
        raise ConversionStageError("Mihomo classical rules are empty; skipping conversion")
    invalid = validate_mihomo_classical_rules(classical_lines)
    if invalid:
        _report_invalid_mihomo_rules(classical_lines, invalid)
        raise ConversionStageError("Mihomo classical rule validation failed")

    domain_lines, yaml_payload = prepare_mihomo_payload(
        paths,
        environment=context.environment,
    )
    if not domain_lines:
        raise ConversionStageError("No rules available for Mihomo domain MRS conversion")

    binary = get_mihomo_binary(
        paths,
        context.settings.mihomo,
        downloader=downloader,
    )
    temporary_mrs = temporary_output(paths.mihomo_mrs_output)
    temporary_yaml = temporary_output(paths.mihomo_yaml_output)
    try:
        atomic_write_text(temporary_yaml, yaml_payload)
        run_binary(
            (
                str(binary),
                "convert-ruleset",
                "domain",
                "text",
                str(paths.domain_file),
                str(temporary_mrs),
            ),
            cwd=paths.root_dir,
            label="mihomo domain mrs",
            environment=context.environment,
            normalize_stderr=True,
        )
        if not temporary_mrs.is_file():
            raise ConversionStageError("Mihomo produced no domain MRS output file")
        publish_artifacts(
            (
                (temporary_mrs, paths.mihomo_mrs_output),
                (temporary_yaml, paths.mihomo_yaml_output),
            )
        )
    finally:
        remove(temporary_mrs)
        remove(temporary_yaml)
    log_info("Mihomo conversion complete: domain mrs + yaml")


def _cleanup_intermediates(paths: ConverterPaths) -> None:
    for path in (
        paths.mihomo_rule_file,
        paths.singbox_input_file,
        paths.domain_file,
        paths.yaml_raw_file,
        paths.invalid_file,
    ):
        remove(path)


def build_conversion_context(
    root_dir: Path = ROOT_DIR,
    *,
    dns_input: Optional[Path] = None,
    ip_cidr_input: Optional[Path] = None,
    tools_dir: Optional[Path] = None,
    config_path: Optional[Path] = None,
    singbox_output: Optional[Path] = None,
    mihomo_mrs_output: Optional[Path] = None,
    mihomo_yaml_output: Optional[Path] = None,
    awk_dir: Optional[Path] = None,
    strict: Optional[bool] = None,
    strict_mihomo_modifiers: Optional[bool] = None,
    environment: Mapping[str, str],
) -> ConversionContext:
    """Resolve paths and policy once before conversion execution."""

    root = Path(root_dir).resolve()
    config = load_converter_config(
        resolve_path(root, config_path, DEFAULT_CONFIG_NAME)
    )
    paths = ConverterPaths.from_root(
        root,
        dns_input=dns_input,
        ip_cidr_input=ip_cidr_input,
        tools_dir=tools_dir,
        singbox_output=singbox_output,
        mihomo_mrs_output=mihomo_mrs_output,
        mihomo_yaml_output=mihomo_yaml_output,
        awk_dir=awk_dir,
    )
    if not paths.dns_input.is_file():
        raise DnsConverterError(f"DNS input file not found: {paths.dns_input}")

    runtime_environment = dict(environment)
    settings = resolve_converter_settings(
        config,
        runtime_environment,
        strict=strict,
        strict_mihomo_modifiers=strict_mihomo_modifiers,
    )
    runtime_environment["STRICT_MIHOMO_MODIFIERS"] = (
        "true" if settings.strict_mihomo_modifiers else "false"
    )
    return ConversionContext(
        paths=paths,
        settings=settings,
        environment=MappingProxyType(runtime_environment),
    )


def execute_conversion(
    context: ConversionContext,
    *,
    downloader: Optional[Downloader] = None,
) -> ConversionResult:
    """Execute conversion from a fully resolved immutable context."""

    paths = context.paths
    paths.tmp_dir.mkdir(parents=True, exist_ok=True)
    paths.tools_dir.mkdir(parents=True, exist_ok=True)
    selected_downloader = download_file if downloader is None else downloader

    singbox_success = False
    mihomo_success = False
    try:
        try:
            _process_singbox(context, downloader=selected_downloader)
            singbox_success = True
        except (ConversionStageError, OSError, UnicodeError) as exc:
            log_warn(
                "sing-box artifact generation failed; keeping existing "
                f"artifact if present: {exc}"
            )

        try:
            _process_mihomo(context, downloader=selected_downloader)
            mihomo_success = True
        except (ConversionStageError, OSError, UnicodeError) as exc:
            log_warn(
                "Mihomo classical rule generation failed; keeping existing "
                f"artifact if present: {exc}"
            )
    finally:
        _cleanup_intermediates(paths)

    result = ConversionResult(paths, singbox_success, mihomo_success)
    if result.failed:
        if str(context.environment.get("GITHUB_ACTIONS", "")).lower() == "true":
            print("::warning::DNS binary conversion failed (sing-box or mihomo)")
        if context.settings.strict:
            raise DnsConverterError(
                "STRICT_DNS_CONVERTER=true; DNS binary conversion failed; "
                "aborting pipeline"
            )
    return result


def execute_conversion_request(
    request: ConversionRequest,
    *,
    downloader: Optional[Downloader] = None,
) -> ConversionResult:
    """Resolve and execute one typed converter stage request."""

    context = build_conversion_context(
        request.root_dir,
        dns_input=request.dns_input,
        ip_cidr_input=request.ip_cidr_input,
        tools_dir=request.tools_dir,
        config_path=request.config_path,
        singbox_output=request.singbox_output,
        mihomo_mrs_output=request.mihomo_mrs_output,
        mihomo_yaml_output=request.mihomo_yaml_output,
        awk_dir=request.awk_dir,
        strict=request.strict,
        strict_mihomo_modifiers=request.strict_mihomo_modifiers,
        environment=request.environment,
    )
    return execute_conversion(context, downloader=downloader)


def run_conversion(
    root_dir: Path = ROOT_DIR,
    *,
    dns_input: Optional[Path] = None,
    ip_cidr_input: Optional[Path] = None,
    tools_dir: Optional[Path] = None,
    config_path: Optional[Path] = None,
    singbox_output: Optional[Path] = None,
    mihomo_mrs_output: Optional[Path] = None,
    mihomo_yaml_output: Optional[Path] = None,
    awk_dir: Optional[Path] = None,
    downloader: Optional[Downloader] = None,
    strict: Optional[bool] = None,
    strict_mihomo_modifiers: Optional[bool] = None,
    environment: Mapping[str, str],
) -> ConversionResult:
    """Compatibility adapter for CLI callers and existing embedders."""

    request = ConversionRequest(
        root_dir=Path(root_dir),
        environment=environment,
        dns_input=dns_input,
        ip_cidr_input=ip_cidr_input,
        tools_dir=tools_dir,
        config_path=config_path,
        singbox_output=singbox_output,
        mihomo_mrs_output=mihomo_mrs_output,
        mihomo_yaml_output=mihomo_yaml_output,
        awk_dir=awk_dir,
        strict=strict,
        strict_mihomo_modifiers=strict_mihomo_modifiers,
    )
    return execute_conversion_request(request, downloader=downloader)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT_DIR)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--input", dest="dns_input", type=Path)
    parser.add_argument("--ip-cidr-input", type=Path)
    parser.add_argument("--tools-dir", type=Path)
    parser.add_argument("--awk-dir", type=Path)
    parser.add_argument("--singbox-output", type=Path)
    parser.add_argument("--mihomo-mrs-output", type=Path)
    parser.add_argument("--mihomo-yaml-output", type=Path)
    parser.add_argument("--strict", dest="strict", action="store_true", default=None)
    parser.add_argument("--no-strict", dest="strict", action="store_false")
    parser.add_argument(
        "--strict-mihomo-modifiers",
        dest="strict_mihomo_modifiers",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--no-strict-mihomo-modifiers",
        dest="strict_mihomo_modifiers",
        action="store_false",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        from logging_utils import configure_logging
    except ImportError:  # Support ``python -m script.dns_converter``.
        from .logging_utils import configure_logging  # type: ignore[no-redef]

    configure_logging()
    args = parse_args(argv)
    try:
        result = run_conversion(
            args.root,
            dns_input=args.dns_input,
            ip_cidr_input=args.ip_cidr_input,
            tools_dir=args.tools_dir,
            config_path=args.config,
            singbox_output=args.singbox_output,
            mihomo_mrs_output=args.mihomo_mrs_output,
            mihomo_yaml_output=args.mihomo_yaml_output,
            awk_dir=args.awk_dir,
            strict=args.strict,
            strict_mihomo_modifiers=args.strict_mihomo_modifiers,
            environment=os.environ,
        )
    except (DnsConverterError, OSError, UnicodeError, ValueError) as exc:
        log_error(f"DNS converter: {exc}")
        return 1
    log_info(
        f"DNS conversion complete: sing-box={'ok' if result.singbox_success else 'failed'}, "
        f"Mihomo={'ok' if result.mihomo_success else 'failed'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
