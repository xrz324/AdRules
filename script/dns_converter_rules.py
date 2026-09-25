#!/usr/bin/env python3
"""Deterministic rule preparation for sing-box and Mihomo."""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

try:
    from dns_minimizer import minimize_mihomo_lines
except ImportError:  # Support ``python -m script.dns_converter``.
    from .dns_minimizer import minimize_mihomo_lines  # type: ignore[no-redef]

try:
    from dns_converter_io import (
        atomic_write_lines,
        atomic_write_text,
        byte_sort_unique,
        emit_process_stderr,
        log_info,
        read_lines,
    )
    from dns_converter_model import ConversionStageError, ConverterPaths
except ImportError:  # Support ``python -m script.dns_converter``.
    from .dns_converter_io import (  # type: ignore[no-redef]
        atomic_write_lines,
        atomic_write_text,
        byte_sort_unique,
        emit_process_stderr,
        log_info,
        read_lines,
    )
    from .dns_converter_model import (  # type: ignore[no-redef]
        ConversionStageError,
        ConverterPaths,
    )


def _run_awk(
    program: Path,
    input_files: Sequence[Path],
    *,
    variables: Mapping[str, str] | None = None,
    field_separator: str | None = None,
    environment: Mapping[str, str],
) -> list[str]:
    if shutil.which("awk") is None:
        raise ConversionStageError("Missing required dependency: awk")
    if not program.is_file():
        raise ConversionStageError(f"AWK converter not found: {program}")
    command: list[str] = ["awk"]
    if field_separator is not None:
        command.extend(("-F", field_separator))
    for key, value in (variables or {}).items():
        command.extend(("-v", f"{key}={value}"))
    command.extend(("-f", str(program)))
    command.extend(str(path) for path in input_files)
    try:
        completed = subprocess.run(
            command,
            cwd=program.parent.parent,
            env=dict(environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ConversionStageError(f"AWK conversion failed: {program}: {exc}") from exc
    emit_process_stderr(completed.stderr)
    if completed.returncode != 0:
        raise ConversionStageError(
            f"AWK conversion failed ({program.name}, rc={completed.returncode})"
        )
    try:
        output = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConversionStageError(f"AWK output is not UTF-8: {program}") from exc
    return byte_sort_unique(output.splitlines())


def generate_mihomo_classical_rules(
    paths: ConverterPaths,
    *,
    environment: Mapping[str, str],
) -> list[str]:
    """Run the dedicated classical-rule converter and persist its input."""

    program = paths.awk_dir / "mihomo_classical.awk"
    if not paths.ip_cidr_input.is_file():
        raise ConversionStageError(f"DNS CIDR sidecar not found: {paths.ip_cidr_input}")
    lines = _run_awk(
        program,
        (paths.dns_input, paths.ip_cidr_input),
        environment=environment,
    )
    atomic_write_lines(paths.mihomo_rule_file, lines)
    return lines


def generate_singbox_input(
    paths: ConverterPaths,
    *,
    environment: Mapping[str, str],
) -> list[str]:
    """Remove unsupported records before handing rules to sing-box."""

    program = paths.awk_dir / "singbox_preprocess.awk"
    # The first pass builds the badfilter-disabled set and the second pass
    # filters the same source.  Passing the file twice is intentional.
    lines = _run_awk(
        program,
        (paths.dns_input, paths.dns_input),
        environment=environment,
    )
    atomic_write_lines(paths.singbox_input_file, lines)
    return lines


def minimize_mihomo_rules(path: Path) -> list[str]:
    try:
        lines = read_lines(path)
        minimized, stats = minimize_mihomo_lines(lines)
        atomic_write_lines(path, minimized)
    except Exception as exc:  # noqa: BLE001 - provide a stage-specific error.
        raise ConversionStageError(f"Mihomo classical rule minimization failed: {exc}") from exc
    log_info(
        "Mihomo minimizer %d -> %d (-%d; suffix:%d domain:%d wildcard:%d)"
        % (
            len(lines),
            len(minimized),
            stats.removed,
            stats.mihomo_suffix,
            stats.mihomo_domain,
            stats.mihomo_wildcard,
        )
    )
    return minimized


_CLASSICAL_RULE_RE = re.compile(
    r"^(?:DOMAIN(?:-SUFFIX|-WILDCARD|-REGEX)?|IP-CIDR6?|DST-PORT|AND|OR|NOT),"
)


def validate_mihomo_classical_rules(lines: Sequence[str]) -> list[str]:
    """Return syntax violations using the same grammar as the old grep check."""

    return [line for line in lines if not _CLASSICAL_RULE_RE.match(line)]


def prepare_mihomo_payload(
    paths: ConverterPaths,
    *,
    environment: Mapping[str, str],
) -> tuple[list[str], str]:
    """Split domain rules and YAML-only payload records with the AWK helper."""

    paths.domain_file.parent.mkdir(parents=True, exist_ok=True)
    paths.yaml_raw_file.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(paths.domain_file, "")
    atomic_write_text(paths.yaml_raw_file, "")
    _run_awk(
        paths.awk_dir / "mihomo_payload.awk",
        (paths.mihomo_rule_file,),
        variables={
            "domain_file": str(paths.domain_file),
            "yaml_raw_file": str(paths.yaml_raw_file),
        },
        field_separator=",",
        environment=environment,
    )

    domain_lines = byte_sort_unique(read_lines(paths.domain_file))
    yaml_lines = byte_sort_unique(read_lines(paths.yaml_raw_file))
    # The shell adapter used ``LC_ALL=C sort -u`` before invoking mihomo and
    # before composing YAML.  Persist the normalized domain file as well so a
    # converter binary (and diagnostic stub) observes the same deterministic
    # order.
    atomic_write_lines(paths.domain_file, domain_lines)
    atomic_write_lines(paths.yaml_raw_file, yaml_lines)
    yaml_payload = ["payload:"]
    if yaml_lines:
        yaml_payload.extend(
            "  - '%s'" % line.replace("'", "''") for line in yaml_lines
        )
    else:
        yaml_payload = ["payload: []"]
    return domain_lines, "\n".join(yaml_payload) + "\n"
