#!/usr/bin/env python3
"""Shared immutable models for DNS artifact conversion."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional


ROOT_DIR = Path(__file__).resolve().parents[1]


class DnsConverterError(RuntimeError):
    """Raised when a required conversion operation cannot complete."""


class ConverterConfigError(DnsConverterError):
    """Raised when ``config/converter.json`` is missing or malformed."""


class ConversionStageError(DnsConverterError):
    """Raised for an individual sing-box or Mihomo conversion failure."""


@dataclass(frozen=True)
class SingboxConfig:
    version: str
    download_url: str


@dataclass(frozen=True)
class MihomoConfig:
    channel: str
    version: str
    api_base: str
    amd64_level: str


@dataclass(frozen=True)
class ConverterConfig:
    version: int
    singbox: SingboxConfig
    mihomo: MihomoConfig


@dataclass(frozen=True)
class ConverterSettings:
    """One fully resolved converter policy with no ambient configuration."""

    singbox: SingboxConfig
    mihomo: MihomoConfig
    strict: bool
    strict_mihomo_modifiers: bool


def resolve_path(root: Path, value: Optional[Path], default: Path) -> Path:
    candidate = Path(value) if value is not None else default
    if not candidate.is_absolute():
        candidate = root / candidate
    return candidate.resolve()


@dataclass(frozen=True)
class ConverterPaths:
    """All files used by one conversion invocation."""

    root_dir: Path
    tmp_dir: Path
    tools_dir: Path
    dns_input: Path
    ip_cidr_input: Path
    mihomo_rule_file: Path
    singbox_input_file: Path
    domain_file: Path
    yaml_raw_file: Path
    invalid_file: Path
    singbox_output: Path
    mihomo_mrs_output: Path
    mihomo_yaml_output: Path
    awk_dir: Path

    @classmethod
    def from_root(
        cls,
        root_dir: Path = ROOT_DIR,
        *,
        dns_input: Optional[Path] = None,
        ip_cidr_input: Optional[Path] = None,
        tools_dir: Optional[Path] = None,
        singbox_output: Optional[Path] = None,
        mihomo_mrs_output: Optional[Path] = None,
        mihomo_yaml_output: Optional[Path] = None,
        awk_dir: Optional[Path] = None,
    ) -> "ConverterPaths":
        root = Path(root_dir).resolve()
        tmp = root / "tmp"
        configured_tools = resolve_path(root, tools_dir, Path("tmp") / "tools")
        if awk_dir is not None:
            configured_awk = (
                Path(awk_dir).resolve()
                if Path(awk_dir).is_absolute()
                else root / Path(awk_dir)
            )
        else:
            root_script_dir = root / "script"
            configured_awk = (
                root_script_dir
                if (root_script_dir / "mihomo_classical.awk").is_file()
                else Path(__file__).resolve().parent
            )
        configured_awk = configured_awk.resolve()
        return cls(
            root_dir=root,
            tmp_dir=tmp,
            tools_dir=configured_tools,
            dns_input=resolve_path(root, dns_input, Path("dns.txt")),
            ip_cidr_input=resolve_path(
                root, ip_cidr_input, Path("tmp") / "dns_ip_cidr_rules.txt"
            ),
            mihomo_rule_file=tmp / "mihomo_classical.txt",
            singbox_input_file=tmp / "singbox_dns.txt",
            domain_file=tmp / "mihomo_domain.txt",
            yaml_raw_file=tmp / "mihomo_yaml_payload.txt",
            invalid_file=tmp / "mihomo_invalid_rules.txt",
            singbox_output=resolve_path(
                root, singbox_output, Path("adrules-singbox.srs")
            ),
            mihomo_mrs_output=resolve_path(
                root, mihomo_mrs_output, Path("adrules-mihomo.mrs")
            ),
            mihomo_yaml_output=resolve_path(
                root, mihomo_yaml_output, Path("adrules-mihomo.yaml")
            ),
            awk_dir=configured_awk,
        )

    @property
    def root(self) -> Path:
        return self.root_dir

    @property
    def dns_file(self) -> Path:
        return self.dns_input

    @property
    def ip_cidr_file(self) -> Path:
        return self.ip_cidr_input


@dataclass(frozen=True)
class ConversionContext:
    """Explicit runtime values shared by the two converter backends."""

    paths: ConverterPaths
    settings: ConverterSettings
    environment: Mapping[str, str]


@dataclass(frozen=True)
class ConversionRequest:
    """Inputs accepted by the converter boundary before config loading."""

    root_dir: Path
    environment: Mapping[str, str]
    dns_input: Optional[Path] = None
    ip_cidr_input: Optional[Path] = None
    tools_dir: Optional[Path] = None
    config_path: Optional[Path] = None
    singbox_output: Optional[Path] = None
    mihomo_mrs_output: Optional[Path] = None
    mihomo_yaml_output: Optional[Path] = None
    awk_dir: Optional[Path] = None
    strict: Optional[bool] = None
    strict_mihomo_modifiers: Optional[bool] = None


@dataclass(frozen=True)
class ConversionResult:
    paths: ConverterPaths
    singbox_success: bool
    mihomo_success: bool

    @property
    def failed(self) -> bool:
        return not (self.singbox_success and self.mihomo_success)

    @property
    def success(self) -> bool:
        return not self.failed

    @property
    def singbox(self) -> bool:
        return self.singbox_success

    @property
    def mihomo(self) -> bool:
        return self.mihomo_success


Downloader = Callable[[str, Path], bool]
