#!/usr/bin/env python3
"""Load converter policy and resolve the explicit runtime settings."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

try:
    from common import read_utf8_text
except ImportError:  # Support ``python -m script.dns_converter_config``.
    from .common import read_utf8_text  # type: ignore[no-redef]

try:
    from dns_converter_model import (
        ConverterConfig,
        ConverterConfigError,
        ConverterSettings,
        MihomoConfig,
        ROOT_DIR,
        SingboxConfig,
    )
except ImportError:  # Support ``python -m script.dns_converter``.
    from .dns_converter_model import (  # type: ignore[no-redef]
        ConverterConfig,
        ConverterConfigError,
        ConverterSettings,
        MihomoConfig,
        ROOT_DIR,
        SingboxConfig,
    )


CONFIG_VERSION = 1
DEFAULT_CONFIG_NAME = Path("config") / "converter.json"
CONVERTER_CONFIG_PATH = ROOT_DIR / DEFAULT_CONFIG_NAME
CONVERTER_CONFIG_VERSION = CONFIG_VERSION
DEFAULT_CONFIG_PATH = CONVERTER_CONFIG_PATH
VALID_AMD64_LEVELS = frozenset({"v1", "v2", "v3", "v4"})


def _validate_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ConverterConfigError(f"{label} must be a string")
    if not allow_empty and not value.strip():
        raise ConverterConfigError(f"{label} must be a non-empty string")
    if value != value.strip():
        raise ConverterConfigError(f"{label} must not have surrounding whitespace")
    if any(character in value for character in ("\x00", "\t", "\r", "\n")):
        raise ConverterConfigError(f"{label} must not contain control characters")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:  # pragma: no cover - Python strings are UTF-8 here.
        raise ConverterConfigError(f"{label} must be valid UTF-8") from exc
    return value


def _validate_http_url(value: object, label: str) -> str:
    url = _validate_text(value, label)
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConverterConfigError(f"{label} must be an http(s) URL: {url!r}")
    return url


def _version(value: object, label: str, *, allow_empty: bool = False) -> str:
    result = _validate_text(value, label, allow_empty=allow_empty)
    if result and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", result) is None:
        raise ConverterConfigError(f"{label} contains unsupported version characters")
    return result


def load_converter_config(path: Path = CONVERTER_CONFIG_PATH) -> ConverterConfig:
    """Load and validate the independent converter/tool catalogue."""

    path = Path(path)
    try:
        raw = json.loads(read_utf8_text(path))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConverterConfigError(f"failed to read config {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConverterConfigError("converter config root must be an object")
    version = raw.get("version")
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != CONFIG_VERSION
    ):
        raise ConverterConfigError(f"unsupported converter config version: {version!r}")

    singbox_raw = raw.get("singbox")
    if not isinstance(singbox_raw, Mapping):
        raise ConverterConfigError("singbox must be an object")
    singbox_version = _version(singbox_raw.get("version"), "singbox.version")
    singbox_url = _validate_http_url(
        singbox_raw.get("download_url"), "singbox.download_url"
    )
    if "{version}" not in singbox_url:
        raise ConverterConfigError("singbox.download_url must contain {version}")

    mihomo_raw = raw.get("mihomo")
    if not isinstance(mihomo_raw, Mapping):
        raise ConverterConfigError("mihomo must be an object")
    channel = _validate_text(mihomo_raw.get("channel"), "mihomo.channel")
    mihomo_version = _version(
        mihomo_raw.get("version", ""), "mihomo.version", allow_empty=True
    )
    api_base = _validate_http_url(mihomo_raw.get("api_base"), "mihomo.api_base")
    amd64_level = _validate_text(
        mihomo_raw.get("amd64_level", "v1"), "mihomo.amd64_level"
    )

    return ConverterConfig(
        version=CONFIG_VERSION,
        singbox=SingboxConfig(singbox_version, singbox_url),
        mihomo=MihomoConfig(channel, mihomo_version, api_base.rstrip("/"), amd64_level),
    )


def _environment_value(environment: Mapping[str, str], name: str) -> str:
    return str(environment.get(name, "")).strip()


def _environment_bool(
    environment: Mapping[str, str], name: str, default: bool = False
) -> bool:
    value = _environment_value(environment, name)
    if not value:
        return default
    return value.lower() in {"1", "true", "yes", "y", "on"}


def resolve_converter_settings(
    config: ConverterConfig,
    environment: Mapping[str, str],
    *,
    strict: bool | None = None,
    strict_mihomo_modifiers: bool | None = None,
) -> ConverterSettings:
    """Resolve explicit overrides without reading process-global state.

    Environment variables are intentionally accepted as a mapping.  The CLI
    boundary may construct that mapping from ``os.environ``; conversion code
    below this function receives the resulting immutable policy instead.
    """

    singbox_version = _environment_value(environment, "SINGBOX_VERSION")
    singbox = SingboxConfig(
        (singbox_version or config.singbox.version).lstrip("v"),
        config.singbox.download_url,
    )
    channel = _environment_value(environment, "MIHOMO_CHANNEL") or config.mihomo.channel
    version = _environment_value(environment, "MIHOMO_VERSION") or config.mihomo.version
    level = _environment_value(environment, "MIHOMO_AMD64_LEVEL") or config.mihomo.amd64_level
    mihomo = MihomoConfig(channel, version.lstrip("v"), config.mihomo.api_base, level)
    resolved_strict = (
        strict
        if strict is not None
        else _environment_bool(environment, "STRICT_DNS_CONVERTER")
    )
    resolved_modifiers = (
        strict_mihomo_modifiers
        if strict_mihomo_modifiers is not None
        else _environment_bool(environment, "STRICT_MIHOMO_MODIFIERS")
    )
    return ConverterSettings(
        singbox=singbox,
        mihomo=mihomo,
        strict=bool(resolved_strict),
        strict_mihomo_modifiers=bool(resolved_modifiers),
    )
