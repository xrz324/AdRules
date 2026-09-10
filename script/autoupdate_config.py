#!/usr/bin/env python3
"""Load and validate the repository's scheduled-update configuration."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Dict, Iterable, List, Mapping, Optional

try:
    from common import read_utf8_text
except ImportError:  # Support ``python -m script.autoupdate_config``.
    from .common import read_utf8_text  # type: ignore[no-redef]


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = ROOT_DIR / "config" / "autoupdate.json"
DEFAULT_MAX_RULE_DROP_PERCENT = 40.0
CONFIG_VERSION = 1
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")
ARTIFACT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
PATH_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
REQUIRED_RUNTIME_KEYS = {
    "dns_prune_cache",
    "dns_prune_log",
    "download_failed_log",
}
DEFAULT_PIPELINE_PATHS = MappingProxyType(
    {
        "upstream_config": "config/upstream.json",
        "converter_config": "config/converter.json",
        "dns_title": "mod/title/dns-title.txt",
        "dns_ip_cidr": "tmp/dns_ip_cidr_rules.txt",
        "baseline_dir": "tmp/baseline",
    }
)
REQUIRED_PIPELINE_PATH_KEYS = frozenset(DEFAULT_PIPELINE_PATHS)
DERIVED_RUNTIME_ENV = {
    "DNS_PRUNE_CACHE_FILE": "dns_prune_cache",
    "DNS_PRUNE_REMOVED_LOG": "dns_prune_log",
    "DOWNLOAD_FAILED_LOG": "download_failed_log",
}
REQUIRED_ARTIFACT_NAMES = {
    "adblock",
    "dns",
    "singbox",
    "mihomo_mrs",
    "mihomo_yaml",
}


class ConfigError(ValueError):
    """Raised when the autoupdate configuration is invalid."""


@dataclass(frozen=True)
class RuntimeSettings:
    """Typed settings shared by every Actions pipeline stage.

    ``environment`` is retained only for stage-specific values such as DNS
    resolver budgets.  Values that control orchestration and validation are
    parsed once here, so individual stages do not repeatedly interpret
    strings or consult process-global state.
    """

    environment: Mapping[str, str]
    dns_prune_enabled: bool
    strict_dns_prune: bool
    strict_upstream_download: bool
    strict_dns_converter: bool
    strict_mihomo_modifiers: bool
    max_rule_drop_percent: float
    dns_environment: Mapping[str, str] = MappingProxyType({})
    upstream_environment: Mapping[str, str] = MappingProxyType({})
    converter_environment: Mapping[str, str] = MappingProxyType({})
    reporting_environment: Mapping[str, str] = MappingProxyType({})


def _parse_bool(value: object, label: str, *, default: bool = False) -> bool:
    if value is None or str(value).strip() == "":
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ConfigError(f"{label} must be a boolean value: {value!r}")


def _parse_drop_percent(value: object) -> float:
    try:
        result = float(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            f"MAX_RULE_DROP_PERCENT must be numeric: {value!r}"
        ) from exc
    if not 0 <= result < 100:
        raise ConfigError(
            f"MAX_RULE_DROP_PERCENT must be in [0, 100): {result!r}"
        )
    return result


def _validate_relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label} must be a non-empty string")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ConfigError(f"{label} must be a relative repository path: {value!r}")
    if any(character in value for character in ("\t", "\n", "\r")):
        raise ConfigError(f"{label} must not contain tabs or newlines")
    return value


def _validate_environment(raw: object) -> Dict[str, str]:
    if not isinstance(raw, dict):
        raise ConfigError("environment must be an object")

    environment: Dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or ENV_KEY_RE.fullmatch(key) is None:
            raise ConfigError(f"invalid environment key: {key!r}")
        if key in DERIVED_RUNTIME_ENV:
            raise ConfigError(f"{key} must be defined by runtime, not environment")
        if not isinstance(value, str):
            raise ConfigError(f"environment value must be a string: {key}")
        if "\n" in value or "\r" in value:
            raise ConfigError(f"environment value must not contain newlines: {key}")
        environment[key] = value
    return environment


def _validate_runtime(raw: object) -> Dict[str, str]:
    if not isinstance(raw, dict):
        raise ConfigError("runtime must be an object")
    runtime = {
        str(key): _validate_relative_path(value, f"runtime.{key}")
        for key, value in raw.items()
    }
    missing = REQUIRED_RUNTIME_KEYS - runtime.keys()
    if missing:
        raise ConfigError(f"runtime is missing keys: {', '.join(sorted(missing))}")
    return runtime


def _validate_pipeline_paths(raw: object) -> Dict[str, str]:
    """Validate paths shared by the in-process pipeline stages.

    The paths are repository-relative on purpose.  A single root directory is
    supplied by :func:`script.pipeline.create_context`, so a stage cannot
    accidentally resolve one of these files relative to the caller's current
    working directory.
    """

    if not isinstance(raw, dict):
        raise ConfigError("paths must be an object")

    paths = dict(DEFAULT_PIPELINE_PATHS)
    for key, value in raw.items():
        if not isinstance(key, str) or PATH_NAME_RE.fullmatch(key) is None:
            raise ConfigError(f"invalid pipeline path key: {key!r}")
        paths[key] = _validate_relative_path(value, f"paths.{key}")

    missing = REQUIRED_PIPELINE_PATH_KEYS - paths.keys()
    if missing:
        raise ConfigError(
            f"paths is missing keys: {', '.join(sorted(missing))}"
        )
    return paths


def _validate_artifacts(raw: object) -> List[Dict[str, object]]:
    if not isinstance(raw, list) or not raw:
        raise ConfigError("artifacts must be a non-empty array")

    artifacts: List[Dict[str, object]] = []
    names = set()
    paths = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError(f"artifacts[{index}] must be an object")
        name = item.get("name")
        if (
            not isinstance(name, str)
            or ARTIFACT_NAME_RE.fullmatch(name) is None
            or name in names
        ):
            raise ConfigError(f"invalid or duplicate artifact name at index {index}")
        path = _validate_relative_path(item.get("path"), f"artifacts[{name}].path")
        if path in paths:
            raise ConfigError(f"duplicate artifact path: {path}")
        kind = item.get("kind")
        if (
            not isinstance(kind, str)
            or not kind
            or any(character in kind for character in ("\t", "\n", "\r"))
        ):
            raise ConfigError(f"artifacts[{name}].kind must be a non-empty string")
        required = item.get("required")
        if not isinstance(required, bool):
            raise ConfigError(f"artifacts[{name}].required must be boolean")
        names.add(name)
        paths.add(path)
        artifacts.append(
            {
                "name": name,
                "path": path,
                "kind": kind,
                "required": required,
            }
        )

    missing = REQUIRED_ARTIFACT_NAMES - names
    if missing:
        raise ConfigError(f"artifacts are missing names: {', '.join(sorted(missing))}")
    return artifacts


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Dict[str, object]:
    """Load and validate a config file, returning normalized plain objects."""
    try:
        raw = json.loads(read_utf8_text(path))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"failed to read config {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("config root must be an object")
    version = raw.get("version")
    if version != CONFIG_VERSION:
        raise ConfigError(f"unsupported config version: {version!r}")

    return {
        "version": version,
        "environment": _validate_environment(raw.get("environment")),
        "runtime": _validate_runtime(raw.get("runtime")),
        "paths": _validate_pipeline_paths(raw.get("paths", {})),
        "artifacts": _validate_artifacts(raw.get("artifacts")),
    }


def environment_values(config: Mapping[str, object]) -> Dict[str, str]:
    """Return environment values, deriving path variables from runtime paths."""
    raw_environment = config["environment"]
    if not isinstance(raw_environment, Mapping):
        raise ConfigError("normalized config has invalid environment")
    environment = {
        str(key): str(value)
        for key, value in raw_environment.items()
    }
    runtime = config["runtime"]
    if not isinstance(runtime, Mapping):
        raise ConfigError("normalized config has invalid runtime")

    derived_paths = {
        env_key: str(runtime[runtime_key])
        for env_key, runtime_key in DERIVED_RUNTIME_ENV.items()
    }
    for key in derived_paths:
        if key in environment:
            raise ConfigError(f"{key} must be defined by runtime, not environment")
    environment.update(derived_paths)
    return environment


def runtime_settings(
    config: Mapping[str, object],
    process_environment: Optional[Mapping[str, str]] = None,
) -> RuntimeSettings:
    """Merge process/config values and return one immutable typed snapshot.

    Repository configuration deliberately wins over ambient process values;
    this preserves the Actions contract while making the merge happen once at
    the pipeline boundary.
    """

    values = dict(os.environ if process_environment is None else process_environment)
    values.update(environment_values(config))
    frozen = MappingProxyType(values)

    # Stage adapters receive only the settings they own plus the small set of
    # process values required by child processes.  ``environment`` remains as
    # a compatibility view for external callers, but is no longer the stage
    # dependency boundary.
    inherited_keys = {
        "PATH",
        "HOME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "LD_LIBRARY_PATH",
        "SYSTEMROOT",
        "WINDIR",
    }

    def scoped(keys: set[str]) -> Mapping[str, str]:
        return MappingProxyType(
            {
                key: value
                for key, value in values.items()
                if key in inherited_keys or key in keys
            }
        )

    dns_keys = {key for key in values if key.startswith("DNS_PRUNE_")}
    upstream_keys = {"DOWNLOAD_FAILED_LOG"}
    converter_keys = {
        "SINGBOX_VERSION",
        "MIHOMO_CHANNEL",
        "MIHOMO_VERSION",
        "MIHOMO_AMD64_LEVEL",
        "STRICT_DNS_CONVERTER",
        "STRICT_MIHOMO_MODIFIERS",
    }
    reporting_keys = {"GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY"}
    return RuntimeSettings(
        environment=frozen,
        dns_environment=scoped(dns_keys),
        upstream_environment=scoped(upstream_keys),
        converter_environment=scoped(converter_keys | reporting_keys),
        reporting_environment=MappingProxyType(
            {key: values[key] for key in reporting_keys if key in values}
        ),
        dns_prune_enabled=_parse_bool(
            values.get("DNS_PRUNE_ENABLED"), "DNS_PRUNE_ENABLED"
        ),
        strict_dns_prune=_parse_bool(
            values.get("STRICT_DNS_PRUNE"), "STRICT_DNS_PRUNE"
        ),
        strict_upstream_download=_parse_bool(
            values.get("STRICT_UPSTREAM_DOWNLOAD"), "STRICT_UPSTREAM_DOWNLOAD"
        ),
        strict_dns_converter=_parse_bool(
            values.get("STRICT_DNS_CONVERTER"), "STRICT_DNS_CONVERTER"
        ),
        strict_mihomo_modifiers=_parse_bool(
            values.get("STRICT_MIHOMO_MODIFIERS"), "STRICT_MIHOMO_MODIFIERS"
        ),
        max_rule_drop_percent=_parse_drop_percent(
            values.get(
                "MAX_RULE_DROP_PERCENT", str(DEFAULT_MAX_RULE_DROP_PERCENT)
            )
        ),
    )


def artifact_entries(config: Mapping[str, object]) -> List[Dict[str, object]]:
    artifacts = config["artifacts"]
    if not isinstance(artifacts, list):
        raise ConfigError("normalized config has invalid artifacts")
    return [dict(item) for item in artifacts]


def artifact_paths(config: Mapping[str, object]) -> Dict[str, str]:
    """Return artifact paths keyed by their stable manifest names."""
    return {
        str(item["name"]): str(item["path"])
        for item in artifact_entries(config)
    }


def runtime_path(config: Mapping[str, object], key: str) -> str:
    runtime = config["runtime"]
    if not isinstance(runtime, Mapping) or key not in runtime:
        raise ConfigError(f"normalized config has invalid runtime key: {key}")
    return str(runtime[key])


def pipeline_paths(config: Mapping[str, object]) -> Dict[str, str]:
    """Return normalized repository paths shared by pipeline stages."""

    raw = config.get("paths", dict(DEFAULT_PIPELINE_PATHS))
    # ``load_config`` always normalizes this section.  Applying the same
    # defaults here keeps the helper safe for callers constructing a mapping
    # programmatically while still validating every value at the boundary.
    return _validate_pipeline_paths(raw)


def pipeline_path(config: Mapping[str, object], key: str) -> str:
    """Return one normalized shared pipeline path by stable manifest key."""

    paths = pipeline_paths(config)
    if key not in paths:
        raise ConfigError(f"normalized config has invalid path key: {key}")
    return paths[key]


def _append_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as target:
        for line in lines:
            target.write(f"{line}\n")


def write_github_env(config: Mapping[str, object], path: Path) -> None:
    values = environment_values(config)
    _append_lines(path, (f"{key}={values[key]}" for key in sorted(values)))


def write_github_output(config: Mapping[str, object], path: Path) -> None:
    runtime = config["runtime"]
    if not isinstance(runtime, Mapping):
        raise ConfigError("normalized config has invalid runtime")
    configured_paths = pipeline_paths(config)
    outputs = {
        "config_version": str(config["version"]),
        "dns_prune_cache_file": str(runtime["dns_prune_cache"]),
        "dns_prune_removed_log": str(runtime["dns_prune_log"]),
        "download_failed_log": str(runtime["download_failed_log"]),
        "upstream_config_path": configured_paths["upstream_config"],
        "converter_config_path": configured_paths["converter_config"],
    }
    outputs.update(
        {
            f"artifact_{name}_path": artifact_path
            for name, artifact_path in artifact_paths(config).items()
        }
    )
    _append_lines(path, (f"{key}={outputs[key]}" for key in sorted(outputs)))


def print_environment(config: Mapping[str, object]) -> None:
    for key, value in sorted(environment_values(config).items()):
        print(f"{key}={value}")


def print_artifacts(config: Mapping[str, object]) -> None:
    for item in artifact_entries(config):
        required = "required" if item["required"] else "optional"
        print(f"{required}\t{item['name']}\t{item['kind']}\t{item['path']}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument(
        "--github-env",
        type=Path,
        help="Append environment assignments to this GitHub Actions env file",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        help="Append path/config outputs to this GitHub Actions output file",
    )
    parser.add_argument("--print-env", action="store_true", help="Print normalized environment assignments")
    parser.add_argument("--print-artifacts", action="store_true", help="Print artifact manifest entries")
    parser.add_argument(
        "--print-runtime-path",
        choices=sorted(REQUIRED_RUNTIME_KEYS),
        help="Print one normalized runtime path",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        config = load_config(args.config)
        if args.github_env:
            write_github_env(config, args.github_env)
        if args.github_output:
            write_github_output(config, args.github_output)
        if args.print_env:
            print_environment(config)
        if args.print_artifacts:
            print_artifacts(config)
        if args.print_runtime_path:
            print(runtime_path(config, args.print_runtime_path))
        if not any(
            (
                args.github_env,
                args.github_output,
                args.print_env,
                args.print_artifacts,
                args.print_runtime_path,
            )
        ):
            raise ConfigError("one output mode is required")
    except (ConfigError, OSError) as exc:
        print(f"[ERROR] autoupdate config: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
