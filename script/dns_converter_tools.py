#!/usr/bin/env python3
"""Download, select, and install DNS converter tool binaries."""

from __future__ import annotations

import gzip
import json
import os
import re
import tarfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Optional

try:
    from download import download_file
except ImportError:  # Support ``python -m script.dns_converter``.
    from .download import download_file  # type: ignore[no-redef]

try:
    from common import read_utf8_text
except ImportError:  # Support ``python -m script.dns_converter_tools``.
    from .common import read_utf8_text  # type: ignore[no-redef]

try:
    from dns_converter_config import VALID_AMD64_LEVELS
    from dns_converter_io import (
        log_info,
        log_warn,
        remove,
        write_executable,
    )
    from dns_converter_model import (
        ConversionStageError,
        ConverterPaths,
        Downloader,
        MihomoConfig,
        SingboxConfig,
    )
except ImportError:  # Support ``python -m script.dns_converter``.
    from .dns_converter_config import VALID_AMD64_LEVELS  # type: ignore[no-redef]
    from .dns_converter_io import (  # type: ignore[no-redef]
        log_info,
        log_warn,
        remove,
        write_executable,
    )
    from .dns_converter_model import (  # type: ignore[no-redef]
        ConversionStageError,
        ConverterPaths,
        Downloader,
        MihomoConfig,
        SingboxConfig,
    )


def _extract_tar_member(archive: Path, member_name: str, destination: Path) -> None:
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            try:
                member = bundle.getmember(member_name)
            except KeyError as exc:
                raise ConversionStageError(
                    f"Archive is missing expected file: {member_name}"
                ) from exc
            if not member.isfile():
                raise ConversionStageError(f"Archive member is not a regular file: {member_name}")
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise ConversionStageError(f"Unable to read archive member: {member_name}")
            write_executable(destination, extracted.read())
    except ConversionStageError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise ConversionStageError(f"Failed to extract sing-box archive: {exc}") from exc


def get_singbox_binary(
    paths: ConverterPaths,
    settings: SingboxConfig,
    *,
    downloader: Downloader,
) -> Path:
    binary = paths.tools_dir / "sing-box"
    try:
        local_binary = (
            binary.is_file()
            and binary.stat().st_size > 0
            and os.access(binary, os.X_OK)
        )
    except OSError:
        local_binary = False
    if local_binary:
        log_info("Using local sing-box binary; download skipped")
        return binary

    version = settings.version.lstrip("v")
    try:
        url = settings.download_url.format(version=version)
    except (KeyError, ValueError) as exc:
        raise ConversionStageError(f"Invalid sing-box download URL template: {exc}") from exc
    archive = paths.tools_dir / f"sing-box-{version}.tar.gz"
    paths.tools_dir.mkdir(parents=True, exist_ok=True)
    log_info(f"Downloading sing-box ({url})...")
    if not downloader(url, archive):
        remove(archive)
        raise ConversionStageError("Failed to download sing-box")
    member_name = f"sing-box-{version}-linux-amd64/sing-box"
    try:
        _extract_tar_member(archive, member_name, binary)
    finally:
        remove(archive)
    return binary


def _detect_mihomo_level(name: str) -> tuple[str, bool, bool]:
    if "compatible" in name:
        return "v1", True, False
    match = re.search(r"^mihomo-linux-amd64-(v[1-4])-", name)
    if match:
        return match.group(1), False, False
    if re.search(r"^mihomo-linux-amd64-v\d+\.\d+\.\d+", name):
        return "legacy", False, True
    return "unknown", False, False


def extract_mihomo_asset_url(
    release: Mapping[str, object] | Path | str,
    preferred_level: str,
) -> Optional[str]:
    """Select a mihomo amd64 asset using the historical preference scores."""

    if isinstance(release, Path):
        try:
            payload: object = json.loads(read_utf8_text(release))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
    elif isinstance(release, str):
        try:
            release_path = Path(release)
            release_is_file = release_path.is_file()
        except OSError:
            release_is_file = False
            release_path = Path()
        if release_is_file:
            try:
                payload = json.loads(read_utf8_text(release_path))
            except (OSError, UnicodeError, json.JSONDecodeError):
                return None
        else:
            try:
                payload = json.loads(release)
            except (UnicodeError, json.JSONDecodeError):
                return None
    else:
        payload = release
    if not isinstance(payload, Mapping):
        return None

    candidates: list[tuple[int, int, str, str]] = []
    assets = payload.get("assets")
    if not isinstance(assets, Sequence) or isinstance(assets, (str, bytes, bytearray)):
        return None
    for item in assets:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name", ""))
        url = str(item.get("browser_download_url", ""))
        if not url or not name.startswith("mihomo-linux-amd64") or not name.endswith(".gz"):
            continue
        level, compatible, legacy = _detect_mihomo_level(name)
        score = 100
        if level == preferred_level:
            score = 0
        elif preferred_level == "v1" and compatible:
            score = 1
        elif legacy:
            score = 2
        elif level.startswith("v") and preferred_level.startswith("v"):
            score = 10 + abs(int(level[1:]) - int(preferred_level[1:]))
        if "alpha" in name or "beta" in name or "rc" in name:
            score += 1
        candidates.append((score, len(name), name, url))
    if not candidates:
        return None
    candidates.sort()
    return candidates[0][3]


def resolve_mihomo_download_url(
    channel: str,
    version: str,
    preferred_level: str,
    api_base: str,
    release_json: Path,
    *,
    downloader: Downloader,
) -> Optional[str]:
    """Resolve a release tag/channel to the best matching amd64 asset."""

    base = api_base.rstrip("/")
    if version:
        tags = [version] if version.startswith("v") else [f"v{version}", version]
        for tag in tags:
            remove(release_json)
            endpoint = f"{base}/releases/tags/{tag}"
            if downloader(endpoint, release_json):
                url = extract_mihomo_asset_url(release_json, preferred_level)
                if url:
                    return url
        return None

    aliases = {"stable", "latest", "release", "official"}
    endpoint = (
        f"{base}/releases/latest"
        if channel in aliases
        else f"{base}/releases/tags/{channel}"
    )
    remove(release_json)
    if downloader(endpoint, release_json):
        return extract_mihomo_asset_url(release_json, preferred_level)
    return None


def get_mihomo_binary(
    paths: ConverterPaths,
    settings: MihomoConfig,
    *,
    downloader: Downloader,
) -> Path:
    binary = paths.tools_dir / "mihomo"
    if binary.is_file() and os.access(binary, os.X_OK):
        log_info("Using local Mihomo binary; download skipped")
        return binary

    preferred_level = settings.amd64_level
    if preferred_level not in VALID_AMD64_LEVELS:
        log_warn(f"Invalid MIHOMO_AMD64_LEVEL={preferred_level}; falling back to v1")
        preferred_level = "v1"

    release_json = paths.tools_dir / "mihomo_release.json"
    try:
        url = resolve_mihomo_download_url(
            settings.channel,
            settings.version,
            preferred_level,
            settings.api_base,
            release_json,
            downloader=downloader,
        )
        if (
            not url
            and not settings.version
            and settings.channel not in {"stable", "latest", "release", "official"}
        ):
            log_warn(f"Failed to resolve Mihomo channel {settings.channel}; falling back to stable")
            url = resolve_mihomo_download_url(
                "stable",
                "",
                preferred_level,
                settings.api_base,
                release_json,
                downloader=downloader,
            )
        if not url:
            raise ConversionStageError("Failed to resolve Mihomo download URL")

        archive = paths.tools_dir / "mihomo.gz"
        log_info(f"Downloading and configuring Mihomo ({url})...")
        if not downloader(url, archive):
            raise ConversionStageError("Failed to download Mihomo")
        try:
            with gzip.open(archive, "rb") as source:
                write_executable(binary, source.read())
        except (OSError, EOFError) as exc:
            raise ConversionStageError(f"Failed to extract Mihomo archive: {exc}") from exc
        finally:
            remove(archive)
        return binary
    finally:
        remove(release_json)
