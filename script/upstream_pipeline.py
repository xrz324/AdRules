#!/usr/bin/env python3
"""Download and normalize the configured upstream rule sources.

The previous orchestration mixed the source catalogue, filesystem layout,
network retries, and the two output groups in one process.  The source
catalogue now lives in ``config/upstream.json`` and this module owns the
complete upstream stage in a small, injectable Python pipeline.

No rule parsing happens here.  Each successful download is written as a
standalone UTF-8-compatible source file with the source URL recorded in its
header; the content and DNS stages consume those files afterwards.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Optional, Sequence
from urllib.parse import urlsplit

try:
    from common import atomic_write_bytes, log_error, log_info, log_warn, read_utf8_text
    from download import (
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_MAX_RETRIES,
        DEFAULT_RETRY_DELAY,
        USER_AGENT,
        download_file,
    )
except ImportError:  # Support ``python -m script.upstream_pipeline``.
    from .common import (  # type: ignore[no-redef]
        atomic_write_bytes,
        log_error,
        log_info,
        log_warn,
        read_utf8_text,
    )
    from .download import (  # type: ignore[no-redef]
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_MAX_RETRIES,
        DEFAULT_RETRY_DELAY,
        USER_AGENT,
        download_file,
    )


ROOT_DIR = Path(__file__).resolve().parents[1]
UPSTREAM_CONFIG_PATH = ROOT_DIR / "config" / "upstream.json"
UPSTREAM_CONFIG_VERSION = 1
DEFAULT_MAX_WORKERS = 8
UTF8_BOM = b"\xef\xbb\xbf"
SOURCE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


class UpstreamPipelineError(RuntimeError):
    """Raised when the upstream stage cannot satisfy its configured policy."""


class UpstreamConfigError(UpstreamPipelineError):
    """Raised when ``config/upstream.json`` is missing or malformed."""


@dataclass(frozen=True)
class UpstreamSource:
    """One named upstream source in the external source catalogue."""

    name: str
    url: str


@dataclass(frozen=True)
class UpstreamConfig:
    """Validated upstream source catalogue and download limits."""

    version: int
    max_workers: int
    content: tuple[UpstreamSource, ...]
    dns: tuple[UpstreamSource, ...]

    @property
    def content_urls(self) -> tuple[str, ...]:
        return tuple(source.url for source in self.content)

    @property
    def dns_urls(self) -> tuple[str, ...]:
        return tuple(source.url for source in self.dns)


def _validate_source_url(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UpstreamConfigError(f"{label} must be a non-empty URL")
    if value != value.strip():
        raise UpstreamConfigError(f"{label} must not have surrounding whitespace")
    if any(character in value for character in ("\x00", "\t", "\r", "\n")):
        raise UpstreamConfigError(f"{label} must not contain control characters")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise UpstreamConfigError(f"{label} must be an http(s) URL: {value!r}")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise UpstreamConfigError(f"{label} must be valid UTF-8") from exc
    return value


def _validate_sources(raw: object, label: str) -> tuple[UpstreamSource, ...]:
    if not isinstance(raw, list) or not raw:
        raise UpstreamConfigError(f"{label} must be a non-empty array")

    sources: list[UpstreamSource] = []
    names: set[str] = set()
    urls: set[str] = set()
    for index, item in enumerate(raw):
        item_label = f"{label}[{index}]"
        if isinstance(item, str):
            name = f"source_{index + 1}"
            url_value = item
        elif isinstance(item, dict):
            name = item.get("name", f"source_{index + 1}")
            url_value = item.get("url")
        else:
            raise UpstreamConfigError(f"{item_label} must be a URL or object")

        if not isinstance(name, str) or SOURCE_NAME_RE.fullmatch(name) is None:
            raise UpstreamConfigError(f"{item_label}.name is invalid")
        if name in names:
            raise UpstreamConfigError(f"duplicate source name: {name}")
        url = _validate_source_url(url_value, f"{item_label}.url")
        if url in urls:
            raise UpstreamConfigError(f"duplicate source URL in {label}: {url}")
        names.add(name)
        urls.add(url)
        sources.append(UpstreamSource(name=name, url=url))
    return tuple(sources)


def load_upstream_config(path: Path = UPSTREAM_CONFIG_PATH) -> UpstreamConfig:
    """Load and validate the independent upstream source catalogue."""

    path = Path(path)
    try:
        raw = json.loads(read_utf8_text(path))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UpstreamConfigError(
            f"failed to read upstream config {path}: {exc}"
        ) from exc

    if not isinstance(raw, dict):
        raise UpstreamConfigError("upstream config root must be an object")
    version = raw.get("version")
    if isinstance(version, bool) or version != UPSTREAM_CONFIG_VERSION:
        raise UpstreamConfigError(
            f"unsupported upstream config version: {version!r}"
        )
    max_workers = raw.get("max_workers", DEFAULT_MAX_WORKERS)
    if (
        isinstance(max_workers, bool)
        or not isinstance(max_workers, int)
        or max_workers < 1
    ):
        raise UpstreamConfigError("max_workers must be a positive integer")

    return UpstreamConfig(
        version=UPSTREAM_CONFIG_VERSION,
        max_workers=max_workers,
        content=_validate_sources(raw.get("content"), "content"),
        dns=_validate_sources(raw.get("dns"), "dns"),
    )


def _resolve_config_path(root_dir: Path, config_path: Optional[Path]) -> Path:
    configured = (
        Path(config_path)
        if config_path is not None
        else Path("config/upstream.json")
    )
    if configured.is_absolute():
        return configured.resolve()
    return Path(root_dir).resolve() / configured


@dataclass(frozen=True)
class UpstreamPaths:
    """Filesystem locations shared by all upstream download workers."""

    root_dir: Path
    tmp_dir: Path
    content_dir: Path
    dns_dir: Path
    failed_log: Path

    @classmethod
    def from_root(
        cls,
        root_dir: Path = ROOT_DIR,
        *,
        environment: Mapping[str, str],
        tmp_dir: Optional[Path] = None,
        failed_log: Optional[Path] = None,
    ) -> "UpstreamPaths":
        root = Path(root_dir).resolve()

        configured_tmp = Path(tmp_dir) if tmp_dir is not None else Path("tmp")
        if not configured_tmp.is_absolute():
            configured_tmp = root / configured_tmp
        else:
            configured_tmp = configured_tmp.resolve()

        if failed_log is not None:
            failed_value = str(failed_log)
        else:
            failed_value = (
                str(environment.get("DOWNLOAD_FAILED_LOG", "")).strip()
                or "download_failed.log"
            )
        configured_failed = Path(failed_value)
        if not configured_failed.is_absolute():
            configured_failed = root / configured_failed
        else:
            configured_failed = configured_failed.resolve()

        return cls(
            root_dir=root,
            tmp_dir=configured_tmp,
            content_dir=configured_tmp / "content",
            dns_dir=configured_tmp / "dns",
            failed_log=configured_failed,
        )


@dataclass(frozen=True)
class DownloadResult:
    """Outcome of one source download."""

    url: str
    target_dir: Path
    path: Path
    success: bool
    mirrored: bool = False
    error: Optional[str] = None


@dataclass(frozen=True)
class UpstreamBuildResult:
    """Summary of a completed upstream stage."""

    paths: UpstreamPaths
    attempted: int
    succeeded: int
    mirrored: int
    failed_urls: tuple[str, ...]


@dataclass(frozen=True)
class UpstreamRequest:
    """Validated source catalogue, paths, and execution policy for one run."""

    paths: UpstreamPaths
    content_sources: tuple[str, ...]
    dns_sources: tuple[str, ...]
    max_workers: int
    strict: bool


@dataclass(frozen=True)
class UpstreamStageRequest:
    """Inputs accepted by the upstream stage boundary before config loading."""

    root_dir: Path
    environment: Mapping[str, str]
    content_sources: Optional[tuple[str, ...]] = None
    dns_sources: Optional[tuple[str, ...]] = None
    max_workers: Optional[int] = None
    strict: Optional[bool] = None
    tmp_dir: Optional[Path] = None
    failed_log: Optional[Path] = None
    config_path: Optional[Path] = None


DownloadFunction = Callable[[str, Path], bool]


def get_download_filename(url: str) -> str:
    """Return the stable target filename historically used by the pipeline.

    The URL hash deliberately uses the complete URL (including query and
    fragment), while the human-readable suffix is derived from the path with
    query/fragment removed.  This preserves collision mitigation and the old
    file names byte-for-byte.
    """

    if not isinstance(url, str) or not url:
        raise ValueError("download URL must be a non-empty string")
    if any(character in url for character in ("\x00", "\r", "\n")):
        raise ValueError("download URL must not contain control characters")
    try:
        url.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("download URL must be valid UTF-8") from exc

    url_hash = hashlib.md5(
        url.encode("utf-8"), usedforsecurity=False
    ).hexdigest()[:8]
    path_without_query = url.split("?", 1)[0].split("#", 1)[0]
    # ``basename`` in the old script ignores a trailing slash and returns the
    # host for a URL without an explicit path.  posixpath.basename alone would
    # return an empty string for those forms, so trim trailing separators first.
    stripped_path = path_without_query.rstrip("/")
    original_filename = posixpath.basename(stripped_path) or "download"
    if not original_filename.endswith(".txt"):
        original_filename = f"{original_filename}.txt"
    return f"{url_hash}_{original_filename}"


def normalize_download_bytes(data: bytes) -> bytes:
    """Remove a leading UTF-8 BOM and CR characters at line ends.

    This is the byte-level equivalent of the former ``sed`` expression.  It
    intentionally does not decode or otherwise rewrite the source, allowing
    the later rule stages to report malformed encodings with their own context.
    """

    if data.startswith(UTF8_BOM):
        data = data[len(UTF8_BOM) :]
    lines = data.split(b"\n")
    return b"\n".join(
        line[:-1] if line.endswith(b"\r") else line for line in lines
    )


def normalize_download_file(input_file: Path) -> bytes:
    """Read and normalize one downloaded file without changing its encoding."""

    return normalize_download_bytes(Path(input_file).read_bytes())


def _atomic_copy(source: Path, target: Path) -> None:
    """Copy a mirror source atomically so readers never see a partial file."""

    try:
        mode = source.stat().st_mode & 0o777
    except OSError:
        mode = 0o644
    atomic_write_bytes(target, source.read_bytes(), mode=mode)


def _mirror_dir(target_dir: Path, paths: UpstreamPaths) -> Optional[Path]:
    if target_dir == paths.content_dir:
        return paths.dns_dir
    if target_dir == paths.dns_dir:
        return paths.content_dir
    return None


def download_source(
    url: str,
    target_dir: Path,
    paths: UpstreamPaths,
    *,
    downloader: DownloadFunction,
) -> DownloadResult:
    """Download one source, reusing the opposite group's mirror when present."""

    target_dir = Path(target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    filename = get_download_filename(url)
    filepath = target_dir / filename
    mirror = _mirror_dir(target_dir, paths)
    mirror_path = mirror / filename if mirror is not None else None

    if mirror_path is not None:
        try:
            mirror_available = (
                mirror_path.is_file() and mirror_path.stat().st_size > 0
            )
        except OSError:
            mirror_available = False
        if mirror_available:
            try:
                _atomic_copy(mirror_path, filepath)
                return DownloadResult(url, target_dir, filepath, True, mirrored=True)
            except OSError as exc:
                # A broken mirror should not prevent an independent download.
                log_warn(f"Mirror reuse failed; retrying download for {url}: {exc}")

    tmp_filepath = filepath.with_name(f"{filepath.name}.tmp")
    try:
        if not downloader(url, tmp_filepath):
            return DownloadResult(
                url, target_dir, filepath, False, error="download failed"
            )
        if not tmp_filepath.is_file() or tmp_filepath.stat().st_size == 0:
            return DownloadResult(
                url, target_dir, filepath, False, error="downloaded file is empty"
            )
        normalized = normalize_download_file(tmp_filepath)
        payload = f"! url: {url}\n".encode("utf-8") + normalized
        atomic_write_bytes(filepath, payload)
        return DownloadResult(url, target_dir, filepath, True)
    except (OSError, UnicodeError, ValueError) as exc:
        log_error(f"Failed to process downloaded content: {url}: {exc}")
        return DownloadResult(url, target_dir, filepath, False, error=str(exc))
    finally:
        for temporary in (tmp_filepath,):
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                log_warn(f"Failed to remove temporary download file: {temporary}: {exc}")


def _unique_urls(urls: Iterable[str]) -> tuple[str, ...]:
    """Drop duplicate URLs while retaining their first occurrence order."""

    seen: set[str] = set()
    unique: list[str] = []
    for url in urls:
        if not isinstance(url, str) or not url:
            raise UpstreamPipelineError("upstream URL must be a non-empty string")
        if any(character in url for character in ("\x00", "\r", "\n")):
            raise UpstreamPipelineError(
                "upstream URL must not contain control characters"
            )
        try:
            url.encode("utf-8")
        except UnicodeError as exc:
            raise UpstreamPipelineError("upstream URL must be valid UTF-8") from exc
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return tuple(unique)


def _download_group(
    urls: Sequence[str],
    target_dir: Path,
    paths: UpstreamPaths,
    *,
    downloader: DownloadFunction,
    max_workers: int,
) -> list[DownloadResult]:
    if not urls:
        return []
    worker_count = max(1, min(max_workers, len(urls)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(
                download_source,
                url,
                target_dir,
                paths,
                downloader=downloader,
            )
            for url in urls
        ]
        # Reading futures in source order makes the result and failure log
        # deterministic even though the actual network work is concurrent.
        results: list[DownloadResult] = []
        for future, url in zip(futures, urls):
            try:
                results.append(future.result())
            except Exception as exc:  # defensive worker boundary
                results.append(
                    DownloadResult(
                        url,
                        target_dir,
                        target_dir / get_download_filename(url),
                        False,
                        error=str(exc),
                    )
                )
                log_error(f"Download task failed unexpectedly: {url}: {exc}")
        return results


def _download_groups_parallel(
    groups: Sequence[tuple[Sequence[str], Path]],
    paths: UpstreamPaths,
    *,
    downloader: DownloadFunction,
    max_workers: int,
) -> list[list[DownloadResult]]:
    """Download independent source groups through one bounded executor."""

    results: list[list[Optional[DownloadResult]]] = [
        [None] * len(urls) for urls, _target_dir in groups
    ]
    tasks: list[tuple[int, int, str, Path]] = []
    for group_index, (urls, target_dir) in enumerate(groups):
        for item_index, url in enumerate(urls):
            tasks.append((group_index, item_index, url, target_dir))
    if not tasks:
        return [[] for _urls, _target_dir in groups]

    configured_groups = max(1, len(groups))
    worker_limit = max_workers if max_workers <= 1 else max_workers * configured_groups
    worker_count = max(1, min(worker_limit, len(tasks)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                download_source,
                url,
                target_dir,
                paths,
                downloader=downloader,
            ): (group_index, item_index, url, target_dir)
            for group_index, item_index, url, target_dir in tasks
        }
        for future, (group_index, item_index, url, target_dir) in futures.items():
            try:
                results[group_index][item_index] = future.result()
            except Exception as exc:  # defensive worker boundary
                results[group_index][item_index] = DownloadResult(
                    url,
                    target_dir,
                    target_dir / get_download_filename(url),
                    False,
                    error=str(exc),
                )
                log_error(f"Download task failed unexpectedly: {url}: {exc}")

    return [
        [item for item in group if item is not None]
        for group in results
    ]


def _write_failure_log(path: Path, urls: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write atomically so an interrupted run cannot leave a half-written list.
    atomic_write_bytes(path, "".join(f"{url}\n" for url in urls).encode("utf-8"))


def build_upstream_request(
    root_dir: Path = ROOT_DIR,
    *,
    environment: Mapping[str, str],
    content_sources: Optional[Sequence[str]] = None,
    dns_sources: Optional[Sequence[str]] = None,
    max_workers: Optional[int] = None,
    strict: Optional[bool] = None,
    tmp_dir: Optional[Path] = None,
    failed_log: Optional[Path] = None,
    config_path: Optional[Path] = None,
) -> UpstreamRequest:
    """Resolve configuration and overrides into one validated request."""

    loaded_config: Optional[UpstreamConfig] = None
    if config_path is not None or content_sources is None or dns_sources is None:
        loaded_config = load_upstream_config(
            _resolve_config_path(root_dir, config_path)
        )
        if content_sources is None:
            content_sources = loaded_config.content_urls
        if dns_sources is None:
            dns_sources = loaded_config.dns_urls
    resolved_workers = (
        max_workers
        if max_workers is not None
        else loaded_config.max_workers
        if loaded_config is not None
        else DEFAULT_MAX_WORKERS
    )
    if resolved_workers < 1:
        raise ValueError("max_workers must be at least one")
    resolved_strict = (
        strict
        if strict is not None
        else str(environment.get("STRICT_UPSTREAM_DOWNLOAD", "false"))
        .strip()
        .lower()
        in {"1", "true", "yes", "y", "on"}
    )
    return UpstreamRequest(
        paths=UpstreamPaths.from_root(
            root_dir,
            tmp_dir=tmp_dir,
            failed_log=failed_log,
            environment=environment,
        ),
        content_sources=tuple(content_sources or ()),
        dns_sources=tuple(dns_sources or ()),
        max_workers=resolved_workers,
        strict=bool(resolved_strict),
    )


def execute_upstream(
    request: UpstreamRequest,
    *,
    downloader: Optional[DownloadFunction] = None,
) -> UpstreamBuildResult:
    """Execute a fully resolved upstream request."""

    paths = request.paths
    if downloader is None:
        if shutil.which("curl") is None:
            raise UpstreamPipelineError("Missing required dependency: curl")
        downloader = download_file

    paths.content_dir.mkdir(parents=True, exist_ok=True)
    paths.dns_dir.mkdir(parents=True, exist_ok=True)
    _write_failure_log(paths.failed_log, ())

    content_urls_unique = _unique_urls(request.content_sources)
    dns_urls_unique = _unique_urls(request.dns_sources)
    log_info("Starting concurrent rule downloads...")
    dns_url_set = set(dns_urls_unique)
    shared_urls = tuple(url for url in content_urls_unique if url in dns_url_set)
    content_only_urls = tuple(
        url for url in content_urls_unique if url not in dns_url_set
    )
    content_results_by_url = {
        result.url: result
        for result in _download_group(
            shared_urls,
            paths.content_dir,
            paths,
            downloader=downloader,
            max_workers=request.max_workers,
        )
    }
    dns_results_by_url = {
        result.url: result
        for result in _download_group(
            shared_urls,
            paths.dns_dir,
            paths,
            downloader=downloader,
            max_workers=request.max_workers,
        )
    }
    parallel_results = _download_groups_parallel(
        (
            (content_only_urls, paths.content_dir),
            (
                tuple(
                    url
                    for url in dns_urls_unique
                    if url not in content_results_by_url
                ),
                paths.dns_dir,
            ),
        ),
        paths,
        downloader=downloader,
        max_workers=request.max_workers,
    )
    content_results_by_url.update(
        {result.url: result for result in parallel_results[0]}
    )
    dns_results_by_url.update(
        {result.url: result for result in parallel_results[1]}
    )
    content_results = [
        content_results_by_url[url] for url in content_urls_unique
    ]
    dns_results = [dns_results_by_url[url] for url in dns_urls_unique]
    results = content_results + dns_results
    failed_urls = tuple(result.url for result in results if not result.success)
    _write_failure_log(paths.failed_log, failed_urls)

    if failed_urls:
        log_error(f"The following downloads failed ({len(failed_urls)}):")
        for url in failed_urls:
            log_error(f"  {url}")
        if request.strict:
            log_error("STRICT_UPSTREAM_DOWNLOAD=true; aborting pipeline")
            raise UpstreamPipelineError(
                f"{len(failed_urls)} upstream download(s) failed"
            )

    result = UpstreamBuildResult(
        paths=paths,
        attempted=len(results),
        succeeded=sum(1 for item in results if item.success),
        mirrored=sum(1 for item in results if item.success and item.mirrored),
        failed_urls=failed_urls,
    )
    log_info("Download tasks complete.")
    return result


def execute_upstream_stage(
    request: UpstreamStageRequest,
    *,
    downloader: Optional[DownloadFunction] = None,
) -> UpstreamBuildResult:
    """Resolve and execute one typed upstream stage request."""

    resolved = build_upstream_request(
        request.root_dir,
        environment=request.environment,
        content_sources=request.content_sources,
        dns_sources=request.dns_sources,
        max_workers=request.max_workers,
        strict=request.strict,
        tmp_dir=request.tmp_dir,
        failed_log=request.failed_log,
        config_path=request.config_path,
    )
    return execute_upstream(resolved, downloader=downloader)


def run_upstream(
    root_dir: Path = ROOT_DIR,
    *,
    environment: Mapping[str, str],
    content_sources: Optional[Sequence[str]] = None,
    dns_sources: Optional[Sequence[str]] = None,
    downloader: Optional[DownloadFunction] = None,
    max_workers: Optional[int] = None,
    strict: Optional[bool] = None,
    tmp_dir: Optional[Path] = None,
    failed_log: Optional[Path] = None,
    config_path: Optional[Path] = None,
) -> UpstreamBuildResult:
    """Compatibility adapter for CLI callers and existing embedders."""

    request = UpstreamStageRequest(
        root_dir=Path(root_dir),
        environment=environment,
        content_sources=(
            tuple(content_sources) if content_sources is not None else None
        ),
        dns_sources=tuple(dns_sources) if dns_sources is not None else None,
        max_workers=max_workers,
        strict=strict,
        tmp_dir=tmp_dir,
        failed_log=failed_log,
        config_path=config_path,
    )
    return execute_upstream_stage(request, downloader=downloader)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT_DIR,
        help="repository root (default: directory containing tmp/)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="upstream source catalogue, relative to --root when not absolute",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        help="override the configured concurrent downloads per source group",
    )
    parser.add_argument(
        "--tmp-dir",
        type=Path,
        help="temporary directory, relative to --root when not absolute",
    )
    parser.add_argument(
        "--failed-log",
        type=Path,
        help="failure log path, relative to --root when not absolute",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        from logging_utils import configure_logging
    except ImportError:  # Support ``python -m script.upstream_pipeline``.
        from .logging_utils import configure_logging  # type: ignore[no-redef]

    configure_logging()
    args = _parse_args(argv)
    try:
        result = run_upstream(
            args.root,
            max_workers=args.max_workers,
            tmp_dir=args.tmp_dir,
            failed_log=args.failed_log,
            config_path=args.config,
            environment=os.environ,
        )
    except (OSError, UnicodeError, UpstreamPipelineError, ValueError) as exc:
        print(f"[ERROR] upstream pipeline: {exc}", file=sys.stderr)
        return 1

    log_info(
        f"Upstream downloads complete: sources={result.succeeded}/{result.attempted} "
        f"reused={result.mirrored} failed={len(result.failed_urls)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
