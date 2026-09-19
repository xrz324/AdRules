#!/usr/bin/env python3
"""Stage configured rule artifacts for the GitHub Actions commit step."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

try:
    from autoupdate_config import (
        ConfigError,
        artifact_entries,
        load_config,
        runtime_path,
    )
except ImportError:  # Support ``python -m script.publish_pipeline``.
    from .autoupdate_config import (  # type: ignore[no-redef]
        ConfigError,
        artifact_entries,
        load_config,
        runtime_path,
    )


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_NAME = Path("config") / "autoupdate.json"


class PublishPipelineError(RuntimeError):
    """Raised when configured artifacts cannot be staged safely."""


@dataclass(frozen=True)
class ArtifactStagingResult:
    """Summary of one manifest-driven git staging transaction."""

    root_dir: Path
    config_path: Path
    staged: tuple[Path, ...]
    removed: tuple[Path, ...]
    skipped: tuple[Path, ...]


def _resolve_config_path(root_dir: Path, config_path: Path) -> Path:
    configured = Path(config_path)
    if not configured.is_absolute():
        configured = root_dir / configured
    return configured.resolve()


def _repository_path(value: object, label: str) -> Path:
    """Return one validated repository-relative path from normalized config."""

    path = Path(str(value))
    if path.is_absolute() or ".." in path.parts or path == Path("."):
        raise PublishPipelineError(
            f"{label} must be a repository-relative file path: {value!r}"
        )
    return path


def _git(
    root_dir: Path,
    arguments: Sequence[str],
    *,
    allowed_return_codes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=root_dir,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise PublishPipelineError(f"unable to execute git: {exc}") from exc
    if completed.returncode not in allowed_return_codes:
        detail = completed.stderr.strip() or completed.stdout.strip()
        suffix = f": {detail}" if detail else ""
        raise PublishPipelineError(
            f"git {' '.join(arguments)} failed with exit code "
            f"{completed.returncode}{suffix}"
        )
    return completed


def _is_tracked(root_dir: Path, path: Path) -> bool:
    completed = _git(
        root_dir,
        ("ls-files", "--error-unmatch", "--", path.as_posix()),
        allowed_return_codes=(0, 1),
    )
    return completed.returncode == 0


def _git_index_path(root_dir: Path) -> Path:
    completed = _git(root_dir, ("rev-parse", "--git-path", "index"))
    path = Path(completed.stdout.strip())
    if not path.is_absolute():
        path = root_dir / path
    return path.resolve()


def _cached_paths(root_dir: Path) -> set[Path]:
    completed = _git(root_dir, ("diff", "--cached", "--name-only"))
    return {
        Path(line)
        for line in completed.stdout.splitlines()
        if line.strip()
    }


def _normalized_manifest(
    config: Mapping[str, object],
) -> tuple[tuple[str, Path, bool], ...]:
    manifest: list[tuple[str, Path, bool]] = []
    for item in artifact_entries(config):
        name = str(item["name"])
        path = _repository_path(item["path"], f"artifacts[{name}].path")
        manifest.append((name, path, bool(item["required"])))
    if not manifest:
        raise PublishPipelineError("artifact manifest is empty")
    return tuple(manifest)


def stage_artifacts(
    root_dir: Path = ROOT_DIR,
    *,
    config_path: Path = DEFAULT_CONFIG_NAME,
) -> ArtifactStagingResult:
    """Stage exactly the configured artifacts and obsolete failure log.

    Required outputs are preflighted before mutating the git index.  Existing
    optional outputs are staged, tracked optional outputs that disappeared are
    staged as deletions, and missing untracked optional outputs are skipped.
    """

    root = Path(root_dir).resolve()
    if not root.is_dir():
        raise PublishPipelineError(f"repository root does not exist: {root}")
    resolved_config = _resolve_config_path(root, config_path)
    config = load_config(resolved_config)
    manifest = _normalized_manifest(config)
    failure_log = _repository_path(
        runtime_path(config, "download_failed_log"),
        "runtime.download_failed_log",
    )
    artifact_paths = {path for _name, path, _required in manifest}
    if failure_log in artifact_paths:
        raise PublishPipelineError(
            "runtime.download_failed_log must not overlap a published artifact"
        )

    missing_required = [
        (name, path)
        for name, path, required in manifest
        if required and not (root / path).is_file()
    ]
    if missing_required:
        name, path = missing_required[0]
        raise PublishPipelineError(f"missing required output: {path} ({name})")

    allowed_staged_paths = artifact_paths | {failure_log}
    unrelated_staged = _cached_paths(root) - allowed_staged_paths
    if unrelated_staged:
        paths = ", ".join(
            sorted(path.as_posix() for path in unrelated_staged)
        )
        raise PublishPipelineError(
            f"unrelated files are already staged; refusing to publish: {paths}"
        )

    index_path = _git_index_path(root)
    if not index_path.is_file():
        raise PublishPipelineError(f"git index does not exist: {index_path}")
    backup_fd, backup_name = tempfile.mkstemp(
        prefix=".publish-index-",
        suffix=".bak",
        dir=index_path.parent,
    )
    os.close(backup_fd)
    backup_path = Path(backup_name)
    shutil.copy2(index_path, backup_path)

    staged: list[Path] = []
    removed: list[Path] = []
    skipped: list[Path] = []
    try:
        for _name, path, required in manifest:
            target = root / path
            if target.is_file():
                _git(root, ("add", "--", path.as_posix()))
                staged.append(path)
            elif not required and _is_tracked(root, path):
                _git(root, ("rm", "-f", "--", path.as_posix()))
                removed.append(path)
            else:
                skipped.append(path)

        if _is_tracked(root, failure_log):
            _git(root, ("rm", "-f", "--", failure_log.as_posix()))
            removed.append(failure_log)
    except BaseException:
        shutil.copy2(backup_path, index_path)
        raise
    finally:
        try:
            backup_path.unlink()
        except FileNotFoundError:
            pass

    return ArtifactStagingResult(
        root_dir=root,
        config_path=resolved_config,
        staged=tuple(staged),
        removed=tuple(removed),
        skipped=tuple(skipped),
    )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT_DIR)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_NAME)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        result = stage_artifacts(args.root, config_path=args.config)
    except (ConfigError, OSError, PublishPipelineError, ValueError) as exc:
        print(f"[ERROR] publish pipeline: {exc}", file=sys.stderr)
        return 1

    for path in result.skipped:
        print(f"[INFO] Skipped missing optional artifact: {path}", file=sys.stderr)
    print(
        f"[INFO] Artifact staging complete: staged={len(result.staged)} "
        f"removed={len(result.removed)} skipped={len(result.skipped)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
