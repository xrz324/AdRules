"""Human-readable and GitHub Actions reporting for the rule pipeline."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence


@dataclass(frozen=True)
class StageReport:
    """One concise execution record for logs and the Actions summary."""

    name: str
    api: str
    status: str
    duration_seconds: float
    summary: str = ""


def format_duration(seconds: float) -> str:
    """Format durations compactly while keeping short stages visible."""

    if seconds < 1:
        return f"{seconds:.2f}s"
    return f"{seconds:.1f}s"


def one_line(value: object) -> str:
    """Keep an exception or summary on one searchable log line."""

    return " ".join(str(value).split())


class PipelineReporter:
    """Render pipeline events without owning stage execution or state."""

    def __init__(self, root_dir: Path, environment: Mapping[str, str]) -> None:
        self.root_dir = Path(root_dir).resolve()
        self.environment = environment

    @property
    def github_actions_enabled(self) -> bool:
        return str(self.environment.get("GITHUB_ACTIONS", "")).strip().lower() in {
            "1",
            "true",
            "yes",
            "y",
            "on",
        }

    @staticmethod
    def _escape_github_value(value: object) -> str:
        return (
            str(value)
            .replace("%", "%25")
            .replace("\r", "%0D")
            .replace("\n", "%0A")
        )

    def _github_command(self, command: str) -> None:
        if self.github_actions_enabled:
            print(command, file=sys.stderr, flush=True)

    def stage_start(self, name: str, api: str) -> None:
        self._github_command(f"::group::[PIPELINE] {name}")
        print(
            f"[PIPELINE] START {name} | {api}",
            file=sys.stderr,
            flush=True,
        )

    def stage_done(self, report: StageReport) -> None:
        detail = f" | {report.summary}" if report.summary else ""
        status_suffix = " | status=warning" if report.status == "warning" else ""
        print(
            f"[PIPELINE] DONE {report.name} | "
            f"{format_duration(report.duration_seconds)}"
            f"{detail}{status_suffix}",
            file=sys.stderr,
            flush=True,
        )
        if report.status == "warning":
            message = one_line(report.summary) or "stage completed with warnings"
            escaped = self._escape_github_value(f"{report.name}: {message}")
            self._github_command(
                f"::warning title=Pipeline stage degraded::{escaped}"
            )

    def stage_failure(self, report: StageReport, error: object) -> None:
        message = one_line(error)
        print(
            f"[PIPELINE] FAIL {report.name} | "
            f"{format_duration(report.duration_seconds)} | {message}",
            file=sys.stderr,
            flush=True,
        )
        escaped = self._escape_github_value(f"{report.name}: {message}")
        self._github_command(f"::error title=Pipeline stage failed::{escaped}")

    def stage_end(self) -> None:
        self._github_command("::endgroup::")

    def write_summary(
        self,
        baseline_report: Optional[StageReport],
        stage_reports: Sequence[StageReport],
    ) -> None:
        """Append a compact stage table to the Actions step summary."""

        if not self.github_actions_enabled:
            return
        summary_value = self.environment.get("GITHUB_STEP_SUMMARY")
        if not summary_value:
            return

        summary_path = Path(summary_value)
        if not summary_path.is_absolute():
            summary_path = self.root_dir / summary_path
        reports = ([baseline_report] if baseline_report is not None else []) + list(
            stage_reports
        )
        lines = [
            "## Rule pipeline",
            "",
            "| Stage | Status | Duration | Key result |",
            "| --- | --- | ---: | --- |",
        ]
        for report in reports:
            summary = one_line(report.summary).replace("|", "\\|")
            lines.append(
                f"| `{report.name}` | {report.status.upper()} | "
                f"{format_duration(report.duration_seconds)} | {summary} |"
            )
        lines.append("")
        try:
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            with summary_path.open("a", encoding="utf-8", newline="\n") as target:
                if summary_path.stat().st_size:
                    target.write("\n")
                target.write("\n".join(lines))
        except OSError as exc:
            print(
                f"[PIPELINE] WARN summary unavailable | {one_line(exc)}",
                file=sys.stderr,
                flush=True,
            )
