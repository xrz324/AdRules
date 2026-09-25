"""Shared immutable models and batching helpers for content minimizers."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Optional


class MinimizerError(RuntimeError):
    """Raised when an input cannot be minimized safely."""


@dataclass(frozen=True)
class StageStats:
    name: str
    input_lines: int
    output_lines: int
    input_bytes: int
    output_bytes: int
    eligible_lines: int
    groups: int
    changed_groups: int
    oversize_groups: int

    @property
    def saved_lines(self) -> int:
        return self.input_lines - self.output_lines

    @property
    def saved_bytes(self) -> int:
        return self.input_bytes - self.output_bytes


def serialized_bytes(lines: Sequence[str]) -> int:
    total = 0
    for line in lines:
        total += len(line) + 1 if line.isascii() else len(line.encode("utf-8")) + 1
    return total


def sort_unique(lines: Iterable[str]) -> list[str]:
    return sorted(set(lines))


def compress_domain_set(domains: Iterable[str]) -> tuple[str, ...]:
    pool = set(domains)
    kept: list[str] = []
    for domain in sorted(pool):
        suffix = domain
        covered = False
        while True:
            separator = suffix.find(".")
            if separator < 0:
                break
            suffix = suffix[separator + 1 :]
            if suffix in pool:
                covered = True
                break
        if not covered:
            kept.append(domain)
    return tuple(kept)


def batch_domains(
    domains: Sequence[str],
    render: Callable[[Sequence[str]], str],
    max_line_bytes: int,
) -> Optional[list[str]]:
    batches: list[str] = []
    current: list[str] = []
    for domain in domains:
        candidate = [*current, domain]
        if len(render(candidate).encode("utf-8")) <= max_line_bytes:
            current = candidate
            continue
        if not current:
            return None
        batches.append(render(current))
        current = [domain]
        if len(render(current).encode("utf-8")) > max_line_bytes:
            return None
    if current:
        batches.append(render(current))
    return batches
