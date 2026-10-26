"""Read Cowrie JSON log lines from files, directories and rotated archives."""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class ReadStats:
    files: int = 0
    lines: int = 0
    skipped: int = 0
    paths: list[str] = field(default_factory=list)


def expand_paths(inputs: Iterable[Path]) -> list[Path]:
    """Directories expand to cowrie.json and its rotations (cowrie.json.2026-10-25, .gz)."""
    out: list[Path] = []
    for p in inputs:
        if p.is_dir():
            out.extend(sorted(x for x in p.glob("cowrie.json*") if x.is_file()))
        elif p.is_file():
            out.append(p)
    return out


def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def iter_events(paths: Iterable[Path], stats: ReadStats | None = None) -> Iterator[dict]:
    """Yield one dict per valid JSON line.

    Bad lines are counted and skipped, never fatal: the file Cowrie is writing
    can end in a partial line, and the content is attacker-influenced anyway.
    """
    stats = stats if stats is not None else ReadStats()
    for path in paths:
        stats.files += 1
        stats.paths.append(path.name)
        with _open(path) as fh:
            for line in fh:
                stats.lines += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    stats.skipped += 1
                    continue
                if not isinstance(event, dict) or "eventid" not in event:
                    stats.skipped += 1
                    continue
                yield event


def parse_ts(value: object) -> datetime | None:
    """Cowrie writes ISO 8601 UTC (2026-10-26T03:08:22.134687Z)."""
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC)
