"""Production disabled-baseline loading helpers."""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pkcs11_check.core.collection import CollectedPytestItem


@dataclass(frozen=True)
class DisabledBaseline:
    """Normalized disabled-baseline contents plus a stable fingerprint."""

    source_path: Path
    disabled_nodeids: frozenset[str]
    fingerprint: str


@dataclass(frozen=True)
class DisabledSelectionPlan:
    """Final scheduled units plus per-file deselection details."""

    units: list[str]
    deselect_by_file: dict[str, set[str]]
    baseline_fingerprint: str


def parse_disabled_nodeids(text: str) -> list[str]:
    """Parse exact nodeids from a comment-friendly text file."""
    nodeids: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        nodeids.append(line)
        seen.add(line)
    return nodeids


def _baseline_fingerprint(path: Path, text: str) -> str:
    payload = f"{path.resolve()}\n{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_disabled_baseline(path: Path | None) -> DisabledBaseline | None:
    """Load the configured disabled-baseline file."""
    if path is None:
        return None
    try:
        text = path.read_text()
    except FileNotFoundError as exc:
        msg = f"disabled baseline file not found: {path}"
        raise FileNotFoundError(msg) from exc
    nodeids = parse_disabled_nodeids(text)
    return DisabledBaseline(
        source_path=path,
        disabled_nodeids=frozenset(nodeids),
        fingerprint=_baseline_fingerprint(path, text),
    )


def _unit_file_key(unit: str) -> str:
    return str(Path(unit.split("::", 1)[0]).resolve())


def build_disabled_selection_plan(
    *,
    units: list[str],
    disabled_nodeids: set[str],
    baseline_fingerprint: str,
    collected_items: list[CollectedPytestItem] | None,
) -> DisabledSelectionPlan:
    """Build the scheduled unit list and per-file deselect mapping."""
    planned_units: list[str] = []
    deselect_by_file: dict[str, set[str]] = {}

    items_by_file: dict[str, list[str]] = {}
    if collected_items is not None:
        for item in collected_items:
            items_by_file.setdefault(str(Path(item.file_path).resolve()), []).append(item.nodeid)

    for unit in units:
        if "::" in unit:
            if unit in disabled_nodeids:
                continue
            planned_units.append(unit)
            continue

        file_key = _unit_file_key(unit)
        unit_nodeids = items_by_file.get(file_key)
        if not unit_nodeids:
            planned_units.append(unit)
            continue

        disabled_for_unit = {nodeid for nodeid in unit_nodeids if nodeid in disabled_nodeids}
        if len(disabled_for_unit) == len(unit_nodeids):
            continue
        if disabled_for_unit:
            deselect_by_file[unit] = disabled_for_unit
        planned_units.append(unit)

    return DisabledSelectionPlan(
        units=planned_units,
        deselect_by_file=deselect_by_file,
        baseline_fingerprint=baseline_fingerprint,
    )


def write_deselect_file(nodeids: Iterable[str]) -> Path:
    """Materialize an exact-nodeid deselect file for pytest/plugin use."""
    unique_sorted = sorted({nodeid for nodeid in nodeids if nodeid})
    fd, raw_path = tempfile.mkstemp(prefix="pkcs11-check-deselect-", suffix=".txt")
    path = Path(raw_path)
    os.close(fd)
    path.write_text("".join(f"{nodeid}\n" for nodeid in unique_sorted))
    return path
