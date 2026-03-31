"""Production disabled-baseline loading helpers."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

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
    payload = f"{path.resolve()}\n{text}".encode()
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


def _load_report_log_records(path: Path) -> list[dict[str, object]]:
    try:
        text = path.read_text()
    except (FileNotFoundError, OSError):
        return []

    records: list[dict[str, object]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


def _map_report_outcome(raw_outcome: str, wasxfail: object) -> str:
    if raw_outcome == "passed" and wasxfail is not None:
        return "xpassed"
    if raw_outcome == "skipped" and wasxfail is not None:
        return "xfailed"
    return raw_outcome


def _collect_report_nodeids(records: list[dict[str, object]]) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    seen_call: set[str] = set()
    setup_only: list[dict[str, object]] = []

    for record in records:
        report_type = str(record.get("$report_type", "TestReport"))
        when = str(record.get("when", ""))
        if report_type == "CollectReport":
            nodeid = str(record.get("nodeid", "")).strip()
            if nodeid:
                outcomes[nodeid] = "error"
            continue
        if report_type != "TestReport":
            continue

        nodeid = str(record.get("nodeid", "")).strip()
        if not nodeid:
            continue

        if when == "call":
            seen_call.add(nodeid)
            outcomes[nodeid] = _map_report_outcome(
                str(record.get("outcome", "passed")),
                record.get("wasxfail"),
            )
        elif when == "setup" and str(record.get("outcome", "")) in {"skipped", "failed", "error"}:
            setup_only.append(record)

    for record in setup_only:
        nodeid = str(record.get("nodeid", "")).strip()
        if not nodeid or nodeid in seen_call:
            continue
        raw_outcome = str(record.get("outcome", ""))
        outcomes[nodeid] = "skipped" if raw_outcome == "skipped" else "error"

    return outcomes


def _identify_culprit_for_file(records: list[dict[str, object]], file_target: str) -> str | None:
    phases: dict[str, set[str]] = {}
    for record in records:
        if str(record.get("$report_type", "TestReport")) != "TestReport":
            continue
        nodeid = str(record.get("nodeid", "")).strip()
        when = str(record.get("when", "")).strip()
        if not nodeid or not when:
            continue
        if nodeid.split("::", 1)[0] != file_target:
            continue
        phases.setdefault(nodeid, set()).add(when)

    for nodeid, node_phases in phases.items():
        if "teardown" not in node_phases and "setup" in node_phases:
            return nodeid
    return None


def _load_results_units(path: Path) -> list[dict[str, object]]:
    try:
        payload = json.loads(path.read_text())
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    units = payload.get("units", []) if isinstance(payload, dict) else []
    return [unit for unit in units if isinstance(unit, dict)]


def collect_disabled_candidates(
    artifact_dirs: list[Path],
    *,
    outcomes: set[str],
) -> tuple[list[str], list[str]]:
    """Collect exact nodeid candidates and manual-review notes from artifacts."""
    candidates: set[str] = set()
    manual_review: set[str] = set()

    for artifact_dir in artifact_dirs:
        records = _load_report_log_records(artifact_dir / "report.jsonl")
        report_nodeids = _collect_report_nodeids(records)
        for nodeid, outcome in report_nodeids.items():
            if outcome in outcomes:
                candidates.add(nodeid)

        if outcomes & {"crashed", "timeout"}:
            for unit in _load_results_units(artifact_dir / "results.json"):
                status = str(unit.get("status", "")).strip()
                target = str(unit.get("target", "")).strip()
                if status not in outcomes or not target:
                    continue
                culprit = _identify_culprit_for_file(records, target)
                if culprit is not None:
                    candidates.add(culprit)
                else:
                    manual_review.add(
                        f"{artifact_dir}: {status} unit {target} requires manual review"
                    )

    return sorted(candidates), sorted(manual_review)


def write_deselect_file(nodeids: Iterable[str]) -> Path:
    """Materialize an exact-nodeid deselect file for pytest/plugin use."""
    unique_sorted = sorted({nodeid for nodeid in nodeids if nodeid})
    fd, raw_path = tempfile.mkstemp(prefix="pkcs11-check-deselect-", suffix=".txt")
    path = Path(raw_path)
    os.close(fd)
    path.write_text("".join(f"{nodeid}\n" for nodeid in unique_sorted))
    return path
