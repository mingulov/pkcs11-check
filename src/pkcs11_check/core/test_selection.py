"""Production disabled-baseline loading helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pkcs11_check.core.collection import CollectedPytestItem
from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.report_log import (
    iter_report_log_records as _iter_report_log_records,
)
from pkcs11_check.core.report_log import (
    map_report_outcome as _map_report_outcome,
)


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


@dataclass(frozen=True, order=True)
class DisabledCandidateReviewRecord:
    """Machine-readable evidence for one disabled-test candidate."""

    artifact_dir: str
    nodeid: str
    outcome: str
    file_target: str
    unit_target: str
    unit_status: str | None
    discovery_mode: Literal["explicit", "inferred"]
    sources: tuple[str, ...]


_REQUIRED_MECHANISMS_RE = re.compile(
    r"^REQUIRED_MECHANISMS\s*=\s*\[([^\]]*)\]",
    re.MULTILINE,
)


def extract_required_mechanisms(filepath: str) -> list[str] | None:
    """Parse REQUIRED_MECHANISMS list from a Python test file (no import).

    Returns the mechanism name list, or None if the file has no declaration
    or the list is empty.
    """
    try:
        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = _REQUIRED_MECHANISMS_RE.search(text)
    if not match:
        return None
    inner = match.group(1).strip()
    if not inner:
        return None
    names = [s.strip().strip("\"'") for s in inner.split(",") if s.strip().strip("\"'")]
    return names or None


def parse_disabled_nodeids(text: str) -> list[str]:
    """Parse exact nodeids from a comment-friendly text file."""
    nodeids: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = normalize_nodeid(line)
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
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        msg = f"disabled baseline file not found: {path}"
        raise FileNotFoundError(msg) from exc
    nodeids = parse_disabled_nodeids(text)
    return DisabledBaseline(
        source_path=path,
        disabled_nodeids=frozenset(nodeids),
        fingerprint=_baseline_fingerprint(path, text),
    )


def auto_discover_disabled_baseline() -> Path | None:
    """Check if a disabled-tests.txt exists in the resolved data directory."""
    from pkcs11_check.testcases.data import resolve_data_dir

    candidate = resolve_data_dir() / "disabled-tests.txt"
    if candidate.is_file():
        return candidate
    return None


def _unit_file_key(unit: str) -> str:
    return str(Path(unit.split("::", 1)[0]).resolve())


def build_disabled_selection_plan(
    *,
    units: list[str],
    disabled_nodeids: set[str],
    baseline_fingerprint: str,
    collected_items: list[CollectedPytestItem] | None,
) -> DisabledSelectionPlan:
    """Build the scheduled unit list and per-file deselect mapping.

    ``disabled_nodeids`` may arrive in either separator form. Every comparison below is
    made in normalized (forward-slash) space, so normalize the incoming set here rather
    than trusting the caller to have done it: the production path happens to normalize in
    ``parse_disabled_nodeids``, which made this an invisible unenforced precondition, and
    any future source of disabled node-ids (a resume state file, a manifest, a new flag)
    would silently match nothing on Windows.
    """
    disabled_nodeids = {normalize_nodeid(nodeid) for nodeid in disabled_nodeids}
    planned_units: list[str] = []
    deselect_by_file: dict[str, set[str]] = {}

    items_by_file: dict[str, list[str]] = {}
    if collected_items is not None:
        for item in collected_items:
            items_by_file.setdefault(str(Path(item.file_path).resolve()), []).append(
                normalize_nodeid(item.nodeid)
            )

    for unit in units:
        if "::" in unit:
            if normalize_nodeid(unit) in disabled_nodeids:
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
    return list(_iter_report_log_records(path))


def _collect_report_evidence(
    records: Iterable[dict[str, object]],
) -> tuple[dict[str, str], dict[str, dict[str, set[str]]]]:
    outcomes: dict[str, str] = {}
    seen_call: set[str] = set()
    setup_only: list[dict[str, object]] = []
    phases_by_file: dict[str, dict[str, set[str]]] = {}

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
        if when:
            file_target = nodeid.split("::", 1)[0]
            phases_by_file.setdefault(file_target, {}).setdefault(nodeid, set()).add(when)

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

    return outcomes, phases_by_file


def _identify_culprit_for_file(
    phases_by_file: dict[str, dict[str, set[str]]],
    file_target: str,
) -> str | None:
    phases = phases_by_file.get(file_target, {})
    for nodeid, node_phases in phases.items():
        if "teardown" not in node_phases and "setup" in node_phases:
            return nodeid
    return None


def _load_results_units(path: Path) -> list[dict[str, object]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    units = payload.get("units", []) if isinstance(payload, dict) else []
    return [unit for unit in units if isinstance(unit, dict)]


def _collect_results_test_nodeids(
    units: list[dict[str, object]],
    *,
    outcomes: set[str],
) -> tuple[set[str], set[tuple[str, str]]]:
    candidates: set[str] = set()
    explicit_special_units: set[tuple[str, str]] = set()

    for unit in units:
        target = str(unit.get("target", "")).strip()
        tests = unit.get("tests", [])
        if not isinstance(tests, list):
            continue
        for record in tests:
            if not isinstance(record, dict):
                continue
            nodeid = str(record.get("nodeid", "")).strip()
            outcome = str(record.get("outcome", "")).strip()
            if not nodeid or not outcome:
                continue
            if outcome in outcomes:
                candidates.add(nodeid)
            if target and outcome in {"crashed", "timeout"}:
                explicit_special_units.add((target, outcome))

    return candidates, explicit_special_units


def _add_review_record(
    review_map: dict[tuple[str, str, str], dict[str, object]],
    *,
    artifact_dir: Path,
    nodeid: str,
    outcome: str,
    file_target: str,
    unit_target: str,
    unit_status: str | None,
    source: str,
    discovery_mode: Literal["explicit", "inferred"],
) -> None:
    key = (str(artifact_dir), nodeid, outcome)
    record = review_map.get(key)
    if record is None:
        review_map[key] = {
            "artifact_dir": str(artifact_dir),
            "nodeid": nodeid,
            "outcome": outcome,
            "file_target": file_target,
            "unit_target": unit_target,
            "unit_status": unit_status,
            "discovery_mode": discovery_mode,
            "sources": {source},
        }
        return

    sources = record.get("sources")
    if isinstance(sources, set):
        sources.add(source)
    if discovery_mode == "explicit":
        record["discovery_mode"] = "explicit"
    if unit_status is not None:
        record["unit_status"] = unit_status


def _record_sources(record: dict[str, object]) -> tuple[str, ...]:
    """Coerce a review_map record's ``sources`` field into a sorted tuple."""
    raw = record.get("sources")
    if raw is None or not isinstance(raw, (set, list, tuple)):
        return ()
    return tuple(sorted(str(source) for source in raw))


def collect_disabled_candidate_review_records(
    artifact_dirs: list[Path],
    *,
    outcomes: set[str],
) -> tuple[list[DisabledCandidateReviewRecord], list[str]]:
    """Collect machine-readable disabled-candidate evidence plus review notes."""
    review_map: dict[tuple[str, str, str], dict[str, object]] = {}
    manual_review: set[str] = set()

    for artifact_dir in artifact_dirs:
        report_nodeids, report_phases = _collect_report_evidence(
            _iter_report_log_records(artifact_dir / "report.jsonl")
        )
        results_units = _load_results_units(artifact_dir / "results.json")
        _, explicit_special_units = _collect_results_test_nodeids(
            results_units,
            outcomes=outcomes,
        )

        for nodeid, outcome in report_nodeids.items():
            if outcome not in outcomes:
                continue
            file_target = nodeid.split("::", 1)[0]
            _add_review_record(
                review_map,
                artifact_dir=artifact_dir,
                nodeid=nodeid,
                outcome=outcome,
                file_target=file_target,
                unit_target=file_target,
                unit_status=None,
                source="report.jsonl",
                discovery_mode="explicit",
            )

        for unit in results_units:
            target = str(unit.get("target", "")).strip()
            status = str(unit.get("status", "")).strip() or None
            tests = unit.get("tests", [])
            if not isinstance(tests, list):
                continue
            for record in tests:
                if not isinstance(record, dict):
                    continue
                nodeid = str(record.get("nodeid", "")).strip()
                outcome = str(record.get("outcome", "")).strip()
                if not nodeid or outcome not in outcomes:
                    continue
                _add_review_record(
                    review_map,
                    artifact_dir=artifact_dir,
                    nodeid=nodeid,
                    outcome=outcome,
                    file_target=nodeid.split("::", 1)[0],
                    unit_target=target or nodeid.split("::", 1)[0],
                    unit_status=status,
                    source="results.tests",
                    discovery_mode="explicit",
                )

        if outcomes & {"crashed", "timeout"}:
            for unit in results_units:
                status = str(unit.get("status", "")).strip()
                target = str(unit.get("target", "")).strip()
                if status not in outcomes or not target:
                    continue
                if (target, status) in explicit_special_units:
                    continue
                culprit = _identify_culprit_for_file(report_phases, target)
                if culprit is not None:
                    _add_review_record(
                        review_map,
                        artifact_dir=artifact_dir,
                        nodeid=culprit,
                        outcome=status,
                        file_target=culprit.split("::", 1)[0],
                        unit_target=target,
                        unit_status=status,
                        source="results.status+report.jsonl",
                        discovery_mode="inferred",
                    )
                else:
                    manual_review.add(
                        f"{artifact_dir}: {status} unit {target} requires manual review"
                    )

    review_records: list[DisabledCandidateReviewRecord] = [
        DisabledCandidateReviewRecord(
            artifact_dir=str(record["artifact_dir"]),
            nodeid=str(record["nodeid"]),
            outcome=str(record["outcome"]),
            file_target=str(record["file_target"]),
            unit_target=str(record["unit_target"]),
            unit_status=(
                str(record["unit_status"]) if record.get("unit_status") is not None else None
            ),
            discovery_mode=str(record["discovery_mode"]),  # type: ignore[arg-type]
            sources=_record_sources(record),
        )
        for _, record in sorted(review_map.items())
    ]
    return review_records, sorted(manual_review)


def collect_disabled_candidates(
    artifact_dirs: list[Path],
    *,
    outcomes: set[str],
) -> tuple[list[str], list[str]]:
    """Collect exact nodeid candidates and manual-review notes from artifacts."""
    records, manual_review = collect_disabled_candidate_review_records(
        artifact_dirs,
        outcomes=outcomes,
    )
    candidates = sorted({record.nodeid for record in records})
    return candidates, manual_review


def write_deselect_file(nodeids: Iterable[str]) -> Path:
    """Materialize an exact-nodeid deselect file for pytest/plugin use."""
    unique_sorted = sorted({nodeid for nodeid in nodeids if nodeid})
    fd, raw_path = tempfile.mkstemp(prefix="pkcs11-check-deselect-", suffix=".txt")
    path = Path(raw_path)
    os.close(fd)
    path.write_text("".join(f"{nodeid}\n" for nodeid in unique_sorted), encoding="utf-8")
    return path
