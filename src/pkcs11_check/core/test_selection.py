"""Production disabled-baseline loading helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pkcs11_check.core._run_units import _absolute_nodeid
from pkcs11_check.core.collection import CollectedPytestItem
from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.report_log import (
    iter_report_log_records as _iter_report_log_records,
)
from pkcs11_check.core.report_log import (
    map_report_record_outcome as _map_report_record_outcome,
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

    items_by_file: dict[str, list[tuple[str, str]]] = {}
    raw_nodeids_by_unit: dict[str, set[str]] = {}
    if collected_items is not None:
        for item in collected_items:
            file_key = str(Path(item.file_path).resolve())
            raw_nodeid = normalize_nodeid(item.nodeid)
            canonical_nodeid = normalize_nodeid(_absolute_nodeid(file_key, item.nodeid))
            items_by_file.setdefault(file_key, []).append((raw_nodeid, canonical_nodeid))
            raw_nodeids_by_unit.setdefault(canonical_nodeid, set()).add(raw_nodeid)

    for unit in units:
        if "::" in unit:
            canonical_nodeid = normalize_nodeid(unit)
            if canonical_nodeid in disabled_nodeids or disabled_nodeids.intersection(
                raw_nodeids_by_unit.get(canonical_nodeid, set())
            ):
                continue
            planned_units.append(unit)
            continue

        file_key = _unit_file_key(unit)
        unit_nodeids = items_by_file.get(file_key)
        if not unit_nodeids:
            planned_units.append(unit)
            continue

        disabled_for_unit = {
            raw_nodeid
            for raw_nodeid, canonical_nodeid in unit_nodeids
            if raw_nodeid in disabled_nodeids or canonical_nodeid in disabled_nodeids
        }
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
            outcomes[nodeid] = _map_report_record_outcome(record)
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
    try:
        os.close(fd)
        fd = -1
        path.write_text("".join(f"{nodeid}\n" for nodeid in unique_sorted), encoding="utf-8")
    except BaseException:
        if fd >= 0:
            with suppress(OSError):
                os.close(fd)
        with suppress(OSError):
            path.unlink(missing_ok=True)
        raise
    return path


@dataclass(frozen=True)
class CaseSelection:
    """Validated selection manifest for one exact case batch."""

    schema: int
    plan_id: str
    batch_id: str
    source: str
    source_collection_count: int
    source_collection_sha256: str
    nodeids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "batch_id": self.batch_id,
            "source": self.source,
            "source_collection_count": self.source_collection_count,
            "source_collection_sha256": self.source_collection_sha256,
            "nodeids": list(self.nodeids),
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @classmethod
    def from_dict(
        cls,
        data: Any,
        *,
        disabled_nodeids: Iterable[str] | None = None,
        testcases_root: Path | None = None,
    ) -> CaseSelection:
        """Validate and construct a CaseSelection from a manifest dictionary."""
        return _validate_selection_manifest_dict(
            data,
            disabled_nodeids=disabled_nodeids,
            testcases_root=testcases_root,
        )


_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DRIVE_LETTER_RE = re.compile(r"^[a-zA-Z]:")


def get_testcases_root() -> Path:
    """Return the resolved path to the packaged testcases root directory."""
    import pkcs11_check.testcases

    return Path(pkcs11_check.testcases.__file__).resolve().parent


def compute_collection_sha256(nodeids: Iterable[str]) -> str:
    """Compute SHA-256 over canonical JSON of the sorted unique node IDs."""
    canonical_list = sorted(set(nodeids))
    canonical_bytes = json.dumps(
        canonical_list,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_batch_id(
    *,
    source: str,
    source_collection_count: int,
    source_collection_sha256: str,
    nodeids: Iterable[str],
) -> str:
    """Compute SHA-256 over canonical JSON for one exact case batch."""
    payload = {
        "nodeids": sorted(set(nodeids)),
        "source": source,
        "source_collection_count": source_collection_count,
        "source_collection_sha256": source_collection_sha256,
    }
    canonical_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def _validate_source_path(source: str, root: Path) -> Path:
    if not isinstance(source, str) or not source or source != source.strip():
        raise ValueError(f"invalid source path: {source!r}")
    if "\\" in source:
        raise ValueError(f"source path must use forward slashes: {source!r}")
    if source.startswith("/"):
        raise ValueError(f"source path must not be absolute: {source!r}")
    if _DRIVE_LETTER_RE.match(source):
        raise ValueError(f"source path must not contain a drive letter: {source!r}")
    parts = source.split("/")
    if any(p in {"..", ".", ""} for p in parts):
        raise ValueError(f"source path must not contain '.' or '..': {source!r}")

    resolved_root = root.resolve()
    target_path = (root / source).resolve()
    if not target_path.is_relative_to(resolved_root):
        raise ValueError(f"source escapes testcase root: {source!r}")
    if not target_path.is_file():
        raise ValueError(f"source does not resolve to a regular file: {source!r}")
    return target_path


def _resolve_candidate_file(head: str, expected_file: Path, root: Path) -> Path | None:
    norm_head = head.replace("\\", "/")
    # Direct match or relative to testcases root
    try:
        if (root / norm_head).resolve() == expected_file:
            return expected_file
    except OSError:
        pass
    p = Path(head)
    try:
        if p.is_absolute() and p.resolve() == expected_file:
            return expected_file
    except OSError:
        pass
    # Slash-less absolute path (e.g. 'usr/lib/.../testcases/test_encrypt.py')
    try:
        if Path("/" + norm_head).resolve() == expected_file:
            return expected_file
    except OSError:
        pass
    # Relative to project / repo root (walk up from root)
    curr: Path | None = root.parent
    while curr is not None and curr != curr.parent:
        try:
            if (curr / norm_head).resolve() == expected_file:
                return expected_file
        except OSError:
            pass
        curr = curr.parent
    # Check relative to CWD if not resolved yet
    try:
        if p.resolve() == expected_file:
            return expected_file
    except OSError:
        pass
    return None


def load_case_selection(
    path: Path | str,
    *,
    disabled_nodeids: Iterable[str] | None = None,
    testcases_root: Path | None = None,
) -> CaseSelection:
    """Load and validate an exact case batch selection manifest."""
    manifest_path = Path(path)
    if not manifest_path.is_file():
        raise FileNotFoundError(f"selection manifest file not found: {manifest_path}")

    try:
        raw_text = manifest_path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in selection manifest {manifest_path}: {exc}") from exc

    return CaseSelection.from_dict(
        data,
        disabled_nodeids=disabled_nodeids,
        testcases_root=testcases_root,
    )


def _validate_selection_manifest_dict(
    data: Any,
    *,
    disabled_nodeids: Iterable[str] | None = None,
    testcases_root: Path | None = None,
) -> CaseSelection:
    if not isinstance(data, dict):
        raise ValueError(
            f"selection manifest root must be a JSON object, got {type(data).__name__}"
        )

    required_keys = {
        "schema",
        "plan_id",
        "batch_id",
        "source",
        "source_collection_count",
        "source_collection_sha256",
        "nodeids",
    }
    manifest_keys = set(data.keys())
    missing_keys = required_keys - manifest_keys
    if missing_keys:
        raise ValueError(f"missing required keys in selection manifest: {sorted(missing_keys)}")
    unknown_keys = manifest_keys - required_keys
    if unknown_keys:
        raise ValueError(f"unknown keys in selection manifest: {sorted(unknown_keys)}")

    # Schema
    schema = data["schema"]
    if isinstance(schema, bool) or not isinstance(schema, int):
        raise ValueError(f"schema must be an integer, got {type(schema).__name__}")
    if schema != 1:
        raise ValueError(f"unsupported selection schema version: {schema}")

    # plan_id
    plan_id = data["plan_id"]
    if not isinstance(plan_id, str) or not _HEX_SHA256_RE.match(plan_id):
        raise ValueError(f"invalid plan_id (expected 64-char lowercase hex): {plan_id!r}")

    # source
    root = (testcases_root or get_testcases_root()).resolve()
    source = data["source"]
    expected_file = _validate_source_path(source, root)

    # source_collection_sha256
    source_collection_sha256 = data["source_collection_sha256"]
    if not isinstance(source_collection_sha256, str) or not _HEX_SHA256_RE.match(
        source_collection_sha256
    ):
        raise ValueError(
            "invalid source_collection_sha256 (expected 64-char lowercase hex): "
            f"{source_collection_sha256!r}"
        )

    # source_collection_count
    source_collection_count = data["source_collection_count"]
    if isinstance(source_collection_count, bool) or not isinstance(source_collection_count, int):
        raise ValueError(
            "source_collection_count must be an integer, "
            f"got {type(source_collection_count).__name__}"
        )
    if source_collection_count <= 0:
        raise ValueError(f"source_collection_count must be positive, got {source_collection_count}")

    # nodeids
    raw_nodeids = data["nodeids"]
    if not isinstance(raw_nodeids, list) or isinstance(raw_nodeids, (str, bytes)):
        raise ValueError(f"nodeids must be a list of strings, got {type(raw_nodeids).__name__}")
    if not raw_nodeids:
        raise ValueError("nodeids must not be empty")

    nodeids: list[str] = []
    seen_nodeids: set[str] = set()
    for nid in raw_nodeids:
        if not isinstance(nid, str):
            raise ValueError(f"nodeid item must be a string, got {type(nid).__name__}")
        if nid in seen_nodeids:
            raise ValueError(f"duplicate nodeid in selection manifest: {nid!r}")
        seen_nodeids.add(nid)

        head, sep, tail = nid.partition("::")
        if not sep or not head or not tail:
            raise ValueError(
                f"malformed nodeid (must contain '::' with non-empty head and tail): {nid!r}"
            )
        if head != source:
            raise ValueError(
                f"mixed source in nodeid: {head!r} does not match manifest source {source!r}"
            )
        nodeids.append(nid)

    if source_collection_count < len(nodeids):
        raise ValueError(
            f"source_collection_count ({source_collection_count}) cannot be less than "
            f"selected nodeids count ({len(nodeids)})"
        )

    # batch_id validation
    batch_id = data["batch_id"]
    if not isinstance(batch_id, str) or not _HEX_SHA256_RE.match(batch_id):
        raise ValueError(f"invalid batch_id (expected 64-char lowercase hex): {batch_id!r}")
    expected_batch_id = compute_batch_id(
        source=source,
        source_collection_count=source_collection_count,
        source_collection_sha256=source_collection_sha256,
        nodeids=nodeids,
    )
    if batch_id != expected_batch_id:
        raise ValueError(f"batch_id mismatch: expected {expected_batch_id}, got {batch_id}")

    # disabled baseline intersection check
    if disabled_nodeids is not None:
        disabled_portable: set[str] = set()
        for d in disabled_nodeids:
            d_norm = normalize_nodeid(d)
            d_head, d_sep, d_tail = d_norm.partition("::")
            if not d_sep or not d_tail:
                continue
            resolved = _resolve_candidate_file(d_head, expected_file, root)
            if resolved == expected_file:
                disabled_portable.add(f"{source}::{d_tail}")
            else:
                disabled_portable.add(d_norm)

        intersect = {
            nid
            for nid in nodeids
            if nid in disabled_portable or normalize_nodeid(nid) in disabled_portable
        }
        if intersect:
            raise ValueError(f"selected nodeids intersect disabled baseline: {sorted(intersect)}")

    return CaseSelection(
        schema=schema,
        plan_id=plan_id,
        batch_id=batch_id,
        source=source,
        source_collection_count=source_collection_count,
        source_collection_sha256=source_collection_sha256,
        nodeids=tuple(nodeids),
    )


def portable_nodeid(
    source: str,
    collected_nodeid: str,
    *,
    testcases_root: Path | None = None,
) -> str:
    """Convert a collected pytest item node-id to a testcase-root-relative portable node-id.

    Replaces only the path head before the first ``::`` with the given manifest ``source``,
    preserving the test and parameter identity after ``::`` byte-for-byte.
    """
    head, sep, tail = collected_nodeid.partition("::")
    if not sep or not head or not tail:
        raise ValueError(f"malformed collected nodeid: {collected_nodeid!r}")

    root = (testcases_root or get_testcases_root()).resolve()
    _validate_source_path(source, root)
    expected_file = (root / source).resolve()

    resolved = _resolve_candidate_file(head, expected_file, root)
    if resolved != expected_file:
        raise ValueError(
            f"collected nodeid source {head!r} does not match manifest source {source!r} "
            f"(expected file: {expected_file})"
        )

    return f"{source}{sep}{tail}"
