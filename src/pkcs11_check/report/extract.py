"""Extract and group at-source classification findings from a pytest report log.

A finding is one serialized :class:`pkcs11_check.classification.Classification`
dict. They come from two places:

* ``report.jsonl`` (pytest-reportlog): every call-phase ``TestReport`` carries a
  ``pkcs11_classification`` list in ``user_properties``.
* the ``crashes`` list: crash findings produced runner-side via
  :func:`pkcs11_check.core.file_runner.crash_classification` (the process was
  dead, so they could not be emitted in-test).

Findings are grouped on a *readable* tuple key - no hashes anywhere - so the
output stays inspectable. The key is::

    (test_file, reason, kind, mechanism, operation, tuple(expected_ckr or []), actual_ckr)

where ``test_file`` is the file part of the nodeid (``nodeid.split("::", 1)[0]``).
Crash findings have no nodeid; their ``label`` is the crashing target/file.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path
from typing import Any

# How many sample nodeids / vector ids to retain per group.
_MAX_NODEIDS = 5
_MAX_VECTOR_IDS = 8

GroupKey = tuple[str, str, str | None, str | None, str | None, tuple[str, ...], str | None]


def _iter_report_records(path: Path) -> list[dict[str, Any]]:
    """Yield JSON objects from a JSONL report log, skipping blank/garbage lines."""
    records: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


def _user_property(report: dict[str, Any], key: str) -> Any:
    """Return the value for ``key`` in a report's ``user_properties`` list."""
    for pair in report.get("user_properties", []) or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[0] == key:
            return pair[1]
    return None


def _classifications_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull the ``pkcs11_classification`` finding list off a call-phase TestReport."""
    if report.get("$report_type", "TestReport") != "TestReport":
        return []
    if report.get("when") != "call":
        return []
    value = _user_property(report, "pkcs11_classification")
    if not isinstance(value, list):
        return []
    return [rec for rec in value if isinstance(rec, dict)]


def _test_file_for(rec: dict[str, Any], nodeid: str | None) -> str:
    """Determine the grouping ``test_file`` for a finding.

    Call-phase findings split it off the nodeid; crash findings (no nodeid) use
    their ``label``, which the runner sets to the crashing target/file.
    """
    if nodeid:
        return nodeid.split("::", 1)[0]
    label = rec.get("label")
    return str(label) if label else ""


def _group_key(rec: dict[str, Any], test_file: str) -> GroupKey:
    expected = rec.get("expected_ckr") or []
    expected_tuple = tuple(str(c) for c in expected)
    return (
        test_file,
        str(rec.get("reason", "")),
        rec.get("kind"),
        rec.get("mechanism"),
        rec.get("operation"),
        expected_tuple,
        rec.get("actual_ckr"),
    )


def _new_group(rec: dict[str, Any], test_file: str) -> dict[str, Any]:
    """Seed a group dict, carrying first-member metadata."""
    return {
        "test_file": test_file,
        "reason": rec.get("reason", ""),
        "outcome": rec.get("outcome", ""),
        "severity": rec.get("severity", ""),
        "kind": rec.get("kind"),
        "operation": rec.get("operation"),
        "mechanism": rec.get("mechanism"),
        "expected_ckr": rec.get("expected_ckr"),
        "actual_ckr": rec.get("actual_ckr"),
        "spec_ref": rec.get("spec_ref", ""),
        "summary": rec.get("summary", ""),
        "detail": rec.get("detail"),
        "count": 0,
        "nodeids": [],
        "vector_ids": [],
        "sources": [],
        # internal accumulators (dropped on finalize)
        "_vector_id_set": set(),
        "_source_set": set(),
    }


def _accumulate(group: dict[str, Any], rec: dict[str, Any], nodeid: str | None) -> None:
    group["count"] += 1
    if nodeid and len(group["nodeids"]) < _MAX_NODEIDS and nodeid not in group["nodeids"]:
        group["nodeids"].append(nodeid)
    vid = rec.get("vector_id")
    if vid is not None:
        group["_vector_id_set"].add(str(vid))
    src = rec.get("source")
    if src is not None:
        group["_source_set"].add(str(src))


def _finalize(group: dict[str, Any]) -> dict[str, Any]:
    """Turn accumulators into sorted, capped public fields."""
    vids = sorted(group.pop("_vector_id_set"))
    if len(vids) > _MAX_VECTOR_IDS:
        shown = vids[:_MAX_VECTOR_IDS]
        shown.append(f"+{len(vids) - _MAX_VECTOR_IDS}")
        group["vector_ids"] = shown
    else:
        group["vector_ids"] = vids
    group["sources"] = sorted(group.pop("_source_set"))
    return group


def extract_groups(
    report_jsonl_path: str | Path, crashes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Group classification findings from a report log plus crash findings.

    Returns a list of group dicts, each with ``count``, sample ``nodeids``,
    sorted unique ``vector_ids`` (capped, with a ``+N`` overflow marker),
    ``sources``, and first-member metadata
    (severity/summary/spec_ref/reason/kind/operation/mechanism/expected_ckr/actual_ckr/detail).
    """
    path = Path(report_jsonl_path)
    groups: OrderedDict[GroupKey, dict[str, Any]] = OrderedDict()

    def ingest(rec: dict[str, Any], nodeid: str | None) -> None:
        test_file = _test_file_for(rec, nodeid)
        key = _group_key(rec, test_file)
        group = groups.get(key)
        if group is None:
            group = _new_group(rec, test_file)
            groups[key] = group
        _accumulate(group, rec, nodeid)

    for report in _iter_report_records(path):
        nodeid = report.get("nodeid")
        for rec in _classifications_from_report(report):
            ingest(rec, nodeid)

    for crash in crashes:
        ingest(crash, None)

    return [_finalize(group) for group in groups.values()]
