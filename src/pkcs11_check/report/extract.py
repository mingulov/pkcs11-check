"""Extract and group at-source classification findings from a pytest report log.

A finding occurrence is one serialized :class:`pkcs11_check.classification.Classification`
dict. Counts in this module are occurrence counts, not unique-testcase counts. Occurrences come
from two places:

* ``report.jsonl`` (pytest-reportlog): a setup/call/teardown ``TestReport`` can carry a
  phase-scoped ``pkcs11_classification`` list in ``user_properties``.
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

from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any

from pkcs11_check.classification import normalize_param
from pkcs11_check.core.crash_codes import (
    CTYPES_ACCESS_VIOLATION,
    ctypes_access_violation_from_stderr,
)
from pkcs11_check.core.report_log import (
    iter_report_log_records as _iter_report_records,
)
from pkcs11_check.core.report_log import (
    user_property as _user_property,
)

# How many sample nodeids / vector ids to retain per group.
_MAX_NODEIDS = 5
_MAX_VECTOR_IDS = 8
_MAX_PARAMS = 20

GroupKey = tuple[str, str, str | None, str | None, str | None, tuple[str, ...], str | None]


def _classifications_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull phase-scoped classifications off a setup/call/teardown TestReport."""
    if report.get("$report_type", "TestReport") != "TestReport":
        return []
    if report.get("when") not in {"setup", "call", "teardown"}:
        return []
    value = _user_property(report, "pkcs11_classification")
    if not isinstance(value, list):
        return []
    return [rec for rec in value if isinstance(rec, dict)]


def _classification_from_teardown_finalize(report: dict[str, Any]) -> dict[str, Any] | None:
    """Represent a non-green C_Finalize record as a grouped lifecycle finding."""
    if report.get("$report_type") != "TeardownFinalize":
        return None
    outcome = str(report.get("outcome", "")).casefold()
    if outcome == "ok":
        return None
    crashed = outcome == "crashed" or (
        report.get("windows_status") == CTYPES_ACCESS_VIOLATION
        or ctypes_access_violation_from_stderr(str(report.get("error"))) is not None
    )
    rv_name = report.get("rv_name")
    summary = str(report.get("error") or "").strip()
    if not summary:
        summary = (
            f"C_Finalize returned {rv_name}"
            if rv_name
            else f"C_Finalize ended with {outcome or 'an invalid outcome'}"
        )
    return {
        "schema": 1,
        "reason": "crash" if crashed else "self_contradiction",
        "outcome": "fail",
        "severity": "HIGH",
        "kind": "lifecycle",
        "label": "C_Finalize",
        "summary": summary,
        "operation": "C_Finalize",
        "mechanism": None,
        "expected_ckr": ["CKR_OK"],
        "actual_ckr": rv_name,
        "spec_ref": "PKCS#11 C_Finalize",
        "source": None,
        "vector_id": None,
        "detail": dict(report),
    }


def _test_file_for(rec: dict[str, Any], nodeid: str | None) -> str:
    """Determine the grouping ``test_file`` for a finding.

    TestReport findings split it off the nodeid; crash findings (no nodeid) use
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
        "param_breakdown": {},
        # internal accumulators (dropped on finalize)
        "_vector_id_set": set(),
        "_source_set": set(),
        "_param_counter": Counter(),
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
    params = rec.get("params")
    if isinstance(params, dict) and params:
        key = ",".join(f"{k}={normalize_param(k, str(params[k]))}" for k in sorted(params))
        group["_param_counter"][key] += 1


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
    group["param_breakdown"] = dict(group.pop("_param_counter").most_common(_MAX_PARAMS))
    return group


def extract_groups(
    report_jsonl_path: str | Path, crashes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Group classification findings from a report log plus crash findings.

    Returns a list of group dicts, each with classification-occurrence ``count``, sample
    ``nodeids``, sorted unique ``vector_ids`` (capped, with a ``+N`` overflow marker),
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
        finalize = _classification_from_teardown_finalize(report)
        if finalize is not None:
            ingest(finalize, "C_Finalize::teardown")

    for crash in crashes:
        ingest(crash, None)

    return [_finalize(group) for group in groups.values()]
