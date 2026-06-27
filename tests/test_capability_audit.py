# tests/test_capability_audit.py
"""Per-provider capability audit summary over grouped report records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pkcs11_check.report.capability import capability_audit, render_capability_section
from pkcs11_check.report.extract import extract_groups


def _group(reason: str, count: int, verdict: str | None) -> dict[str, Any]:
    detail: dict[str, Any] | None = {"capability_verdict": verdict} if verdict is not None else None
    return {"reason": reason, "count": count, "detail": detail}


def test_counts_in_range_contradictions() -> None:
    groups = [
        _group("not_operational", 5, "IN_RANGE"),
        _group("not_operational", 3, None),
        _group("wrong_result", 2, None),
    ]
    audit = capability_audit(groups)
    assert audit["not_operational_total"] == 8
    assert audit["claimed_refused"] == 5


def test_render_section_mentions_contradictions() -> None:
    md = render_capability_section(capability_audit([_group("not_operational", 4, "IN_RANGE")]))
    assert "capability audit" in md.lower()
    assert "**4**" in md
    assert "claimed" in md.lower()


def test_empty_groups_render_cleanly() -> None:
    audit = capability_audit([])
    assert audit == {"not_operational_total": 0, "claimed_refused": 0}
    md = render_capability_section(audit)
    assert "capability audit" in md.lower()
    assert "**0**" in md


def test_extract_groups_propagates_detail_to_capability_audit(tmp_path: Path) -> None:
    """Regression: extract_groups must propagate detail so capability_audit sees IN_RANGE.

    Before the fix, _new_group dropped the ``detail`` field, so claimed_refused was always 0
    even when the record carried capability_verdict=IN_RANGE.
    """
    rec = {
        "reason": "not_operational",
        "outcome": "xfail",
        "severity": "LOW",
        "kind": None,
        "label": "RSA:sign",
        "summary": "RSA-3072 advertised but not operational",
        "operation": "C_Sign",
        "mechanism": "CKM_RSA_PKCS",
        "expected_ckr": None,
        "actual_ckr": "CKR_FUNCTION_FAILED",
        "spec_ref": "",
        "source": None,
        "vector_id": None,
        "detail": {"capability_verdict": "IN_RANGE", "key_size": 3072},
        "schema": 1,
    }
    report_line = {
        "$report_type": "TestReport",
        "when": "call",
        "nodeid": "tests/test_mech_rsa.py::test_sign",
        "outcome": "skipped",
        "user_properties": [["pkcs11_classification", [rec]]],
    }
    path = tmp_path / "report.jsonl"
    path.write_text(json.dumps(report_line) + "\n")

    groups = extract_groups(path, crashes=[])
    audit = capability_audit(groups)

    assert audit["not_operational_total"] == 1
    assert audit["claimed_refused"] == 1
