# tests/test_capability_audit.py
"""Per-provider capability audit summary over grouped report records."""

from __future__ import annotations

from typing import Any

from tools.report.capability import capability_audit, render_capability_section


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
    assert "4" in md
