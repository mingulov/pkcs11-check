"""Tests for provenance wiring into postprocess_jsonl_to_unified, merge, and isolated writer."""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core.file_runner import (
    FileRunState,
    _build_isolated_json_payload,
    postprocess_jsonl_to_unified,
    write_isolated_json_report,
)
from pkcs11_check.core.merge import merge_results_payloads


def test_postprocess_includes_provenance(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("", encoding="utf-8")  # empty run is fine for this structural test
    out = tmp_path / "results.json"
    postprocess_jsonl_to_unified(jsonl, out, provenance={"framework": {"version": "v1"}})
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["provenance"] == {"framework": {"version": "v1"}}


def test_postprocess_omits_provenance_when_none(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("", encoding="utf-8")
    out = tmp_path / "results.json"
    postprocess_jsonl_to_unified(jsonl, out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert "provenance" not in payload


def test_merge_carries_provenance_from_first_payload() -> None:
    prov = {"framework": {"version": "v1"}, "provider": {"name": "softhsm2"}}
    p1 = {"summary": {"passed": 1}, "units": [], "provenance": prov}
    p2 = {"summary": {"passed": 2}, "units": []}
    merged = merge_results_payloads([p1, p2], coverage=None)
    assert merged["provenance"] == prov


def test_merge_omits_provenance_when_absent_in_all_payloads() -> None:
    p1 = {"summary": {"passed": 1}, "units": []}
    p2 = {"summary": {"passed": 2}, "units": []}
    merged = merge_results_payloads([p1, p2], coverage=None)
    assert "provenance" not in merged


# ---------------------------------------------------------------------------
# Isolated writer path (FIX 1 regression tests)
# ---------------------------------------------------------------------------

_SAMPLE_PROVENANCE: dict[str, object] = {"framework": {"version": "v1"}}


def _empty_state() -> FileRunState:
    return FileRunState(units=[], fingerprint="test", results=[])


def test_build_isolated_json_payload_includes_provenance() -> None:
    """_build_isolated_json_payload writes provenance into the payload dict."""
    state = _empty_state()
    payload = _build_isolated_json_payload(state, provenance=_SAMPLE_PROVENANCE)
    assert payload["provenance"] == _SAMPLE_PROVENANCE


def test_build_isolated_json_payload_omits_provenance_when_none() -> None:
    """_build_isolated_json_payload omits the provenance key when not supplied."""
    state = _empty_state()
    payload = _build_isolated_json_payload(state)
    assert "provenance" not in payload


def test_write_isolated_json_report_includes_provenance(tmp_path: Path) -> None:
    """write_isolated_json_report propagates provenance into the written file."""
    state = _empty_state()
    out = tmp_path / "results.json"
    write_isolated_json_report(out, state, provenance=_SAMPLE_PROVENANCE)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["provenance"] == _SAMPLE_PROVENANCE


def test_write_isolated_json_report_omits_provenance_when_none(tmp_path: Path) -> None:
    """write_isolated_json_report omits provenance when the param is not supplied."""
    state = _empty_state()
    out = tmp_path / "results.json"
    write_isolated_json_report(out, state)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert "provenance" not in payload
