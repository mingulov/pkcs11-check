"""Tests for provenance wiring into postprocess_jsonl_to_unified and merge."""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core.file_runner import postprocess_jsonl_to_unified


def test_postprocess_includes_provenance(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("")  # empty run is fine for this structural test
    out = tmp_path / "results.json"
    postprocess_jsonl_to_unified(jsonl, out, provenance={"framework": {"version": "v1"}})
    payload = json.loads(out.read_text())
    assert payload["provenance"] == {"framework": {"version": "v1"}}


def test_postprocess_omits_provenance_when_none(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("")
    out = tmp_path / "results.json"
    postprocess_jsonl_to_unified(jsonl, out)
    payload = json.loads(out.read_text())
    assert "provenance" not in payload
