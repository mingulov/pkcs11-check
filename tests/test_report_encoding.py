"""Report JSON artifacts are written as readable UTF-8 (no ``\\uXXXX`` escapes)."""

from __future__ import annotations

import json

from pkcs11_check.core.file_runner import (
    FileRunResult,
    FileRunState,
    write_isolated_json_report,
)


def test_results_json_is_readable_utf8_not_escaped(tmp_path) -> None:  # type: ignore[no-untyped-def]
    state = FileRunState(
        units=["t.py::a"],
        fingerprint="x",
        results=[
            FileRunResult(
                target="t.py::a",
                status="crashed",
                returncode=-11,
                duration_s=0.1,
                stderr="boom — weak § ref → x",
            ),
        ],
    )
    out = tmp_path / "results.json"
    write_isolated_json_report(out, state)

    raw = out.read_bytes()
    assert "—".encode() in raw  # literal UTF-8 em dash, not an escape
    assert b"\\u2014" not in raw  # no escaped em dash
    # Still valid JSON that round-trips to the original text.
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["crashed"] == 1
    assert any(
        "boom — weak § ref → x" in (t.get("longrepr") or "") for t in data["units"][0]["tests"]
    )
