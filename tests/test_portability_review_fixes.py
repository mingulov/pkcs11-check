"""Regression tests for Windows-only gaps found in the cross-platform review:
raw node-ids in the isolation-escalation path, the un-pinned probe-params JSON handoff,
and the un-pinned subprocess-coverage ingest (sibling channel the review first missed)."""

from __future__ import annotations

import builtins
import json
import subprocess

from pkcs11_check.core import file_runner
from pkcs11_check.testcases._probes.params import ProbeParams


def test_collect_pytest_nodeids_normalizes_backslashes(monkeypatch) -> None:
    """collect_pytest_nodeids must return forward-slash node-ids so the escalation-path
    membership test against the (normalized) disabled set matches on Windows."""
    fake = subprocess.CompletedProcess(
        args=["x"],
        returncode=0,
        stdout="src\\pkcs11_check\\testcases\\test_x.py::TestC::test_m[rsa-2048]\n",
        stderr="",
    )
    monkeypatch.setattr(file_runner.subprocess, "run", lambda *a, **k: fake)
    got = file_runner.collect_pytest_nodeids(["target"], [])
    assert got == ["src/pkcs11_check/testcases/test_x.py::TestC::test_m[rsa-2048]"]


def test_probe_params_roundtrip_non_ascii_path(tmp_path) -> None:
    """The parent->child probe-params handoff is UTF-8 on both ends, so a non-ASCII
    module path (e.g. a non-English Windows profile dir) round-trips instead of raising
    UnicodeEncodeError/decode errors under a non-UTF-8 locale codepage."""
    non_ascii_path = "C:\\Üsers\\élève\\softhsm2.dll"
    p = tmp_path / "params.json"
    # Mirror the runner's write contract (utf-8), then load via the production path.
    p.write_text(json.dumps({"module_path": non_ascii_path, "slot_id": 0}), encoding="utf-8")
    loaded = ProbeParams.load(str(p))
    assert loaded.module_path == non_ascii_path
    assert loaded.slot_id == 0


def test_subprocess_coverage_ingest_reads_utf8(tmp_path, monkeypatch) -> None:
    """The parent-side subprocess-coverage ingest must read the coverage JSON as UTF-8, to
    match the child's write side (_probes/_emit.write_coverage, which pins utf-8). An unpinned
    read would decode as the platform codepage (cp1252 on a non-UTF-8 Windows locale), mangling
    or dropping any non-ASCII key. The review pinned the probe-params channel but first missed
    this sibling channel's two read sites (_raw_subprocess / _subprocess_preamble ingest)."""
    from pkcs11_check.testcases import _raw_subprocess, _subprocess_preamble

    seen_encodings: list[str | None] = []
    real_open = builtins.open

    def recording_open(file, mode="r", *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        seen_encodings.append(kwargs.get("encoding"))
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", recording_open)

    # A synthetic non-ASCII key -- real PKCS#11 names are all ASCII, so we stand one in as a
    # canary. Its UTF-8 bytes (U+00CB -> 0xC3 0x8B) decode to a *different* string under cp1252,
    # so it survives the round-trip only if the ingest reads utf-8; a pure-ASCII key could not
    # tell a pinned read from an unpinned one.
    utf8_canary_key = "utf8-canary-Ë"
    cov = tmp_path / "cov.json"
    cov.write_text(
        json.dumps({"call_log": {utf8_canary_key: 1}, "mechanism_counts": {}}), encoding="utf-8"
    )

    # Drain any residual accumulator state, then ingest through both production read paths.
    _raw_subprocess.get_raw_subprocess_coverage()
    _subprocess_preamble.get_preamble_subprocess_coverage()
    _raw_subprocess.ingest_raw_subprocess_coverage(str(cov))
    _subprocess_preamble.ingest_subprocess_coverage(str(cov))

    # Both ingests pinned utf-8 (fails before the fix, where encoding defaults to None).
    assert seen_encodings == ["utf-8", "utf-8"], seen_encodings
    func_raw, _ = _raw_subprocess.get_raw_subprocess_coverage()
    func_pre, _ = _subprocess_preamble.get_preamble_subprocess_coverage()
    assert func_raw[utf8_canary_key] == 1
    assert func_pre[utf8_canary_key] == 1
