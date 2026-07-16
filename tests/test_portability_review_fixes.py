"""Regression tests for two Windows-only gaps found in the cross-platform review:
raw node-ids in the isolation-escalation path, and the un-pinned probe-params JSON handoff."""

from __future__ import annotations

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
