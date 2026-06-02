"""Regression tests for v3.0 session subprocess RV trace capture."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.testcases import test_v30_session
from pkcs11_check.testcases._subprocess_trace import drain_subprocess_rv_trace


def test_session_cancel_subprocess_failure_records_child_rv_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = (
        'P11_RV_TRACE_JSON:[{"i":0,"fn":"C_OpenSession","mech":null,'
        '"rv":177,"rv_name":"CKR_SESSION_COUNT"}]'
    )

    class _Result:
        returncode = 1
        stdout = marker
        stderr = "AssertionError: C_OpenSession: 0x000000b1"

    def _fake_run(args: list[str], **_kwargs: Any) -> _Result:
        return _Result()

    monkeypatch.setattr(subprocess, "run", _fake_run)

    test_case = test_v30_session.TestSessionCancel()
    p11_raw_session = SimpleNamespace(slot_id=0)
    p11_config = SimpleNamespace(module="/tmp/fake-module.so", pin=None)

    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        test_case.test_cancel_after_digest_init_subprocess(p11_raw_session, p11_config)

    assert drain_subprocess_rv_trace() == [
        {"i": 0, "fn": "C_OpenSession", "mech": None, "rv": 177, "rv_name": "CKR_SESSION_COUNT"}
    ]
