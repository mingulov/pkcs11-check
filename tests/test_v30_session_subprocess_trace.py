"""Regression tests for v3.0 session subprocess RV trace capture."""

from __future__ import annotations

import inspect
import subprocess
from typing import Any

import pytest

from pkcs11_check.testcases import test_v30_session
from pkcs11_check.testcases._probes import v30_session
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
    p11_config = type("Config", (), {"module": "/tmp/fake-module.so", "pin": None, "slot": None})()

    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        test_case.test_cancel_after_digest_init_subprocess(p11_config)

    assert drain_subprocess_rv_trace() == [
        {"i": 0, "fn": "C_OpenSession", "mech": None, "rv": 177, "rv_name": "CKR_SESSION_COUNT"}
    ]


def test_session_cancel_subprocess_launches_probe_with_teardown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The migrated cancel-after-digest test launches the ``v30_session`` probe module
    (``python -m ...``), and that probe guarantees C_CloseSession + C_Finalize teardown.

    Replaces the legacy assertion on the generated ``-c`` script's
    ``_p11check_cleanup_raw_subprocess`` body: cleanup is now the probe's own ``_teardown``
    (called at every exit point) plus ``probe_main_raw``'s atexit handler, not an inline
    script string.
    """
    captured: dict[str, list[str]] = {}

    class _Result:
        returncode = 1
        stdout = "P11_RV_TRACE_JSON:[]"
        stderr = "AssertionError: C_OpenSession: 0x000000b1"

    def _fake_run(args: list[str], **_kwargs: Any) -> _Result:
        captured["args"] = args
        return _Result()

    monkeypatch.setattr(subprocess, "run", _fake_run)

    test_case = test_v30_session.TestSessionCancel()
    p11_config = type("Config", (), {"module": "/tmp/fake-module.so", "pin": None, "slot": None})()

    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        test_case.test_cancel_after_digest_init_subprocess(p11_config)

    # The child is launched as the v30_session probe module (python -m ...), not an inline script.
    args = captured["args"]
    assert "-m" in args
    assert "pkcs11_check.testcases._probes.v30_session" in args

    # Cleanup contract is now the probe's own _teardown: C_CloseSession + C_Finalize.
    teardown_src = inspect.getsource(v30_session._teardown)
    assert "raw.C_CloseSession(session_handle)" in teardown_src
    assert "raw.C_Finalize(None)" in teardown_src
