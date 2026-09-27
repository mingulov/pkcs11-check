"""Regression tests for v3.0 session subprocess RV trace capture."""

from __future__ import annotations

import ctypes
import inspect
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.core.subprocess_trace import drain_subprocess_rv_trace
from pkcs11_check.raw.types_std import (
    CK_INTERFACE,
    CK_INTERFACE_PTR_PTR,
    CK_VERSION,
    CKR_FUNCTION_NOT_SUPPORTED,
)
from pkcs11_check.testcases import test_v30_session
from pkcs11_check.testcases._probes import v30_session
from pkcs11_check.testcases._probes.raw_session import RawCtypesContext


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
        # A real child that dies of a Python exception prints a full traceback; the
        # header is what tells the parent this was a Python-level death rather than
        # the module tearing the process down from inside a PKCS#11 call.
        stderr = (
            "Traceback (most recent call last):\n"
            '  File "probe.py", line 1, in <module>\n'
            "AssertionError: C_OpenSession: 0x000000b1"
        )

    def _fake_run(args: list[str], **_kwargs: Any) -> _Result:
        return _Result()

    monkeypatch.setattr(subprocess, "run", _fake_run)

    test_case = test_v30_session.TestSessionCancel()
    p11_config = type(
        "Config",
        (),
        {"module": "/tmp/fake-module.so", "pin": None, "slot": None, "interface": "auto"},
    )()

    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
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
        # A real child that dies of a Python exception prints a full traceback; the
        # header is what tells the parent this was a Python-level death rather than
        # the module tearing the process down from inside a PKCS#11 call.
        stderr = (
            "Traceback (most recent call last):\n"
            '  File "probe.py", line 1, in <module>\n'
            "AssertionError: C_OpenSession: 0x000000b1"
        )

    def _fake_run(args: list[str], **_kwargs: Any) -> _Result:
        captured["args"] = args
        return _Result()

    monkeypatch.setattr(subprocess, "run", _fake_run)

    test_case = test_v30_session.TestSessionCancel()
    p11_config = type(
        "Config",
        (),
        {"module": "/tmp/fake-module.so", "pin": None, "slot": None, "interface": "auto"},
    )()

    with pytest.raises(pytest.fail.Exception, match="subprocess exited with code 1"):
        test_case.test_cancel_after_digest_init_subprocess(p11_config)

    # The child is launched as the v30_session probe module (python -m ...), not an inline script.
    args = captured["args"]
    assert "-m" in args
    assert "pkcs11_check.testcases._probes.v30_session" in args

    # Cleanup contract is now the probe's own _teardown: C_CloseSession + C_Finalize.
    teardown_src = inspect.getsource(v30_session._teardown)
    assert "raw.C_CloseSession(session_handle)" in teardown_src
    assert "raw.C_Finalize(None)" in teardown_src


def _v30_context(
    requested: str,
    *,
    table_version: tuple[int, int] = (3, 1),
    rv: int = 0,
    return_interface: bool = True,
    p_function_list: bool = True,
) -> tuple[RawCtypesContext, dict[str, object], object, object]:
    """Build a fake raw context whose C_GetInterface exposes one exact table."""
    requested_calls: dict[str, object] = {}
    table_version_obj = CK_VERSION(*table_version)
    interface = CK_INTERFACE(
        None,
        ctypes.cast(ctypes.pointer(table_version_obj), ctypes.c_void_p)
        if p_function_list
        else None,
        0,
    )
    interface_ptr = ctypes.pointer(interface)

    def _get_interface(_name: object, version: object, output: object, _flags: int) -> int:
        requested_calls["version"] = None if version is None else version._obj  # type: ignore[attr-defined]
        if return_interface:
            ctypes.cast(output, CK_INTERFACE_PTR_PTR)[0] = interface_ptr
        return rv

    _get_interface.restype = ctypes.c_ulong  # type: ignore[attr-defined]
    _get_interface.argtypes = []  # type: ignore[attr-defined]
    lib = SimpleNamespace(C_GetInterface=_get_interface)
    context = RawCtypesContext(
        lib=lib,  # type: ignore[arg-type]
        func_list=ctypes.c_void_p(0x1234),
        cleanup=lambda: None,
        interface=requested,
    )
    return context, requested_calls, table_version_obj, interface


@pytest.mark.parametrize("requested", ("3.0", "3.1", "3.2"))
def test_v30_child_requests_exact_interface_and_uses_returned_function_list(
    requested: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    version = tuple(int(part) for part in requested.split("."))
    context, calls, table_version, _interface = _v30_context(
        requested,
        table_version=version,  # type: ignore[arg-type]
    )
    captured: dict[str, object] = {}

    class _Raw:
        def __init__(self, funclist_ptr: int, *, funclist3_ptr: int) -> None:
            captured.update(funclist_ptr=funclist_ptr, funclist3_ptr=funclist3_ptr)

    monkeypatch.setattr(v30_session, "RawPKCS11", _Raw)
    result = v30_session._negotiate_v30(context)

    assert isinstance(result, _Raw)
    version = calls["version"]
    assert (version.major, version.minor) == tuple(  # type: ignore[union-attr]
        int(part) for part in requested.split(".")
    )
    assert captured == {
        "funclist_ptr": 0x1234,
        "funclist3_ptr": ctypes.cast(ctypes.pointer(table_version), ctypes.c_void_p).value,
    }


def test_v30_child_auto_preserves_default_interface_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, calls, _table_version, _interface = _v30_context("auto")
    monkeypatch.setattr(v30_session, "RawPKCS11", lambda *_args, **_kwargs: object())

    v30_session._negotiate_v30(context)

    assert calls["version"] is None


def test_v30_child_rejects_selected_v240_before_negotiation() -> None:
    context, _calls, _table_version, _interface = _v30_context("2.40")

    with pytest.raises(RuntimeError, match="requires a PKCS#11 v3 interface"):
        v30_session._negotiate_v30(context)


def test_v30_child_rejects_mismatched_returned_header() -> None:
    context, _calls, _table_version, _interface = _v30_context("3.0", table_version=(3, 1))

    with pytest.raises(RuntimeError, match="requested.*3.0.*got 3.1"):
        v30_session._negotiate_v30(context)


def test_v30_child_rejects_non_ok_get_interface_rv() -> None:
    context, _calls, _table_version, _interface = _v30_context(
        "3.1", rv=int(CKR_FUNCTION_NOT_SUPPORTED)
    )

    with pytest.raises(RuntimeError, match="returned CK_RV 0x00000054"):
        v30_session._negotiate_v30(context)


def test_v30_child_rejects_null_interface_pointer() -> None:
    context, _calls, _table_version, _interface = _v30_context("3.1", return_interface=False)

    with pytest.raises(RuntimeError, match="returned NULL"):
        v30_session._negotiate_v30(context)


def test_v30_child_rejects_null_function_list_pointer() -> None:
    context, _calls, _table_version, _interface = _v30_context("3.1", p_function_list=False)

    with pytest.raises(RuntimeError, match="NULL pFunctionList"):
        v30_session._negotiate_v30(context)
