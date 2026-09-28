"""Pins for the C_OpenSession callback/application-pointer matrix.

Each of the four (callback NULL/non-NULL) x (app-data NULL/non-NULL) rows
must reach C_OpenSession with the exact pointer shape, return a fresh usable
session, and close the opened session. These tests drive the real matrix
node with a fake token.
"""

from __future__ import annotations

import ctypes
from ctypes import c_void_p
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.classification import get_records
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKR_OK,
    CKR_SESSION_COUNT,
    CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED,
)
from pkcs11_check.testcases import test_session_edge_cases as session_cases

_CASES = ("null-null", "null-data", "callback-null", "callback-data")


def _is_null(ptr: Any) -> bool:
    if ptr is None:
        return True
    return ctypes.cast(ptr, c_void_p).value in (None, 0)


def _info_ok(_session: int, _info_ptr: Any) -> int:
    return int(CKR_OK)


def _run_case(raw: SimpleNamespace, case_id: str, *, sh: int = 1) -> None:
    rs = SimpleNamespace(raw=raw, sh=sh, slot_id=0)
    case = dict(session_cases._OPEN_SESSION_MATRIX[case_id])
    session_cases.TestCKNotifyCallback().test_open_session_callback_matrix(rs, case)


def _assert_fail_record(reason: str, kind: str | None) -> None:
    records = get_records()
    assert len(records) == 1
    assert records[0].reason == reason
    assert records[0].reason != "unclassified"
    assert records[0].kind == kind
    assert records[0].outcome == "fail"


@pytest.mark.parametrize("case_id", _CASES)
def test_open_session_matrix_row_pointer_shapes(case_id: str) -> None:
    """Each matrix row sends the expected callback/app-data NULL-ness and
    closes the session it opened."""
    captured: dict[str, Any] = {}

    def _open_session(_slot: int, _flags: int, app: Any, notify: Any, sh_ptr: Any) -> int:
        captured["app_null"] = _is_null(app)
        captured["notify_null"] = _is_null(notify)
        sh_ptr._obj.value = 9
        return int(CKR_OK)

    closed: list[int] = []

    def _close_session(sh: int) -> int:
        closed.append(sh)
        return int(CKR_OK)

    raw = SimpleNamespace(
        C_OpenSession=_open_session, C_CloseSession=_close_session, C_GetSessionInfo=_info_ok
    )
    _run_case(raw, case_id)

    want_notify, want_app = case_id.split("-")
    assert captured["notify_null"] == (want_notify == "null")
    assert captured["app_null"] == (want_app == "null")
    assert closed == [9]
    assert get_records() == []


def test_open_session_ok_with_zero_handle_fails() -> None:
    """CKR_OK with a null handle must fail: no session exists to close.

    Regression pin: the matrix oracle used to close quietly, swallowing the
    missing handle and passing the row.
    """

    def _open_session(_slot: int, _flags: int, _app: Any, _notify: Any, sh_ptr: Any) -> int:
        sh_ptr._obj.value = 0
        return int(CKR_OK)

    def _close_session(_sh: int) -> int:
        return int(CKR_OK)

    raw = SimpleNamespace(
        C_OpenSession=_open_session, C_CloseSession=_close_session, C_GetSessionInfo=_info_ok
    )
    with pytest.raises(Failed) as ei:
        _run_case(raw, "null-null")
    assert not isinstance(ei.value, XFailed)
    assert "null handle" in str(ei.value)
    _assert_fail_record("self_contradiction", "lifecycle")


def test_open_session_fixture_handle_reuse_fails() -> None:
    """CKR_OK echoing the live fixture handle is not a fresh session.

    Regression pin: the oracle only checked for a nonzero handle, so a
    module returning the already-open fixture session passed the row.
    The fixture handle itself must never be closed on this path.
    """

    def _open_session(_slot: int, _flags: int, _app: Any, _notify: Any, sh_ptr: Any) -> int:
        sh_ptr._obj.value = 1  # == rs.sh: fixture reuse, not a fresh session
        return int(CKR_OK)

    closed: list[int] = []

    def _close_session(sh: int) -> int:
        closed.append(sh)
        return int(CKR_OK)

    raw = SimpleNamespace(
        C_OpenSession=_open_session, C_CloseSession=_close_session, C_GetSessionInfo=_info_ok
    )
    with pytest.raises(Failed) as ei:
        _run_case(raw, "null-null")
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "lifecycle")
    assert closed == []


def test_open_session_unusable_handle_fails() -> None:
    """A fresh handle that C_GetSessionInfo rejects was never usable."""

    def _open_session(_slot: int, _flags: int, _app: Any, _notify: Any, sh_ptr: Any) -> int:
        sh_ptr._obj.value = 9
        return int(CKR_OK)

    def _info_dead(_session: int, _info_ptr: Any) -> int:
        return int(CKR_SESSION_HANDLE_INVALID)

    closed: list[int] = []

    def _close_session(sh: int) -> int:
        closed.append(sh)
        return int(CKR_OK)

    raw = SimpleNamespace(
        C_OpenSession=_open_session, C_CloseSession=_close_session, C_GetSessionInfo=_info_dead
    )
    with pytest.raises(Failed) as ei:
        _run_case(raw, "null-null")
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "lifecycle")
    assert closed == [9]


def _echo_app(app: Any) -> int | None:
    """Address the fake token echoes back through the callback."""
    if app is None:
        return None
    value = ctypes.cast(app, c_void_p).value
    assert value is not None
    return int(value)


@pytest.mark.parametrize("case_id", ("callback-null", "callback-data"))
def test_open_session_callback_correct_identity_passes(case_id: str) -> None:
    """A callback invoked with the new session and the supplied app pointer passes."""

    def _open_session(_slot: int, _flags: int, app: Any, notify: Any, sh_ptr: Any) -> int:
        sh_ptr._obj.value = 9
        notify(9, 0, _echo_app(app))
        return int(CKR_OK)

    closed: list[int] = []

    def _close_session(sh: int) -> int:
        closed.append(sh)
        return int(CKR_OK)

    raw = SimpleNamespace(
        C_OpenSession=_open_session, C_CloseSession=_close_session, C_GetSessionInfo=_info_ok
    )
    _run_case(raw, case_id)
    assert closed == [9]
    assert get_records() == []


@pytest.mark.parametrize("wrong", ["session", "app"])
def test_open_session_callback_identity_mismatch_fails(wrong: str) -> None:
    """A callback delivering the wrong session or app identity fails the row.

    Regression pin: captured callback calls were never inspected, so a
    module reporting a foreign session handle or application pointer
    passed the row.
    """
    other = ctypes.c_ulong(0)

    def _open_session(_slot: int, _flags: int, app: Any, notify: Any, sh_ptr: Any) -> int:
        sh_ptr._obj.value = 9
        if wrong == "session":
            notify(12345, 0, _echo_app(app))
        else:
            notify(9, 0, ctypes.addressof(other))
        return int(CKR_OK)

    closed: list[int] = []

    def _close_session(sh: int) -> int:
        closed.append(sh)
        return int(CKR_OK)

    raw = SimpleNamespace(
        C_OpenSession=_open_session, C_CloseSession=_close_session, C_GetSessionInfo=_info_ok
    )
    with pytest.raises(Failed) as ei:
        _run_case(raw, "callback-data")
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "lifecycle")
    assert closed == [9]


def test_open_session_callback_null_app_mismatch_fails() -> None:
    """A callback-null row whose callback delivers a non-NULL app pointer fails."""

    def _open_session(_slot: int, _flags: int, app: Any, notify: Any, sh_ptr: Any) -> int:
        assert app is None
        sh_ptr._obj.value = 9
        notify(9, 0, 0x1234)
        return int(CKR_OK)

    def _close_session(_sh: int) -> int:
        return int(CKR_OK)

    raw = SimpleNamespace(
        C_OpenSession=_open_session, C_CloseSession=_close_session, C_GetSessionInfo=_info_ok
    )
    with pytest.raises(Failed) as ei:
        _run_case(raw, "callback-null")
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("self_contradiction", "lifecycle")


def test_open_session_parallel_refusal_fails() -> None:
    """CKR_SESSION_PARALLEL_NOT_SUPPORTED must fail the row.

    Regression pin: the serial flag IS set, so a parallel refusal means the
    module mishandled the flags -- the old substring oracle passed it.
    """

    def _open_session(_slot: int, _flags: int, _app: Any, _notify: Any, sh_ptr: Any) -> int:
        sh_ptr._obj.value = 0
        return int(CKR_SESSION_PARALLEL_NOT_SUPPORTED)

    raw = SimpleNamespace(C_OpenSession=_open_session)
    with pytest.raises(Failed) as ei:
        _run_case(raw, "null-null")
    assert not isinstance(ei.value, XFailed)
    _assert_fail_record("wrong_result", "lifecycle")
    assert get_records()[0].actual_ckr == ckr_name(int(CKR_SESSION_PARALLEL_NOT_SUPPORTED))


def test_open_session_count_refusal_passes() -> None:
    """CKR_SESSION_COUNT stays an accepted row outcome (session limit)."""

    def _open_session(_slot: int, _flags: int, _app: Any, _notify: Any, sh_ptr: Any) -> int:
        sh_ptr._obj.value = 0
        return int(CKR_SESSION_COUNT)

    raw = SimpleNamespace(C_OpenSession=_open_session)
    _run_case(raw, "null-null")
    assert get_records() == []
