"""Pins for the C_OpenSession callback/application-pointer matrix.

Each of the four (callback NULL/non-NULL) x (app-data NULL/non-NULL) rows
must reach C_OpenSession with the exact pointer shape and close the opened
session. These tests drive the real matrix node with a fake token.
"""

from __future__ import annotations

import ctypes
from ctypes import c_void_p
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_OK,
    CKR_SESSION_COUNT,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED,
)
from pkcs11_check.testcases import test_session_edge_cases as session_cases

_CASES = ("null-null", "null-data", "callback-null", "callback-data")


def _is_null(ptr: Any) -> bool:
    if ptr is None:
        return True
    return ctypes.cast(ptr, c_void_p).value in (None, 0)


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

    raw = SimpleNamespace(C_OpenSession=_open_session, C_CloseSession=_close_session)
    rs = SimpleNamespace(raw=raw, sh=1, slot_id=0)

    case = dict(session_cases._OPEN_SESSION_MATRIX[case_id])
    session_cases.TestCKNotifyCallback().test_open_session_callback_matrix(rs, case)

    want_notify, want_app = case_id.split("-")
    assert captured["notify_null"] == (want_notify == "null")
    assert captured["app_null"] == (want_app == "null")
    assert closed == [9]


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

    raw = SimpleNamespace(C_OpenSession=_open_session, C_CloseSession=_close_session)
    rs = SimpleNamespace(raw=raw, sh=1, slot_id=0)
    case = dict(session_cases._OPEN_SESSION_MATRIX["null-null"])
    with pytest.raises(AssertionError, match="null handle"):
        session_cases.TestCKNotifyCallback().test_open_session_callback_matrix(rs, case)


def test_open_session_parallel_refusal_fails() -> None:
    """CKR_SESSION_PARALLEL_NOT_SUPPORTED must fail the row.

    Regression pin: the serial flag IS set, so a parallel refusal means the
    module mishandled the flags -- the old substring oracle passed it.
    """

    def _open_session(_slot: int, _flags: int, _app: Any, _notify: Any, sh_ptr: Any) -> int:
        sh_ptr._obj.value = 0
        return int(CKR_SESSION_PARALLEL_NOT_SUPPORTED)

    raw = SimpleNamespace(C_OpenSession=_open_session)
    rs = SimpleNamespace(raw=raw, sh=1, slot_id=0)
    case = dict(session_cases._OPEN_SESSION_MATRIX["null-null"])
    with pytest.raises(AssertionError, match="failed unexpectedly"):
        session_cases.TestCKNotifyCallback().test_open_session_callback_matrix(rs, case)


def test_open_session_count_refusal_passes() -> None:
    """CKR_SESSION_COUNT stays an accepted row outcome (session limit)."""

    def _open_session(_slot: int, _flags: int, _app: Any, _notify: Any, sh_ptr: Any) -> int:
        sh_ptr._obj.value = 0
        return int(CKR_SESSION_COUNT)

    raw = SimpleNamespace(C_OpenSession=_open_session)
    rs = SimpleNamespace(raw=raw, sh=1, slot_id=0)
    case = dict(session_cases._OPEN_SESSION_MATRIX["null-null"])
    session_cases.TestCKNotifyCallback().test_open_session_callback_matrix(rs, case)
