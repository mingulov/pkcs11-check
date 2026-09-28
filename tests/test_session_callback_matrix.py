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

from pkcs11_check.raw.types_std import CKR_OK
from pkcs11_check.testcases import test_session_edge_cases as session_cases

_CASES = ("null-null", "null-data", "callback-null", "callback-data")


def _is_null(ptr: Any) -> bool:
    if ptr is None:
        return True
    return ctypes.cast(ptr, c_void_p).value in (None, 0)


@pytest.mark.parametrize("case_id", _CASES)
def test_open_session_matrix_row_pointer_shapes(
    monkeypatch: pytest.MonkeyPatch, case_id: str
) -> None:
    """Each matrix row sends the expected callback/app-data NULL-ness and
    closes the session it opened."""
    captured: dict[str, Any] = {}

    def _open_session(_slot: int, _flags: int, app: Any, notify: Any, sh_ptr: Any) -> int:
        captured["app_null"] = _is_null(app)
        captured["notify_null"] = _is_null(notify)
        sh_ptr._obj.value = 9
        return int(CKR_OK)

    closed: list[int] = []
    raw = SimpleNamespace(C_OpenSession=_open_session)
    rs = SimpleNamespace(raw=raw, sh=1, slot_id=0)
    monkeypatch.setattr(
        session_cases,
        "close_session_quietly",
        lambda _raw, sh: closed.append(sh),
    )

    case = dict(session_cases._OPEN_SESSION_MATRIX[case_id])
    session_cases.TestCKNotifyCallback().test_open_session_callback_matrix(rs, case)

    want_notify, want_app = case_id.split("-")
    assert captured["notify_null"] == (want_notify == "null")
    assert captured["app_null"] == (want_app == "null")
    assert closed == [9]
