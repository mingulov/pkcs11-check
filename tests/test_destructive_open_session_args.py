"""Prototype-enforced NULL-callback guards for the destructive probes (fw#49).

``C_OpenSession`` declares its ``Notify`` parameter as ``CK_NOTIFY``, a
``CFUNCTYPE`` the ctypes converter rejects ``None`` for, so the NULL callback
must be spelled ``CK_NOTIFY()`` (as ``raw.bootstrap.open_session`` does).
Passing ``None`` dies with ``ArgumentError`` before the module is reached --
the same pre-call rejection family as the ``C_AsyncGetID`` selector.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_OK,
    CK_C_GetSlotList,
    CK_C_InitPIN,
    CK_C_InitToken,
    CK_C_Login,
    CK_C_Logout,
    CK_C_OpenSession,
    CK_C_SetPIN,
)
from pkcs11_check.testcases._probes import ckr_destructive
from pkcs11_check.testcases._probes.session import ProbeContext


class _FakeRaw:
    """Report one slot and accept every destructive setup call (fw#49)."""

    def __init__(self) -> None:
        self.C_GetSlotList = CK_C_GetSlotList(self._get_slot_list)
        self.C_OpenSession = CK_C_OpenSession(self._open_session)
        self.C_InitToken = CK_C_InitToken(self._ok)
        self.C_Login = CK_C_Login(self._ok)
        self.C_SetPIN = CK_C_SetPIN(self._ok)
        self.C_InitPIN = CK_C_InitPIN(self._ok)
        self.C_Logout = CK_C_Logout(self._ok)

    def _get_slot_list(self, token_present: int, slots: Any, count: Any) -> int:
        del token_present
        if not slots:
            count.contents.value = 1
        else:
            slots[0] = 7
            count.contents.value = 1
        return int(CKR_OK)

    def _open_session(
        self, slot: int, flags: int, application: Any, notify: Any, session: Any
    ) -> int:
        del slot, flags, application, notify
        session.contents.value = 42
        return int(CKR_OK)

    def _ok(self, *args: Any) -> int:
        del args
        return int(CKR_OK)


def _ctx(raw: _FakeRaw) -> Any:
    return ProbeContext(raw=raw, sh=0, slot_id=0, cleanup=lambda: None, module_path="fake")


@pytest.mark.parametrize(
    "probe",
    [
        "init_token_session_exists",
        "set_pin_wrong_old",
        "init_pin_not_logged_in",
        "init_pin_short_pin",
        "init_pin_token_not_initialized",
    ],
)
def test_probe_opens_session_with_null_callback(probe: str, capsys: Any) -> None:
    """Session-opening destructive probes must survive C_OpenSession (fw#49)."""
    ckr_destructive._PROBES[probe](_ctx(_FakeRaw()))
    out = capsys.readouterr().out
    assert out.rstrip().endswith("OK")
