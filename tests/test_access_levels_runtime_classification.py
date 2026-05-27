"""Runtime classification meta-tests for test_access_levels login guards (Phase 4 N2).

The login/SO-conflict guards check that a forbidden login rejects. Converted
from a flat ``assert rv in (...)`` to a 3-way ``classify_negative_rv``:

- ``CKR_OK`` (the forbidden login succeeded) -> ``fail``,
- the spec-preferred code -> ``pass``,
- any other clean reject code -> ``xfail``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_OK,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_USER_TYPE_INVALID,
)
from pkcs11_check.testcases import test_access_levels as tal


def _session(login_rv: int) -> SimpleNamespace:
    def _login(*_a: object, **_k: object) -> int:
        return int(login_rv)

    raw = SimpleNamespace(C_Login=_login)
    return SimpleNamespace(raw=raw, sh=1, slot_id=0, has_mechanism=lambda n: True)


def _run(monkeypatch: pytest.MonkeyPatch, login_rv: int) -> None:
    monkeypatch.setattr(tal, "get_pin_bytes", lambda *_a, **_k: b"1234")
    monkeypatch.setattr(tal, "raw_open_session", lambda *_a, **_k: 3)
    monkeypatch.setattr(tal, "_logout_safe", lambda *_a, **_k: None)
    monkeypatch.setattr(tal, "close_session_quietly", lambda *_a, **_k: None)
    tal.TestSOOnROSession().test_so_login_rejected_on_ro_session(
        _session(login_rv), SimpleNamespace()
    )


def test_so_login_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, int(CKR_SESSION_READ_ONLY_EXISTS))


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_SESSION_READ_ONLY))


def test_quirk_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_USER_TYPE_INVALID))
