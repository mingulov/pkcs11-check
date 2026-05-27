"""Runtime classification meta-tests for test_ro_session_restrictions (Phase 4 N2).

Read-only-session write guards check that a write op on an RO session rejects.
Converted from a flat ``assert rv in _RO_ERROR_RVS`` to a 3-way
``classify_negative_rv``:

- ``CKR_OK`` (the module performed a write on an RO session) -> ``fail``,
- ``CKR_SESSION_READ_ONLY`` (spec) -> ``pass``,
- any other clean reject code (e.g. ``CKR_ACTION_PROHIBITED``,
  ``CKR_SESSION_READ_ONLY_EXISTS``) -> ``xfail``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_ACTION_PROHIBITED,
    CKR_OK,
    CKR_SESSION_READ_ONLY,
)
from pkcs11_check.testcases import test_ro_session_restrictions as tro


def _session(create_rv: int) -> SimpleNamespace:
    def _create(*_a: object, **_k: object) -> int:
        return int(create_rv)

    raw = SimpleNamespace(C_CreateObject=_create)
    return SimpleNamespace(raw=raw, sh=1, slot_id=0, has_mechanism=lambda n: True)


def _run(monkeypatch: pytest.MonkeyPatch, create_rv: int) -> None:
    monkeypatch.setattr(tro, "get_pin_bytes", lambda *_a, **_k: b"1234")
    monkeypatch.setattr(tro, "raw_open_session", lambda *_a, **_k: 7)
    monkeypatch.setattr(tro, "_login_ro", lambda *_a, **_k: None)
    monkeypatch.setattr(tro, "close_session_quietly", lambda *_a, **_k: None)
    tro.TestROExactCKR().test_create_token_object_returns_session_read_only(
        _session(create_rv), SimpleNamespace()
    )


def test_ro_write_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, int(CKR_SESSION_READ_ONLY))


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_ACTION_PROHIBITED))
