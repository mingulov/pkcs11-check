"""Runtime classification meta-tests for test_session_edge_cases (Phase 4 N2).

Stale-session-handle guards check that an operation on a *closed* session
rejects. Converted from a flat ``assert rv in (CKR_SESSION_HANDLE_INVALID,
CKR_SESSION_CLOSED)`` to a 3-way ``classify_negative_rv``:

- ``CKR_OK`` (the module performed an op on a closed session) -> ``fail``,
- ``CKR_SESSION_HANDLE_INVALID`` / ``CKR_SESSION_CLOSED`` (spec) -> ``pass``,
- any other clean reject code -> ``xfail``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases import test_session_edge_cases as tse


def _session(op_rv: int) -> SimpleNamespace:
    def _op(*_a: object, **_k: object) -> int:
        return int(op_rv)

    raw = SimpleNamespace(C_FindObjectsInit=_op, C_GenerateKey=_op)
    return SimpleNamespace(raw=raw, sh=1, slot_id=0)


def _patch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tse, "get_pin_bytes", lambda *_a, **_k: None)
    monkeypatch.setattr(tse, "raw_open_session", lambda *_a, **_k: 7)
    monkeypatch.setattr(tse, "login_user", lambda *_a, **_k: None)
    monkeypatch.setattr(tse, "close_session_quietly", lambda *_a, **_k: None)


def _run_find(monkeypatch: pytest.MonkeyPatch, op_rv: int) -> None:
    _patch(monkeypatch)
    tse.TestStaleSessionHandles().test_find_after_close(_session(op_rv), SimpleNamespace())


def _run_gen(monkeypatch: pytest.MonkeyPatch, op_rv: int) -> None:
    _patch(monkeypatch)
    tse.TestStaleSessionHandles().test_generate_key_after_close(_session(op_rv), SimpleNamespace())


def test_find_accepted_on_closed_session_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_find(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_find_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_find(monkeypatch, int(CKR_SESSION_HANDLE_INVALID))
    _run_find(monkeypatch, int(CKR_SESSION_CLOSED))


def test_find_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_find(monkeypatch, int(CKR_FUNCTION_FAILED))


def test_gen_accepted_on_closed_session_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_gen(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_gen_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_gen(monkeypatch, int(CKR_SESSION_HANDLE_INVALID))
    _run_gen(monkeypatch, int(CKR_SESSION_CLOSED))


def test_gen_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_gen(monkeypatch, int(CKR_FUNCTION_FAILED))
