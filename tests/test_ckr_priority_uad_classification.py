"""Runtime classification meta-test for ckr/test_ckr_priority use-after-destroy (Type C).

test_destroyed_handle_with_wrong_mechanism previously did 'if rv == CKR_OK: pass',
hiding a use-after-destroy. Now: destroy claimed CKR_OK and C_EncryptInit on the
destroyed handle still succeeds -> fail; an honest rejection (handle/mechanism
error) is still accepted (priority note / pass).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_MECHANISM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.ckr import test_ckr_priority


def _session(destroy_rv: int, init_rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(
        C_DestroyObject=lambda *_a, **_k: int(destroy_rv),
        C_EncryptInit=lambda *_a, **_k: int(init_rv),
    )
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)


def _run(monkeypatch: pytest.MonkeyPatch, *, destroy_rv: int, init_rv: int) -> None:
    monkeypatch.setattr(test_ckr_priority, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ckr_priority, "destroy_quietly", lambda *_a, **_k: None)
    test_ckr_priority.TestErrorPriority().test_destroyed_handle_with_wrong_mechanism(
        _session(destroy_rv, init_rv)
    )


def test_uad_init_succeeds_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, destroy_rv=int(CKR_OK), init_rv=int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_handle_error_priority_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, destroy_rv=int(CKR_OK), init_rv=int(CKR_OBJECT_HANDLE_INVALID))


def test_mechanism_first_note_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Lower-priority but honest rejection -- still a posture note, not a fail.
    _run(monkeypatch, destroy_rv=int(CKR_OK), init_rv=int(CKR_MECHANISM_INVALID))


def test_uad_destroy_declined_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, destroy_rv=int(CKR_MECHANISM_INVALID), init_rv=int(CKR_OK))
