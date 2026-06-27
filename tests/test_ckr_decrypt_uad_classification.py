"""Runtime classification meta-test for ckr/test_ckr_decrypt use-after-destroy (lifecycle).

C_DecryptInit on a destroyed key handle that returns CKR_OK is a use-after-destroy
self-contradiction: the destroy claimed success yet the handle is still usable.
Effect-check: destroy claimed CKR_OK and DecryptInit succeeds -> fail; an expected
reject -> pass; another clean reject -> xfail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.ckr import test_ckr_decrypt


def _session(destroy_rv: int, init_rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(
        C_DestroyObject=lambda *_a, **_k: int(destroy_rv),
        C_DecryptInit=lambda *_a, **_k: int(init_rv),
    )
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)


def _run(monkeypatch: pytest.MonkeyPatch, *, destroy_rv: int, init_rv: int) -> None:
    monkeypatch.setattr(test_ckr_decrypt, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ckr_decrypt, "encrypt_single", lambda *_a, **_k: b"\x00" * 16)
    test_ckr_decrypt.TestDecryptDataErrors().test_key_handle_invalid(
        _session(destroy_rv, init_rv), ckr_strict=False
    )


def test_uad_init_succeeds_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, destroy_rv=int(CKR_OK), init_rv=int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_uad_expected_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, destroy_rv=int(CKR_OK), init_rv=int(CKR_KEY_HANDLE_INVALID))


def test_uad_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, destroy_rv=int(CKR_OK), init_rv=int(CKR_DEVICE_ERROR))


def test_uad_destroy_declined_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, destroy_rv=int(CKR_DEVICE_ERROR), init_rv=int(CKR_OK))
