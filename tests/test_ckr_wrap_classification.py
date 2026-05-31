"""Classification meta-tests for ckr/test_ckr_wrap non-extractable wrap (Phase 6 C).

Type-B: a module that claims CKA_EXTRACTABLE=False then wraps (exports) the key
is a self-contradiction -> fail (was masked by skip). A module that does not
claim the protection -> xfail. A claimed-and-rejected wrap -> pass.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import CKR_OK
from pkcs11_check.testcases.ckr import test_ckr_wrap as tcw


def _session(*, extractable_readback: int, getattr_rv: int, wrap_rv: int) -> SimpleNamespace:
    keys = iter([10, 11])  # wrap_key, target

    def _gen(*_a: object, **_k: object) -> int:
        return next(keys)

    def _getattr(_sh: int, _obj: int, check: object, _n: int) -> int:
        # check[0].pValue points at a CK_BBOOL; write the read-back value.
        bbool = ctypes.cast(check[0].pValue, ctypes.POINTER(ctypes.c_ubyte))
        bbool[0] = extractable_readback
        return int(getattr_rv)

    raw = SimpleNamespace(
        C_GenerateKey=lambda *_a, **_k: None,
        C_GetAttributeValue=_getattr,
        C_WrapKey=lambda *_a, **_k: int(wrap_rv),
    )
    return SimpleNamespace(raw=raw, sh=1, slot_id=0, has_mechanism=lambda _n: True)


def _run(monkeypatch: pytest.MonkeyPatch, **kw: int) -> None:
    monkeypatch.setattr(tcw, "gen_aes_key", lambda *_a, **_k: 10)
    monkeypatch.setattr(tcw, "destroy_quietly", lambda *_a, **_k: None)
    tcw.TestWrapKeyErrors().test_key_not_extractable(_session(**kw), False)


def test_claimed_then_wrapped_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # Module honoured EXTRACTABLE=False (readback 0) but wrap succeeded.
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, extractable_readback=0, getattr_rv=int(CKR_OK), wrap_rv=int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    # Module did NOT honour EXTRACTABLE=False (readback 1) -> honest non-support.
    with pytest.raises(XFailed):
        _run(monkeypatch, extractable_readback=1, getattr_rv=int(CKR_OK), wrap_rv=int(CKR_OK))


def test_claimed_and_rejected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Honoured EXTRACTABLE=False and wrap rejected (CKR_KEY_UNEXTRACTABLE=0x68).
    _run(monkeypatch, extractable_readback=0, getattr_rv=int(CKR_OK), wrap_rv=0x68)
