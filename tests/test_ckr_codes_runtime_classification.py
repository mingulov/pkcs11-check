"""Runtime classification meta-tests for ckr/test_ckr_codes Type-B + Type-C.

Type B -- test_ckr_attribute_sensitive: claimed=CKA_SENSITIVE=True read-back,
violated=CKA_VALUE actually readable -> fail; not claimed -> xfail.

Type C -- test_ckr_object_handle_invalid_after_destroy: destroy claimed CKR_OK
and the tagged object survives a subsequent read -> fail; honest decline -> xfail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKR_FUNCTION_FAILED,
    CKR_OK,
)
from pkcs11_check.testcases.ckr import test_ckr_codes


def _real_fail(ei: pytest.ExceptionInfo[Failed]) -> None:
    assert not isinstance(ei.value, XFailed)


# --- Type B: sensitive value read -----------------------------------------


def _run_sensitive(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, readable: bool) -> None:
    monkeypatch.setattr(test_ckr_codes, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ckr_codes, "destroy_quietly", lambda *_a, **_k: None)

    def _read(_raw: object, _sh: object, _h: object, attrs: list[int]) -> dict:
        if CKA_SENSITIVE in attrs:
            return {CKA_SENSITIVE: True} if claimed else {CKA_SENSITIVE: False}
        if CKA_VALUE in attrs:
            return {CKA_VALUE: b"\x00" * 32} if readable else {}
        return {}

    monkeypatch.setattr(test_ckr_codes, "read_attributes", _read)
    test_ckr_codes.TestCKRAttributeErrors().test_ckr_attribute_sensitive(
        SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)
    )


def test_sensitive_claimed_readable_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_sensitive(monkeypatch, claimed=True, readable=True)
    _real_fail(ei)


def test_sensitive_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_sensitive(monkeypatch, claimed=False, readable=True)


def test_sensitive_protected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_sensitive(monkeypatch, claimed=True, readable=False)


# --- Type C: use-after-destroy ---------------------------------------------

_TAG = b"ckr-codes-uad"


def _run_uad(monkeypatch: pytest.MonkeyPatch, *, destroy_rv: int, survives: bool) -> None:
    monkeypatch.setattr(test_ckr_codes, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ckr_codes, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_ckr_codes,
        "read_attributes",
        lambda *_a, **_k: {CKA_LABEL: _TAG} if survives else {},
    )
    raw = SimpleNamespace(
        C_DestroyObject=lambda *_a, **_k: int(destroy_rv),
        C_SetAttributeValue=lambda *_a, **_k: int(CKR_OK),
    )
    test_ckr_codes.TestCKRObjectErrors().test_ckr_object_handle_invalid_after_destroy(
        SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)
    )


def test_uad_survives_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_uad(monkeypatch, destroy_rv=int(CKR_OK), survives=True)
    _real_fail(ei)


def test_uad_gone_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_uad(monkeypatch, destroy_rv=int(CKR_OK), survives=False)


def test_uad_destroy_declined_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_uad(monkeypatch, destroy_rv=int(CKR_FUNCTION_FAILED), survives=True)
