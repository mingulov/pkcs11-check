"""Runtime classification meta-tests for security/test_tookan Type-B sites.

:203 copy extractable-escalation: claimed = original reads CKA_EXTRACTABLE=False,
violated = the copy reads CKA_EXTRACTABLE=True -> fail; not claimed -> xfail.

:268 wrap-decrypt extraction: the target is created non-extractable/sensitive;
claimed = it reads CKA_EXTRACTABLE=False, violated = the wrap-decrypt oracle
yields its key material -> fail; not claimed/no extraction -> xfail/pass.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EXTRACTABLE,
    CKR_ATTRIBUTE_READ_ONLY,
)
from pkcs11_check.testcases.security import test_tookan as tt


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)


# --- :203 copy escalation -------------------------------------------------


def _run_copy(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, escalated: bool) -> None:
    # The setup key is generated via the canonical gen_aes_key_or_xfail helper,
    # which lazily imports gen_aes_key from raw.recipes -- patch there.
    monkeypatch.setattr(raw_recipes, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tt, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tt, "copy_object", lambda *_a, **_k: 5)

    def _read(_raw: object, _sh: object, handle: int, attrs: list[int]) -> dict:
        # handle 1 = original, 5 = copy
        if handle == 5:
            return {CKA_EXTRACTABLE: True if escalated else False}
        return {CKA_EXTRACTABLE: False if claimed else True}

    monkeypatch.setattr(tt, "read_attributes", _read)
    tt.TestSensitivePreservation().test_extractable_cannot_escalate_on_copy(_session())


def test_copy_claimed_escalated_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_copy(monkeypatch, claimed=True, escalated=True)
    assert not isinstance(ei.value, XFailed)


def test_copy_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_copy(monkeypatch, claimed=False, escalated=True)


def test_copy_not_escalated_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_copy(monkeypatch, claimed=True, escalated=False)


def test_copy_rejected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tt, "destroy_quietly", lambda *_a, **_k: None)

    def _copy_reject(*_a: object, **_k: object) -> int:
        raise CkrAssertionError("rv", int(CKR_ATTRIBUTE_READ_ONLY))

    monkeypatch.setattr(tt, "copy_object", _copy_reject)
    monkeypatch.setattr(tt, "read_attributes", lambda *_a, **_k: {CKA_EXTRACTABLE: False})
    tt.TestSensitivePreservation().test_extractable_cannot_escalate_on_copy(_session())


# --- :268 wrap-decrypt extraction -----------------------------------------


def _run_oracle(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, extracted: bool) -> None:
    monkeypatch.setattr(tt, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tt, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tt, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(
        tt, "read_attributes", lambda *_a, **_k: {CKA_EXTRACTABLE: False if claimed else True}
    )
    monkeypatch.setattr(tt, "decrypt_single", lambda *_a, **_k: b"\x22" * 16 if extracted else b"")
    tt.TestWrapExtraction().test_wrap_decrypt_extraction_attempt(_session())


def test_oracle_claimed_extracted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_oracle(monkeypatch, claimed=True, extracted=True)
    assert not isinstance(ei.value, XFailed)


def test_oracle_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_oracle(monkeypatch, claimed=False, extracted=True)


def test_oracle_no_extraction_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_oracle(monkeypatch, claimed=True, extracted=False)
