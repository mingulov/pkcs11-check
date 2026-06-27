"""Runtime classification meta-tests for security/test_api_security policy sites.

:241 wrap-decrypt oracle: the target key is created non-extractable/sensitive
(claimed protected). If the wrap-decrypt oracle yields its key material the
protection is violated -> fail; if the module declines the dangerous
combination or the target was not protected -> xfail/return.

:363 copy extractable-escalation: claimed = original reads CKA_EXTRACTABLE=False;
violated = the copy exposes CKA_VALUE -> fail; not claimed -> xfail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKA_EXTRACTABLE,
    CKA_VALUE,
)
from pkcs11_check.testcases.security import test_api_security as tas


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)


# --- :241 wrap-decrypt oracle ---------------------------------------------


def _run_oracle(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, extracted: bool) -> None:
    monkeypatch.setattr(tas, "_skip_unless_mechanism", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "require_operational_aes_keygen", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "_raw_gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tas, "_gen_api_security_aes_key", lambda *_a, **_k: 2)
    monkeypatch.setattr(tas, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "wrap_key", lambda *_a, **_k: b"wrapped")
    monkeypatch.setattr(tas, "decrypt_single", lambda *_a, **_k: b"\x11" * 16 if extracted else b"")
    monkeypatch.setattr(
        tas,
        "read_attributes",
        lambda *_a, **_k: {CKA_EXTRACTABLE: False} if claimed else {CKA_EXTRACTABLE: True},
    )
    tas.TestWrapDecryptOracle().test_wrap_decrypt_combination_prevented(_session())


def test_oracle_claimed_extracted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_oracle(monkeypatch, claimed=True, extracted=True)
    assert not isinstance(ei.value, XFailed)


def test_oracle_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_oracle(monkeypatch, claimed=False, extracted=True)


def test_oracle_no_extraction_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_oracle(monkeypatch, claimed=True, extracted=False)


# --- :363 copy extractable-escalation -------------------------------------


def _run_copy(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, exposed: bool) -> None:
    monkeypatch.setattr(tas, "_skip_unless_mechanism", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "require_operational_aes_keygen", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "_gen_api_security_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(tas, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(tas, "copy_object", lambda *_a, **_k: 5)

    def _read(_raw: object, _sh: object, handle: int, attrs: list[int]) -> dict:
        if CKA_EXTRACTABLE in attrs:
            return {CKA_EXTRACTABLE: False} if claimed else {CKA_EXTRACTABLE: True}
        if CKA_VALUE in attrs:
            return {CKA_VALUE: b"\x00" * 16} if exposed else {}
        return {}

    monkeypatch.setattr(tas, "read_attributes", _read)
    tas.TestAttributeLaunderingViaCopy().test_copy_cannot_escalate_extractable(_session())


def test_copy_claimed_exposed_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_copy(monkeypatch, claimed=True, exposed=True)
    assert not isinstance(ei.value, XFailed)


def test_copy_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_copy(monkeypatch, claimed=False, exposed=True)


def test_copy_not_exposed_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_copy(monkeypatch, claimed=True, exposed=False)
