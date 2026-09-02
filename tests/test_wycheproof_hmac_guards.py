"""Regression tests for Wycheproof HMAC invalid-vector classification.

Phase-2 V2: HMAC invalid vectors were exercised as *produce* (C_Sign + compare)
operations, so a fresh correct tag never matched the modified expected tag and
rejection was never tested. Re-framed to verify-and-reject: a module that
verifies an invalid (forged) HMAC tag as valid is a crypto-correctness break
(crypto -> fail). A valid MAC that the module rejects (e.g. an unsupported
truncated tag length) is an honest deviation -> xfail.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKK_GENERIC_SECRET,
    CKK_SHA_1_HMAC,
    CKM_SHA_1_HMAC,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases.wycheproof import test_wycheproof_hmac as hmac


def _first(result: str) -> tuple[str, dict[str, Any]]:
    hit = next(((cid, v) for cid, v in hmac._ALL_HMAC_VECTORS if v["result"] == result), None)
    if hit is None:
        pytest.skip(
            "Wycheproof HMAC vectors not available (run `pkcs11-check fetch-data wycheproof`)"
        )
    return hit


class _HmacSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "SHA_1_HMAC"


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


@pytest.fixture(autouse=True)
def _clear_hmac_state() -> None:
    hmac._UNSUPPORTED_HMAC_KEYS.clear()
    classification.clear()
    yield
    hmac._UNSUPPORTED_HMAC_KEYS.clear()
    classification.clear()


def _vector(result: str) -> dict[str, Any]:
    return {
        "key": "00" * 16,
        "msg": "01",
        "tag": "02" * 20,
        "result": result,
        "_key_type": CKK_SHA_1_HMAC,
        "_mechanism": CKM_SHA_1_HMAC,
        "_fallback_type": CKK_GENERIC_SECRET,
    }


def _raise_ckr(rv: int) -> Any:
    def _raise(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("synthetic CK_RV", int(rv))

    return _raise


def test_hmac_invalid_key_import_rejection_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid vector cannot turn a rejected subject-key setup into a pass."""
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _raise_ckr(CKR_KEY_SIZE_RANGE))

    with pytest.raises(XFailed):
        hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)

    records = classification.serialize(classification.get_records())
    assert len(records) == 1
    assert records[0]["reason"] == "not_operational"
    assert records[0]["actual_ckr"] == "CKR_KEY_SIZE_RANGE"


def test_hmac_non_ckr_key_import_failure_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Python/setup failure is not a provider capability deviation."""
    vec = _vector("invalid")

    def _raise_non_ckr(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("synthetic setup failure")

    monkeypatch.setattr(hmac, "import_secret_key", _raise_non_ckr)

    with pytest.raises(AssertionError, match="synthetic setup failure"):
        hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)


def test_hmac_invalid_expected_signature_reject_is_a_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", _raise_ckr(CKR_SIGNATURE_INVALID))
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)
    assert classification.get_records() == []


@pytest.mark.parametrize("rv", [CKR_DEVICE_ERROR, CKR_GENERAL_ERROR, CKR_VENDOR_DEFINED + 1])
def test_hmac_invalid_noncanonical_signature_reject_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", _raise_ckr(rv))
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(XFailed):
        hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)

    records = classification.serialize(classification.get_records())
    assert len(records) == 1
    assert records[0]["reason"] == "nonspec_reject"


def test_hmac_invalid_undefined_signature_reject_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", _raise_ckr(0x7FFFFFFF))
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)


def test_hmac_invalid_non_ckr_signature_failure_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(
        hmac,
        "verify_single",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("synthetic verify failure")),
    )
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError, match="synthetic verify failure"):
        hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)


def test_hmac_invalid_signature_length_reject_is_a_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec = _vector("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", _raise_ckr(CKR_SIGNATURE_LEN_RANGE))
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    hmac.test_hmac_wycheproof(_HmacSession(), "synthetic-invalid", vec)
    assert classification.get_records() == []


def test_hmac_invalid_vector_accepted_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid HMAC tag that verifies must fail (forged tag accepted)."""
    vec_id, vec = _first("invalid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    supplied_tags: list[bytes] = []

    def _verify(*args: Any, **_kwargs: Any) -> bool:
        supplied_tags.append(args[-1])
        return True

    monkeypatch.setattr(hmac, "verify_single", _verify)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid tag"):
        hmac.test_hmac_wycheproof(_HmacSession(), vec_id, vec)
    assert supplied_tags == [bytes.fromhex(vec["tag"])]


def test_hmac_valid_vector_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid HMAC vector that verifies passes (no exception)."""
    vec_id, vec = _first("valid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    hmac.test_hmac_wycheproof(_HmacSession(), vec_id, vec)


def test_hmac_valid_vector_rejected_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid HMAC vector the module fails to verify is an honest deviation (xfail)."""
    vec_id, vec = _first("valid")
    monkeypatch.setattr(hmac, "import_secret_key", _handle)
    monkeypatch.setattr(hmac, "verify_single", lambda *_a, **_k: False)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.xfail.Exception, match="did not verify a valid HMAC tag"):
        hmac.test_hmac_wycheproof(_HmacSession(), vec_id, vec)
