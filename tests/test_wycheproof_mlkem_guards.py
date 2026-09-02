"""Regression tests for Wycheproof ML-KEM decapsulation result routing."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_NOT_SUPPORTED,
)
from pkcs11_check.testcases.wycheproof import test_wycheproof_mlkem as mlkem


class _MlKemSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "ML_KEM"


def _valid_vector(*, result: str = "valid", flags: list[str] | None = None) -> dict[str, Any]:
    return {
        "tcId": 1,
        "result": result,
        "flags": flags or [],
        "dk": "00",
        "c": "00",
        "K": "aa",
        "_parameter_set": 512,
        "_group": {},
    }


def _wire_success(monkeypatch: pytest.MonkeyPatch, *, value: bytes = b"\xaa") -> None:
    monkeypatch.setattr(mlkem, "import_pqc_private_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(mlkem, "decapsulate_key", lambda *_a, **_k: 2)
    monkeypatch.setattr(mlkem, "read_attributes", lambda *_a, **_k: {CKA_VALUE: value})
    monkeypatch.setattr(mlkem, "destroy_quietly", lambda *_a, **_k: None)


def test_mlkem_valid_vector_compares_uppercase_k_readback(monkeypatch: pytest.MonkeyPatch) -> None:
    """The corpus's ``K`` field is the expected derived secret, not optional metadata."""
    _wire_success(monkeypatch)

    mlkem.test_mlkem_decaps("mlkem_512:tc1-valid", _valid_vector(), _MlKemSession())


def test_mlkem_wrong_shared_secret_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _wire_success(monkeypatch, value=b"\xbb")

    with pytest.raises(pytest.fail.Exception, match="does not match known answer"):
        mlkem.test_mlkem_decaps("mlkem_512:tc1-valid", _valid_vector(), _MlKemSession())


def test_mlkem_invalid_ciphertext_does_not_hide_valid_key_import_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IncorrectCiphertextLength has a valid dk, so import refusal is xfail evidence."""
    vec = _valid_vector(result="invalid", flags=["IncorrectCiphertextLength"])

    def reject_import(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("valid dk import rejected", int(CKR_ATTRIBUTE_VALUE_INVALID))

    monkeypatch.setattr(mlkem, "import_pqc_private_key", reject_import)
    monkeypatch.setattr(mlkem, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(pytest.xfail.Exception, match="raw ML-KEM private-key import"):
        mlkem.test_mlkem_decaps("mlkem_512:tc1-invalid", vec, _MlKemSession())


def test_mlkem_invalid_key_import_expected_reject_is_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    vec = _valid_vector(result="invalid", flags=["InvalidDecapsulationKey"])

    def reject_import(*_a: Any, **_k: Any) -> int:
        raise CkrAssertionError("invalid key", int(CKR_ATTRIBUTE_VALUE_INVALID))

    monkeypatch.setattr(mlkem, "import_pqc_private_key", reject_import)
    monkeypatch.setattr(mlkem, "destroy_quietly", lambda *_a, **_k: None)
    classification.clear()

    mlkem.test_mlkem_decaps("mlkem_512:tc1-invalid", vec, _MlKemSession())

    assert classification.get_records() == []


def test_mlkem_invalid_ciphertext_success_is_accepted_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR_OK on an invalid ciphertext remains a crypto finding."""
    vec = _valid_vector(result="invalid", flags=["ModifiedCiphertext"])
    _wire_success(monkeypatch)
    classification.clear()

    with pytest.raises(pytest.fail.Exception, match="Invalid ML-KEM decapsulation"):
        mlkem.test_mlkem_decaps("mlkem_512:tc1-invalid", vec, _MlKemSession())

    assert classification.get_records()[-1].reason == "accepted_invalid"


def test_mlkem_invalid_ciphertext_expected_reject_is_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    vec = _valid_vector(result="invalid", flags=["IncorrectCiphertextLength"])
    monkeypatch.setattr(mlkem, "import_pqc_private_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        mlkem,
        "decapsulate_key",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("invalid ciphertext length", int(CKR_ENCRYPTED_DATA_LEN_RANGE))
        ),
    )
    monkeypatch.setattr(mlkem, "destroy_quietly", lambda *_a, **_k: None)
    classification.clear()

    mlkem.test_mlkem_decaps("mlkem_512:tc1-invalid", vec, _MlKemSession())

    assert classification.get_records() == []


def test_mlkem_invalid_ciphertext_broad_unavailable_reject_is_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An advertised-but-unusable decapsulation cannot pass an invalid vector."""
    vec = _valid_vector(result="invalid", flags=["ModifiedCiphertext"])
    monkeypatch.setattr(mlkem, "import_pqc_private_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        mlkem,
        "decapsulate_key",
        lambda *_a, **_k: (_ for _ in ()).throw(
            CkrAssertionError("decapsulation unavailable", int(CKR_FUNCTION_NOT_SUPPORTED))
        ),
    )
    monkeypatch.setattr(mlkem, "destroy_quietly", lambda *_a, **_k: None)
    classification.clear()

    with pytest.raises(pytest.xfail.Exception, match="invalid vector reject"):
        mlkem.test_mlkem_decaps("mlkem_512:tc1-invalid", vec, _MlKemSession())

    assert classification.get_records()[-1].reason == "nonspec_reject"


def test_mlkem_invalid_ciphertext_plain_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    vec = _valid_vector(result="invalid", flags=["IncorrectCiphertextLength"])
    monkeypatch.setattr(mlkem, "import_pqc_private_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        mlkem,
        "decapsulate_key",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("binding bug")),
    )
    monkeypatch.setattr(mlkem, "destroy_quietly", lambda *_a, **_k: None)

    with pytest.raises(AssertionError, match="binding bug"):
        mlkem.test_mlkem_decaps("mlkem_512:tc1-invalid", vec, _MlKemSession())


def test_mlkem_invalid_ciphertext_undefined_rv_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    vec = _valid_vector(result="invalid", flags=["IncorrectCiphertextLength"])
    monkeypatch.setattr(mlkem, "import_pqc_private_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        mlkem,
        "decapsulate_key",
        lambda *_a, **_k: (_ for _ in ()).throw(CkrAssertionError("undefined", 0x7FFFFFFF)),
    )
    monkeypatch.setattr(mlkem, "destroy_quietly", lambda *_a, **_k: None)
    classification.clear()

    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        mlkem.test_mlkem_decaps("mlkem_512:tc1-invalid", vec, _MlKemSession())
