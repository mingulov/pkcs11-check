"""Regression tests for Wycheproof PBES2 runtime-result classification."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_GENERAL_ERROR
from pkcs11_check.testcases.wycheproof import test_wycheproof_pbes2, test_wycheproof_pbkdf2


class _Pbes2Session:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name in ("PKCS5_PBKD2", "AES_CBC_PAD")


def _invalid_vec() -> dict[str, Any]:
    return {
        "result": "invalid",
        "password": "70617373",
        "salt": "00112233",
        "iterationCount": 1,
        "iv": "00" * 16,
        "ct": "11" * 16,
        "msg": "2a" * 16,
        "_prf": test_wycheproof_pbes2._PRF_MAP["hmacsha1"],
        "_prf_name": "hmacsha1",
        "_key_bits": 128,
        "_file": "synthetic",
    }


@pytest.mark.parametrize(
    ("rv", "operation"),
    [
        (CKR_DEVICE_ERROR, "key derivation"),
        (CKR_GENERAL_ERROR, "decrypt"),
    ],
)
def test_pbes2_valid_runtime_rejects_are_xfail(rv: int, operation: str) -> None:
    """Advertised PBES2 setup/use rejects are findings, not raw failures."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match=f"PBES2 {operation}"):
        test_wycheproof_pbes2._xfail_if_pbes2_runtime_reject(
            exc,
            "pbes2_hmacsha1_aes_128_test.json:tc1-valid",
            operation,
        )


def test_pbes2_invalid_vector_decrypt_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid PBES2 vector that decrypts must fail (forged ciphertext accepted).

    Structural guard (Phase 2 Task 2j): the bundled Wycheproof PBES2 corpus has
    no invalid vectors today, so this drives a synthetic invalid vector to lock
    in the accept->fail branch.
    """
    vec = _invalid_vec()
    monkeypatch.setattr(test_wycheproof_pbes2, "_generate_key_with_mech", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        test_wycheproof_pbes2, "decrypt_single", lambda *_a, **_k: bytes.fromhex(vec["msg"])
    )
    monkeypatch.setattr(test_wycheproof_pbes2, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid ciphertext"):
        test_wycheproof_pbes2.test_pbes2_decrypt(_Pbes2Session(), "synthetic:tc1-invalid", vec)


def test_pbkdf2_valid_runtime_rejects_are_xfail() -> None:
    """Advertised PBKDF2 vector rejects are findings, not raw failures."""
    exc = CkrAssertionError("Unexpected CK_RV", int(CKR_DEVICE_ERROR))

    with pytest.raises(pytest.xfail.Exception, match="PBKDF2 key derivation"):
        test_wycheproof_pbkdf2._xfail_if_pbkdf2_runtime_reject(
            exc,
            "pbkdf2_hmacsha1_test.json:tc1-valid",
        )
