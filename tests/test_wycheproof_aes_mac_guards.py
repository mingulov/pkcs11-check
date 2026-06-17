"""Regression tests for Wycheproof AES MAC/AEAD/keywrap invalid-vector classification.

Phase-2 V2: these families were exercised as *produce* operations
(sign/encrypt/wrap), so a fresh correct output never matched the modified
expected output and rejection of invalid vectors was never tested. They are
re-framed to the verify/decrypt/unwrap direction; a module that ACCEPTS an
invalid vector is a crypto-correctness break (Type A -> fail).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import test_wycheproof_aes as aes

_NO_VECTORS = "Wycheproof vectors not available (run `pkcs11-check fetch-data wycheproof`)"


def _vec(vecs: list[tuple[str, dict[str, Any]]], vec_id: str) -> dict[str, Any]:
    hit = next((v for cid, v in vecs if cid == vec_id), None)
    if hit is None:
        pytest.skip(_NO_VECTORS)
    return hit


def _first(vecs: list[tuple[str, dict[str, Any]]], result: str) -> tuple[str, dict[str, Any]]:
    hit = next(((cid, v) for cid, v in vecs if v["result"] == result), None)
    if hit is None:
        pytest.skip(_NO_VECTORS)
    return hit


class _AesSession:
    raw = object()
    sh = 1

    def __init__(self, mech: str) -> None:
        self._mech = mech

    def has_mechanism(self, name: str) -> bool:
        return name == self._mech


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


# --- AES-CMAC (Task 2d) ---


def test_cmac_invalid_vector_accepted_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid CMAC tag that verifies must fail (forged-tag accepted)."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(aes, "generate_random", lambda *_a, **_k: b"")

    with pytest.raises(pytest.fail.Exception, match="accepted invalid tag"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


def test_cmac_valid_vector_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CMAC vector that verifies passes (no exception)."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(aes, "generate_random", lambda *_a, **_k: b"")

    aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


def test_cmac_valid_vector_rejected_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CMAC vector that does not verify is a finding (fail)."""
    vec_id, vec = _first(aes._AES_CMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: False)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(aes, "generate_random", lambda *_a, **_k: b"")

    with pytest.raises(pytest.fail.Exception, match="valid CMAC vector"):
        aes.test_aes_cmac(_AesSession("AES_CMAC"), vec_id, vec)


# --- AES-GMAC (Task 2e) ---


def test_gmac_invalid_vector_accepted_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid GMAC tag that verifies must fail (forged-tag accepted)."""
    vec_id, vec = _first(aes._AES_GMAC_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid tag"):
        aes.test_aes_gmac(_AesSession("AES_GMAC"), vec_id, vec)


def test_gmac_valid_vector_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid GMAC vector that verifies passes (no exception)."""
    vec_id, vec = _first(aes._AES_GMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: True)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    aes.test_aes_gmac(_AesSession("AES_GMAC"), vec_id, vec)


def test_gmac_valid_vector_rejected_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid GMAC vector that does not verify is a finding (fail)."""
    vec_id, vec = _first(aes._AES_GMAC_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "verify_single", lambda *_a, **_k: False)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="valid GMAC vector"):
        aes.test_aes_gmac(_AesSession("AES_GMAC"), vec_id, vec)


# --- AES-CCM (Task 2f) ---


def test_ccm_invalid_vector_decrypt_success_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid CCM vector that decrypts must fail (forged ciphertext/tag accepted)."""
    vec_id, vec = _first(aes._AES_CCM_VECTORS, "invalid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "decrypt_single", lambda *_a, **_k: bytes.fromhex(vec["msg"]))
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid ciphertext"):
        aes.test_aes_ccm(_AesSession("AES_CCM"), vec_id, vec)


def test_ccm_valid_vector_decrypts(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CCM vector that decrypts to the expected plaintext passes."""
    vec_id, vec = _first(aes._AES_CCM_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "decrypt_single", lambda *_a, **_k: bytes.fromhex(vec["msg"]))
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    aes.test_aes_ccm(_AesSession("AES_CCM"), vec_id, vec)


def test_ccm_valid_vector_clean_reject_xfails_when_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid CCM vector cleanly rejected (ENCRYPTED_DATA_INVALID) when the
    canonical CCM probe is NOT operational is an advertised-but-not-operational
    deviation -> xfail, not a hard fail. (bouncyhsm CCM: 357 such rejects.)"""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_ENCRYPTED_DATA_INVALID
    from pkcs11_check.testcases._operability import Operability, OperabilityResult

    vec_id, vec = _first(aes._AES_CCM_VECTORS, "valid")
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)

    def _reject(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    monkeypatch.setattr(aes, "decrypt_single", _reject)
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(
        aes,
        "_ccm_operability",
        lambda *_a: OperabilityResult(Operability.NOT_OPERATIONAL, "canonical CCM rejected"),
    )

    with pytest.raises(pytest.xfail.Exception, match="not operational"):
        aes.test_aes_ccm(_AesSession("AES_CCM"), vec_id, vec)


def test_ccm_valid_vector_wrong_plaintext_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid CCM vector that decrypts to the wrong plaintext is a finding (fail)."""
    vec_id = "tc2-valid"
    vec = _vec(aes._AES_CCM_VECTORS, vec_id)
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "decrypt_single", lambda *_a, **_k: b"\xde\xad\xbe\xef")
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="does not match known answer"):
        aes.test_aes_ccm(_AesSession("AES_CCM"), vec_id, vec)


# --- AES-KW (Task 2g) ---


def test_aes_kw_invalid_vector_unwrap_success_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid AES-KW blob that unwraps must fail (forged wrap accepted)."""
    vec_id, vec = _first(aes._AES_WRAP_VECTORS, "invalid")
    msg = bytes.fromhex(vec["msg"])
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "unwrap_key", _handle)
    monkeypatch.setattr(aes, "read_attributes", lambda *_a, **_k: {aes.CKA_VALUE: msg})
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid wrapped key"):
        aes.test_aes_key_wrap(_AesSession("AES_KEY_WRAP"), vec_id, vec)


def test_aes_kw_valid_vector_unwraps(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid AES-KW blob that unwraps to the expected key material passes."""
    vec_id, vec = _first(aes._AES_WRAP_VECTORS, "valid")
    msg = bytes.fromhex(vec["msg"])
    monkeypatch.setattr(aes, "import_secret_key_negotiated", _handle)
    monkeypatch.setattr(aes, "unwrap_key", _handle)
    monkeypatch.setattr(aes, "read_attributes", lambda *_a, **_k: {aes.CKA_VALUE: msg})
    monkeypatch.setattr(aes, "destroy_quietly", lambda *_a: None)

    aes.test_aes_key_wrap(_AesSession("AES_KEY_WRAP"), vec_id, vec)
