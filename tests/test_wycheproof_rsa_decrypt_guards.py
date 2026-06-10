"""Behavioral guards for Wycheproof RSA decrypt / RSA-OAEP invalid-vector rejection.

Phase-2 V2/Task 2k (investigate): both RSA PKCS#1 v1.5 decrypt and RSA-OAEP
already decrypt the supplied ciphertext and fail on accept of an invalid
(Bleichenbacher/Manger oracle surface) vector. These guards lock in that
accept->fail behavior behaviorally, not just by source-string hygiene.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.wycheproof import (
    test_wycheproof_rsa_decrypt as rsa_dec,
)
from pkcs11_check.testcases.wycheproof import (
    test_wycheproof_rsa_oaep as rsa_oaep,
)


def _handle(*_args: Any, **_kwargs: Any) -> int:
    return 1


class _RsaSession:
    raw = object()
    sh = 1

    def has_mechanism(self, name: str) -> bool:
        return name == "RSA_PKCS_OAEP"


def _first_invalid_pkcs1() -> tuple[str, dict[str, Any]]:
    hit = next(
        ((vid, v) for vid, v in rsa_dec._ALL_DECRYPT_VECTORS if v["result"] == "invalid"), None
    )
    if hit is None:
        pytest.skip("Wycheproof RSA decrypt vectors not available (run `fetch-data wycheproof`)")
    return hit


def test_rsa_pkcs1_invalid_padding_bypass_returns_real_msg_is_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The REAL Bleichenbacher-class break: a module that returns the actual
    target message for an invalid-padding ciphertext bypassed the padding
    check -> fail. (Each invalid Wycheproof vector carries the target msg.)"""
    vec_id, vec = _first_invalid_pkcs1()
    monkeypatch.setattr(rsa_dec, "import_rsa_private_key", _handle)
    monkeypatch.setattr(rsa_dec, "decrypt_single", lambda *_a, **_k: bytes.fromhex(vec["msg"]))
    monkeypatch.setattr(rsa_dec, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="recovered the target message"):
        rsa_dec.test_rsa_pkcs1_decrypt(_RsaSession(), vec_id, vec)


def test_rsa_pkcs1_invalid_synthetic_plaintext_is_secure_not_a_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Returning a SYNTHETIC plaintext (!= target msg) for invalid padding is the
    recommended anti-Bleichenbacher mitigation (RFC 8017 §7.2.2 / Marvin 2023),
    NOT a finding. Every real provider (softhsm2/kryoptic/NSS) does this; the old
    'any decrypt-success -> fail' guard wrongly penalized the secure behavior."""
    vec_id, vec = _first_invalid_pkcs1()
    synthetic = b"\x00" + b"\xa5" * 31  # != bytes.fromhex(vec["msg"])
    assert synthetic != bytes.fromhex(vec["msg"])
    monkeypatch.setattr(rsa_dec, "import_rsa_private_key", _handle)
    monkeypatch.setattr(rsa_dec, "decrypt_single", lambda *_a, **_k: synthetic)
    monkeypatch.setattr(rsa_dec, "destroy_quietly", lambda *_a: None)

    # No exception: secure non-rejection is accepted.
    rsa_dec.test_rsa_pkcs1_decrypt(_RsaSession(), vec_id, vec)


def test_rsa_pkcs1_invalid_clean_rejection_is_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A constant-time clean rejection of invalid padding is also acceptable."""
    from pkcs11_check.raw.rv import CkrAssertionError
    from pkcs11_check.raw.types_std import CKR_ENCRYPTED_DATA_INVALID

    vec_id, vec = _first_invalid_pkcs1()
    monkeypatch.setattr(rsa_dec, "import_rsa_private_key", _handle)

    def _reject(*_a: Any, **_k: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID", int(CKR_ENCRYPTED_DATA_INVALID)
        )

    monkeypatch.setattr(rsa_dec, "decrypt_single", _reject)
    monkeypatch.setattr(rsa_dec, "destroy_quietly", lambda *_a: None)

    rsa_dec.test_rsa_pkcs1_decrypt(_RsaSession(), vec_id, vec)  # no exception


def test_rsa_oaep_invalid_ciphertext_decrypt_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid RSA-OAEP ciphertext that decrypts must fail (Manger oracle break)."""
    hit = next(
        ((vid, v) for vid, v in rsa_oaep._ALL_OAEP_VECTORS if v["result"] == "invalid"), None
    )
    if hit is None:
        pytest.skip(
            "Wycheproof RSA-OAEP vectors not available (run `pkcs11-check fetch-data wycheproof`)"
        )
    vec_id, vec = hit
    monkeypatch.setattr(rsa_oaep, "import_rsa_private_key_negotiated", _handle)
    monkeypatch.setattr(rsa_oaep, "decrypt_single", lambda *_a, **_k: b"\x00recovered")
    monkeypatch.setattr(rsa_oaep, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid ciphertext"):
        rsa_oaep.test_rsa_oaep(_RsaSession(), vec_id, vec)
