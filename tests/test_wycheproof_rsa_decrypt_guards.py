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


def test_rsa_pkcs1_invalid_ciphertext_decrypt_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid RSA PKCS#1 v1.5 ciphertext that decrypts must fail (padding oracle break)."""
    vec_id, vec = next(
        (vid, v) for vid, v in rsa_dec._ALL_DECRYPT_VECTORS if v["result"] == "invalid"
    )
    monkeypatch.setattr(rsa_dec, "import_rsa_private_key", _handle)
    monkeypatch.setattr(rsa_dec, "decrypt_single", lambda *_a, **_k: b"\x00recovered")
    monkeypatch.setattr(rsa_dec, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid ciphertext"):
        rsa_dec.test_rsa_pkcs1_decrypt(_RsaSession(), vec_id, vec)


def test_rsa_oaep_invalid_ciphertext_decrypt_success_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid RSA-OAEP ciphertext that decrypts must fail (Manger oracle break)."""
    vec_id, vec = next(
        (vid, v) for vid, v in rsa_oaep._ALL_OAEP_VECTORS if v["result"] == "invalid"
    )
    monkeypatch.setattr(rsa_oaep, "import_rsa_private_key", _handle)
    monkeypatch.setattr(rsa_oaep, "decrypt_single", lambda *_a, **_k: b"\x00recovered")
    monkeypatch.setattr(rsa_oaep, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid ciphertext"):
        rsa_oaep.test_rsa_oaep(_RsaSession(), vec_id, vec)
