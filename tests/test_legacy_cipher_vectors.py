"""Coverage guardrails for legacy cipher known-answer vectors."""

from __future__ import annotations

from pkcs11_check.raw.types_std import CKM_CAST128_CBC, CKM_CAST128_ECB
from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY
from pkcs11_check.testcases.mechanism_vectors import load_positive_vectors


def test_cast128_encrypt_mechanisms_have_kat_vectors() -> None:
    expected = {
        int(CKM_CAST128_ECB): "cast128_ecb.json",
        int(CKM_CAST128_CBC): "cast128_cbc.json",
    }

    for mech_id, vector_file in expected.items():
        config = MECHANISM_REGISTRY[mech_id]
        assert config.vector_file == vector_file

        vectors = load_positive_vectors(vector_file)
        assert vectors, f"{vector_file} must contain positive vectors"
        for vec in vectors:
            assert vec["type"] == "positive"
            assert vec["key_hex"]
            assert vec["plaintext_hex"]
            assert vec["ciphertext_hex"]
