"""Mechanism-driven KEM (encapsulate/decapsulate) tests."""
from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong
from pkcs11_check.raw.recipes import (
    decapsulate_key,
    decrypt_single,
    destroy_quietly,
    encapsulate_key,
    encrypt_single,
    gen_keypair,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECAPSULATE,
    CKA_DECRYPT,
    CKA_ENCAPSULATE,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_AES,
    CKM_AES_ECB,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKO_SECRET_KEY,
    CKP_ML_KEM_768,
)

pytestmark = [pytest.mark.mechanism_coverage, pytest.mark.kem]


def _ml_kem_keypair(rs: Any) -> tuple[int, int]:
    """Generate an ML-KEM-768 keypair. Returns (pub, priv)."""
    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_ML_KEM_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768)],
        priv_base=[],
        public_attrs={CKA_TOKEN: False, CKA_ENCAPSULATE: True},
        private_attrs={CKA_TOKEN: False, CKA_DECAPSULATE: True},
        pub_skip={CKA_PARAMETER_SET},
    )


_AES_DERIVED_ATTRS: dict[int, Any] = {
    CKA_KEY_TYPE: CKK_AES,
    CKA_VALUE_LEN: 32,
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_TOKEN: False,
    CKA_ENCRYPT: True,
    CKA_DECRYPT: True,
}


class TestMechKEM:
    """KEM encapsulate/decapsulate tests."""

    def test_ml_kem_roundtrip(self, p11_raw_session: Any) -> None:
        """ML-KEM encapsulate -> decapsulate produces same shared secret."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        pub, priv = _ml_kem_keypair(rs)
        try:
            enc_key, ct = encapsulate_key(
                rs.raw, rs.sh, pub, CKM_ML_KEM, attrs=_AES_DERIVED_ATTRS
            )
            try:
                dec_key = decapsulate_key(
                    rs.raw, rs.sh, priv, CKM_ML_KEM, ct, attrs=_AES_DERIVED_ATTRS
                )
                try:
                    # Verify both keys produce the same encryption result
                    plaintext = b"KEM roundtrip test data!12345678"
                    ciphertext = encrypt_single(
                        rs.raw, rs.sh, enc_key, CKM_AES_ECB, plaintext
                    )
                    recovered = decrypt_single(
                        rs.raw, rs.sh, dec_key, CKM_AES_ECB, ciphertext
                    )
                    assert recovered == plaintext, (
                        "Decapsulated key differs from encapsulated key"
                    )
                finally:
                    destroy_quietly(rs.raw, rs.sh, dec_key)
            finally:
                destroy_quietly(rs.raw, rs.sh, enc_key)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ml_kem_wrong_key_fails(self, p11_raw_session: Any) -> None:
        """Decapsulate with wrong private key produces a different shared secret.

        ML-KEM uses implicit rejection (FIPS 203 Section 6.3): decapsulating a
        ciphertext with the wrong private key always succeeds but returns a
        pseudorandom key derived from a rejection value.  The two derived keys
        are therefore different, which is confirmed by showing that ciphertext
        encrypted under enc_key cannot be decrypted correctly by dec_key_wrong.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM"):
            pytest.skip("ML_KEM not supported")
        pub1, priv1 = _ml_kem_keypair(rs)
        pub2, priv2 = _ml_kem_keypair(rs)
        try:
            enc_key, ct = encapsulate_key(
                rs.raw, rs.sh, pub1, CKM_ML_KEM, attrs=_AES_DERIVED_ATTRS
            )
            try:
                # Decapsulate with wrong private key — produces a different derived key
                dec_key_wrong = decapsulate_key(
                    rs.raw, rs.sh, priv2, CKM_ML_KEM, ct, attrs=_AES_DERIVED_ATTRS
                )
                try:
                    plaintext = b"KEM wrong-key test data!12345678"
                    ciphertext = encrypt_single(
                        rs.raw, rs.sh, enc_key, CKM_AES_ECB, plaintext
                    )
                    # Decrypting with the wrong-key-derived key should yield garbage
                    wrong_plaintext = decrypt_single(
                        rs.raw, rs.sh, dec_key_wrong, CKM_AES_ECB, ciphertext
                    )
                    assert wrong_plaintext != plaintext, (
                        "Wrong private key unexpectedly produced the same shared secret"
                    )
                finally:
                    destroy_quietly(rs.raw, rs.sh, dec_key_wrong)
            finally:
                destroy_quietly(rs.raw, rs.sh, enc_key)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub1)
            destroy_quietly(rs.raw, rs.sh, priv1)
            destroy_quietly(rs.raw, rs.sh, pub2)
            destroy_quietly(rs.raw, rs.sh, priv2)
