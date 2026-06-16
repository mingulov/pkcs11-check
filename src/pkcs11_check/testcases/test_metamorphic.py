"""Metamorphic tests - verify invariants that must hold across operations.

These tests check mathematical/logical invariants rather than specific values:
- Encrypt then decrypt = original plaintext (round-trip)
- Sign then verify = True
- Wrap then unwrap = same key material
- Copy behaves identically to original
- Multiple encryptions of same data with same key produce same result (ECB)
- Different keys produce different results
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    copy_object,
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    generate_random,
    read_attributes,
    sign_single,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKK_AES,
    CKM_AES_CBC_PAD,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA512,
    CKM_SHA_1,
    CKO_SECRET_KEY,
    CKR_FUNCTION_NOT_SUPPORTED,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import (
    assert_correct,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    import_secret_key_negotiated,
    is_known_error,
    skip_unless_mechanism,
    unwrap_key_for_mechanism_roundtrip,
)

pytestmark = pytest.mark.metamorphic


class TestRoundTripInvariants:
    """Operation followed by its inverse must produce the original."""

    @pytest.mark.parametrize("key_size", [128, 192, 256])
    def test_aes_ecb_roundtrip(self, p11_raw_session: Any, key_size: int) -> None:
        """AES-ECB: decrypt(encrypt(pt)) == pt for all key sizes."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, key_size, purpose="AES-ECB metamorphic roundtrip")
        try:
            plaintext = b"roundtrip_verify"  # exactly 16 bytes
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="AES_ECB:decrypt(encrypt(pt)) roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_AES_ECB",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_cbc_roundtrip(self, p11_raw_session: Any) -> None:
        """AES-CBC: decrypt(encrypt(pt, iv), iv) == pt."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, purpose="AES-CBC metamorphic roundtrip")
        try:
            iv = generate_random(rs.raw, rs.sh, 16)
            plaintext = b"cbc roundtrip!!!"  # 16 bytes
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="AES_CBC_PAD:decrypt(encrypt(pt)) roundtrip",
                operation="C_Decrypt",
                mechanism="CKM_AES_CBC_PAD",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """RSA: verify(sign(data)) == True."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            data = b"sign-verify roundtrip"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            assert verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig) is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_wrong_data_verify_fails(self, p11_raw_session: Any) -> None:
        """RSA: verify(sign(data), different_data) must fail."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"original data")
            try:
                result = verify_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_SHA256_RSA_PKCS,
                    b"tampered data",
                    sig,
                )
            except AssertionError as exc:
                signature_rejected_or_xfail(exc, "RSA wrong-data metamorphic verification")
                return
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_wrap_unwrap_preserves_material(self, p11_raw_session: Any, p11_config: Any) -> None:
        """wrap(key) then unwrap must produce identical key material."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrapping_key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
            },
            purpose="AES key-wrap metamorphic invariant",
        )
        key_bytes = bytes(range(16))
        original = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_TOKEN: False,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )
        try:
            wrapped = wrap_key(rs.raw, rs.sh, wrapping_key, original, CKM_AES_KEY_WRAP)
            unwrapped = unwrap_key_for_mechanism_roundtrip(
                rs,
                p11_config,
                unwrapping_key=wrapping_key,
                wrapped_key=wrapped,
                mechanism=CKM_AES_KEY_WRAP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                },
                purpose="AES-KEY-WRAP metamorphic roundtrip",
            )
            try:
                unwrapped_attrs = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])
                assert_correct(
                    actual=unwrapped_attrs[CKA_VALUE],
                    expected=key_bytes,
                    label="AES_KEY_WRAP:wrap/unwrap preserves key material",
                    operation="C_UnwrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
            destroy_quietly(rs.raw, rs.sh, original)


class TestDeterminismInvariants:
    """Operations that must be deterministic should give same result."""

    def test_ecb_deterministic(self, p11_raw_session: Any) -> None:
        """AES-ECB with same key+plaintext must produce same ciphertext."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256, purpose="AES-ECB determinism invariant")
        try:
            plaintext = b"determinism test"
            ct1 = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            ct2 = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            assert ct1 == ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_deterministic(self, p11_raw_session: Any) -> None:
        """SHA-256 of same data must always be the same."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256")
        data = b"hash determinism test"
        d1 = digest_single(rs.raw, rs.sh, CKM_SHA256, data)
        d2 = digest_single(rs.raw, rs.sh, CKM_SHA256, data)
        assert d1 == d2

    def test_different_keys_different_ciphertext(self, p11_raw_session: Any) -> None:
        """AES-ECB with different keys must produce different ciphertext."""
        rs = p11_raw_session
        k1 = gen_aes_key_or_xfail(rs, 256, purpose="different-key invariant")
        k2 = gen_aes_key_or_xfail(rs, 256, purpose="different-key invariant")
        try:
            plaintext = b"different keys!!"
            ct1 = encrypt_single(rs.raw, rs.sh, k1, CKM_AES_ECB, plaintext)
            ct2 = encrypt_single(rs.raw, rs.sh, k2, CKM_AES_ECB, plaintext)
            if ct1 == ct2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="AES_ECB:distinct keys produce identical ciphertext",
                    operation="C_Encrypt",
                    mechanism="CKM_AES_ECB",
                    summary=(
                        "AES_ECB: two different keys produced identical ciphertext for the "
                        "same plaintext -- encryption ignores the key (crypto break)"
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
            destroy_quietly(rs.raw, rs.sh, k2)


class TestCopyEquivalence:
    """A copied key must behave identically to the original."""

    def test_copy_produces_same_ciphertext(self, p11_raw_session: Any) -> None:
        """Encrypting with original and copy produces identical output."""
        rs = p11_raw_session
        original = gen_aes_key_or_xfail(rs, 256, purpose="copy equivalence invariant")
        try:
            try:
                copy = copy_object(
                    rs.raw,
                    rs.sh,
                    original,
                    {CKA_LABEL: "copy-equiv"},
                )
            except AssertionError as exc:
                if is_known_error(exc, {CKR_FUNCTION_NOT_SUPPORTED}):
                    pytest.skip("C_CopyObject not supported")
                raise

            try:
                plaintext = b"copy equivalence"
                ct_orig = encrypt_single(rs.raw, rs.sh, original, CKM_AES_ECB, plaintext)
                ct_copy = encrypt_single(rs.raw, rs.sh, copy, CKM_AES_ECB, plaintext)
                assert ct_orig == ct_copy
            finally:
                destroy_quietly(rs.raw, rs.sh, copy)
        finally:
            destroy_quietly(rs.raw, rs.sh, original)

    def test_copy_can_decrypt_original(self, p11_raw_session: Any) -> None:
        """Copy can decrypt what original encrypted."""
        rs = p11_raw_session
        original = gen_aes_key_or_xfail(rs, 256, purpose="copy decrypt invariant")
        try:
            try:
                copy = copy_object(
                    rs.raw,
                    rs.sh,
                    original,
                    {CKA_LABEL: "copy-decrypt"},
                )
            except AssertionError as exc:
                if is_known_error(exc, {CKR_FUNCTION_NOT_SUPPORTED}):
                    pytest.skip("C_CopyObject not supported")
                raise

            try:
                plaintext = b"cross-decrypt!!!"
                ct = encrypt_single(rs.raw, rs.sh, original, CKM_AES_ECB, plaintext)
                pt = decrypt_single(rs.raw, rs.sh, copy, CKM_AES_ECB, ct)
                assert_correct(
                    actual=pt,
                    expected=plaintext,
                    label="AES_ECB:copy decrypts original's ciphertext",
                    operation="C_Decrypt",
                    mechanism="CKM_AES_ECB",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copy)
        finally:
            destroy_quietly(rs.raw, rs.sh, original)


class TestDigestProperties:
    """Mathematical properties that hash functions must satisfy."""

    def test_different_inputs_different_outputs(self, p11_raw_session: Any) -> None:
        """Different inputs must produce different digests (collision resistance)."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256")
        digests = set()
        for i in range(100):
            d = digest_single(rs.raw, rs.sh, CKM_SHA256, f"input {i}".encode())
            digests.add(d)
        assert len(digests) == 100

    def test_output_length_consistent(self, p11_raw_session: Any) -> None:
        """SHA-256 always produces 32 bytes regardless of input size."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256")
        for size in [0, 1, 16, 64, 1024, 10000]:
            d = digest_single(rs.raw, rs.sh, CKM_SHA256, b"X" * size)
            assert len(d) == 32

    def test_sha_family_different_outputs(self, p11_raw_session: Any) -> None:
        """Different SHA variants produce different outputs for same input."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA_1")
        skip_unless_mechanism(rs, "SHA256")
        skip_unless_mechanism(rs, "SHA512")
        data = b"sha family test"
        sha1 = digest_single(rs.raw, rs.sh, CKM_SHA_1, data)
        sha256 = digest_single(rs.raw, rs.sh, CKM_SHA256, data)
        sha512 = digest_single(rs.raw, rs.sh, CKM_SHA512, data)
        assert sha1 != sha256
        assert sha256 != sha512
        assert sha1 != sha512
