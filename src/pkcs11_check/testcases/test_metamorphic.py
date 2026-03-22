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

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.metamorphic


class TestRoundTripInvariants:
    """Operation followed by its inverse must produce the original."""

    @pytest.mark.parametrize("key_size", [128, 192, 256])
    def test_aes_ecb_roundtrip(self, p11_session: Any, key_size: int) -> None:
        """AES-ECB: decrypt(encrypt(pt)) == pt for all key sizes."""
        key = p11_session.generate_key(KeyType.AES, key_size)
        plaintext = b"roundtrip_verify"  # exactly 16 bytes
        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext
        key.destroy()

    def test_aes_cbc_roundtrip(self, p11_session: Any) -> None:
        """AES-CBC: decrypt(encrypt(pt, iv), iv) == pt."""
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        plaintext = b"cbc roundtrip!!!"  # 16 bytes
        ct = key.encrypt(plaintext, mechanism_param=iv)
        pt = key.decrypt(ct, mechanism_param=iv)
        assert pt == plaintext

    def test_rsa_sign_verify_roundtrip(self, p11_session: Any) -> None:
        """RSA: verify(sign(data)) == True."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"sign-verify roundtrip"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS) is True

    def test_rsa_wrong_data_verify_fails(self, p11_session: Any) -> None:
        """RSA: verify(sign(data), different_data) must fail."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        sig = priv.sign(b"original data", mechanism=Mechanism.SHA256_RSA_PKCS)
        try:
            result = pub.verify(b"tampered data", sig, mechanism=Mechanism.SHA256_RSA_PKCS)
            assert result is False
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected - signature invalid

    def test_wrap_unwrap_preserves_material(self, p11_session: Any) -> None:
        """wrap(key) then unwrap must produce identical key material."""
        wrapping_key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.WRAP: True, Attribute.UNWRAP: True},
        )
        key_bytes = bytes(range(16))
        original = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.TOKEN: False,
                Attribute.EXTRACTABLE: True,
                Attribute.SENSITIVE: False,
            }
        )
        wrapped = wrapping_key.wrap_key(original)
        unwrapped = wrapping_key.unwrap_key(
            ObjectClass.SECRET_KEY,
            KeyType.AES,
            wrapped,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        assert unwrapped[Attribute.VALUE] == key_bytes


class TestDeterminismInvariants:
    """Operations that must be deterministic should give same result."""

    def test_ecb_deterministic(self, p11_session: Any) -> None:
        """AES-ECB with same key+plaintext must produce same ciphertext."""
        key = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"determinism test"
        ct1 = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        ct2 = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert ct1 == ct2

    def test_digest_deterministic(self, p11_session: Any) -> None:
        """SHA-256 of same data must always be the same."""
        data = b"hash determinism test"
        d1 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        d2 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        assert d1 == d2

    def test_different_keys_different_ciphertext(self, p11_session: Any) -> None:
        """AES-ECB with different keys must produce different ciphertext."""
        k1 = p11_session.generate_key(KeyType.AES, 256)
        k2 = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"different keys!!"
        ct1 = k1.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        ct2 = k2.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert ct1 != ct2


class TestCopyEquivalence:
    """A copied key must behave identically to the original."""

    def test_copy_produces_same_ciphertext(self, p11_session: Any) -> None:
        """Encrypting with original and copy produces identical output."""
        original = p11_session.generate_key(KeyType.AES, 256)
        copy = original.copy({Attribute.LABEL: "copy-equiv"})

        plaintext = b"copy equivalence"
        ct_orig = original.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        ct_copy = copy.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert ct_orig == ct_copy

    def test_copy_can_decrypt_original(self, p11_session: Any) -> None:
        """Copy can decrypt what original encrypted."""
        original = p11_session.generate_key(KeyType.AES, 256)
        copy = original.copy({Attribute.LABEL: "copy-decrypt"})

        plaintext = b"cross-decrypt!!!"
        ct = original.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        pt = copy.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext


class TestDigestProperties:
    """Mathematical properties that hash functions must satisfy."""

    def test_different_inputs_different_outputs(self, p11_session: Any) -> None:
        """Different inputs must produce different digests (collision resistance)."""
        digests = set()
        for i in range(100):
            d = p11_session.digest(f"input {i}".encode(), mechanism=Mechanism.SHA256)
            digests.add(d)
        assert len(digests) == 100

    def test_output_length_consistent(self, p11_session: Any) -> None:
        """SHA-256 always produces 32 bytes regardless of input size."""
        for size in [0, 1, 16, 64, 1024, 10000]:
            d = p11_session.digest(b"X" * size, mechanism=Mechanism.SHA256)
            assert len(d) == 32

    def test_sha_family_different_outputs(self, p11_session: Any) -> None:
        """Different SHA variants produce different outputs for same input."""
        data = b"sha family test"
        sha1 = p11_session.digest(data, mechanism=Mechanism.SHA_1)
        sha256 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        sha512 = p11_session.digest(data, mechanism=Mechanism.SHA512)
        assert sha1 != sha256
        assert sha256 != sha512
        assert sha1 != sha512
