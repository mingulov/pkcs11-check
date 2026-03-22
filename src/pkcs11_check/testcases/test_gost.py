"""Tests for GOST PKCS#11 mechanisms.

Covers GOST 28147-89 (symmetric), GOST R 34.10-2001 (signature),
and GOST R 34.11-94 (digest/HMAC).

Almost no modules support GOST -- tests skip cleanly when unsupported.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import FunctionFailed, MechanismInvalid

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.full

# 16 bytes -- 2 x 8-byte GOST 28147-89 blocks
_TWO_BLOCKS = b"12345678abcdefgh"

# 32 bytes -- typical GOST R 34.11-94 hash output size
_HASH_SIZE_DATA = bytes(range(32))

# Common error tuple for GOST encrypt/decrypt operations
_CIPHER_ERRORS = (MechanismInvalid, FunctionFailed)

# Common error tuple for sign/verify operations
_SIGN_ERRORS = (MechanismInvalid, FunctionFailed)

# Common error tuple for digest/HMAC operations
_DIGEST_ERRORS = (MechanismInvalid, FunctionFailed)


def _gost_iv(session: Any) -> bytes:
    """Generate an 8-byte IV for GOST 28147-89 (non-ECB) modes."""
    result: bytes = session.generate_random(64)  # 64 bits = 8 bytes
    return result


class TestGOST28147KeyGen:
    """CKM_GOST28147_KEY_GEN -- generate GOST 28147-89 symmetric keys."""

    def test_gost28147_key_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a 256-bit GOST 28147-89 secret key."""
        if not has_mechanism(p11_module, "GOST28147_KEY_GEN"):
            pytest.skip("CKM_GOST28147_KEY_GEN not supported")

        key = p11_session.generate_key(
            KeyType.GOST28147,
            256,
            mechanism=Mechanism.GOST28147_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            },
        )
        try:
            assert key is not None
            assert key[Attribute.KEY_TYPE] == KeyType.GOST28147
        finally:
            key.destroy()


class TestGOST28147Encryption:
    """CKM_GOST28147_ECB and CKM_GOST28147 -- GOST 28147-89 encrypt/decrypt."""

    def test_ecb_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Encrypt and decrypt two blocks with CKM_GOST28147_ECB."""
        if not has_mechanism(p11_module, "GOST28147_ECB"):
            pytest.skip("CKM_GOST28147_ECB not supported")
        if not has_mechanism(p11_module, "GOST28147_KEY_GEN"):
            pytest.skip("CKM_GOST28147_KEY_GEN not supported")

        key = p11_session.generate_key(
            KeyType.GOST28147,
            256,
            mechanism=Mechanism.GOST28147_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.GOST28147_ECB)
            pt = key.decrypt(ct, mechanism=Mechanism.GOST28147_ECB)
            assert pt == _TWO_BLOCKS
        except _CIPHER_ERRORS as exc:
            pytest.xfail(f"CKM_GOST28147_ECB not operational: {exc}")
        finally:
            key.destroy()

    def test_ecb_different_keys_produce_different_ciphertext(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Two distinct keys must produce different ECB ciphertext for the same plaintext."""
        if not has_mechanism(p11_module, "GOST28147_ECB"):
            pytest.skip("CKM_GOST28147_ECB not supported")
        if not has_mechanism(p11_module, "GOST28147_KEY_GEN"):
            pytest.skip("CKM_GOST28147_KEY_GEN not supported")

        template = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False}
        key1 = p11_session.generate_key(
            KeyType.GOST28147, 256, mechanism=Mechanism.GOST28147_KEY_GEN, template=template
        )
        key2 = p11_session.generate_key(
            KeyType.GOST28147, 256, mechanism=Mechanism.GOST28147_KEY_GEN, template=template
        )
        try:
            ct1 = key1.encrypt(_TWO_BLOCKS, mechanism=Mechanism.GOST28147_ECB)
            ct2 = key2.encrypt(_TWO_BLOCKS, mechanism=Mechanism.GOST28147_ECB)
            assert ct1 != ct2, "Different keys produced identical ECB ciphertext"
        except _CIPHER_ERRORS as exc:
            pytest.xfail(f"CKM_GOST28147_ECB not operational: {exc}")
        finally:
            key2.destroy()
            key1.destroy()

    def test_cbc_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Encrypt and decrypt two blocks with CKM_GOST28147 (CBC-like mode) with an IV."""
        if not has_mechanism(p11_module, "GOST28147"):
            pytest.skip("CKM_GOST28147 not supported")
        if not has_mechanism(p11_module, "GOST28147_KEY_GEN"):
            pytest.skip("CKM_GOST28147_KEY_GEN not supported")

        key = p11_session.generate_key(
            KeyType.GOST28147,
            256,
            mechanism=Mechanism.GOST28147_KEY_GEN,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            iv = _gost_iv(p11_session)
            ct = key.encrypt(_TWO_BLOCKS, mechanism=Mechanism.GOST28147, mechanism_param=iv)
            pt = key.decrypt(ct, mechanism=Mechanism.GOST28147, mechanism_param=iv)
            assert pt == _TWO_BLOCKS
        except _CIPHER_ERRORS as exc:
            pytest.xfail(f"CKM_GOST28147 not operational: {exc}")
        finally:
            key.destroy()


class TestGOST28147MAC:
    """CKM_GOST28147_MAC -- GOST 28147-89 message authentication code."""

    def test_mac_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Sign and verify a MAC with CKM_GOST28147_MAC."""
        if not has_mechanism(p11_module, "GOST28147_MAC"):
            pytest.skip("CKM_GOST28147_MAC not supported")
        if not has_mechanism(p11_module, "GOST28147_KEY_GEN"):
            pytest.skip("CKM_GOST28147_KEY_GEN not supported")

        key = p11_session.generate_key(
            KeyType.GOST28147,
            256,
            mechanism=Mechanism.GOST28147_KEY_GEN,
            template={
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            },
        )
        try:
            mac = key.sign(_TWO_BLOCKS, mechanism=Mechanism.GOST28147_MAC)
            assert mac is not None
            assert len(mac) > 0
            key.verify(_TWO_BLOCKS, mac, mechanism=Mechanism.GOST28147_MAC)
        except _SIGN_ERRORS as exc:
            pytest.xfail(f"CKM_GOST28147_MAC not operational: {exc}")
        finally:
            key.destroy()


class TestGOSTR3410Signature:
    """CKM_GOSTR3410 and CKM_GOSTR3410_WITH_GOSTR3411 -- GOST R 34.10-2001 signatures."""

    def test_keypair_gen(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a GOST R 34.10-2001 key pair."""
        if not has_mechanism(p11_module, "GOSTR3410_KEY_PAIR_GEN"):
            pytest.skip("CKM_GOSTR3410_KEY_PAIR_GEN not supported")

        pub, priv = p11_session.generate_keypair(
            KeyType.GOSTR3410,
            mechanism=Mechanism.GOSTR3410_KEY_PAIR_GEN,
        )
        try:
            assert pub is not None
            assert priv is not None
            assert pub[Attribute.KEY_TYPE] == KeyType.GOSTR3410
            assert priv[Attribute.KEY_TYPE] == KeyType.GOSTR3410
            assert pub[Attribute.CLASS] == ObjectClass.PUBLIC_KEY
            assert priv[Attribute.CLASS] == ObjectClass.PRIVATE_KEY
        finally:
            priv.destroy()
            pub.destroy()

    def test_sign_verify_raw(self, p11_session: Any, p11_module: Any) -> None:
        """Sign 32 bytes of data with CKM_GOSTR3410 (raw) and verify."""
        if not has_mechanism(p11_module, "GOSTR3410_KEY_PAIR_GEN"):
            pytest.skip("CKM_GOSTR3410_KEY_PAIR_GEN not supported")
        if not has_mechanism(p11_module, "GOSTR3410"):
            pytest.skip("CKM_GOSTR3410 not supported")

        pub, priv = p11_session.generate_keypair(
            KeyType.GOSTR3410,
            mechanism=Mechanism.GOSTR3410_KEY_PAIR_GEN,
        )
        try:
            # GOSTR3410 signs a pre-hashed 32-byte value (GOST R 34.11-94 output size)
            sig = priv.sign(_HASH_SIZE_DATA, mechanism=Mechanism.GOSTR3410)
            assert sig is not None
            assert len(sig) > 0
            pub.verify(_HASH_SIZE_DATA, sig, mechanism=Mechanism.GOSTR3410)
        except _SIGN_ERRORS as exc:
            pytest.xfail(f"CKM_GOSTR3410 sign/verify not operational: {exc}")
        finally:
            priv.destroy()
            pub.destroy()

    def test_sign_verify_with_hash(self, p11_session: Any, p11_module: Any) -> None:
        """Sign arbitrary data with CKM_GOSTR3410_WITH_GOSTR3411 (hash-then-sign) and verify."""
        if not has_mechanism(p11_module, "GOSTR3410_KEY_PAIR_GEN"):
            pytest.skip("CKM_GOSTR3410_KEY_PAIR_GEN not supported")
        if not has_mechanism(p11_module, "GOSTR3410_WITH_GOSTR3411"):
            pytest.skip("CKM_GOSTR3410_WITH_GOSTR3411 not supported")

        pub, priv = p11_session.generate_keypair(
            KeyType.GOSTR3410,
            mechanism=Mechanism.GOSTR3410_KEY_PAIR_GEN,
        )
        try:
            data = b"GOST signature test data"
            sig = priv.sign(data, mechanism=Mechanism.GOSTR3410_WITH_GOSTR3411)
            assert sig is not None
            assert len(sig) > 0
            pub.verify(data, sig, mechanism=Mechanism.GOSTR3410_WITH_GOSTR3411)
        except _SIGN_ERRORS as exc:
            pytest.xfail(f"CKM_GOSTR3410_WITH_GOSTR3411 sign/verify not operational: {exc}")
        finally:
            priv.destroy()
            pub.destroy()


class TestGOSTR3411Digest:
    """CKM_GOSTR3411 and CKM_GOSTR3411_HMAC -- GOST R 34.11-94 digest and HMAC."""

    def test_digest(self, p11_session: Any, p11_module: Any) -> None:
        """Compute a GOST R 34.11-94 digest (no key needed)."""
        if not has_mechanism(p11_module, "GOSTR3411"):
            pytest.skip("CKM_GOSTR3411 not supported")

        data = b"GOST digest test data"
        try:
            digest = p11_session.digest(data, mechanism=Mechanism.GOSTR3411)
            assert digest is not None
            # GOST R 34.11-94 produces a 256-bit (32-byte) hash
            assert len(digest) == 32, f"Expected 32-byte GOST digest, got {len(digest)}"
        except _DIGEST_ERRORS as exc:
            pytest.xfail(f"CKM_GOSTR3411 digest not operational: {exc}")

    def test_digest_deterministic(self, p11_session: Any, p11_module: Any) -> None:
        """Same input must always produce the same GOST R 34.11-94 digest."""
        if not has_mechanism(p11_module, "GOSTR3411"):
            pytest.skip("CKM_GOSTR3411 not supported")

        data = b"deterministic GOST digest"
        try:
            d1 = p11_session.digest(data, mechanism=Mechanism.GOSTR3411)
            d2 = p11_session.digest(data, mechanism=Mechanism.GOSTR3411)
            assert d1 == d2, "CKM_GOSTR3411 digest is not deterministic"
        except _DIGEST_ERRORS as exc:
            pytest.xfail(f"CKM_GOSTR3411 digest not operational: {exc}")

    def test_hmac_sign_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Sign and verify an HMAC with CKM_GOSTR3411_HMAC."""
        if not has_mechanism(p11_module, "GOSTR3411_HMAC"):
            pytest.skip("CKM_GOSTR3411_HMAC not supported")

        # GOSTR3411_HMAC uses the GOSTR3411 key type for HMAC operations
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.GOSTR3411,
                Attribute.VALUE: bytes(range(32)),
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        try:
            data = b"GOST HMAC test data"
            mac = key.sign(data, mechanism=Mechanism.GOSTR3411_HMAC)
            assert mac is not None
            assert len(mac) > 0
            key.verify(data, mac, mechanism=Mechanism.GOSTR3411_HMAC)
        except _DIGEST_ERRORS as exc:
            pytest.xfail(f"CKM_GOSTR3411_HMAC not operational: {exc}")
        finally:
            key.destroy()
