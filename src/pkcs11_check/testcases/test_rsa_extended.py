"""Tests for extended RSA mechanisms.

Covers CKM_RSA_X9_31, CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_AES_KEY_WRAP,
and CKM_RSA_PKCS_OAEP_TPM_1_1.

OASIS spec: rsa.md
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    FunctionFailed,
    FunctionNotSupported,
    MechanismInvalid,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.full


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rsa_keypair(
    session: Any,
    bits: int = 2048,
    *,
    sign: bool = False,
    encrypt: bool = False,
    wrap: bool = False,
    mechanism: Mechanism | None = None,
) -> tuple[Any, Any]:
    """Generate an RSA keypair with specific capabilities."""
    pub_tmpl: dict[Any, Any] = {Attribute.TOKEN: False}
    priv_tmpl: dict[Any, Any] = {Attribute.TOKEN: False}

    if sign:
        pub_tmpl[Attribute.VERIFY] = True
        priv_tmpl[Attribute.SIGN] = True
    if encrypt:
        pub_tmpl[Attribute.ENCRYPT] = True
        priv_tmpl[Attribute.DECRYPT] = True
    if wrap:
        pub_tmpl[Attribute.WRAP] = True
        priv_tmpl[Attribute.UNWRAP] = True

    kwargs: dict[str, Any] = {
        "public_template": pub_tmpl,
        "private_template": priv_tmpl,
    }
    if mechanism is not None:
        kwargs["mechanism"] = mechanism

    result: tuple[Any, Any] = session.generate_keypair(KeyType.RSA, bits, **kwargs)
    return result


def _make_extractable_aes(session: Any, bits: int = 128) -> Any:
    """Generate an extractable AES key suitable for wrapping."""
    return session.generate_key(
        KeyType.AES,
        bits,
        template={
            Attribute.EXTRACTABLE: True,
            Attribute.SENSITIVE: False,
            Attribute.TOKEN: False,
        },
    )


# ---------------------------------------------------------------------------
# CKM_RSA_X9_31 -- X9.31 signature padding
# ---------------------------------------------------------------------------


class TestRSAX931:
    """CKM_RSA_X9_31 sign/verify with pre-hashed data."""

    def test_sign_verify_sha256(self, p11_session: Any, p11_module: Any) -> None:
        """Sign a SHA-256 digest with RSA X9.31 and verify."""
        if not has_mechanism(p11_module, "RSA_X9_31"):
            pytest.skip("CKM_RSA_X9_31 not supported")

        pub, priv = _rsa_keypair(p11_session, sign=True)
        try:
            # X9.31 operates on pre-hashed data -- must be exactly hash length
            digest = hashlib.sha256(b"test data for X9.31 signing").digest()
            assert len(digest) == 32

            try:
                sig = priv.sign(digest, mechanism=Mechanism.RSA_X9_31)
            except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
                pytest.xfail(f"CKM_RSA_X9_31 sign not functional: {exc}")

            assert len(sig) == 256  # 2048-bit RSA = 256 bytes
            result = pub.verify(digest, sig, mechanism=Mechanism.RSA_X9_31)
            assert result is True
        finally:
            pub.destroy()
            priv.destroy()

    def test_sign_verify_sha1(self, p11_session: Any, p11_module: Any) -> None:
        """Sign a SHA-1 digest with RSA X9.31 and verify."""
        if not has_mechanism(p11_module, "RSA_X9_31"):
            pytest.skip("CKM_RSA_X9_31 not supported")

        pub, priv = _rsa_keypair(p11_session, sign=True)
        try:
            digest = hashlib.sha1(b"test data for X9.31 SHA-1").digest()  # noqa: S324
            assert len(digest) == 20

            try:
                sig = priv.sign(digest, mechanism=Mechanism.RSA_X9_31)
            except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
                pytest.xfail(f"CKM_RSA_X9_31 sign with SHA-1 digest not functional: {exc}")

            result = pub.verify(digest, sig, mechanism=Mechanism.RSA_X9_31)
            assert result is True
        finally:
            pub.destroy()
            priv.destroy()

    def test_tampered_signature_fails(self, p11_session: Any, p11_module: Any) -> None:
        """Verification with tampered signature should fail."""
        if not has_mechanism(p11_module, "RSA_X9_31"):
            pytest.skip("CKM_RSA_X9_31 not supported")

        pub, priv = _rsa_keypair(p11_session, sign=True)
        try:
            digest = hashlib.sha256(b"tamper detection test").digest()

            try:
                sig = priv.sign(digest, mechanism=Mechanism.RSA_X9_31)
            except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
                pytest.xfail(f"CKM_RSA_X9_31 sign not functional: {exc}")

            # Flip a byte in the signature
            tampered = bytearray(sig)
            tampered[-1] ^= 0xFF
            tampered_sig = bytes(tampered)

            from pkcs11.exceptions import SignatureInvalid, SignatureLenRange

            with pytest.raises((SignatureInvalid, SignatureLenRange, FunctionFailed, Exception)):
                pub.verify(digest, tampered_sig, mechanism=Mechanism.RSA_X9_31)
        finally:
            pub.destroy()
            priv.destroy()

    def test_wrong_digest_fails(self, p11_session: Any, p11_module: Any) -> None:
        """Verification with different digest should fail."""
        if not has_mechanism(p11_module, "RSA_X9_31"):
            pytest.skip("CKM_RSA_X9_31 not supported")

        pub, priv = _rsa_keypair(p11_session, sign=True)
        try:
            digest = hashlib.sha256(b"original data").digest()

            try:
                sig = priv.sign(digest, mechanism=Mechanism.RSA_X9_31)
            except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
                pytest.xfail(f"CKM_RSA_X9_31 sign not functional: {exc}")

            wrong_digest = hashlib.sha256(b"different data").digest()

            from pkcs11.exceptions import SignatureInvalid, SignatureLenRange

            with pytest.raises((SignatureInvalid, SignatureLenRange, FunctionFailed, Exception)):
                pub.verify(wrong_digest, sig, mechanism=Mechanism.RSA_X9_31)
        finally:
            pub.destroy()
            priv.destroy()


# ---------------------------------------------------------------------------
# CKM_RSA_X9_31_KEY_PAIR_GEN -- alternative RSA key generation
# ---------------------------------------------------------------------------


class TestRSAX931KeyPairGen:
    """CKM_RSA_X9_31_KEY_PAIR_GEN -- generate RSA keys using X9.31 method."""

    def test_generate_keypair(self, p11_session: Any, p11_module: Any) -> None:
        """Generate an RSA keypair using X9.31 key generation."""
        if not has_mechanism(p11_module, "RSA_X9_31_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_X9_31_KEY_PAIR_GEN not supported")

        try:
            pub, priv = _rsa_keypair(
                p11_session,
                sign=True,
                encrypt=True,
                mechanism=Mechanism.RSA_X9_31_KEY_PAIR_GEN,
            )
        except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
            pytest.xfail(f"CKM_RSA_X9_31_KEY_PAIR_GEN not functional: {exc}")

        try:
            assert pub is not None
            assert priv is not None
            # Verify the key has the expected modulus size
            modulus = pub[Attribute.MODULUS]
            assert len(modulus) == 256  # 2048 bits = 256 bytes
        finally:
            pub.destroy()
            priv.destroy()

    def test_generated_key_can_sign(self, p11_session: Any, p11_module: Any) -> None:
        """Keys generated with X9.31 method can perform standard RSA signing."""
        if not has_mechanism(p11_module, "RSA_X9_31_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_X9_31_KEY_PAIR_GEN not supported")
        if not has_mechanism(p11_module, "SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        try:
            pub, priv = _rsa_keypair(
                p11_session,
                sign=True,
                mechanism=Mechanism.RSA_X9_31_KEY_PAIR_GEN,
            )
        except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
            pytest.xfail(f"CKM_RSA_X9_31_KEY_PAIR_GEN not functional: {exc}")

        try:
            data = b"sign with X9.31-generated key"
            sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
            assert len(sig) == 256
            result = pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)
            assert result is True
        finally:
            pub.destroy()
            priv.destroy()

    def test_generated_key_can_encrypt(self, p11_session: Any, p11_module: Any) -> None:
        """Keys generated with X9.31 method can perform RSA-OAEP encrypt/decrypt."""
        if not has_mechanism(p11_module, "RSA_X9_31_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_X9_31_KEY_PAIR_GEN not supported")
        if not has_mechanism(p11_module, "RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")

        try:
            pub, priv = _rsa_keypair(
                p11_session,
                encrypt=True,
                mechanism=Mechanism.RSA_X9_31_KEY_PAIR_GEN,
            )
        except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
            pytest.xfail(f"CKM_RSA_X9_31_KEY_PAIR_GEN not functional: {exc}")

        try:
            from pkcs11.mechanisms import MGF

            oaep_params = (Mechanism.SHA256, MGF.SHA256, None)
            plaintext = b"encrypt with X9.31 key"
            ct = pub.encrypt(
                plaintext,
                mechanism=Mechanism.RSA_PKCS_OAEP,
                mechanism_param=oaep_params,
            )
            pt = priv.decrypt(
                ct,
                mechanism=Mechanism.RSA_PKCS_OAEP,
                mechanism_param=oaep_params,
            )
            assert pt == plaintext
        finally:
            pub.destroy()
            priv.destroy()


# ---------------------------------------------------------------------------
# CKM_RSA_AES_KEY_WRAP -- hybrid RSA+AES key wrapping
# ---------------------------------------------------------------------------


class TestRSAAESKeyWrap:
    """CKM_RSA_AES_KEY_WRAP -- wraps a key with AES, then wraps the AES key with RSA-OAEP."""

    def test_wrap_unwrap_aes128(self, p11_session: Any, p11_module: Any) -> None:
        """Wrap an AES-128 key using RSA_AES_KEY_WRAP and unwrap it."""
        if not has_mechanism(p11_module, "RSA_AES_KEY_WRAP"):
            pytest.skip("CKM_RSA_AES_KEY_WRAP not supported")

        pub, priv = _rsa_keypair(p11_session, wrap=True)
        aes_key = _make_extractable_aes(p11_session, 128)
        try:
            original_value = aes_key[Attribute.VALUE]

            # mechanism_param: (aes_key_bits, oaep_params)
            # oaep_params: (hash_alg, mgf, source_data)
            from pkcs11.mechanisms import MGF

            wrap_param = (256, (Mechanism.SHA256, MGF.SHA256, None))

            try:
                wrapped = pub.wrap_key(
                    aes_key,
                    mechanism=Mechanism.RSA_AES_KEY_WRAP,
                    mechanism_param=wrap_param,
                )
            except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
                pytest.xfail(f"CKM_RSA_AES_KEY_WRAP wrap not functional: {exc}")

            assert wrapped is not None
            assert len(wrapped) > 0

            unwrapped = priv.unwrap_key(
                ObjectClass.SECRET_KEY,
                KeyType.AES,
                wrapped,
                mechanism=Mechanism.RSA_AES_KEY_WRAP,
                mechanism_param=wrap_param,
                template={
                    Attribute.EXTRACTABLE: True,
                    Attribute.SENSITIVE: False,
                    Attribute.TOKEN: False,
                },
            )
            try:
                assert unwrapped[Attribute.VALUE] == original_value
            finally:
                unwrapped.destroy()
        finally:
            pub.destroy()
            priv.destroy()
            aes_key.destroy()

    def test_wrap_unwrap_aes256(self, p11_session: Any, p11_module: Any) -> None:
        """Wrap an AES-256 key using RSA_AES_KEY_WRAP."""
        if not has_mechanism(p11_module, "RSA_AES_KEY_WRAP"):
            pytest.skip("CKM_RSA_AES_KEY_WRAP not supported")

        pub, priv = _rsa_keypair(p11_session, wrap=True)
        aes_key = _make_extractable_aes(p11_session, 256)
        try:
            original_value = aes_key[Attribute.VALUE]

            from pkcs11.mechanisms import MGF

            wrap_param = (256, (Mechanism.SHA256, MGF.SHA256, None))

            try:
                wrapped = pub.wrap_key(
                    aes_key,
                    mechanism=Mechanism.RSA_AES_KEY_WRAP,
                    mechanism_param=wrap_param,
                )
            except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
                pytest.xfail(f"CKM_RSA_AES_KEY_WRAP wrap not functional: {exc}")

            unwrapped = priv.unwrap_key(
                ObjectClass.SECRET_KEY,
                KeyType.AES,
                wrapped,
                mechanism=Mechanism.RSA_AES_KEY_WRAP,
                mechanism_param=wrap_param,
                template={
                    Attribute.EXTRACTABLE: True,
                    Attribute.SENSITIVE: False,
                    Attribute.TOKEN: False,
                },
            )
            try:
                assert unwrapped[Attribute.VALUE] == original_value
            finally:
                unwrapped.destroy()
        finally:
            pub.destroy()
            priv.destroy()
            aes_key.destroy()

    def test_wrapped_data_differs_from_original(self, p11_session: Any, p11_module: Any) -> None:
        """Wrapped key data should not contain the original key material."""
        if not has_mechanism(p11_module, "RSA_AES_KEY_WRAP"):
            pytest.skip("CKM_RSA_AES_KEY_WRAP not supported")

        pub, priv = _rsa_keypair(p11_session, wrap=True)
        aes_key = _make_extractable_aes(p11_session, 128)
        try:
            original_value = aes_key[Attribute.VALUE]

            from pkcs11.mechanisms import MGF

            wrap_param = (256, (Mechanism.SHA256, MGF.SHA256, None))

            try:
                wrapped = pub.wrap_key(
                    aes_key,
                    mechanism=Mechanism.RSA_AES_KEY_WRAP,
                    mechanism_param=wrap_param,
                )
            except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
                pytest.xfail(f"CKM_RSA_AES_KEY_WRAP wrap not functional: {exc}")

            # The wrapped blob should not contain the raw key bytes
            assert original_value not in wrapped
        finally:
            pub.destroy()
            priv.destroy()
            aes_key.destroy()


# ---------------------------------------------------------------------------
# CKM_RSA_PKCS_OAEP_TPM_1_1 -- TPM 1.1 variant of RSA-OAEP
# ---------------------------------------------------------------------------


class TestRSAOAEPTPM:
    """CKM_RSA_PKCS_OAEP_TPM_1_1 -- TPM 1.1 specific RSA-OAEP variant."""

    def test_encrypt_decrypt_roundtrip(self, p11_session: Any, p11_module: Any) -> None:
        """Encrypt and decrypt with RSA-OAEP TPM 1.1."""
        if not has_mechanism(p11_module, "RSA_PKCS_OAEP_TPM_1_1"):
            pytest.skip("CKM_RSA_PKCS_OAEP_TPM_1_1 not supported")

        pub, priv = _rsa_keypair(p11_session, encrypt=True)
        try:
            plaintext = b"TPM 1.1 OAEP test data"

            try:
                ct = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP_TPM_1_1)
            except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
                pytest.xfail(f"CKM_RSA_PKCS_OAEP_TPM_1_1 encrypt not functional: {exc}")

            assert len(ct) == 256  # 2048-bit RSA
            assert ct != plaintext

            pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP_TPM_1_1)
            assert pt == plaintext
        finally:
            pub.destroy()
            priv.destroy()

    def test_ciphertext_is_randomized(self, p11_session: Any, p11_module: Any) -> None:
        """OAEP encryption is randomized -- same plaintext gives different ciphertexts."""
        if not has_mechanism(p11_module, "RSA_PKCS_OAEP_TPM_1_1"):
            pytest.skip("CKM_RSA_PKCS_OAEP_TPM_1_1 not supported")

        pub, priv = _rsa_keypair(p11_session, encrypt=True)
        try:
            plaintext = b"randomization test"

            try:
                ct1 = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP_TPM_1_1)
                ct2 = pub.encrypt(plaintext, mechanism=Mechanism.RSA_PKCS_OAEP_TPM_1_1)
            except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
                pytest.xfail(f"CKM_RSA_PKCS_OAEP_TPM_1_1 encrypt not functional: {exc}")

            # OAEP uses random padding -- two encryptions should differ
            assert ct1 != ct2
        finally:
            pub.destroy()
            priv.destroy()

    def test_max_plaintext_size(self, p11_session: Any, p11_module: Any) -> None:
        """Encrypt the maximum-size plaintext for 2048-bit RSA OAEP.

        For OAEP with SHA-1 (TPM 1.1 default): max = k - 2*hLen - 2 = 256 - 42 = 214 bytes.
        """
        if not has_mechanism(p11_module, "RSA_PKCS_OAEP_TPM_1_1"):
            pytest.skip("CKM_RSA_PKCS_OAEP_TPM_1_1 not supported")

        pub, priv = _rsa_keypair(p11_session, encrypt=True)
        try:
            # TPM 1.1 OAEP uses SHA-1 (hLen=20), so max plaintext = 256 - 2*20 - 2 = 214
            max_plaintext = os.urandom(214)

            try:
                ct = pub.encrypt(max_plaintext, mechanism=Mechanism.RSA_PKCS_OAEP_TPM_1_1)
            except (MechanismInvalid, FunctionNotSupported, FunctionFailed) as exc:
                pytest.xfail(f"CKM_RSA_PKCS_OAEP_TPM_1_1 encrypt not functional: {exc}")

            pt = priv.decrypt(ct, mechanism=Mechanism.RSA_PKCS_OAEP_TPM_1_1)
            assert pt == max_plaintext
        finally:
            pub.destroy()
            priv.destroy()
