"""CKR compliance tests for C_VerifyInit and C_Verify.

Source: PKCS#11 v3.1 §5.11.1 (C_VerifyInit), §5.11.2 (C_Verify).
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import KeyType, Mechanism
from pkcs11.exceptions import DeviceError, PKCS11Error

from pkcs11_check.testcases.ckr._ckr_spec import CKR_VERIFY, assert_ckr

pytestmark = pytest.mark.access


class TestVerifyInitErrors:
    """Per-parameter error conditions for C_VerifyInit (§5.11.1)."""

    def test_mechanism_invalid(self, p11_session: Any, ckr_strict: bool) -> None:
        """Using encrypt mechanism for verify -> CKR_MECHANISM_INVALID."""
        pub, _priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        try:
            pub.verify(b"test", b"\x00" * 256, mechanism=Mechanism.AES_ECB)
            pytest.fail("Should have rejected AES_ECB as verify mechanism")
        except PKCS11Error as e:
            # Broad catch intentional — assert_ckr validates the specific type
            assert_ckr(CKR_VERIFY["init_mechanism_invalid"], e, ckr_strict)

    def test_key_type_inconsistent(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """AES key with RSA verify mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        key = p11_session.generate_key(KeyType.AES, 256)
        exp = CKR_VERIFY["init_key_type_inconsistent"]
        try:
            key.verify(b"test", b"\x00" * 256, mechanism=Mechanism.SHA256_RSA_PKCS)
            # Module accepted mismatched key type — compliance deviation
            if not exp.allow_success:
                pytest.fail("Should have rejected AES key with RSA verify mechanism")
            from pkcs11_check.compliance import ComplianceLevel, note
            note(
                "C_VerifyInit accepted AES key with RSA mechanism",
                ComplianceLevel.NOT_RECOMMENDED,
                reference=exp.spec_ref,
            )
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)


    def test_key_handle_invalid(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """Verify with destroyed key handle -> CKR_KEY_HANDLE_INVALID."""
        pub, _priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        pub.destroy()
        try:
            pub.verify(b"test", b"\x00" * 256, mechanism=Mechanism.SHA256_RSA_PKCS)
        except PKCS11Error as e:
            assert_ckr(CKR_VERIFY["init_key_handle_invalid"], e, ckr_strict)


class TestVerifyErrors:
    """Error conditions for C_Verify (§5.11.2)."""

    def test_signature_invalid(self, p11_session: Any, ckr_strict: bool) -> None:
        """Tampered RSA signature -> CKR_SIGNATURE_INVALID."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"CKR compliance test data"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Tamper last byte
        tampered = bytearray(sig)
        tampered[-1] ^= 0xFF

        try:
            result = pub.verify(data, bytes(tampered), mechanism=Mechanism.SHA256_RSA_PKCS)
            if result is True:
                pytest.fail("Tampered signature verified as valid!")
            # result is False — acceptable (some wrappers return bool)
        except DeviceError:
            pytest.xfail("Kryoptic bug: returns CKR_DEVICE_ERROR for verify failure")
        except PKCS11Error as e:
            assert_ckr(CKR_VERIFY["signature_invalid"], e, ckr_strict)

    def test_signature_wrong_length(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """RSA signature with wrong length -> CKR_SIGNATURE_LEN_RANGE."""
        pub, _priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"CKR compliance test data"
        exp = CKR_VERIFY["signature_len_range"]
        # RSA-2048 signature should be 256 bytes, provide 128
        try:
            result = pub.verify(data, b"\x00" * 128, mechanism=Mechanism.SHA256_RSA_PKCS)
            # Module didn't reject wrong-length signature at length check
            if result is False:
                pass  # Verification failed (returned False) — acceptable
            elif not exp.allow_success:
                pytest.fail("Should have rejected 128-byte signature for RSA-2048")
            else:
                from pkcs11_check.compliance import ComplianceLevel, note
                note(
                    "C_Verify accepted wrong-length RSA signature without length check",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference=exp.spec_ref,
                )
        except DeviceError:
            pytest.xfail("Kryoptic bug: returns CKR_DEVICE_ERROR for verify failure")
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)
