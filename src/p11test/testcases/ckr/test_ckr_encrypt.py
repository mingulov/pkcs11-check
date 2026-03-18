"""CKR compliance tests for C_EncryptInit and C_Encrypt.

Each test triggers a specific error condition and validates the CKR code
against the OASIS PKCS#11 spec. In compat mode (default), acceptable
alternatives are logged as compliance notes. In strict mode (--ckr-strict),
only the spec-mandated CKR is accepted.

Source: PKCS#11 v3.1 §5.8.1 (C_EncryptInit), §5.8.2 (C_Encrypt).
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import PKCS11Error

from p11test.testcases.ckr._ckr_spec import CKR_ENCRYPT, assert_ckr
from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.access


class TestEncryptInitErrors:
    """Per-parameter error conditions for C_EncryptInit (§5.8.1)."""

    def test_mechanism_invalid(self, p11_session: Any, ckr_strict: bool) -> None:
        """Using digest mechanism for encrypt -> CKR_MECHANISM_INVALID."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key.encrypt(b"\x00" * 16, mechanism=Mechanism.SHA256)
            pytest.fail("Should have rejected SHA256 as encryption mechanism")
        except PKCS11Error as e:
            # Broad catch intentional — assert_ckr validates the specific type
            assert_ckr(CKR_ENCRYPT["init_mechanism_invalid"], e, ckr_strict)

    def test_key_function_not_permitted(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """Key with CKA_ENCRYPT=False -> CKR_KEY_FUNCTION_NOT_PERMITTED.

        python-pkcs11 enforces CKA_ENCRYPT at wrapper level — key object
        won't have .encrypt() method. Test via sign-only key + encrypt attempt.
        Full NULL/ctypes testing in test_ckr_null_params.py (Tier 6).
        """
        # Generate a sign-only key (no encrypt permission)
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.ENCRYPT: False, Attribute.SIGN: True},
        )
        exp = CKR_ENCRYPT["init_key_function_not_permitted"]
        # Wrapper blocks .encrypt() — verify the key lacks the method
        if not hasattr(key, "encrypt"):
            pytest.skip(
                "python-pkcs11 wrapper blocks encrypt on CKA_ENCRYPT=False keys "
                "(testable via ctypes in Tier 6)"
            )
        try:
            key.encrypt(b"\x00" * 16, mechanism=Mechanism.AES_ECB)
            if not exp.allow_success:
                pytest.fail("Should have rejected key without CKA_ENCRYPT")
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)

    def test_key_type_inconsistent(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """RSA public key with AES mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        pub, _priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        try:
            pub.encrypt(b"\x00" * 16, mechanism=Mechanism.AES_ECB)
            pytest.fail("Should have rejected RSA key with AES mechanism")
        except PKCS11Error as e:
            assert_ckr(CKR_ENCRYPT["init_key_type_inconsistent"], e, ckr_strict)

    def test_mechanism_param_invalid(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """AES-CBC with wrong-length IV -> CKR_MECHANISM_PARAM_INVALID."""
        if not has_mechanism(p11_module, "AES_CBC"):
            pytest.skip("AES_CBC not supported")
        key = p11_session.generate_key(KeyType.AES, 256)
        # AES-CBC needs 16-byte IV, provide 8 bytes
        try:
            key.encrypt(
                b"\x00" * 16,
                mechanism=Mechanism.AES_CBC,
                mechanism_param=b"\x00" * 8,
            )
            pytest.fail("Should have rejected 8-byte IV for AES-CBC")
        except PKCS11Error as e:
            assert_ckr(CKR_ENCRYPT["init_mechanism_param_invalid"], e, ckr_strict)


class TestEncryptDataErrors:
    """Data-level error conditions for C_Encrypt (§5.8.2)."""

    @pytest.mark.parametrize("size", [1, 7, 15, 17, 31, 33])
    def test_ecb_non_aligned(
        self, p11_session: Any, ckr_strict: bool, size: int
    ) -> None:
        """AES-ECB with non-block-aligned data -> CKR_DATA_LEN_RANGE."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key.encrypt(b"\xAA" * size, mechanism=Mechanism.AES_ECB)
            pytest.fail(f"Should have rejected {size}-byte ECB data")
        except PKCS11Error as e:
            assert_ckr(CKR_ENCRYPT["data_len_range"], e, ckr_strict)

    def test_empty_data(self, p11_session: Any, ckr_strict: bool) -> None:
        """AES-ECB with empty data — reject or return empty ciphertext."""
        key = p11_session.generate_key(KeyType.AES, 256)
        exp = CKR_ENCRYPT["data_empty"]
        try:
            ct = key.encrypt(b"", mechanism=Mechanism.AES_ECB)
            # Some modules accept empty -> empty (spec doesn't forbid it)
            assert ct == b"" or len(ct) == 0
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)

    def test_rsa_pkcs_too_long(self, p11_session: Any, ckr_strict: bool) -> None:
        """RSA-PKCS data > k-11 bytes -> CKR_DATA_LEN_RANGE."""
        pub, _priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        # Max data for RSA-2048 PKCS#1 v1.5 = 245 bytes (256 - 11)
        try:
            pub.encrypt(b"\x42" * 246, mechanism=Mechanism.RSA_PKCS)
            pytest.fail("Should have rejected 246 bytes for RSA-2048 PKCS")
        except PKCS11Error as e:
            assert_ckr(CKR_ENCRYPT["data_too_long_rsa"], e, ckr_strict)
