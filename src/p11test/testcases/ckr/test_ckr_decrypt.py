"""CKR compliance tests for C_DecryptInit and C_Decrypt.

Each test triggers a specific error condition and validates the CKR code
against the OASIS PKCS#11 spec.

Source: PKCS#11 v3.1 §5.9.1 (C_DecryptInit), §5.9.2 (C_Decrypt).
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import PKCS11Error

from p11test.testcases.ckr._ckr_spec import CKR_DECRYPT, assert_ckr
from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.access


class TestDecryptInitErrors:
    """Per-parameter error conditions for C_DecryptInit (§5.9.1)."""

    def test_mechanism_invalid(self, p11_session: Any, ckr_strict: bool) -> None:
        """Using digest mechanism for decrypt -> CKR_MECHANISM_INVALID."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key.decrypt(b"\x00" * 16, mechanism=Mechanism.SHA256)
            pytest.fail("Should have rejected SHA256 as decryption mechanism")
        except PKCS11Error as e:
            # Broad catch intentional — assert_ckr validates the specific type
            assert_ckr(CKR_DECRYPT["init_mechanism_invalid"], e, ckr_strict)

    def test_key_type_inconsistent(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """AES key with RSA mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key.decrypt(b"\x00" * 256, mechanism=Mechanism.RSA_PKCS)
            pytest.fail("Should have rejected AES key with RSA mechanism")
        except PKCS11Error as e:
            assert_ckr(CKR_DECRYPT["init_key_type_inconsistent"], e, ckr_strict)

    def test_mechanism_param_invalid(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """AES-CBC with wrong-length IV -> CKR_MECHANISM_PARAM_INVALID."""
        if not has_mechanism(p11_module, "AES_CBC"):
            pytest.skip("AES_CBC not supported")
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key.decrypt(
                b"\x00" * 16,
                mechanism=Mechanism.AES_CBC,
                mechanism_param=b"\x00" * 8,  # Wrong: needs 16
            )
            pytest.fail("Should have rejected 8-byte IV for AES-CBC")
        except PKCS11Error as e:
            assert_ckr(CKR_DECRYPT["init_mechanism_param_invalid"], e, ckr_strict)


class TestDecryptDataErrors:
    """Data-level error conditions for C_Decrypt (§5.9.2)."""

    @pytest.mark.parametrize("size", [1, 7, 15, 17, 31])
    def test_ecb_ciphertext_not_aligned(
        self, p11_session: Any, ckr_strict: bool, size: int
    ) -> None:
        """AES-ECB with non-block-aligned ciphertext -> CKR_ENCRYPTED_DATA_LEN_RANGE."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key.decrypt(b"\xBB" * size, mechanism=Mechanism.AES_ECB)
            pytest.fail(f"Should have rejected {size}-byte ECB ciphertext")
        except PKCS11Error as e:
            assert_ckr(CKR_DECRYPT["encrypted_data_len_range"], e, ckr_strict)

    def test_ecb_garbage_ciphertext(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """AES-ECB decrypt of garbage (block-aligned) — may return data or error."""
        key = p11_session.generate_key(KeyType.AES, 256)
        exp = CKR_DECRYPT["encrypted_data_invalid"]
        try:
            # Block-aligned garbage: AES-ECB will "decrypt" it (ECB has no integrity)
            pt = key.decrypt(b"\xCC" * 16, mechanism=Mechanism.AES_ECB)
            # ECB decrypts anything block-aligned — not an error
            assert len(pt) == 16
        except PKCS11Error as e:
            # Some modules may reject garbage ciphertext
            assert_ckr(exp, e, ckr_strict)

    def test_rsa_ciphertext_wrong_length(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """RSA-PKCS decrypt with wrong ciphertext length -> CKR_ENCRYPTED_DATA_LEN_RANGE."""
        _pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        exp = CKR_DECRYPT["rsa_ciphertext_wrong_length"]
        # RSA-2048 expects 256-byte ciphertext, provide 128
        try:
            priv.decrypt(b"\x00" * 128, mechanism=Mechanism.RSA_PKCS)
            # Module accepted wrong-length ciphertext — compliance deviation
            if not exp.allow_success:
                pytest.fail("Should have rejected 128-byte ciphertext for RSA-2048")
            from p11test.compliance import ComplianceLevel, note
            note(
                "C_Decrypt accepted wrong-length RSA ciphertext (128 bytes for RSA-2048)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference=exp.spec_ref,
            )
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)
