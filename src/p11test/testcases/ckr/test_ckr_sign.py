"""CKR compliance tests for C_SignInit and C_Sign.

Source: PKCS#11 v3.1 §5.10.1 (C_SignInit), §5.10.2 (C_Sign).
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import KeyType, Mechanism
from pkcs11.exceptions import PKCS11Error

from p11test.testcases.ckr._ckr_spec import CKR_SIGN, assert_ckr
from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.access


class TestSignInitErrors:
    """Per-parameter error conditions for C_SignInit (§5.10.1)."""

    def test_mechanism_invalid(self, p11_session: Any, ckr_strict: bool) -> None:
        """Using encrypt mechanism for sign -> CKR_MECHANISM_INVALID."""
        _pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        try:
            priv.sign(b"test data", mechanism=Mechanism.AES_ECB)
            pytest.fail("Should have rejected AES_ECB as signing mechanism")
        except PKCS11Error as e:
            # Broad catch intentional — assert_ckr validates the specific type
            assert_ckr(CKR_SIGN["init_mechanism_invalid"], e, ckr_strict)

    def test_key_type_inconsistent(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """AES key with RSA signing mechanism -> CKR_KEY_TYPE_INCONSISTENT."""
        key = p11_session.generate_key(KeyType.AES, 256)
        try:
            key.sign(b"test data", mechanism=Mechanism.SHA256_RSA_PKCS)
            pytest.fail("Should have rejected AES key with RSA sign mechanism")
        except PKCS11Error as e:
            assert_ckr(CKR_SIGN["init_key_type_inconsistent"], e, ckr_strict)

    def test_mechanism_param_invalid(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """RSA-PSS with invalid salt length param -> CKR_MECHANISM_PARAM_INVALID."""
        if not has_mechanism(p11_module, "SHA256_RSA_PKCS_PSS"):
            pytest.skip("RSA-PSS not supported")
        _pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        # RSA-PSS needs specific param struct — provide garbage bytes
        try:
            priv.sign(
                b"test data",
                mechanism=Mechanism.SHA256_RSA_PKCS_PSS,
                mechanism_param=b"\x00" * 3,  # Wrong: needs CK_RSA_PKCS_PSS_PARAMS
            )
            pytest.fail("Should have rejected garbage PSS params")
        except PKCS11Error as e:
            assert_ckr(CKR_SIGN["init_mechanism_param_invalid"], e, ckr_strict)


class TestSignDataErrors:
    """Data-level error conditions for C_Sign (§5.10.2)."""

    def test_rsa_pkcs_data_too_long(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """RSA-PKCS sign with data > max allowed -> CKR_DATA_LEN_RANGE.

        RSA-PKCS v1.5 signing: max data = k - 11 bytes = 245 for RSA-2048.
        But SHA256_RSA_PKCS hashes first, so use raw RSA_PKCS with long data.
        """
        _pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        # Raw RSA_PKCS sign: max = 245 bytes for 2048-bit key
        try:
            priv.sign(b"\x42" * 246, mechanism=Mechanism.RSA_PKCS)
            pytest.fail("Should have rejected 246-byte data for raw RSA-PKCS sign")
        except PKCS11Error as e:
            assert_ckr(CKR_SIGN["data_len_range"], e, ckr_strict)
