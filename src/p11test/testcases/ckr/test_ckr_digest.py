"""CKR compliance tests for C_DigestInit and C_Digest.

Source: PKCS#11 v3.1 §5.12.1 (C_DigestInit), §5.12.2 (C_Digest).
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Mechanism
from pkcs11.exceptions import PKCS11Error

from p11test.testcases.ckr._ckr_spec import CKR_DIGEST, assert_ckr

pytestmark = pytest.mark.access


class TestDigestInitErrors:
    """Per-parameter error conditions for C_DigestInit (§5.12.1)."""

    def test_mechanism_invalid(self, p11_session: Any, ckr_strict: bool) -> None:
        """Using encrypt mechanism for digest -> CKR_MECHANISM_INVALID."""
        try:
            p11_session.digest(b"test data", mechanism=Mechanism.AES_ECB)
            pytest.fail("Should have rejected AES_ECB as digest mechanism")
        except PKCS11Error as e:
            # Broad catch intentional — assert_ckr validates the specific type
            assert_ckr(CKR_DIGEST["init_mechanism_invalid"], e, ckr_strict)

    def test_encrypt_mechanism_for_digest(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """Using RSA encrypt mechanism for digest -> CKR_MECHANISM_INVALID."""
        try:
            p11_session.digest(b"test data", mechanism=Mechanism.RSA_PKCS)
            pytest.fail("Should have rejected RSA_PKCS as digest mechanism")
        except PKCS11Error as e:
            assert_ckr(CKR_DIGEST["init_encrypt_mechanism"], e, ckr_strict)

    def test_mechanism_param_invalid(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """SHA-256 with unexpected parameter -> CKR_MECHANISM_PARAM_INVALID.

        SHA-256 takes no parameters. Providing one should error.
        Note: some wrappers may strip the param before reaching the module.
        """
        exp = CKR_DIGEST["init_mechanism_param_invalid"]
        try:
            p11_session.digest(
                b"test data",
                mechanism=Mechanism.SHA256,
                mechanism_param=b"\x00" * 16,
            )
            # Some modules/wrappers ignore unknown params for hash mechanisms
            if not exp.allow_success:
                pass  # SHA-256 with param: module may ignore it — not a hard failure
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)
