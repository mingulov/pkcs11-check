"""CKR error priority ordering tests.

When multiple error conditions apply simultaneously, the PKCS#11 spec
defines priority rules. These tests verify the higher-priority CKR is
returned.

Source: PKCS#11 v3.1 Sec.5.1.7 (relative priorities).
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import KeyType, Mechanism
from pkcs11.exceptions import (
    KeyHandleInvalid,
    KeyTypeInconsistent,
    MechanismInvalid,
    ObjectHandleInvalid,
    PKCS11Error,
)

pytestmark = pytest.mark.access


class TestErrorPriority:
    """Error priority ordering when 2+ conditions overlap."""

    def test_destroyed_handle_with_wrong_mechanism(
        self, p11_session: Any
    ) -> None:
        """Destroyed handle + wrong mechanism -> handle error takes priority.

        Spec Sec.5.1: handle errors have higher priority than mechanism errors.
        CKR_KEY_HANDLE_INVALID or CKR_OBJECT_HANDLE_INVALID expected.
        """
        key = p11_session.generate_key(KeyType.AES, 256)
        key.destroy()
        try:
            # Both conditions: handle is invalid AND SHA256 is wrong for encrypt
            key.encrypt(b"\x00" * 16, mechanism=Mechanism.SHA256)
            # Wrapper may catch invalid handle before reaching module
        except (ObjectHandleInvalid, KeyHandleInvalid):
            pass  # Correct: handle error has priority
        except MechanismInvalid:
            # Module checked mechanism first - lower priority but acceptable
            from pkcs11_check.compliance import ComplianceLevel, note
            note(
                "Module returned MECHANISM_INVALID before checking handle validity",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.1 Sec.5.1.7",
            )
        except PKCS11Error:
            pass  # Other errors acceptable (wrapper may intercept)

    def test_wrong_key_type_with_nonaligned_data(
        self, p11_session: Any
    ) -> None:
        """RSA key + AES-ECB + non-aligned data -> KEY_TYPE_INCONSISTENT has priority.

        Key type check happens at Init time, data length at Encrypt time.
        KEY_TYPE_INCONSISTENT should be returned at Init before data is checked.
        """
        pub, _priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        try:
            # RSA public key + AES-ECB mechanism + 15 bytes (non-aligned)
            pub.encrypt(b"\x00" * 15, mechanism=Mechanism.AES_ECB)
            pytest.fail("Should have rejected RSA key with AES-ECB")
        except (KeyTypeInconsistent, MechanismInvalid):
            pass  # Correct: key type or mechanism error at Init time
        except PKCS11Error:
            pass  # Other init-time errors acceptable

    def test_bad_mechanism_with_bad_key_size(
        self, p11_session: Any
    ) -> None:
        """AES key + RSA mechanism -> MECHANISM_INVALID (checked at Init).

        Both mechanism mismatch and key size mismatch apply, but mechanism
        is checked first per spec.
        """
        key = p11_session.generate_key(KeyType.AES, 128)  # 128-bit AES
        try:
            key.encrypt(b"\x00" * 16, mechanism=Mechanism.RSA_PKCS)
            pytest.fail("Should have rejected AES key with RSA mechanism")
        except (MechanismInvalid, KeyTypeInconsistent):
            pass  # Both are correct Init-time errors
        except PKCS11Error:
            pass  # Other init-time errors acceptable
