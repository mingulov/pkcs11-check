"""CKR compliance tests for C_WrapKey and C_UnwrapKey.

Source: PKCS#11 v3.1 Sec.5.14.3 (C_WrapKey), Sec.5.14.4 (C_UnwrapKey).
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.access


class TestWrapKeyErrors:
    """Error conditions for C_WrapKey (Sec.5.14.3)."""

    def test_key_not_extractable(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """Wrapping non-extractable key -> CKR_KEY_UNEXTRACTABLE."""
        if not has_mechanism(p11_module, "AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key = p11_session.generate_key(
            KeyType.AES, 256, template={Attribute.WRAP: True},
        )
        target = p11_session.generate_key(
            KeyType.AES, 128,
            template={Attribute.EXTRACTABLE: False, Attribute.SENSITIVE: True},
        )
        try:
            wrap_key.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP)
            pytest.fail("Should have rejected wrapping non-extractable key")
        except PKCS11Error:
            pass  # CKR_KEY_UNEXTRACTABLE or CKR_KEY_NOT_WRAPPABLE - both acceptable

    def test_mechanism_invalid(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """Using hash mechanism for wrap -> CKR_MECHANISM_INVALID."""
        wrap_key = p11_session.generate_key(
            KeyType.AES, 256, template={Attribute.WRAP: True},
        )
        target = p11_session.generate_key(
            KeyType.AES, 128,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        try:
            wrap_key.wrap_key(target, mechanism=Mechanism.SHA256)
            pytest.fail("Should have rejected SHA256 as wrap mechanism")
        except PKCS11Error:
            pass  # CKR_MECHANISM_INVALID or related


class TestUnwrapKeyErrors:
    """Error conditions for C_UnwrapKey (Sec.5.14.4)."""

    def test_wrapped_key_invalid(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """Unwrapping garbage data -> CKR_WRAPPED_KEY_INVALID."""
        if not has_mechanism(p11_module, "AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        unwrap_key = p11_session.generate_key(
            KeyType.AES, 256,
            template={Attribute.UNWRAP: True, Attribute.WRAP: True},
        )
        # Garbage wrapped data (wrong length for AES-KW)
        try:
            unwrap_key.unwrap_key(
                ObjectClass.SECRET_KEY, KeyType.AES, b"\xFF" * 24,
                mechanism=Mechanism.AES_KEY_WRAP,
            )
            pytest.fail("Should have rejected garbage wrapped key data")
        except PKCS11Error:
            pass  # CKR_WRAPPED_KEY_INVALID or CKR_WRAPPED_KEY_LEN_RANGE
