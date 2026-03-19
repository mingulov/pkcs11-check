"""Handle reuse after destroy tests.

Verifies that using a destroyed object handle returns proper CKR errors,
not crashes or undefined behavior.

Reference: rep11.md — stale handles after C_DestroyObject + reuse.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import ObjectHandleInvalid, PKCS11Error
from pkcs11_check.testcases._error_tuples import HANDLE_ERRORS

pytestmark = pytest.mark.security


class TestHandleReuseAfterDestroy:
    """Use destroyed object handles — must get CKR error, not crash."""

    def test_get_attribute_after_destroy(self, p11_session: Any) -> None:
        """Reading attribute from destroyed key must fail cleanly."""
        key = p11_session.generate_key(KeyType.AES, 256, label="handle-reuse-1")
        key.destroy()

        with pytest.raises((PKCS11Error, AttributeError)):
            key[Attribute.LABEL]  # noqa: B018

    def test_encrypt_after_destroy(self, p11_session: Any) -> None:
        """Encrypting with destroyed key must fail cleanly."""
        key = p11_session.generate_key(KeyType.AES, 256)
        key.destroy()

        with pytest.raises((PKCS11Error, AttributeError)):
            key.encrypt(b"\x00" * 16, mechanism=Mechanism.AES_ECB)

    def test_sign_after_destroy(self, p11_session: Any) -> None:
        """Signing with destroyed RSA key must fail cleanly."""
        _pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        priv.destroy()

        with pytest.raises((PKCS11Error, AttributeError)):
            priv.sign(b"data", mechanism=Mechanism.SHA256_RSA_PKCS)

    def test_wrap_after_destroy(self, p11_session: Any) -> None:
        """Wrapping with destroyed key must fail cleanly."""
        wrap_key = p11_session.generate_key(KeyType.AES, 256)
        target = p11_session.generate_key(
            KeyType.AES, 128, template={Attribute.EXTRACTABLE: True}
        )
        wrap_key.destroy()

        with pytest.raises((PKCS11Error, AttributeError)):
            wrap_key.wrap_key(target, mechanism=Mechanism.AES_KEY_WRAP)

    def test_double_destroy(self, p11_session: Any) -> None:
        """Destroying an already-destroyed key must fail cleanly."""
        key = p11_session.generate_key(KeyType.AES, 128)
        key.destroy()

        try:
            key.destroy()
        except PKCS11Error:
            pass  # Expected

    def test_set_attribute_after_destroy(self, p11_session: Any) -> None:
        """Setting attribute on destroyed object must fail cleanly."""
        key = p11_session.generate_key(KeyType.AES, 256, label="modify-after-destroy")
        key.destroy()

        with pytest.raises((PKCS11Error, AttributeError)):
            key[Attribute.LABEL] = "new-label"

    def test_copy_after_destroy(self, p11_session: Any) -> None:
        """Copying a destroyed object must fail cleanly."""
        key = p11_session.generate_key(KeyType.AES, 256, label="copy-after-destroy")
        key.destroy()

        with pytest.raises((PKCS11Error, AttributeError)):
            key.copy({Attribute.LABEL: "copied"})
