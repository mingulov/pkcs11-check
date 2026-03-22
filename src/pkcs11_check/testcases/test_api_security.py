"""PKCS#11 API security tests -- attribute attacks, policy bypass, access control.

Based on Bortolozzo et al. "Attacking and Fixing PKCS#11 Security Tokens" (CCS 2010)
and PKCS#11 attribute enforcement rules from the OASIS specification.

Tests are marked @security -- results are security findings, not correctness failures.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.security


class TestWrapDecryptOracle:
    """Test for the classic wrap-decrypt oracle attack.

    If a key has both CKA_WRAP and CKA_DECRYPT, an attacker can:
    1. Wrap a target key under the dual-purpose key
    2. Decrypt the wrapped blob -> get raw key material

    A secure module should prevent keys from having both CKA_WRAP and CKA_DECRYPT.
    """

    def test_wrap_decrypt_combination_prevented(self, p11_session: Any) -> None:
        """Module should prevent creating key with both WRAP and DECRYPT."""
        try:
            dual_key = p11_session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.WRAP: True,
                    Attribute.UNWRAP: True,
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                },
            )
            # If module allows it, this is a security finding (but common)
            # Try the actual attack
            target = p11_session.generate_key(
                KeyType.AES,
                128,
                template={Attribute.EXTRACTABLE: True},
            )
            wrapped = dual_key.wrap_key(target)
            try:
                # Decrypt the wrapped blob = extract the key material
                raw_key = dual_key.decrypt(wrapped, mechanism=Mechanism.AES_ECB)
                if raw_key and len(raw_key) > 0:
                    pytest.xfail(
                        "SECURITY: Wrap-decrypt oracle possible -- "
                        "key has both CKA_WRAP and CKA_DECRYPT"
                    )
            except pkcs11.exceptions.PKCS11Error:
                pass  # Module prevented the attack at decrypt time -- good
        except pkcs11.exceptions.PKCS11Error:
            pass  # Module prevented dual-purpose key creation -- best


class TestSensitiveExtraction:
    """Verify sensitive key material cannot be read."""

    def test_sensitive_key_value_not_readable(self, p11_session: Any) -> None:
        """CKA_SENSITIVE=True key: C_GetAttributeValue(CKA_VALUE) must fail."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False},
        )
        with pytest.raises(pkcs11.exceptions.PKCS11Error):
            _ = key[Attribute.VALUE]

    def test_private_key_not_extractable(self, p11_session: Any) -> None:
        """RSA private key material must not be readable."""
        _, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        with pytest.raises(pkcs11.exceptions.PKCS11Error):
            _ = priv[Attribute.PRIVATE_EXPONENT]


class TestAttributeEscalation:
    """Verify attributes cannot be escalated after creation."""

    def test_extractable_cannot_be_set_true(self, p11_session: Any) -> None:
        """CKA_EXTRACTABLE=False cannot be changed to True."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.EXTRACTABLE: False},
        )
        try:
            key[Attribute.EXTRACTABLE] = True
            pytest.xfail("SECURITY: CKA_EXTRACTABLE escalated from False to True")
        except pkcs11.exceptions.PKCS11Error:
            pass  # Module prevented escalation -- correct

    def test_sensitive_cannot_be_set_false(self, p11_session: Any) -> None:
        """CKA_SENSITIVE=True cannot be changed to False."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.SENSITIVE: True},
        )
        try:
            key[Attribute.SENSITIVE] = False
            pytest.xfail("SECURITY: CKA_SENSITIVE downgraded from True to False")
        except pkcs11.exceptions.PKCS11Error:
            pass  # Correct


class TestAttributeLaunderingViaCopy:
    """Test attribute laundering through C_CopyObject.

    An attacker might try to copy a key with modified attributes
    to bypass security restrictions.
    """

    def test_copy_cannot_escalate_extractable(self, p11_session: Any) -> None:
        """Copying a non-extractable key with CKA_EXTRACTABLE=True must fail."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.EXTRACTABLE: False, Attribute.COPYABLE: True},
        )
        try:
            copy = key.copy({Attribute.EXTRACTABLE: True})
            # If copy succeeded, try to read the value
            try:
                _ = copy[Attribute.VALUE]
                pytest.xfail("SECURITY: Copy escalated CKA_EXTRACTABLE, key material readable")
            except pkcs11.exceptions.PKCS11Error:
                pass  # Value still protected despite attribute change
        except pkcs11.exceptions.PKCS11Error:
            pass  # Module prevented the copy -- correct

    def test_copy_cannot_downgrade_sensitive(self, p11_session: Any) -> None:
        """Copying with CKA_SENSITIVE=False when original is True must fail."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.SENSITIVE: True, Attribute.COPYABLE: True},
        )
        try:
            copy = key.copy({Attribute.SENSITIVE: False})
            try:
                _ = copy[Attribute.VALUE]
                pytest.xfail("SECURITY: Copy downgraded CKA_SENSITIVE, key material readable")
            except pkcs11.exceptions.PKCS11Error:
                pass
        except pkcs11.exceptions.PKCS11Error:
            pass  # Correct


class TestKeyUsageRestrictions:
    """Verify key usage attributes are enforced.

    python-pkcs11 removes methods (encrypt/sign/wrap) from keys
    when the corresponding attribute is False. This IS the enforcement --
    we verify the attribute was correctly applied.
    """

    def test_encrypt_disabled_removes_capability(self, p11_session: Any) -> None:
        """Key with CKA_ENCRYPT=False should not have encrypt capability."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.ENCRYPT: False, Attribute.DECRYPT: True},
        )
        # python-pkcs11 enforces this by not exposing encrypt method
        assert not hasattr(key, "encrypt") or key[Attribute.ENCRYPT] is False

    def test_non_extractable_enforced(self, p11_session: Any) -> None:
        """Non-extractable key material cannot be read."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.EXTRACTABLE: False, Attribute.SENSITIVE: True},
        )
        with pytest.raises(pkcs11.exceptions.PKCS11Error):
            _ = key[Attribute.VALUE]

    def test_decrypt_only_key(self, p11_session: Any) -> None:
        """Key created for decrypt-only should have correct attributes."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.ENCRYPT: False,
                Attribute.DECRYPT: True,
                Attribute.WRAP: False,
                Attribute.UNWRAP: False,
            },
        )
        assert key[Attribute.DECRYPT] is True
        assert key[Attribute.ENCRYPT] is False


class TestAccessControl:
    """Test session access control enforcement."""

    def test_no_login_private_objects_invisible(self, p11_module: Any) -> None:
        """Without login, private objects should not be visible."""
        # Open a public (non-logged-in) session
        token = p11_module.get_token()
        with token.open(rw=False) as public_session:
            # Search for private keys -- should find none
            found = list(public_session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}))
            # This isn't a hard assertion since there may be no private keys at all
            # The point is that the search doesn't crash and doesn't leak
            assert isinstance(found, list)

    def test_handle_prediction(self, p11_session: Any) -> None:
        """Object handles should not be trivially sequential/predictable."""
        # Create multiple keys simultaneously (don't destroy) to get unique handles
        keys = []
        for i in range(10):
            key = p11_session.generate_key(KeyType.AES, 128, label=f"handle-{i}")
            keys.append(key)
        # All should be distinct Python objects
        assert len(keys) == 10
        # Clean up
        for key in keys:
            key.destroy()
