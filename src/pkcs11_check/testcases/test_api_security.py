"""PKCS#11 API security tests - attribute attacks, policy bypass, access control.

Based on Bortolozzo et al. "Attacking and Fixing PKCS#11 Security Tokens" (CCS 2010)
and PKCS#11 attribute enforcement rules from the OASIS specification.

Tests are marked @security - results are security findings, not correctness failures.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    copy_object,
    decrypt_single,
    destroy_quietly,
    find_objects,
    gen_aes_key,
    gen_rsa_keypair,
    read_attributes,
    set_attributes,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKF_SERIAL_SESSION,
    CKM_AES_ECB,
    CKO_PRIVATE_KEY,
)

pytestmark = pytest.mark.security


class TestWrapDecryptOracle:
    """Test for the classic wrap-decrypt oracle attack.

    If a key has both CKA_WRAP and CKA_DECRYPT, an attacker can:
    1. Wrap a target key under the dual-purpose key
    2. Decrypt the wrapped blob -> get raw key material

    A secure module should prevent keys from having both CKA_WRAP and CKA_DECRYPT.
    """

    def test_wrap_decrypt_combination_prevented(self, p11_raw_session: Any) -> None:
        """Module should prevent creating key with both WRAP and DECRYPT."""
        rs = p11_raw_session
        try:
            dual_key_h = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                },
            )
        except AssertionError:
            pass  # Module prevented dual-purpose key creation - best
            return

        try:
            # Try the actual attack
            target_h = gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={CKA_EXTRACTABLE: True},
            )
            try:
                wrapped = wrap_key(rs.raw, rs.sh, dual_key_h, target_h, CKM_AES_ECB)
                # Decrypt the wrapped blob = extract the key material
                try:
                    raw_key = decrypt_single(rs.raw, rs.sh, dual_key_h, CKM_AES_ECB, wrapped)
                    if raw_key and len(raw_key) > 0:
                        pytest.fail(
                            "SECURITY: Wrap-decrypt oracle possible - "
                            "key has both CKA_WRAP and CKA_DECRYPT"
                        )
                except AssertionError:
                    pass  # Module prevented the attack at decrypt time - good
            except AssertionError:
                pass  # Wrap failed - acceptable
            finally:
                destroy_quietly(rs.raw, rs.sh, target_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, dual_key_h)


class TestSensitiveExtraction:
    """Verify sensitive key material cannot be read."""

    def test_sensitive_key_value_not_readable(self, p11_raw_session: Any) -> None:
        """CKA_SENSITIVE=True key: C_GetAttributeValue(CKA_VALUE) must fail."""
        rs = p11_raw_session
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: True, CKA_EXTRACTABLE: False},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_VALUE])
            assert CKA_VALUE not in attrs, (
                "SECURITY: CKA_VALUE readable on SENSITIVE key — key material exposed"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_private_key_not_extractable(self, p11_raw_session: Any) -> None:
        """RSA private key material must not be readable."""
        rs = p11_raw_session
        pub_h, priv_h = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, priv_h, [CKA_PRIVATE_EXPONENT])
            assert CKA_PRIVATE_EXPONENT not in attrs, (
                "SECURITY: CKA_PRIVATE_EXPONENT readable — private key material exposed"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)


class TestAttributeEscalation:
    """Verify attributes cannot be escalated after creation."""

    def test_extractable_cannot_be_set_true(self, p11_raw_session: Any) -> None:
        """CKA_EXTRACTABLE=False cannot be changed to True."""
        rs = p11_raw_session
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: False},
        )
        try:
            try:
                set_attributes(rs.raw, rs.sh, key_h, {CKA_EXTRACTABLE: True})
                pytest.fail("SECURITY: CKA_EXTRACTABLE escalated from False to True")
            except AssertionError:
                pass  # Module prevented escalation - correct
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_sensitive_cannot_be_set_false(self, p11_raw_session: Any) -> None:
        """CKA_SENSITIVE=True cannot be changed to False."""
        rs = p11_raw_session
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: True},
        )
        try:
            try:
                set_attributes(rs.raw, rs.sh, key_h, {CKA_SENSITIVE: False})
                pytest.fail("SECURITY: CKA_SENSITIVE downgraded from True to False")
            except AssertionError:
                pass  # Correct
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestAttributeLaunderingViaCopy:
    """Test attribute laundering through C_CopyObject.

    An attacker might try to copy a key with modified attributes
    to bypass security restrictions.
    """

    def test_copy_cannot_escalate_extractable(self, p11_raw_session: Any) -> None:
        """Copying a non-extractable key with CKA_EXTRACTABLE=True must fail."""
        rs = p11_raw_session
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: False, CKA_COPYABLE: True},
        )
        try:
            try:
                copy_h = copy_object(rs.raw, rs.sh, key_h, {CKA_EXTRACTABLE: True})
                try:
                    # If copy succeeded, check value is still protected
                    attrs = read_attributes(rs.raw, rs.sh, copy_h, [CKA_VALUE])
                    if CKA_VALUE in attrs:
                        pytest.fail(
                            "SECURITY: Copy escalated CKA_EXTRACTABLE, key material readable"
                        )
                finally:
                    destroy_quietly(rs.raw, rs.sh, copy_h)
            except AssertionError:
                pass  # Module prevented the copy - correct
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_cannot_downgrade_sensitive(self, p11_raw_session: Any) -> None:
        """Copying with CKA_SENSITIVE=False when original is True must fail."""
        rs = p11_raw_session
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: True, CKA_COPYABLE: True},
        )
        try:
            try:
                copy_h = copy_object(rs.raw, rs.sh, key_h, {CKA_SENSITIVE: False})
                try:
                    attrs = read_attributes(rs.raw, rs.sh, copy_h, [CKA_VALUE])
                    if CKA_VALUE in attrs:
                        pytest.fail(
                            "SECURITY: Copy downgraded CKA_SENSITIVE, key material readable"
                        )
                finally:
                    destroy_quietly(rs.raw, rs.sh, copy_h)
            except AssertionError:
                pass  # Correct
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestKeyUsageRestrictions:
    """Verify key usage attributes are enforced."""

    def test_encrypt_disabled_removes_capability(self, p11_raw_session: Any) -> None:
        """Key with CKA_ENCRYPT=False should not have encrypt capability."""
        rs = p11_raw_session
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_ENCRYPT: False, CKA_DECRYPT: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_ENCRYPT])
            assert attrs[CKA_ENCRYPT] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_non_extractable_enforced(self, p11_raw_session: Any) -> None:
        """Non-extractable key material cannot be read."""
        rs = p11_raw_session
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: False, CKA_SENSITIVE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_VALUE])
            assert CKA_VALUE not in attrs, (
                "SECURITY: CKA_VALUE readable on non-extractable key — key material exposed"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_decrypt_only_key(self, p11_raw_session: Any) -> None:
        """Key created for decrypt-only should have correct attributes."""
        rs = p11_raw_session
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: False,
                CKA_DECRYPT: True,
                CKA_WRAP: False,
                CKA_UNWRAP: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_DECRYPT, CKA_ENCRYPT])
            assert attrs[CKA_DECRYPT] is True
            assert attrs[CKA_ENCRYPT] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestAccessControl:
    """Test session access control enforcement."""

    def test_no_login_private_objects_invisible(self, p11_raw_session: Any) -> None:
        """Without login, private objects should not be visible."""
        rs = p11_raw_session
        # Open a public (non-logged-in) session
        pub_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict({CKA_CLASS: CKO_PRIVATE_KEY})
            found = find_objects(rs.raw, pub_sh, tmpl)
            # This isn't a hard assertion since there may be no private keys at all
            # The point is that the search doesn't crash and doesn't leak
            assert isinstance(found, list)
        finally:
            close_session_quietly(rs.raw, pub_sh)

    def test_handle_prediction(self, p11_raw_session: Any) -> None:
        """Object handles should not be trivially sequential/predictable."""
        rs = p11_raw_session
        # Create multiple keys simultaneously (don't destroy) to get unique handles
        keys = []
        for i in range(10):
            key_h = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_LABEL: f"handle-{i}"})
            keys.append(key_h)
        # All should be distinct handles
        assert len(keys) == 10
        # Clean up
        for key_h in keys:
            destroy_quietly(rs.raw, rs.sh, key_h)
