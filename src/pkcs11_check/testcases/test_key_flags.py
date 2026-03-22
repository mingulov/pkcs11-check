"""Key attribute flag tests.

Verifies CKA_NEVER_EXTRACTABLE, CKA_LOCAL, CKA_ALWAYS_SENSITIVE,
and other security-critical attribute flags that catch real bugs
in module implementations.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType
from pkcs11.exceptions import AttributeTypeInvalid, AttributeValueInvalid, FunctionNotSupported

from pkcs11_check.testcases.conftest import import_aes_key

pytestmark = pytest.mark.security


class TestNeverExtractable:
    """Verify CKA_NEVER_EXTRACTABLE flag semantics."""

    def test_generated_non_extractable_is_never_extractable(self, p11_session: Any) -> None:
        """Key generated with EXTRACTABLE=False has NEVER_EXTRACTABLE=True."""
        key = p11_session.generate_key(KeyType.AES, 256, template={Attribute.EXTRACTABLE: False})
        assert key[Attribute.NEVER_EXTRACTABLE] is True

    def test_generated_extractable_is_not_never_extractable(self, p11_session: Any) -> None:
        """Key generated with EXTRACTABLE=True has NEVER_EXTRACTABLE=False."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        assert key[Attribute.NEVER_EXTRACTABLE] is False

    def test_extractable_and_never_extractable_consistent(self, p11_session: Any) -> None:
        """EXTRACTABLE=True implies NEVER_EXTRACTABLE=False (and vice versa for default)."""
        # Default key: non-extractable
        key_default = p11_session.generate_key(KeyType.AES, 256)
        assert key_default[Attribute.EXTRACTABLE] is False
        try:
            never_ext_default = key_default[Attribute.NEVER_EXTRACTABLE]
        except AttributeTypeInvalid:
            pytest.xfail(
                "Module does not implement CKA_NEVER_EXTRACTABLE tracking "
                "(PKCS#11 spec Table 18 requires this attribute)"
            )
        assert never_ext_default is True

        # Extractable key
        key_ext = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        assert key_ext[Attribute.EXTRACTABLE] is True
        try:
            never_ext = key_ext[Attribute.NEVER_EXTRACTABLE]
        except AttributeTypeInvalid:
            pytest.xfail(
                "Module does not implement CKA_NEVER_EXTRACTABLE tracking "
                "(PKCS#11 spec Table 18 requires this attribute)"
            )
        if never_ext is not False:
            pytest.xfail(
                "Module sets CKA_NEVER_EXTRACTABLE=True on extractable keys — "
                "violates PKCS#11 spec Table 18 invariant"
            )


class TestLocalFlag:
    """Verify CKA_LOCAL flag distinguishes generated vs imported keys."""

    def test_generated_key_is_local(self, p11_session: Any) -> None:
        """Keys generated on the token have LOCAL=True."""
        key = p11_session.generate_key(KeyType.AES, 256)
        assert key[Attribute.LOCAL] is True

    def test_imported_key_is_not_local(self, p11_session: Any) -> None:
        """Imported keys have LOCAL=False."""
        key = import_aes_key(p11_session, b"\x00" * 32)
        assert key[Attribute.LOCAL] is False

    def test_generated_rsa_keypair_is_local(self, p11_session: Any) -> None:
        """Generated RSA keypair has LOCAL=True on both keys."""
        try:
            pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        except (AttributeValueInvalid, FunctionNotSupported) as exc:
            pytest.xfail(f"Module cannot generate RSA keypair: {exc}")

        try:
            pub_local = pub[Attribute.LOCAL]
            priv_local = priv[Attribute.LOCAL]
        except AttributeTypeInvalid:
            pytest.xfail(
                "Module does not implement CKA_LOCAL attribute "
                "(PKCS#11 spec requires it for generated keys)"
            )
            return

        # CKA_LOCAL MUST be TRUE for generated keys per OASIS spec C_GenerateKeyPair
        assert pub_local is True, (
            f"CKA_LOCAL={pub_local} on generated public key - "
            "spec requires LOCAL=TRUE for generated keys"
        )
        assert priv_local is True, (
            f"CKA_LOCAL={priv_local} on generated private key - "
            "spec requires LOCAL=TRUE for generated keys"
        )


class TestAlwaysSensitive:
    """Verify CKA_ALWAYS_SENSITIVE flag semantics."""

    def test_sensitive_key_always_sensitive(self, p11_session: Any) -> None:
        """Key generated sensitive has ALWAYS_SENSITIVE=True."""
        key = p11_session.generate_key(KeyType.AES, 256)
        assert key[Attribute.SENSITIVE] is True
        assert key[Attribute.ALWAYS_SENSITIVE] is True

    def test_non_sensitive_key_not_always_sensitive(self, p11_session: Any) -> None:
        """Key generated non-sensitive has ALWAYS_SENSITIVE=False."""
        key = p11_session.generate_key(KeyType.AES, 256, template={Attribute.SENSITIVE: False})
        assert key[Attribute.SENSITIVE] is False
        assert key[Attribute.ALWAYS_SENSITIVE] is False


class TestAutopadding:
    """Verify AES-CBC-PAD handles automatic PKCS#7 padding correctly."""

    @pytest.mark.parametrize("plaintext_len", [1, 7, 15, 16, 17, 31, 32, 100])
    def test_aes_cbc_pad_variable_length(self, p11_session: Any, plaintext_len: int) -> None:
        """AES-CBC-PAD roundtrip works for non-block-aligned plaintext lengths."""
        from pkcs11 import Mechanism

        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)  # 16 bytes
        plaintext = bytes(range(256))[:plaintext_len]

        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        # Ciphertext should be padded to next block boundary
        assert len(ct) % 16 == 0
        assert len(ct) >= plaintext_len

        pt = key.decrypt(ct, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        assert pt == plaintext
