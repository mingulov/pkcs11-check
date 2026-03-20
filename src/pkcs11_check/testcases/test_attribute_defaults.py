"""Default attribute value tests.

Verifies that newly generated keys and objects have correct default
attribute values — especially security-critical defaults like
CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_LOCAL, CKA_ALWAYS_SENSITIVE,
and CKA_NEVER_EXTRACTABLE.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import AttributeTypeInvalid

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = [pytest.mark.object]


def _read_attr(obj: Any, attr: Any) -> Any:
    """Read an attribute, skipping if the module doesn't support it."""
    try:
        return obj[attr]
    except AttributeTypeInvalid as e:
        pytest.skip(f"Module does not expose {attr!r}: {e}")


class TestSecretKeyDefaults:
    """Verify default attribute values on a newly generated AES-256 key.

    Only CKA_TOKEN=False is set explicitly; all other attributes
    should reflect the module's defaults.
    """

    @pytest.fixture()
    def aes_key(self, p11_session: Any) -> Any:
        """Generate an AES-256 key with minimal template."""
        key = p11_session.generate_key(
            KeyType.AES, 256, template={Attribute.TOKEN: False}
        )
        yield key
        key.destroy()

    def test_token_is_false(self, aes_key: Any) -> None:
        """CKA_TOKEN is False (explicitly set)."""
        assert aes_key[Attribute.TOKEN] is False

    def test_local_is_true(self, aes_key: Any) -> None:
        """CKA_LOCAL should be True for a generated key."""
        assert aes_key[Attribute.LOCAL] is True

    def test_sensitive_is_bool(self, aes_key: Any) -> None:
        """CKA_SENSITIVE defaults to a boolean (True on most modules)."""
        val = _read_attr(aes_key, Attribute.SENSITIVE)
        assert isinstance(val, bool)

    def test_extractable_is_bool(self, aes_key: Any) -> None:
        """CKA_EXTRACTABLE defaults to a boolean (False on most modules)."""
        val = _read_attr(aes_key, Attribute.EXTRACTABLE)
        assert isinstance(val, bool)

    def test_modifiable_default(self, aes_key: Any) -> None:
        """CKA_MODIFIABLE defaults to True."""
        val = _read_attr(aes_key, Attribute.MODIFIABLE)
        assert val is True

    def test_copyable_default(self, aes_key: Any) -> None:
        """CKA_COPYABLE defaults to True."""
        val = _read_attr(aes_key, Attribute.COPYABLE)
        assert val is True

    def test_destroyable_default(self, aes_key: Any) -> None:
        """CKA_DESTROYABLE defaults to True."""
        val = _read_attr(aes_key, Attribute.DESTROYABLE)
        assert val is True

    def test_private_default(self, aes_key: Any) -> None:
        """CKA_PRIVATE defaults to True for secret keys."""
        val = _read_attr(aes_key, Attribute.PRIVATE)
        assert val is True

    def test_always_sensitive_consistent(self, aes_key: Any) -> None:
        """CKA_ALWAYS_SENSITIVE is True when SENSITIVE defaults to True."""
        sensitive = _read_attr(aes_key, Attribute.SENSITIVE)
        always_sensitive = _read_attr(aes_key, Attribute.ALWAYS_SENSITIVE)
        if sensitive:
            assert always_sensitive is True
        else:
            # If SENSITIVE defaults to False, ALWAYS_SENSITIVE must be False
            assert always_sensitive is False

    def test_never_extractable_consistent(self, aes_key: Any) -> None:
        """CKA_NEVER_EXTRACTABLE is True when EXTRACTABLE defaults to False."""
        extractable = _read_attr(aes_key, Attribute.EXTRACTABLE)
        never_extractable = _read_attr(aes_key, Attribute.NEVER_EXTRACTABLE)
        if not extractable:
            assert never_extractable is True
        else:
            # If EXTRACTABLE defaults to True, NEVER_EXTRACTABLE must be False
            assert never_extractable is False


class TestKeyPairDefaults:
    """Verify default attribute values on a newly generated RSA-2048 keypair."""

    @pytest.fixture()
    def rsa_keypair(self, p11_session: Any, p11_module: Any) -> Any:
        """Generate an RSA-2048 keypair with minimal template."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        yield pub, priv
        pub.destroy()
        priv.destroy()

    def test_public_key_local(self, rsa_keypair: Any) -> None:
        """Public key CKA_LOCAL should be True."""
        pub, _priv = rsa_keypair
        assert pub[Attribute.LOCAL] is True

    def test_private_key_local(self, rsa_keypair: Any) -> None:
        """Private key CKA_LOCAL should be True."""
        _pub, priv = rsa_keypair
        assert priv[Attribute.LOCAL] is True

    def test_private_key_sensitive(self, rsa_keypair: Any) -> None:
        """Private key CKA_SENSITIVE defaults to True."""
        _pub, priv = rsa_keypair
        val = _read_attr(priv, Attribute.SENSITIVE)
        assert val is True

    def test_private_key_extractable(self, rsa_keypair: Any) -> None:
        """Private key CKA_EXTRACTABLE defaults to False."""
        _pub, priv = rsa_keypair
        val = _read_attr(priv, Attribute.EXTRACTABLE)
        assert val is False

    def test_private_key_private(self, rsa_keypair: Any) -> None:
        """Private key CKA_PRIVATE defaults to True."""
        _pub, priv = rsa_keypair
        val = _read_attr(priv, Attribute.PRIVATE)
        assert val is True

    def test_public_key_encrypt_is_bool(self, rsa_keypair: Any) -> None:
        """Public key CKA_ENCRYPT is a boolean."""
        pub, _priv = rsa_keypair
        val = _read_attr(pub, Attribute.ENCRYPT)
        assert isinstance(val, bool)

    def test_public_key_verify_is_bool(self, rsa_keypair: Any) -> None:
        """Public key CKA_VERIFY is a boolean."""
        pub, _priv = rsa_keypair
        val = _read_attr(pub, Attribute.VERIFY)
        assert isinstance(val, bool)

    def test_private_key_sign_is_bool(self, rsa_keypair: Any) -> None:
        """Private key CKA_SIGN is a boolean."""
        _pub, priv = rsa_keypair
        val = _read_attr(priv, Attribute.SIGN)
        assert isinstance(val, bool)

    def test_private_key_decrypt_is_bool(self, rsa_keypair: Any) -> None:
        """Private key CKA_DECRYPT is a boolean."""
        _pub, priv = rsa_keypair
        val = _read_attr(priv, Attribute.DECRYPT)
        assert isinstance(val, bool)


class TestDataObjectDefaults:
    """Verify default attribute values on a CKO_DATA object."""

    @pytest.fixture()
    def data_obj(self, p11_session: Any) -> Any:
        """Create a CKO_DATA object with minimal template."""
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.VALUE: b"test-defaults",
                Attribute.TOKEN: False,
            }
        )
        yield obj
        obj.destroy()

    def test_token_is_false(self, data_obj: Any) -> None:
        """CKA_TOKEN is False (explicitly set)."""
        assert data_obj[Attribute.TOKEN] is False

    def test_modifiable_default(self, data_obj: Any) -> None:
        """CKA_MODIFIABLE defaults to True."""
        val = _read_attr(data_obj, Attribute.MODIFIABLE)
        assert val is True

    def test_private_is_bool(self, data_obj: Any) -> None:
        """CKA_PRIVATE defaults to a boolean (module-dependent)."""
        val = _read_attr(data_obj, Attribute.PRIVATE)
        assert isinstance(val, bool)
