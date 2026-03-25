"""Default attribute value tests.

Verifies that newly generated keys and objects have correct default
attribute values - especially security-critical defaults like
CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_LOCAL, CKA_ALWAYS_SENSITIVE,
and CKA_NEVER_EXTRACTABLE.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    gen_aes_key,
    gen_rsa_keypair,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_SENSITIVE,
    CKA_CLASS,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_DESTROYABLE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LOCAL,
    CKA_MODIFIABLE,
    CKA_NEVER_EXTRACTABLE,
    CKA_PRIVATE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKO_DATA,
)

pytestmark = [pytest.mark.object]


def _read_attr(raw: Any, sh: int, handle: int, attr: int) -> Any:
    """Read a single attribute, skipping if the module doesn't support it."""
    try:
        attrs = read_attributes(raw, sh, handle, [attr])
        return attrs[attr]
    except (AssertionError, Exception) as e:
        err_msg = str(e)
        if "CKR_ATTRIBUTE_TYPE_INVALID" in err_msg:
            pytest.skip(f"Module does not expose attribute 0x{attr:08X}: {e}")
        raise


class TestSecretKeyDefaults:
    """Verify default attribute values on a newly generated AES-256 key.

    Only CKA_TOKEN=False is set explicitly; all other attributes
    should reflect the module's defaults.
    """

    @pytest.fixture()
    def aes_key(self, p11_raw_session: Any) -> Any:
        """Generate an AES-256 key with minimal template."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES key generation not supported")
        try:
            key = gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_TOKEN): False})
        except (AssertionError, Exception) as e:
            pytest.skip(f"Cannot generate AES key with minimal template: {e}")
        yield rs, key
        destroy_quietly(rs.raw, rs.sh, key)

    def test_token_is_false(self, aes_key: Any) -> None:
        """CKA_TOKEN is False (explicitly set)."""
        rs, key = aes_key
        attrs = read_attributes(rs.raw, rs.sh, key, [int(CKA_TOKEN)])
        assert attrs[int(CKA_TOKEN)] is False

    def test_local_is_true(self, aes_key: Any) -> None:
        """CKA_LOCAL should be True for a generated key."""
        rs, key = aes_key
        attrs = read_attributes(rs.raw, rs.sh, key, [int(CKA_LOCAL)])
        assert attrs[int(CKA_LOCAL)] is True

    def test_sensitive_is_bool(self, aes_key: Any) -> None:
        """CKA_SENSITIVE defaults to a boolean (True on most modules)."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, int(CKA_SENSITIVE))
        assert isinstance(val, bool)

    def test_extractable_is_bool(self, aes_key: Any) -> None:
        """CKA_EXTRACTABLE defaults to a boolean (False on most modules)."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, int(CKA_EXTRACTABLE))
        assert isinstance(val, bool)

    def test_modifiable_default(self, aes_key: Any) -> None:
        """CKA_MODIFIABLE defaults to True."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, int(CKA_MODIFIABLE))
        assert val is True

    def test_copyable_default(self, aes_key: Any) -> None:
        """CKA_COPYABLE defaults to True."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, int(CKA_COPYABLE))
        assert val is True

    def test_destroyable_default(self, aes_key: Any) -> None:
        """CKA_DESTROYABLE defaults to True."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, int(CKA_DESTROYABLE))
        assert val is True

    def test_private_default(self, aes_key: Any) -> None:
        """CKA_PRIVATE defaults to True for secret keys."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, int(CKA_PRIVATE))
        assert val is True

    def test_always_sensitive_consistent(self, aes_key: Any) -> None:
        """CKA_ALWAYS_SENSITIVE is True when SENSITIVE defaults to True."""
        rs, key = aes_key
        sensitive = _read_attr(rs.raw, rs.sh, key, int(CKA_SENSITIVE))
        always_sensitive = _read_attr(rs.raw, rs.sh, key, int(CKA_ALWAYS_SENSITIVE))
        if sensitive:
            assert always_sensitive is True
        else:
            # If SENSITIVE defaults to False, ALWAYS_SENSITIVE must be False
            assert always_sensitive is False

    def test_never_extractable_consistent(self, aes_key: Any) -> None:
        """CKA_NEVER_EXTRACTABLE is True when EXTRACTABLE defaults to False."""
        rs, key = aes_key
        extractable = _read_attr(rs.raw, rs.sh, key, int(CKA_EXTRACTABLE))
        never_extractable = _read_attr(rs.raw, rs.sh, key, int(CKA_NEVER_EXTRACTABLE))
        if not extractable:
            assert never_extractable is True
        else:
            # If EXTRACTABLE defaults to True, NEVER_EXTRACTABLE must be False
            assert never_extractable is False


class TestKeyPairDefaults:
    """Verify default attribute values on a newly generated RSA-2048 keypair."""

    @pytest.fixture()
    def rsa_keypair(self, p11_raw_session: Any) -> Any:
        """Generate an RSA-2048 keypair with minimal template."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        try:
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        except (AssertionError, Exception) as e:
            pytest.skip(f"Cannot generate RSA-2048 keypair: {e}")
        yield rs, pub, priv
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)

    def test_public_key_local(self, rsa_keypair: Any) -> None:
        """Public key CKA_LOCAL should be True."""
        rs, pub, _priv = rsa_keypair
        attrs = read_attributes(rs.raw, rs.sh, pub, [int(CKA_LOCAL)])
        assert attrs[int(CKA_LOCAL)] is True

    def test_private_key_local(self, rsa_keypair: Any) -> None:
        """Private key CKA_LOCAL should be True."""
        rs, _pub, priv = rsa_keypair
        attrs = read_attributes(rs.raw, rs.sh, priv, [int(CKA_LOCAL)])
        assert attrs[int(CKA_LOCAL)] is True

    def test_private_key_sensitive(self, rsa_keypair: Any) -> None:
        """Private key CKA_SENSITIVE is a boolean.

        The PKCS#11 spec does not mandate a default for CKA_SENSITIVE --
        it is implementation-defined. The raw API does not force it, so
        the module may default to either True or False.
        """
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, int(CKA_SENSITIVE))
        assert isinstance(val, bool)

    def test_private_key_extractable(self, rsa_keypair: Any) -> None:
        """Private key CKA_EXTRACTABLE defaults to False."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, int(CKA_EXTRACTABLE))
        assert val is False

    def test_private_key_private(self, rsa_keypair: Any) -> None:
        """Private key CKA_PRIVATE defaults to True."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, int(CKA_PRIVATE))
        assert val is True

    def test_public_key_encrypt_is_bool(self, rsa_keypair: Any) -> None:
        """Public key CKA_ENCRYPT is a boolean."""
        rs, pub, _priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, pub, int(CKA_ENCRYPT))
        assert isinstance(val, bool)

    def test_public_key_verify_is_bool(self, rsa_keypair: Any) -> None:
        """Public key CKA_VERIFY is a boolean."""
        rs, pub, _priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, pub, int(CKA_VERIFY))
        assert isinstance(val, bool)

    def test_private_key_sign_is_bool(self, rsa_keypair: Any) -> None:
        """Private key CKA_SIGN is a boolean."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, int(CKA_SIGN))
        assert isinstance(val, bool)

    def test_private_key_decrypt_is_bool(self, rsa_keypair: Any) -> None:
        """Private key CKA_DECRYPT is a boolean."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, int(CKA_DECRYPT))
        assert isinstance(val, bool)


class TestDataObjectDefaults:
    """Verify default attribute values on a CKO_DATA object."""

    @pytest.fixture()
    def data_obj(self, p11_raw_session: Any) -> Any:
        """Create a CKO_DATA object with minimal template."""
        rs = p11_raw_session
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_VALUE): b"test-defaults",
            int(CKA_TOKEN): False,
        })
        yield rs, h
        destroy_quietly(rs.raw, rs.sh, h)

    def test_token_is_false(self, data_obj: Any) -> None:
        """CKA_TOKEN is False (explicitly set)."""
        rs, h = data_obj
        attrs = read_attributes(rs.raw, rs.sh, h, [int(CKA_TOKEN)])
        assert attrs[int(CKA_TOKEN)] is False

    def test_modifiable_default(self, data_obj: Any) -> None:
        """CKA_MODIFIABLE defaults to True."""
        rs, h = data_obj
        val = _read_attr(rs.raw, rs.sh, h, int(CKA_MODIFIABLE))
        assert val is True

    def test_private_is_bool(self, data_obj: Any) -> None:
        """CKA_PRIVATE defaults to a boolean (module-dependent)."""
        rs, h = data_obj
        val = _read_attr(rs.raw, rs.sh, h, int(CKA_PRIVATE))
        assert isinstance(val, bool)
