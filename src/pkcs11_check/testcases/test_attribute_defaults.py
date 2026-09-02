"""Default attribute value tests.

Verifies that newly generated keys and objects have correct default
attribute values - especially security-critical defaults like
CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_LOCAL, CKA_ALWAYS_SENSITIVE,
and CKA_NEVER_EXTRACTABLE.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.attr_metadata import ATTR_VALUE_TYPES
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError
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
    CKR_ATTRIBUTE_TYPE_INVALID,
)
from pkcs11_check.testcases._attribute_values import require_bool_attr
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    is_known_error,
    skip_if_data_objects_unsupported,
)

pytestmark = [pytest.mark.object]


def _read_attr(raw: Any, sh: int, handle: int, attr: int) -> Any:
    """Read a single attribute, skipping if the module doesn't support it."""
    try:
        attrs = read_attributes(raw, sh, handle, [attr])
        if attr not in attrs:
            pytest.skip(f"Module does not expose attribute 0x{attr:08X} (not in response)")
        value = attrs[attr]
        if ATTR_VALUE_TYPES.get(attr) == "bool":
            return require_bool_attr(value, f"attribute 0x{attr:08X}")
        return value
    except CkrAssertionError as e:
        if is_known_error(e, {CKR_ATTRIBUTE_TYPE_INVALID}):
            pytest.skip(f"Module does not expose attribute 0x{attr:08X}: {e}")
        raise


class TestSecretKeyDefaults:
    """Verify default attribute values on a newly generated AES key.

    Only CKA_TOKEN=False is set explicitly; all other attributes
    should reflect the module's defaults.
    """

    @pytest.fixture()
    def aes_key(self, p11_raw_session: Any) -> Any:
        """Generate an AES setup key with minimal template."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_TOKEN: False},
            purpose="default attribute checks",
        )
        yield rs, key
        destroy_quietly(rs.raw, rs.sh, key)

    def test_token_is_false(self, aes_key: Any) -> None:
        """CKA_TOKEN is False (explicitly set)."""
        rs, key = aes_key
        attrs = read_attributes(rs.raw, rs.sh, key, [CKA_TOKEN])
        assert require_bool_attr(attrs[CKA_TOKEN], "CKA_TOKEN") is False

    def test_local_is_true(self, aes_key: Any) -> None:
        """CKA_LOCAL should be True for a generated key."""
        rs, key = aes_key
        attrs = read_attributes(rs.raw, rs.sh, key, [CKA_LOCAL])
        local = require_bool_attr(attrs[CKA_LOCAL], "CKA_LOCAL")
        if local is not True:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module returns CKA_LOCAL=False for generated secret key (spec requires True)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: CKA_LOCAL True if key generated on token",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_LOCAL default (generated AES key)",
                spec_ref="PKCS#11 v3.2",
                summary="Module returns CKA_LOCAL=False for generated key (spec violation)",
            )

    def test_sensitive_is_bool(self, aes_key: Any) -> None:
        """CKA_SENSITIVE defaults to a boolean (True on most modules)."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_SENSITIVE)
        assert isinstance(val, bool)

    def test_extractable_is_bool(self, aes_key: Any) -> None:
        """CKA_EXTRACTABLE defaults to a boolean (False on most modules)."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_EXTRACTABLE)
        assert isinstance(val, bool)

    def test_modifiable_default(self, aes_key: Any) -> None:
        """CKA_MODIFIABLE defaults to True."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_MODIFIABLE)
        assert val is True

    def test_copyable_default(self, aes_key: Any) -> None:
        """CKA_COPYABLE defaults to True."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_COPYABLE)
        assert val is True

    def test_destroyable_default(self, aes_key: Any) -> None:
        """CKA_DESTROYABLE defaults to True."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_DESTROYABLE)
        assert val is True

    def test_private_default(self, aes_key: Any) -> None:
        """CKA_PRIVATE defaults to True for secret keys."""
        rs, key = aes_key
        val = _read_attr(rs.raw, rs.sh, key, CKA_PRIVATE)
        if val is not True:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module defaults CKA_PRIVATE to False for secret keys (spec requires True)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: default CKA_PRIVATE is True for secret keys",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_PRIVATE default (secret key)",
                spec_ref="PKCS#11 v3.2",
                summary="Module defaults CKA_PRIVATE=False for secret keys (spec violation)",
            )

    def test_always_sensitive_consistent(self, aes_key: Any) -> None:
        """CKA_ALWAYS_SENSITIVE is True when SENSITIVE defaults to True."""
        rs, key = aes_key
        sensitive = _read_attr(rs.raw, rs.sh, key, CKA_SENSITIVE)
        always_sensitive = _read_attr(rs.raw, rs.sh, key, CKA_ALWAYS_SENSITIVE)
        if sensitive:
            assert always_sensitive is True
        else:
            # If SENSITIVE defaults to False, ALWAYS_SENSITIVE must be False
            assert always_sensitive is False

    def test_never_extractable_consistent(self, aes_key: Any) -> None:
        """CKA_NEVER_EXTRACTABLE is True when EXTRACTABLE defaults to False."""
        rs, key = aes_key
        extractable = _read_attr(rs.raw, rs.sh, key, CKA_EXTRACTABLE)
        never_extractable = _read_attr(rs.raw, rs.sh, key, CKA_NEVER_EXTRACTABLE)
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
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        yield rs, pub, priv
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)

    def test_public_key_local(self, rsa_keypair: Any) -> None:
        """Public key CKA_LOCAL should be True."""
        rs, pub, _priv = rsa_keypair
        attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_LOCAL])
        local = require_bool_attr(attrs[CKA_LOCAL], "CKA_LOCAL")
        if local is not True:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module returns CKA_LOCAL=False for generated RSA public key (spec requires True)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: CKA_LOCAL True if key generated on token",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_LOCAL default (RSA public key)",
                spec_ref="PKCS#11 v3.2",
                summary=(
                    "Module returns CKA_LOCAL=False for generated RSA public key (spec violation)"
                ),
            )

    def test_private_key_local(self, rsa_keypair: Any) -> None:
        """Private key CKA_LOCAL should be True."""
        rs, _pub, priv = rsa_keypair
        attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_LOCAL])
        local = require_bool_attr(attrs[CKA_LOCAL], "CKA_LOCAL")
        if local is not True:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module returns CKA_LOCAL=False for generated RSA private key (spec requires True)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: CKA_LOCAL True if key generated on token",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_LOCAL default (RSA private key)",
                spec_ref="PKCS#11 v3.2",
                summary=(
                    "Module returns CKA_LOCAL=False for generated RSA private key (spec violation)"
                ),
            )

    def test_private_key_sensitive(self, rsa_keypair: Any) -> None:
        """Private key CKA_SENSITIVE is a boolean.

        The PKCS#11 spec does not mandate a default for CKA_SENSITIVE --
        it is implementation-defined. The raw API does not force it, so
        the module may default to either True or False.
        """
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, CKA_SENSITIVE)
        assert isinstance(val, bool)

    def test_private_key_extractable(self, rsa_keypair: Any) -> None:
        """Private key CKA_EXTRACTABLE defaults to False."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, CKA_EXTRACTABLE)
        if val is not False:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module defaults CKA_EXTRACTABLE=True for RSA private key (spec recommends False)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: default CKA_EXTRACTABLE for private keys",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_EXTRACTABLE default (RSA private key)",
                spec_ref="PKCS#11 v3.2",
                summary="Module defaults CKA_EXTRACTABLE=True for RSA private key (spec violation)",
            )

    def test_private_key_private(self, rsa_keypair: Any) -> None:
        """Private key CKA_PRIVATE defaults to True."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, CKA_PRIVATE)
        if val is not True:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module defaults CKA_PRIVATE=False for RSA private key (spec requires True)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.2: default CKA_PRIVATE is True for private keys",
            )
            classify(
                "honest_deviation",
                kind="metadata",
                label="CKA_PRIVATE default (RSA private key)",
                spec_ref="PKCS#11 v3.2",
                summary="Module defaults CKA_PRIVATE=False for RSA private key (spec violation)",
            )

    def test_public_key_encrypt_is_bool(self, rsa_keypair: Any) -> None:
        """Public key CKA_ENCRYPT is a boolean."""
        rs, pub, _priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, pub, CKA_ENCRYPT)
        assert isinstance(val, bool)

    def test_public_key_verify_is_bool(self, rsa_keypair: Any) -> None:
        """Public key CKA_VERIFY is a boolean."""
        rs, pub, _priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, pub, CKA_VERIFY)
        assert isinstance(val, bool)

    def test_private_key_sign_is_bool(self, rsa_keypair: Any) -> None:
        """Private key CKA_SIGN is a boolean."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, CKA_SIGN)
        assert isinstance(val, bool)

    def test_private_key_decrypt_is_bool(self, rsa_keypair: Any) -> None:
        """Private key CKA_DECRYPT is a boolean."""
        rs, _pub, priv = rsa_keypair
        val = _read_attr(rs.raw, rs.sh, priv, CKA_DECRYPT)
        assert isinstance(val, bool)


class TestDataObjectDefaults:
    """Verify default attribute values on a CKO_DATA object."""

    @pytest.fixture()
    def data_obj(self, p11_raw_session: Any) -> Any:
        """Create a CKO_DATA object with minimal template."""
        rs = p11_raw_session
        skip_if_data_objects_unsupported(rs)
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_VALUE: b"test-defaults",
                CKA_TOKEN: False,
            },
        )
        yield rs, h
        destroy_quietly(rs.raw, rs.sh, h)

    def test_token_is_false(self, data_obj: Any) -> None:
        """CKA_TOKEN is False (explicitly set)."""
        rs, h = data_obj
        attrs = read_attributes(rs.raw, rs.sh, h, [CKA_TOKEN])
        assert require_bool_attr(attrs[CKA_TOKEN], "CKA_TOKEN") is False

    def test_modifiable_default(self, data_obj: Any) -> None:
        """CKA_MODIFIABLE defaults to True."""
        rs, h = data_obj
        val = _read_attr(rs.raw, rs.sh, h, CKA_MODIFIABLE)
        assert val is True

    def test_private_is_bool(self, data_obj: Any) -> None:
        """CKA_PRIVATE defaults to a boolean (module-dependent)."""
        rs, h = data_obj
        val = _read_attr(rs.raw, rs.sh, h, CKA_PRIVATE)
        assert isinstance(val, bool)
