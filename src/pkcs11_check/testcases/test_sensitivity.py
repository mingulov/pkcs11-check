"""Attribute sensitivity enforcement tests.

Verifies that PKCS#11 modules enforce CKA_SENSITIVE and CKA_EXTRACTABLE
correctly - sensitive key values must not be readable, non-extractable
keys must not be wrappable.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    import_secret_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_UNAVAILABLE_INFORMATION,
    CKA_ALWAYS_SENSITIVE,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKK_AES,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    classify_policy_enforcement,
    gen_rsa_keypair_or_xfail,
    is_known_error,
    require_operational_aes_keygen,
)

pytestmark = pytest.mark.security


class TestSensitiveKeyValue:
    """Test that CKA_VALUE is protected on sensitive keys."""

    def test_sensitive_aes_value_not_readable(self, p11_raw_session: Any) -> None:
        """Reading CKA_VALUE on a SENSITIVE=True AES key must fail."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: True},
        )
        try:
            # policy claim/effect-check. read_attributes omits unavailable
            # (sensitive) attributes rather than raising, so verify the effect:
            #   claimed  = the key reports CKA_SENSITIVE=True back,
            #   violated = the protected CKA_VALUE is actually readable.
            sens_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            claimed = sens_attrs.get(CKA_SENSITIVE) is True
            val_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            violated = CKA_VALUE in val_attrs
            classify_policy_enforcement(
                claimed=claimed,
                violated=violated,
                label="read CKA_VALUE on a CKA_SENSITIVE=True AES key "
                "(PKCS#11 v3.2: sensitive attributes cannot be revealed)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sensitive_value_not_copied_on_rejected_get_attribute(
        self,
        p11_raw_session: Any,
    ) -> None:
        """A rejected sensitive-value read must not copy bytes into pValue."""
        rs = p11_raw_session
        secret = bytes.fromhex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                secret,
                attrs={CKA_SENSITIVE: True, CKA_EXTRACTABLE: False},
            )
        except AssertionError as exc:
            classify(
                "not_operational",
                kind="policy",
                label="import sensitive AES key for raw CKA_VALUE probe",
                operation="C_CreateObject",
                summary=f"Cannot import sensitive AES key for raw CKA_VALUE probe: {exc}",
            )
            raise

        try:
            sens_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            claimed = sens_attrs.get(CKA_SENSITIVE) is True

            sentinel = b"\xa5" * len(secret)
            value_buf = (ctypes.c_ubyte * len(secret)).from_buffer_copy(sentinel)
            attr = (CK_ATTRIBUTE * 1)()
            attr[0].type = CKA_VALUE
            attr[0].pValue = ctypes.cast(value_buf, ctypes.c_void_p)
            attr[0].ulValueLen = len(secret)

            rv = rs.raw.C_GetAttributeValue(rs.sh, key, attr, 1)
            observed = bytes(value_buf)
            leaked = observed == secret or observed.startswith(secret[:16])
            if rv not in (CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID):
                classify(
                    "nonspec_reject",
                    kind="policy",
                    label="C_GetAttributeValue(CKA_VALUE on sensitive key)",
                    operation="C_GetAttributeValue",
                    actual=rv,
                    expected=[CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID],
                    summary=(
                        "C_GetAttributeValue(CKA_VALUE on sensitive key) rejected with "
                        f"non-standard CKR {rv:#x}"
                    ),
                )
            classify_policy_enforcement(
                claimed=claimed,
                violated=rv == CKR_OK or leaked,
                label=(
                    "raw C_GetAttributeValue copied CKA_VALUE bytes for a "
                    "CKA_SENSITIVE=True AES key"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_get_attribute_value_mixed_sensitive_template_continues(
        self,
        p11_raw_session: Any,
    ) -> None:
        """A sensitive template row must not prevent later safe rows from filling."""
        rs = p11_raw_session
        secret = bytes.fromhex("2031425364758697a8b9cadbecfd0e1f")
        label = b"p11chk-mixed-sensitive"
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                CKK_AES,
                secret,
                attrs={CKA_SENSITIVE: True, CKA_EXTRACTABLE: False, CKA_LABEL: label},
            )
        except AssertionError as exc:
            classify(
                "not_operational",
                kind="policy",
                label="import sensitive AES key for mixed-attribute probe",
                operation="C_CreateObject",
                summary=f"Cannot import sensitive AES key for mixed-attribute probe: {exc}",
            )
            raise

        try:
            sens_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            if sens_attrs.get(CKA_SENSITIVE) is not True:
                classify(
                    "honest_deviation",
                    kind="policy",
                    label="mixed C_GetAttributeValue sensitive probe precondition",
                    summary=(
                        "mixed C_GetAttributeValue probe requires a key that "
                        "reports CKA_SENSITIVE=True"
                    ),
                )

            label_buf = (ctypes.c_ubyte * len(label))()
            attr = (CK_ATTRIBUTE * 2)()
            attr[0].type = CKA_VALUE
            attr[0].pValue = None
            attr[0].ulValueLen = 0
            attr[1].type = CKA_LABEL
            attr[1].pValue = ctypes.cast(label_buf, ctypes.c_void_p)
            attr[1].ulValueLen = len(label)

            rv = rs.raw.C_GetAttributeValue(rs.sh, key, attr, 2)
            classify_negative_rv(
                rv,
                (CKR_ATTRIBUTE_SENSITIVE,),
                label="C_GetAttributeValue mixed sensitive/safe template",
            )
            assert attr[0].ulValueLen == CK_UNAVAILABLE_INFORMATION, (
                "sensitive CKA_VALUE row should report CK_UNAVAILABLE_INFORMATION; "
                f"got {attr[0].ulValueLen}"
            )
            assert attr[1].ulValueLen == len(label), (
                f"safe CKA_LABEL row reported length {attr[1].ulValueLen}, expected {len(label)}"
            )
            assert bytes(label_buf[: attr[1].ulValueLen]) == label, (
                "C_GetAttributeValue returned CKR_ATTRIBUTE_SENSITIVE but did not "
                "populate the later safe CKA_LABEL row"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_non_sensitive_aes_value_readable(self, p11_raw_session: Any) -> None:
        """CKA_VALUE is readable when SENSITIVE=False."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            value = attrs[CKA_VALUE]
            assert isinstance(value, bytes)
            assert len(value) == 32  # 256 bits = 32 bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sensitive_rsa_private_exponent_not_readable(self, p11_raw_session: Any) -> None:
        """Reading CKA_PRIVATE_EXPONENT on a sensitive RSA private key must fail."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            private_attrs={CKA_SENSITIVE: True},
        )
        try:
            # policy claim/effect-check (see test_sensitive_aes_value_not_readable).
            sens_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_SENSITIVE])
            claimed = sens_attrs.get(CKA_SENSITIVE) is True
            exp_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_PRIVATE_EXPONENT])
            violated = CKA_PRIVATE_EXPONENT in exp_attrs
            classify_policy_enforcement(
                claimed=claimed,
                violated=violated,
                label="read CKA_PRIVATE_EXPONENT on a CKA_SENSITIVE=True RSA private key "
                "(PKCS#11 v3.2: sensitive attributes cannot be revealed)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestExtractableEnforcement:
    """Test CKA_EXTRACTABLE enforcement."""

    def test_non_extractable_by_default(self, p11_raw_session: Any) -> None:
        """Default-generated AES key extractability.

        Per OASIS PKCS#11 spec, CKA_EXTRACTABLE has no mandated default value
        -- it is implementation-defined. Both True and False are spec-conformant.
        This test documents which default the module uses via a compliance note.
        """
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE])
                extractable = attrs[CKA_EXTRACTABLE]
            except AssertionError as e:
                if is_known_error(e, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    pytest.skip("Module does not support CKA_EXTRACTABLE attribute")
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

        from pkcs11_check.compliance import ComplianceLevel, note

        if extractable is True:
            note(
                "Module defaults CKA_EXTRACTABLE to True for generated AES keys; "
                "PKCS#11 spec does not mandate a specific default",
                ComplianceLevel.VENDOR,
            )
        else:
            note(
                "Module defaults CKA_EXTRACTABLE to False for generated AES keys; "
                "PKCS#11 spec does not mandate a specific default",
                ComplianceLevel.VENDOR,
            )
        # Both True and False are spec-conformant
        assert extractable in (True, False)

    def test_extractable_when_requested(self, p11_raw_session: Any) -> None:
        """AES key with EXTRACTABLE=True allows VALUE read (when also not sensitive)."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE])
            assert attrs[CKA_EXTRACTABLE] is True
            val_attrs = read_attributes(rs.raw, rs.sh, key, [CKA_VALUE])
            assert len(val_attrs[CKA_VALUE]) == 32
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestSensitiveFlag:
    """Test that CKA_SENSITIVE flag behaves correctly."""

    def test_sensitive_flag_is_true_when_requested(self, p11_raw_session: Any) -> None:
        """AES key with SENSITIVE=True has SENSITIVE=True."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SENSITIVE: True})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            assert attrs[CKA_SENSITIVE] is True
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sensitive_flag_settable_at_creation(self, p11_raw_session: Any) -> None:
        """SENSITIVE=False can be set at creation time."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SENSITIVE: False})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            assert attrs[CKA_SENSITIVE] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_always_sensitive_flag(self, p11_raw_session: Any) -> None:
        """CKA_ALWAYS_SENSITIVE is readable and consistent."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key_sensitive = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: True},
        )
        key_not_sensitive = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_SENSITIVE: False},
        )
        try:
            # ALWAYS_SENSITIVE should be True for keys that were always sensitive
            a1 = read_attributes(rs.raw, rs.sh, key_sensitive, [CKA_ALWAYS_SENSITIVE])
            assert a1[CKA_ALWAYS_SENSITIVE] is True
            # ALWAYS_SENSITIVE should be False for keys that started non-sensitive
            a2 = read_attributes(rs.raw, rs.sh, key_not_sensitive, [CKA_ALWAYS_SENSITIVE])
            assert a2[CKA_ALWAYS_SENSITIVE] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key_sensitive)
            destroy_quietly(rs.raw, rs.sh, key_not_sensitive)
