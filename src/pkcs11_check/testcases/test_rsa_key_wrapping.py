"""RSA key wrapping tests.

Tests C_WrapKey / C_UnwrapKey with RSA-PKCS and RSA-OAEP mechanisms.
Wraps an AES key with an RSA public key, unwraps with the private key,
and verifies the key material matches.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_oaep
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    read_attributes,
)
from pkcs11_check.raw.recipes import (
    wrap_key as wrap_key_recipe,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKG_MGF1_SHA1,
    CKK_AES,
    CKM_AES_ECB,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA_1,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_KEY_NOT_WRAPPABLE,
)
from pkcs11_check.testcases._signature_policy import xfail_if_op_not_operational
from pkcs11_check.testcases.conftest import (
    classify_policy_enforcement,
    gen_rsa_keypair_or_xfail,
    reject_or_classify,
    require_operational_aes_keygen,
    unwrap_key_for_mechanism_roundtrip,
)

pytestmark = pytest.mark.keymgmt


def _make_rsa_pair(rs: Any) -> tuple[int, int]:
    """Generate RSA-2048 keypair with default capabilities (includes WRAP/UNWRAP)."""
    return gen_rsa_keypair_or_xfail(
        rs,
        2048,
        public_attrs={
            CKA_WRAP: True,
            CKA_ENCRYPT: True,
            CKA_TOKEN: False,
        },
        private_attrs={
            CKA_UNWRAP: True,
            CKA_DECRYPT: True,
            CKA_TOKEN: False,
        },
    )


def _make_extractable_aes(rs: Any, bits: int = 128) -> int:
    """Generate an extractable AES key suitable for wrapping."""
    require_operational_aes_keygen(rs)
    return gen_aes_key(
        rs.raw,
        rs.sh,
        bits,
        attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
    )


class TestRSAPKCSWrap:
    """Test RSA-PKCS (v1.5) key wrapping."""

    def test_wrap_unwrap_aes128(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Wrap AES-128 key with RSA, unwrap, verify key material matches."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(rs)
        aes_key = _make_extractable_aes(rs, 128)
        try:
            original_value = read_attributes(rs.raw, rs.sh, aes_key, [CKA_VALUE])[CKA_VALUE]

            wrapped = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS,
            )
            assert wrapped != original_value
            assert len(wrapped) == 256  # 2048-bit RSA -> 256 bytes

            try:
                unwrapped = unwrap_key_for_mechanism_roundtrip(
                    rs,
                    p11_config,
                    unwrapping_key=priv,
                    wrapped_key=wrapped,
                    mechanism=CKM_RSA_PKCS,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_EXTRACTABLE: True,
                        CKA_SENSITIVE: False,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    purpose="RSA-PKCS AES-128 wrap/unwrap roundtrip",
                )
            except AssertionError as exc:
                # FIPS restricts RSA PKCS#1 v1.5 key transport -> CKR_DEVICE_ERROR on
                # C_UnwrapKey: advertised but not operational, not a break.
                xfail_if_op_not_operational(exc, "CKM_RSA_PKCS unwrap (key transport)")
            try:
                unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert unwrapped_value == original_value
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)

    def test_wrap_unwrap_aes256(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Wrap AES-256 key - larger key material still fits in RSA-2048."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(rs)
        aes_key = _make_extractable_aes(rs, 256)
        try:
            original_value = read_attributes(rs.raw, rs.sh, aes_key, [CKA_VALUE])[CKA_VALUE]

            wrapped = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS,
            )
            try:
                unwrapped = unwrap_key_for_mechanism_roundtrip(
                    rs,
                    p11_config,
                    unwrapping_key=priv,
                    wrapped_key=wrapped,
                    mechanism=CKM_RSA_PKCS,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_EXTRACTABLE: True,
                        CKA_SENSITIVE: False,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    purpose="RSA-PKCS AES-256 wrap/unwrap roundtrip",
                )
            except AssertionError as exc:
                # FIPS restricts RSA PKCS#1 v1.5 key transport -> CKR_DEVICE_ERROR on
                # C_UnwrapKey: advertised but not operational, not a break.
                xfail_if_op_not_operational(exc, "CKM_RSA_PKCS unwrap (key transport)")
            try:
                unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert unwrapped_value == original_value
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)

    def test_wrapped_key_is_different_each_time(self, p11_raw_session: Any) -> None:
        """RSA-PKCS wrapping is randomized - same key wraps differently each time."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(rs)
        aes_key = _make_extractable_aes(rs)
        try:
            wrapped1 = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS,
            )
            wrapped2 = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS,
            )
            assert wrapped1 != wrapped2  # Randomized padding
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)


class TestRSAOAEPWrap:
    """Test RSA-OAEP key wrapping (more secure than PKCS v1.5)."""

    def test_wrap_unwrap_oaep(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Wrap/unwrap AES key with RSA-OAEP."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")

        pub, priv = _make_rsa_pair(rs)
        aes_key = _make_extractable_aes(rs, 128)
        try:
            original_value = read_attributes(rs.raw, rs.sh, aes_key, [CKA_VALUE])[CKA_VALUE]

            oaep = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )
            wrapped = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS_OAEP,
                mech_param=oaep,
            )
            oaep2 = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )
            unwrapped = unwrap_key_for_mechanism_roundtrip(
                rs,
                p11_config,
                unwrapping_key=priv,
                wrapped_key=wrapped,
                mechanism=CKM_RSA_PKCS_OAEP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_TOKEN: False,
                },
                mech_param=oaep2,
                purpose="RSA-OAEP AES wrap/unwrap roundtrip",
            )
            try:
                unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert unwrapped_value == original_value
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)


class TestWrappedKeyUsability:
    """Verify unwrapped keys are fully functional."""

    def test_unwrapped_key_encrypts(self, p11_raw_session: Any, p11_config: Any) -> None:
        """An unwrapped AES key can be used for encryption."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(rs)
        aes_key = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                CKA_EXTRACTABLE: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            },
        )
        try:
            # Encrypt with original key
            plaintext = b"wrap-test-data!!" * 2  # 32 bytes
            ct = encrypt_single(rs.raw, rs.sh, aes_key, CKM_AES_ECB, plaintext)

            # Wrap -> unwrap -> decrypt with unwrapped key
            wrapped = wrap_key_recipe(
                rs.raw,
                rs.sh,
                pub,
                aes_key,
                CKM_RSA_PKCS,
            )
            try:
                unwrapped = unwrap_key_for_mechanism_roundtrip(
                    rs,
                    p11_config,
                    unwrapping_key=priv,
                    wrapped_key=wrapped,
                    mechanism=CKM_RSA_PKCS,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_EXTRACTABLE: True,
                        CKA_SENSITIVE: False,
                        CKA_ENCRYPT: True,
                        CKA_DECRYPT: True,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_TOKEN: False,
                    },
                    purpose="RSA-PKCS unwrapped-key usability roundtrip",
                )
            except AssertionError as exc:
                # FIPS restricts RSA PKCS#1 v1.5 key transport -> CKR_DEVICE_ERROR on
                # C_UnwrapKey: advertised but not operational, not a break.
                xfail_if_op_not_operational(exc, "CKM_RSA_PKCS unwrap (key transport)")
            try:
                pt = decrypt_single(rs.raw, rs.sh, unwrapped, CKM_AES_ECB, ct)
                assert pt == plaintext
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)

    def test_non_extractable_key_cannot_be_wrapped(self, p11_raw_session: Any) -> None:
        """EXTRACTABLE=False key must not be wrappable.

        PKCS#11 spec: C_WrapKey must return CKR_KEY_NOT_WRAPPABLE or
        CKR_ACTION_PROHIBITED if the key has CKA_EXTRACTABLE=False.

        SECURITY: A module that wraps a non-extractable key allows key material
        exfiltration in violation of the PKCS#11 security model. This is a Type-B
        self-contradiction (the key reads back CKA_EXTRACTABLE=False, then its
        material leaves the token) and must FAIL, not xfail -- consistent with
        the sensitive-value and Tookan extractable-escalation security tests.
        Findings are tracked in docs/module-issues.md.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = _make_rsa_pair(rs)
        non_extractable = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: False},
        )

        try:
            # Establish the claim: the key must actually read back
            # CKA_EXTRACTABLE=False. If the module did not honour the flag at
            # creation, it never claimed the protection -> honest non-support.
            extractable = read_attributes(rs.raw, rs.sh, non_extractable, [CKA_EXTRACTABLE]).get(
                CKA_EXTRACTABLE
            )
            if extractable is not False:
                pytest.xfail("Module did not honour CKA_EXTRACTABLE=False at key creation")
                return

            try:
                wrap_key_recipe(
                    rs.raw,
                    rs.sh,
                    pub,
                    non_extractable,
                    CKM_RSA_PKCS,
                )
            except AssertionError as exc:
                reject_or_classify(
                    exc,
                    (CKR_KEY_NOT_WRAPPABLE, CKR_ACTION_PROHIBITED),
                    label="C_WrapKey of a CKA_EXTRACTABLE=False key",
                )
                return

            # Wrap succeeded on a verified non-extractable key -- Type-B: claimed
            # the protection (CKA_EXTRACTABLE=False) then violated it (material
            # left the token).
            classify_policy_enforcement(
                claimed=True,
                violated=True,
                label="C_WrapKey succeeded on a CKA_EXTRACTABLE=False key -- key "
                "material exfiltration (PKCS#11 requires CKR_KEY_NOT_WRAPPABLE)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, non_extractable)
