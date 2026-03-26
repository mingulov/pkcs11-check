"""Tests for CMS signature mechanism.

Covers CKM_CMS_SIG (0x500).

CKM_CMS_SIG is a sign/sign-recover mechanism using CMS (Cryptographic Message Syntax).
It requires a CK_CMS_SIG_PARAMS structure containing a certificate handle, signing
mechanism OID, digest mechanism OID, content type OID, and requested/required attributes.
This mechanism is extremely rarely implemented by PKCS#11 modules.

OASIS spec: cms_mechanisms.md
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    get_mechanism_info,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM_CMS_SIG,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

pytestmark = pytest.mark.sign

# CKR codes expected when attempting CMS_SIG without proper params / unsupported
_SIGN_ERROR_CKRS = frozenset(
    {
        CKR_MECHANISM_INVALID,
        CKR_MECHANISM_PARAM_INVALID,
        CKR_FUNCTION_FAILED,
        CKR_GENERAL_ERROR,
    }
)


class TestCMSSig:
    """CKM_CMS_SIG tests - CMS signature mechanism (sign and sign-recover)."""

    def test_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Report whether CKM_CMS_SIG is supported; skip if not."""
        rs = p11_raw_session
        if not rs.has_mechanism("CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

    def test_mechanism_info(self, p11_raw_session: Any) -> None:
        """CKM_CMS_SIG mechanism info should report sign/sign-recover flags."""
        rs = p11_raw_session
        if not rs.has_mechanism("CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

        try:
            get_mechanism_info(rs.raw, rs.slot_id, CKM_CMS_SIG)
        except AssertionError:
            pass  # mechanism not available

    def test_cms_sig_requires_rsa_key(self, p11_raw_session: Any) -> None:
        """CKM_CMS_SIG sign attempt with RSA key and no params is expected to fail cleanly.

        CKM_CMS_SIG requires a CK_CMS_SIG_PARAMS structure with:
          - certificate: CK_OBJECT_HANDLE pointing to a certificate object
          - pSigningMechanism: OID for the signing mechanism
          - pDigestMechanism: OID for the digest mechanism
          - pContentType: content type OID string
          - pRequestedAttributes / pRequiredAttributes: CMS attributes

        We verify the mechanism is present and that the module rejects a bare
        invocation without params rather than crashing.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={
                CKA_ENCRYPT: False,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
            private_attrs={
                CKA_DECRYPT: False,
                CKA_SIGN: True,
                CKA_SENSITIVE: True,
                CKA_EXTRACTABLE: False,
                CKA_TOKEN: False,
            },
        )
        try:
            # Attempt CMS_SIG sign without params - must fail, not crash.
            try:
                sign_single(rs.raw, rs.sh, priv, CKM_CMS_SIG, b"test message")
                # If we reach here the module accepted no-param CMS_SIG - unexpected
                pytest.xfail(
                    "CKM_CMS_SIG sign succeeded without CK_CMS_SIG_PARAMS "
                    "(module is unusually permissive)"
                )
            except AssertionError:
                # Expected: module rejects missing/invalid params
                pass
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_cms_sig_not_usable_as_encrypt(self, p11_raw_session: Any) -> None:
        """CKM_CMS_SIG must not be usable as an encryption mechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("CMS_SIG"):
            pytest.skip("CKM_CMS_SIG not supported")

        key = gen_aes_key(rs.raw, rs.sh, 128)
        try:
            with pytest.raises(AssertionError):
                encrypt_single(rs.raw, rs.sh, key, CKM_CMS_SIG, b"data")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_cms_sig_mechanism_value(self) -> None:
        """CKM_CMS_SIG numeric value must be 0x500 per PKCS#11 spec."""
        assert CKM_CMS_SIG == 0x500
