"""Key usage policy enforcement tests.

Verifies that PKCS#11 modules enforce CKA_ENCRYPT, CKA_DECRYPT,
CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP capability flags.

These tests verify at the raw API level that C_EncryptInit / C_SignInit etc.
fail with appropriate CKR when the key lacks the corresponding capability flag.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    read_attributes,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKA_UNWRAP,
    CKA_VERIFY,
    CKA_WRAP,
    CKM_AES_ECB,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    gen_rsa_keypair_or_xfail,
    require_operational_aes_keygen,
)

# Acceptable CKR codes for key usage policy violations.
# Spec mandates CKR_KEY_FUNCTION_NOT_PERMITTED, but some modules return
# CKR_FUNCTION_NOT_SUPPORTED or CKR_ARGUMENTS_BAD instead.
_KEY_POLICY_CKRS = (
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_ARGUMENTS_BAD,
    CKR_KEY_TYPE_INCONSISTENT,
)

pytestmark = pytest.mark.security


class TestAESKeyUsagePolicy:
    """Test AES key capability enforcement."""

    def test_encrypt_only_key_cannot_decrypt(self, p11_raw_session: Any) -> None:
        """AES key with ENCRYPT=True, DECRYPT=False cannot be used for decrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: False,
                CKA_SIGN: False,
                CKA_VERIFY: False,
            },
        )
        try:
            # Encrypt should succeed
            data = b"\x00" * 16
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, data)
            assert len(ct) == 16

            # DecryptInit should fail with KEY_FUNCTION_NOT_PERMITTED
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_DecryptInit(rs.sh, mech.byref(), key)
            assert rv in _KEY_POLICY_CKRS, (
                f"Expected key policy error for DECRYPT=False key, got {ckr_name(rv)}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_decrypt_only_key_cannot_encrypt(self, p11_raw_session: Any) -> None:
        """AES key with DECRYPT=True, ENCRYPT=False cannot be used for encrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: False,
                CKA_DECRYPT: True,
                CKA_SIGN: False,
                CKA_VERIFY: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_DECRYPT])
            assert attrs[CKA_DECRYPT] is True

            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            assert rv in _KEY_POLICY_CKRS, (
                f"Expected key policy error for ENCRYPT=False key, got {ckr_name(rv)}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_sign_only_key_cannot_encrypt(self, p11_raw_session: Any) -> None:
        """Key with SIGN=True but ENCRYPT=False cannot encrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_ENCRYPT: False,
                CKA_DECRYPT: False,
            },
        )
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            assert rv in _KEY_POLICY_CKRS, (
                f"Expected key policy error for ENCRYPT=False key, got {ckr_name(rv)}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_full_capabilities_key(self, p11_raw_session: Any) -> None:
        """Key with all capabilities can encrypt."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_WRAP: True,
                CKA_UNWRAP: True,
            },
        )
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x00" * 16)
            assert len(ct) == 16
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestRSAKeyUsagePolicy:
    """Test RSA key capability enforcement."""

    def test_sign_only_rsa_cannot_encrypt(self, p11_raw_session: Any) -> None:
        """RSA key pair generated for signing only cannot encrypt."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={
                CKA_ENCRYPT: False,
                CKA_VERIFY: True,
                CKA_WRAP: False,
            },
            private_attrs={
                CKA_DECRYPT: False,
                CKA_SIGN: True,
                CKA_UNWRAP: False,
            },
        )
        try:
            # Verify SIGN is True on private
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_SIGN])
            assert priv_attrs[CKA_SIGN] is True

            # Verify VERIFY is True on public
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_VERIFY])
            assert pub_attrs[CKA_VERIFY] is True

            # Encrypt should fail on public key
            from pkcs11_check.raw.types_std import CKM_RSA_PKCS

            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), pub)
            assert rv in _KEY_POLICY_CKRS, (
                f"Expected key policy error for ENCRYPT=False RSA key, got {ckr_name(rv)}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_encrypt_only_rsa_cannot_sign(self, p11_raw_session: Any) -> None:
        """RSA key pair generated for encryption only cannot sign."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={
                CKA_ENCRYPT: True,
                CKA_VERIFY: False,
                CKA_WRAP: False,
            },
            private_attrs={
                CKA_DECRYPT: True,
                CKA_SIGN: False,
                CKA_UNWRAP: False,
            },
        )
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_ENCRYPT])
            assert pub_attrs[CKA_ENCRYPT] is True

            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_DECRYPT])
            assert priv_attrs[CKA_DECRYPT] is True

            # Sign should fail on private key
            from pkcs11_check.raw.types_std import CKM_SHA256_RSA_PKCS

            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            assert rv in _KEY_POLICY_CKRS, (
                f"Expected key policy error for SIGN=False RSA key, got {ckr_name(rv)}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestCapabilityReadback:
    """Verify capability flags are readable and consistent."""

    def test_aes_capabilities_match_template(self, p11_raw_session: Any) -> None:
        """Generated key's capability flags match what was requested."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: False,
                CKA_SIGN: False,
                CKA_VERIFY: False,
                CKA_WRAP: False,
                CKA_UNWRAP: False,
            },
        )
        try:
            attrs = read_attributes(
                rs.raw,
                rs.sh,
                key,
                [CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN],
            )
            assert attrs[CKA_ENCRYPT] is True
            assert attrs[CKA_DECRYPT] is False
            assert attrs[CKA_SIGN] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_capabilities_match_template(self, p11_raw_session: Any) -> None:
        """RSA keypair flags match what was requested."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_VERIFY: False},
            private_attrs={CKA_DECRYPT: True, CKA_SIGN: False},
        )
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_ENCRYPT, CKA_VERIFY])
            assert pub_attrs[CKA_ENCRYPT] is True
            assert pub_attrs[CKA_VERIFY] is False

            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_DECRYPT, CKA_SIGN])
            assert priv_attrs[CKA_DECRYPT] is True
            assert priv_attrs[CKA_SIGN] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
