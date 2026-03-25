"""End-to-end key lifecycle tests.

Tests the full lifecycle of cryptographic keys:
generate -> use -> export/wrap -> import/unwrap -> verify -> destroy.
Catches integration bugs that unit tests miss.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import attr_bytes, template
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    find_objects,
    gen_aes_key,
    gen_ec_keypair,
    gen_rsa_keypair,
    read_attributes,
    sign_single,
    unwrap_key,
    verify_single,
)
from pkcs11_check.raw.recipes import (
    wrap_key as wrap_key_recipe,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKK_EC,
    CKK_RSA,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKM_ECDSA,
    CKM_SHA256_RSA_PKCS,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
)

pytestmark = pytest.mark.keymgmt


class TestRSAKeyLifecycle:
    """Full RSA key lifecycle: generate -> sign -> export -> import -> verify."""

    def test_rsa_export_import_verify(self, p11_raw_session: Any) -> None:
        """Generate RSA, sign, export pub components, import, verify signature."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA not supported")

        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={int(CKA_VERIFY): True, int(CKA_TOKEN): False},
            private_attrs={int(CKA_SIGN): True, int(CKA_TOKEN): False},
        )
        imported = 0
        try:
            # Sign
            data = b"RSA lifecycle test data"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            assert len(sig) == 256

            # Export public key components
            attrs = read_attributes(
                rs.raw, rs.sh, pub, [int(CKA_MODULUS), int(CKA_PUBLIC_EXPONENT)]
            )
            modulus = attrs[int(CKA_MODULUS)]
            exponent = attrs[int(CKA_PUBLIC_EXPONENT)]
            assert isinstance(modulus, bytes)
            assert isinstance(exponent, bytes)

            # Import as new public key
            imported = create_object(
                rs.raw,
                rs.sh,
                {
                    int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                    int(CKA_KEY_TYPE): int(CKK_RSA),
                    int(CKA_MODULUS): modulus,
                    int(CKA_PUBLIC_EXPONENT): exponent,
                    int(CKA_VERIFY): True,
                    int(CKA_TOKEN): False,
                },
            )

            # Verify with imported key
            assert verify_single(
                rs.raw, rs.sh, imported, CKM_SHA256_RSA_PKCS, data, sig
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if imported:
                destroy_quietly(rs.raw, rs.sh, imported)


class TestAESKeyWrapLifecycle:
    """Full AES key wrap lifecycle: generate wrapping key, wrap target, unwrap, verify."""

    def test_aes_wrap_unwrap_roundtrip(self, p11_raw_session: Any) -> None:
        """Wrap AES key with another AES key, unwrap, verify material matches."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")

        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                int(CKA_WRAP): True,
                int(CKA_UNWRAP): True,
                int(CKA_EXTRACTABLE): True,
                int(CKA_SENSITIVE): False,
            },
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={int(CKA_EXTRACTABLE): True, int(CKA_SENSITIVE): False},
        )
        unwrapped = 0
        try:
            # Read original value
            original_value = read_attributes(
                rs.raw, rs.sh, target, [int(CKA_VALUE)]
            )[int(CKA_VALUE)]

            # Wrap
            wrapped = wrap_key_recipe(
                rs.raw, rs.sh, wrap_h, target, CKM_AES_KEY_WRAP
            )
            assert wrapped != original_value

            # Unwrap
            unwrapped = unwrap_key(
                rs.raw,
                rs.sh,
                wrap_h,
                wrapped,
                CKM_AES_KEY_WRAP,
                attrs={
                    int(CKA_CLASS): int(CKO_SECRET_KEY),
                    int(CKA_KEY_TYPE): int(CKK_AES),
                    int(CKA_EXTRACTABLE): True,
                    int(CKA_SENSITIVE): False,
                },
            )

            # Verify material matches
            unwrapped_value = read_attributes(
                rs.raw, rs.sh, unwrapped, [int(CKA_VALUE)]
            )[int(CKA_VALUE)]
            assert unwrapped_value == original_value
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)
            if unwrapped:
                destroy_quietly(rs.raw, rs.sh, unwrapped)

    def test_aes_wrapped_key_functional(self, p11_raw_session: Any) -> None:
        """Unwrapped AES key can encrypt/decrypt correctly."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")

        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={int(CKA_WRAP): True, int(CKA_UNWRAP): True},
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                int(CKA_EXTRACTABLE): True,
                int(CKA_ENCRYPT): True,
                int(CKA_DECRYPT): True,
            },
        )
        unwrapped = 0
        try:
            # Encrypt with original key
            plaintext = b"lifecycle test!!" * 2  # 32 bytes
            ct = encrypt_single(rs.raw, rs.sh, target, CKM_AES_ECB, plaintext)

            # Wrap and unwrap
            wrapped = wrap_key_recipe(
                rs.raw, rs.sh, wrap_h, target, CKM_AES_KEY_WRAP
            )
            unwrapped = unwrap_key(
                rs.raw,
                rs.sh,
                wrap_h,
                wrapped,
                CKM_AES_KEY_WRAP,
                attrs={
                    int(CKA_CLASS): int(CKO_SECRET_KEY),
                    int(CKA_KEY_TYPE): int(CKK_AES),
                    int(CKA_ENCRYPT): True,
                    int(CKA_DECRYPT): True,
                    int(CKA_EXTRACTABLE): True,
                    int(CKA_SENSITIVE): False,
                },
            )

            # Decrypt with unwrapped key
            pt = decrypt_single(rs.raw, rs.sh, unwrapped, CKM_AES_ECB, ct)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)
            if unwrapped:
                destroy_quietly(rs.raw, rs.sh, unwrapped)


class TestECKeyLifecycle:
    """Full EC key lifecycle: generate -> sign -> export -> import -> verify."""

    def test_ec_export_import_verify(self, p11_raw_session: Any) -> None:
        """Generate EC, sign, export point, import, verify signature."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("ECDSA not supported")

        try:
            pub, priv = gen_ec_keypair(
                rs.raw,
                rs.sh,
                encode_named_curve_parameters("secp256r1"),
                public_attrs={int(CKA_VERIFY): True, int(CKA_TOKEN): False},
                private_attrs={int(CKA_SIGN): True, int(CKA_TOKEN): False},
            )
        except AssertionError:
            pytest.skip("secp256r1 not supported")
            return

        imported = 0
        try:
            # Sign
            data = b"EC lifecycle test"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, data)

            # Export
            attrs = read_attributes(
                rs.raw, rs.sh, pub, [int(CKA_EC_POINT), int(CKA_EC_PARAMS)]
            )
            ec_point = attrs[int(CKA_EC_POINT)]
            ec_params = attrs[int(CKA_EC_PARAMS)]
            assert isinstance(ec_point, bytes)
            assert isinstance(ec_params, bytes)

            # Import
            imported = create_object(
                rs.raw,
                rs.sh,
                {
                    int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                    int(CKA_KEY_TYPE): int(CKK_EC),
                    int(CKA_EC_PARAMS): ec_params,
                    int(CKA_EC_POINT): ec_point,
                    int(CKA_VERIFY): True,
                    int(CKA_TOKEN): False,
                },
            )

            # Verify
            assert verify_single(
                rs.raw, rs.sh, imported, CKM_ECDSA, data, sig
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            if imported:
                destroy_quietly(rs.raw, rs.sh, imported)


class TestKeyDestroyVerification:
    """Verify that destroyed keys are truly gone."""

    def test_destroyed_key_not_findable(self, p11_raw_session: Any) -> None:
        """After destroy, key cannot be found by any search."""
        rs = p11_raw_session
        key = gen_aes_key(
            rs.raw, rs.sh, 256, attrs={int(CKA_LABEL): b"destroy-verify"}
        )
        destroy_quietly(rs.raw, rs.sh, key)

        # Search by label
        by_label = find_objects(
            rs.raw, rs.sh, template(attr_bytes(CKA_LABEL, b"destroy-verify"))
        )
        assert len(by_label) == 0

    def test_destroy_does_not_affect_other_keys(self, p11_raw_session: Any) -> None:
        """Destroying one key doesn't affect other keys."""
        rs = p11_raw_session
        k1 = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                int(CKA_LABEL): b"keep-me",
                int(CKA_ENCRYPT): True,
                int(CKA_DECRYPT): True,
            },
        )
        k2 = gen_aes_key(
            rs.raw, rs.sh, 128, attrs={int(CKA_LABEL): b"destroy-me"}
        )
        try:
            destroy_quietly(rs.raw, rs.sh, k2)

            # k1 should still work
            ct = encrypt_single(rs.raw, rs.sh, k1, CKM_AES_ECB, b"\x00" * 16)
            assert len(ct) == 16
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
