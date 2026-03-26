"""Classic Diffie-Hellman key agreement tests.

Tests CKM_DH_PKCS_KEY_PAIR_GEN, CKM_DH_PKCS_DERIVE, and
CKM_DH_PKCS_PARAMETER_GEN where supported.

Uses RFC 3526 Group 14 (2048-bit MODP) for known-good parameters.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_bytes,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import (
    decrypt_single,
    derive_key,
    destroy_quietly,
    encrypt_single,
    read_attributes,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_BASE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PRIME,
    CKA_PRIME_BITS,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKM_AES_ECB,
    CKM_DH_PKCS_DERIVE,
    CKM_DH_PKCS_KEY_PAIR_GEN,
    CKM_DH_PKCS_PARAMETER_GEN,
    CKO_SECRET_KEY,
    CKR_OK,
)

pytestmark = pytest.mark.keymgmt

# RFC 3526 Group 14 (2048-bit MODP) - widely supported safe prime.
DH_PRIME_2048 = bytes.fromhex(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_GEN = bytes([0x02])


def _skip_no_dh(p11_raw_session: Any) -> None:
    """Skip if DH mechanisms are not available."""
    if not p11_raw_session.has_mechanism("DH_PKCS_KEY_PAIR_GEN"):
        pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")
    if not p11_raw_session.has_mechanism("DH_PKCS_DERIVE"):
        pytest.skip("CKM_DH_PKCS_DERIVE not supported")


def _gen_dh_keypair(
    raw: Any,
    sh: int,
    prime: bytes = DH_PRIME_2048,
    base: bytes = DH_GEN,
    *,
    derive: bool = True,
    extra_pub: dict[int, Any] | None = None,
    extra_priv: dict[int, Any] | None = None,
) -> tuple[int, int]:
    """Generate a DH keypair using C_GenerateKeyPair with given domain params."""
    pub_attrs = [
        attr_bytes(CKA_PRIME, prime),
        attr_bytes(CKA_BASE, base),
        attr_bool(CKA_TOKEN, False),
    ]
    if derive:
        pub_attrs.append(attr_bool(CKA_DERIVE, True))
    if extra_pub:
        from pkcs11_check.raw.pack import attr_auto

        for k, v in extra_pub.items():
            pub_attrs.append(attr_auto(k, v))

    priv_attrs = [
        attr_bool(CKA_TOKEN, False),
    ]
    if derive:
        priv_attrs.append(attr_bool(CKA_DERIVE, True))
    if extra_priv:
        from pkcs11_check.raw.pack import attr_auto

        for k, v in extra_priv.items():
            priv_attrs.append(attr_auto(k, v))

    pub_tmpl = template(*pub_attrs)
    priv_tmpl = template(*priv_attrs)
    mech = mech_simple(CKM_DH_PKCS_KEY_PAIR_GEN)
    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_h),
        byref(priv_h),
    )
    expect_rv(int(rv), CKR_OK)
    return int(pub_h.value), int(priv_h.value)


class TestDHKeyAgreement:
    """Test DH key pair generation and key derivation."""

    def test_dh_keypair_generation(self, p11_raw_session: Any) -> None:
        """Generate a DH keypair from known parameters."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        pub, priv = _gen_dh_keypair(rs.raw, rs.sh)
        try:
            assert pub is not None
            assert priv is not None

            # Public key value should be non-empty
            attrs = read_attributes(rs.raw, rs.sh, pub, [int(CKA_VALUE)])
            pub_value = attrs[int(CKA_VALUE)]
            assert isinstance(pub_value, bytes)
            assert len(pub_value) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_dh_derive_shared_secret(self, p11_raw_session: Any) -> None:
        """Alice and Bob derive the same shared AES key."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        # Alice and Bob each generate a keypair
        alice_pub, alice_priv = _gen_dh_keypair(rs.raw, rs.sh)
        bob_pub, bob_priv = _gen_dh_keypair(rs.raw, rs.sh)
        try:
            alice_attrs = read_attributes(rs.raw, rs.sh, alice_pub, [int(CKA_VALUE)])
            bob_attrs = read_attributes(rs.raw, rs.sh, bob_pub, [int(CKA_VALUE)])
            alice_value = alice_attrs[int(CKA_VALUE)]
            bob_value = bob_attrs[int(CKA_VALUE)]
            assert alice_value != bob_value  # Different public keys

            # Each derives an AES-128 key using the other's public value
            alice_shared = derive_key(
                rs.raw,
                rs.sh,
                alice_priv,
                CKM_DH_PKCS_DERIVE,
                attrs={
                    int(CKA_CLASS): int(CKO_SECRET_KEY),
                    int(CKA_KEY_TYPE): int(CKK_AES),
                    int(CKA_VALUE_LEN): 16,
                    int(CKA_SENSITIVE): False,
                    int(CKA_EXTRACTABLE): True,
                    int(CKA_TOKEN): False,
                },
                mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, bob_value),
            )
            bob_shared = derive_key(
                rs.raw,
                rs.sh,
                bob_priv,
                CKM_DH_PKCS_DERIVE,
                attrs={
                    int(CKA_CLASS): int(CKO_SECRET_KEY),
                    int(CKA_KEY_TYPE): int(CKK_AES),
                    int(CKA_VALUE_LEN): 16,
                    int(CKA_SENSITIVE): False,
                    int(CKA_EXTRACTABLE): True,
                    int(CKA_TOKEN): False,
                },
                mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, alice_value),
            )
            try:
                # Both should derive the same key material
                a_val = read_attributes(rs.raw, rs.sh, alice_shared, [int(CKA_VALUE)])
                b_val = read_attributes(rs.raw, rs.sh, bob_shared, [int(CKA_VALUE)])
                assert a_val[int(CKA_VALUE)] == b_val[int(CKA_VALUE)]
            finally:
                destroy_quietly(rs.raw, rs.sh, alice_shared)
                destroy_quietly(rs.raw, rs.sh, bob_shared)
        finally:
            destroy_quietly(rs.raw, rs.sh, alice_pub)
            destroy_quietly(rs.raw, rs.sh, alice_priv)
            destroy_quietly(rs.raw, rs.sh, bob_pub)
            destroy_quietly(rs.raw, rs.sh, bob_priv)

    def test_dh_derived_key_encrypts(self, p11_raw_session: Any) -> None:
        """Derived AES key from DH can encrypt/decrypt data."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        alice_pub, alice_priv = _gen_dh_keypair(rs.raw, rs.sh)
        bob_pub, bob_priv = _gen_dh_keypair(rs.raw, rs.sh)
        try:
            bob_attrs = read_attributes(rs.raw, rs.sh, bob_pub, [int(CKA_VALUE)])
            alice_attrs = read_attributes(rs.raw, rs.sh, alice_pub, [int(CKA_VALUE)])

            # Alice derives shared key, encrypts
            shared_key = derive_key(
                rs.raw,
                rs.sh,
                alice_priv,
                CKM_DH_PKCS_DERIVE,
                attrs={
                    int(CKA_CLASS): int(CKO_SECRET_KEY),
                    int(CKA_KEY_TYPE): int(CKK_AES),
                    int(CKA_VALUE_LEN): 16,
                    int(CKA_ENCRYPT): True,
                    int(CKA_DECRYPT): True,
                    int(CKA_TOKEN): False,
                },
                mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, bob_attrs[int(CKA_VALUE)]),
            )
            try:
                plaintext = b"DH key agreement!" + b"\x00" * 15  # pad to 32 bytes
                plaintext = plaintext[:32]
                ct = encrypt_single(rs.raw, rs.sh, shared_key, CKM_AES_ECB, plaintext)
                assert ct != plaintext

                # Bob derives the same shared key, decrypts
                bob_key = derive_key(
                    rs.raw,
                    rs.sh,
                    bob_priv,
                    CKM_DH_PKCS_DERIVE,
                    attrs={
                        int(CKA_CLASS): int(CKO_SECRET_KEY),
                        int(CKA_KEY_TYPE): int(CKK_AES),
                        int(CKA_VALUE_LEN): 16,
                        int(CKA_ENCRYPT): True,
                        int(CKA_DECRYPT): True,
                        int(CKA_TOKEN): False,
                    },
                    mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, alice_attrs[int(CKA_VALUE)]),
                )
                try:
                    pt = decrypt_single(rs.raw, rs.sh, bob_key, CKM_AES_ECB, ct)
                    assert pt == plaintext
                finally:
                    destroy_quietly(rs.raw, rs.sh, bob_key)
            finally:
                destroy_quietly(rs.raw, rs.sh, shared_key)
        finally:
            destroy_quietly(rs.raw, rs.sh, alice_pub)
            destroy_quietly(rs.raw, rs.sh, alice_priv)
            destroy_quietly(rs.raw, rs.sh, bob_pub)
            destroy_quietly(rs.raw, rs.sh, bob_priv)

    def test_dh_different_keypairs_different_secrets(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Two independent DH exchanges produce different shared secrets."""
        rs = p11_raw_session
        _skip_no_dh(rs)

        # Exchange 1
        _pub1, priv1 = _gen_dh_keypair(rs.raw, rs.sh)
        pub2, _priv2 = _gen_dh_keypair(rs.raw, rs.sh)
        pub2_val = read_attributes(rs.raw, rs.sh, pub2, [int(CKA_VALUE)])[int(CKA_VALUE)]
        key1 = derive_key(
            rs.raw,
            rs.sh,
            priv1,
            CKM_DH_PKCS_DERIVE,
            attrs={
                int(CKA_CLASS): int(CKO_SECRET_KEY),
                int(CKA_KEY_TYPE): int(CKK_AES),
                int(CKA_VALUE_LEN): 16,
                int(CKA_SENSITIVE): False,
                int(CKA_EXTRACTABLE): True,
                int(CKA_TOKEN): False,
            },
            mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, pub2_val),
        )

        # Exchange 2 (fresh keypairs)
        _pub3, priv3 = _gen_dh_keypair(rs.raw, rs.sh)
        pub4, _priv4 = _gen_dh_keypair(rs.raw, rs.sh)
        pub4_val = read_attributes(rs.raw, rs.sh, pub4, [int(CKA_VALUE)])[int(CKA_VALUE)]
        key2 = derive_key(
            rs.raw,
            rs.sh,
            priv3,
            CKM_DH_PKCS_DERIVE,
            attrs={
                int(CKA_CLASS): int(CKO_SECRET_KEY),
                int(CKA_KEY_TYPE): int(CKK_AES),
                int(CKA_VALUE_LEN): 16,
                int(CKA_SENSITIVE): False,
                int(CKA_EXTRACTABLE): True,
                int(CKA_TOKEN): False,
            },
            mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, pub4_val),
        )

        try:
            # Different exchanges should produce different keys
            v1 = read_attributes(rs.raw, rs.sh, key1, [int(CKA_VALUE)])[int(CKA_VALUE)]
            v2 = read_attributes(rs.raw, rs.sh, key2, [int(CKA_VALUE)])[int(CKA_VALUE)]
            assert v1 != v2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)
            destroy_quietly(rs.raw, rs.sh, _pub1)
            destroy_quietly(rs.raw, rs.sh, priv1)
            destroy_quietly(rs.raw, rs.sh, pub2)
            destroy_quietly(rs.raw, rs.sh, _priv2)
            destroy_quietly(rs.raw, rs.sh, _pub3)
            destroy_quietly(rs.raw, rs.sh, priv3)
            destroy_quietly(rs.raw, rs.sh, pub4)
            destroy_quietly(rs.raw, rs.sh, _priv4)


class TestDHParameterGeneration:
    """Test CKM_DH_PKCS_PARAMETER_GEN (on-token DH parameter generation)."""

    def test_generate_dh_parameters(self, p11_raw_session: Any) -> None:
        """Generate DH domain parameters on the token."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_PARAMETER_GEN"):
            pytest.skip("CKM_DH_PKCS_PARAMETER_GEN not supported")

        tmpl = template(
            attr_ulong(CKA_PRIME_BITS, 2048),
            attr_bool(CKA_TOKEN, False),
        )
        dp_handle = CK_OBJECT_HANDLE(0)
        mech = mech_simple(CKM_DH_PKCS_PARAMETER_GEN)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(dp_handle),
        )
        expect_rv(int(rv), CKR_OK)
        try:
            assert int(dp_handle.value) != 0

            attrs = read_attributes(rs.raw, rs.sh, int(dp_handle.value), [int(CKA_PRIME)])
            prime = attrs[int(CKA_PRIME)]
            assert isinstance(prime, bytes)
            assert len(prime) * 8 >= 2048
        finally:
            destroy_quietly(rs.raw, rs.sh, int(dp_handle.value))

    def test_generated_params_produce_valid_keypair(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Generated parameters can produce a keypair that does key agreement."""
        rs = p11_raw_session
        if not rs.has_mechanism("DH_PKCS_PARAMETER_GEN"):
            pytest.skip("CKM_DH_PKCS_PARAMETER_GEN not supported")
        if not rs.has_mechanism("DH_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")

        # Generate domain parameters
        tmpl = template(
            attr_ulong(CKA_PRIME_BITS, 2048),
            attr_bool(CKA_TOKEN, False),
        )
        dp_handle = CK_OBJECT_HANDLE(0)
        mech = mech_simple(CKM_DH_PKCS_PARAMETER_GEN)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(dp_handle),
        )
        expect_rv(int(rv), CKR_OK)
        try:
            # Read the generated prime and base
            dp_attrs = read_attributes(
                rs.raw,
                rs.sh,
                int(dp_handle.value),
                [int(CKA_PRIME), int(CKA_BASE)],
            )
            prime = dp_attrs[int(CKA_PRIME)]
            base = dp_attrs[int(CKA_BASE)]
            assert isinstance(prime, bytes)
            assert isinstance(base, bytes)

            # Generate two keypairs from the params
            pub_a, priv_a = _gen_dh_keypair(rs.raw, rs.sh, prime, base)
            pub_b, priv_b = _gen_dh_keypair(rs.raw, rs.sh, prime, base)
            try:
                pub_b_val = read_attributes(rs.raw, rs.sh, pub_b, [int(CKA_VALUE)])[int(CKA_VALUE)]
                pub_a_val = read_attributes(rs.raw, rs.sh, pub_a, [int(CKA_VALUE)])[int(CKA_VALUE)]

                key_a = derive_key(
                    rs.raw,
                    rs.sh,
                    priv_a,
                    CKM_DH_PKCS_DERIVE,
                    attrs={
                        int(CKA_CLASS): int(CKO_SECRET_KEY),
                        int(CKA_KEY_TYPE): int(CKK_AES),
                        int(CKA_VALUE_LEN): 16,
                        int(CKA_SENSITIVE): False,
                        int(CKA_EXTRACTABLE): True,
                        int(CKA_TOKEN): False,
                    },
                    mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, pub_b_val),
                )
                key_b = derive_key(
                    rs.raw,
                    rs.sh,
                    priv_b,
                    CKM_DH_PKCS_DERIVE,
                    attrs={
                        int(CKA_CLASS): int(CKO_SECRET_KEY),
                        int(CKA_KEY_TYPE): int(CKK_AES),
                        int(CKA_VALUE_LEN): 16,
                        int(CKA_SENSITIVE): False,
                        int(CKA_EXTRACTABLE): True,
                        int(CKA_TOKEN): False,
                    },
                    mech_param=mech_bytes(CKM_DH_PKCS_DERIVE, pub_a_val),
                )
                try:
                    va = read_attributes(rs.raw, rs.sh, key_a, [int(CKA_VALUE)])[int(CKA_VALUE)]
                    vb = read_attributes(rs.raw, rs.sh, key_b, [int(CKA_VALUE)])[int(CKA_VALUE)]
                    assert va == vb
                finally:
                    destroy_quietly(rs.raw, rs.sh, key_a)
                    destroy_quietly(rs.raw, rs.sh, key_b)
            finally:
                destroy_quietly(rs.raw, rs.sh, pub_a)
                destroy_quietly(rs.raw, rs.sh, priv_a)
                destroy_quietly(rs.raw, rs.sh, pub_b)
                destroy_quietly(rs.raw, rs.sh, priv_b)
        finally:
            destroy_quietly(rs.raw, rs.sh, int(dp_handle.value))
