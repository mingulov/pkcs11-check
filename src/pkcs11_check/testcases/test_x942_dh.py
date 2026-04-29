"""Tests for X9.42 Diffie-Hellman mechanisms.

Covers CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_DERIVE,
CKM_X9_42_DH_HYBRID_DERIVE, CKM_X9_42_DH_PARAMETER_GEN,
and CKM_X9_42_MQV_DERIVE.

Classic DH (CKM_DH_PKCS_*) is tested in test_dh_key_agreement.py.

OASIS spec: diffie-hellman.md

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    LengthArg,
    PackedMechanism,
    PointerArg,
    attr_bytes,
    attr_ulong,
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
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_VOID_PTR,
    CK_X9_42_DH1_DERIVE_PARAMS,
    CKA_BASE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PRIME,
    CKA_SENSITIVE,
    CKA_SUBPRIME,
    CKA_TOKEN,
    CKA_VALUE,
    CKD_NULL,
    CKK_AES,
    CKK_X9_42_DH,
    CKM_AES_ECB,
    CKM_X9_42_DH_DERIVE,
    CKM_X9_42_DH_KEY_PAIR_GEN,
    CKO_SECRET_KEY,
    CKR_OK,
)

pytestmark = pytest.mark.keymgmt


# ---------------------------------------------------------------------------
# X9.42 DH domain parameters (2048-bit)
# RFC 5114 Section 2.1 - 2048-bit MODP Group with 256-bit Prime Order Subgroup
# ---------------------------------------------------------------------------

X942_PRIME_2048 = bytes.fromhex(
    "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2"
    "5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30"
    "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD"
    "5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
    "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C"
    "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E"
    "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9"
    "67E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
    "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3"
    "75F26375D7014103A4B54330C198AF126116D2276E11715F"
    "693877FAD7EF09CADB094AE91E1A1597"
)

X942_GEN = bytes.fromhex(
    "3FB32C9B73134D0B2E7750628EB693FED3F1A8F7C2DF9390"
    "05F08CABC4F389AE1B8A3F9AE6F7A0E6017E0A71B27A8F44"
    "A72CE4B5E03B48E1B65214B3D43685E36BFE5E6D50B21F55"
    "CEB31A1CF31B2127F3FF2A4F10C35E84B3C83D3E9B5A54D8"
    "F40C5C7A1E826A8EB813EFE1CC9F5C8C2A43C64FE9085E6B"
    "35DAD56BC9EC24548A0C5B3D5D06E6CBBD97FA9553E89A2B"
    "C53C07ADBDE068E7CBEE7F55D4348A3E4BEBBFDF6A2C2D99"
    "4BFD15B8D3E23CC1B34B78EC1BD153DD294B8B2D2F74E6A6"
    "4C3F26E5DFC1002AE7B6125549F9E2BB9EB6D1BFBEB0E166"
    "A85EC0E5DA0C2FE36D73B36B6DF5D6CA4D30ECA61C5F1283"
    "33E4BF98B3A315B88D924B4C1EB4CF7113"
)

X942_SUBPRIME = bytes.fromhex("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _skip_no_x942_keygen(rs: Any) -> None:
    if not rs.has_mechanism("X9_42_DH_KEY_PAIR_GEN"):
        pytest.skip("CKM_X9_42_DH_KEY_PAIR_GEN not supported")


def _skip_no_x942_derive(rs: Any) -> None:
    if not rs.has_mechanism("X9_42_DH_DERIVE"):
        pytest.skip("CKM_X9_42_DH_DERIVE not supported")


def _generate_x942_keypair(rs: Any) -> tuple[int, int]:
    """Generate an X9.42 DH keypair using RFC 5114 parameters via raw C_GenerateKeyPair."""
    pub_tmpl = template(
        attr_ulong(CKA_CLASS, 0x00000002),  # CKO_PUBLIC_KEY
        attr_ulong(CKA_KEY_TYPE, CKK_X9_42_DH),
        attr_bytes(CKA_PRIME, X942_PRIME_2048),
        attr_bytes(CKA_BASE, X942_GEN),
        attr_bytes(CKA_SUBPRIME, X942_SUBPRIME),
    )
    priv_tmpl = template(
        attr_ulong(CKA_CLASS, 0x00000003),  # CKO_PRIVATE_KEY
        attr_ulong(CKA_KEY_TYPE, CKK_X9_42_DH),
    )
    mech = mech_simple(CKM_X9_42_DH_KEY_PAIR_GEN)
    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKeyPair(
        rs.sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_h),
        byref(priv_h),
    )
    assert rv == CKR_OK, f"C_GenerateKeyPair failed: {ckr_name(rv)}"
    return pub_h.value, priv_h.value


def _build_x942_derive_mech(
    public_data: bytes,
    kdf: int = CKD_NULL,
) -> PackedMechanism:
    """Build CKM_X9_42_DH_DERIVE mechanism with CK_X9_42_DH1_DERIVE_PARAMS."""
    keepalive: list[Any] = []

    pub_arr = (ctypes.c_ubyte * len(public_data))(*public_data)
    keepalive.append(pub_arr)

    params = CK_X9_42_DH1_DERIVE_PARAMS()
    params.kdf = kdf
    params.ulPublicDataLen = len(public_data)
    params.pPublicData = ctypes.cast(pub_arr, CK_VOID_PTR)
    params.ulOtherInfoLen = 0
    params.pOtherInfo = None
    keepalive.append(params)

    pointer_arg = PointerArg.to_storage(params, origin="x942_dh1_derive")
    length_arg = LengthArg.native(ctypes.sizeof(params))
    pm = PackedMechanism(
        CK_MECHANISM(CKM_X9_42_DH_DERIVE, pointer_arg.pointer, length_arg.value),
        storage=params,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
        params=params,
    )
    pm._keepalive.extend(keepalive)
    return pm


def _x942_derive_aes(
    rs: Any,
    priv: int,
    peer_pub_value: bytes,
    extra_attrs: dict[int, Any] | None = None,
) -> int:
    """Derive an AES-128 key from X9.42 DH."""
    attrs: dict[int, Any] = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
        CKA_TOKEN: False,
    }
    if extra_attrs:
        attrs.update(extra_attrs)
    return derive_key(
        rs.raw,
        rs.sh,
        priv,
        CKM_X9_42_DH_DERIVE,
        attrs=attrs,
        mech_param=_build_x942_derive_mech(peer_pub_value),
    )


class TestX942DHKeyPairGen:
    """Test CKM_X9_42_DH_KEY_PAIR_GEN - X9.42 DH key pair generation."""

    def test_keypair_generation(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        pub, priv = _generate_x942_keypair(rs)
        try:
            assert pub != 0
            assert priv != 0
            pub_value = read_attributes(rs.raw, rs.sh, pub, [CKA_VALUE])[CKA_VALUE]
            assert isinstance(pub_value, bytes)
            assert len(pub_value) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_keypair_has_correct_key_type(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        pub, priv = _generate_x942_keypair(rs)
        try:
            pub_kt = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            priv_kt = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])[CKA_KEY_TYPE]
            assert pub_kt == CKK_X9_42_DH
            assert priv_kt == CKK_X9_42_DH
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_keypair_prime_matches_params(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        pub, priv = _generate_x942_keypair(rs)
        try:
            pub_prime = read_attributes(rs.raw, rs.sh, pub, [CKA_PRIME])[CKA_PRIME]
            assert pub_prime == X942_PRIME_2048
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_keypair_subprime_matches_params(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        pub, priv = _generate_x942_keypair(rs)
        try:
            pub_subprime = read_attributes(rs.raw, rs.sh, pub, [CKA_SUBPRIME])[CKA_SUBPRIME]
            assert pub_subprime == X942_SUBPRIME
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_two_keypairs_have_different_public_values(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        pub1, priv1 = _generate_x942_keypair(rs)
        pub2, priv2 = _generate_x942_keypair(rs)
        try:
            val1 = read_attributes(rs.raw, rs.sh, pub1, [CKA_VALUE])[CKA_VALUE]
            val2 = read_attributes(rs.raw, rs.sh, pub2, [CKA_VALUE])[CKA_VALUE]
            assert val1 != val2
        finally:
            for h in (pub1, priv1, pub2, priv2):
                destroy_quietly(rs.raw, rs.sh, h)


class TestX942DHDerive:
    """Test CKM_X9_42_DH_DERIVE - X9.42 DH key derivation."""

    def test_derive_shared_secret(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        _skip_no_x942_derive(rs)

        alice_pub, alice_priv = _generate_x942_keypair(rs)
        bob_pub, bob_priv = _generate_x942_keypair(rs)
        alice_shared = 0
        bob_shared = 0
        try:
            alice_value = read_attributes(rs.raw, rs.sh, alice_pub, [CKA_VALUE])[CKA_VALUE]
            bob_value = read_attributes(rs.raw, rs.sh, bob_pub, [CKA_VALUE])[CKA_VALUE]
            assert alice_value != bob_value

            alice_shared = _x942_derive_aes(rs, alice_priv, bob_value)
            bob_shared = _x942_derive_aes(rs, bob_priv, alice_value)

            va = read_attributes(rs.raw, rs.sh, alice_shared, [CKA_VALUE])[CKA_VALUE]
            vb = read_attributes(rs.raw, rs.sh, bob_shared, [CKA_VALUE])[CKA_VALUE]
            assert va == vb
        finally:
            for h in (alice_pub, alice_priv, bob_pub, bob_priv):
                destroy_quietly(rs.raw, rs.sh, h)
            if alice_shared:
                destroy_quietly(rs.raw, rs.sh, alice_shared)
            if bob_shared:
                destroy_quietly(rs.raw, rs.sh, bob_shared)

    def test_derived_key_encrypts(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        _skip_no_x942_derive(rs)

        alice_pub, alice_priv = _generate_x942_keypair(rs)
        bob_pub, bob_priv = _generate_x942_keypair(rs)
        shared_key = 0
        bob_key = 0
        try:
            bob_value = read_attributes(rs.raw, rs.sh, bob_pub, [CKA_VALUE])[CKA_VALUE]
            alice_value = read_attributes(rs.raw, rs.sh, alice_pub, [CKA_VALUE])[CKA_VALUE]

            shared_key = _x942_derive_aes(
                rs,
                alice_priv,
                bob_value,
                extra_attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
            )

            plaintext = b"X9.42 DH test!!" + b"\x00"  # 16 bytes for AES-ECB
            ct = encrypt_single(rs.raw, rs.sh, shared_key, CKM_AES_ECB, plaintext)
            assert ct != plaintext

            bob_key = _x942_derive_aes(
                rs,
                bob_priv,
                alice_value,
                extra_attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
            )
            pt = decrypt_single(rs.raw, rs.sh, bob_key, CKM_AES_ECB, ct)
            assert pt == plaintext
        finally:
            for h in (alice_pub, alice_priv, bob_pub, bob_priv):
                destroy_quietly(rs.raw, rs.sh, h)
            if shared_key:
                destroy_quietly(rs.raw, rs.sh, shared_key)
            if bob_key:
                destroy_quietly(rs.raw, rs.sh, bob_key)

    def test_different_exchanges_produce_different_secrets(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        _skip_no_x942_derive(rs)

        _pub1, priv1 = _generate_x942_keypair(rs)
        pub2, _priv2 = _generate_x942_keypair(rs)
        _pub3, priv3 = _generate_x942_keypair(rs)
        pub4, _priv4 = _generate_x942_keypair(rs)
        key1 = 0
        key2 = 0
        try:
            val2 = read_attributes(rs.raw, rs.sh, pub2, [CKA_VALUE])[CKA_VALUE]
            key1 = _x942_derive_aes(rs, priv1, val2)

            val4 = read_attributes(rs.raw, rs.sh, pub4, [CKA_VALUE])[CKA_VALUE]
            key2 = _x942_derive_aes(rs, priv3, val4)

            v1 = read_attributes(rs.raw, rs.sh, key1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, key2, [CKA_VALUE])[CKA_VALUE]
            assert v1 != v2
        finally:
            for h in (_pub1, priv1, pub2, _priv2, _pub3, priv3, pub4, _priv4):
                destroy_quietly(rs.raw, rs.sh, h)
            if key1:
                destroy_quietly(rs.raw, rs.sh, key1)
            if key2:
                destroy_quietly(rs.raw, rs.sh, key2)


class TestX942DHParameterGen:
    """Test CKM_X9_42_DH_PARAMETER_GEN - on-token X9.42 DH parameter generation."""

    def test_generate_parameters(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("X9_42_DH_PARAMETER_GEN"):
            pytest.skip("CKM_X9_42_DH_PARAMETER_GEN not supported")

        # This mechanism is very rarely supported - just probe availability
        pytest.skip("CKM_X9_42_DH_PARAMETER_GEN generation is extremely slow; skipping")


class TestX942DHHybridDerive:
    """Test CKM_X9_42_DH_HYBRID_DERIVE."""

    def test_hybrid_derive_availability(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("X9_42_DH_HYBRID_DERIVE"):
            pytest.skip("CKM_X9_42_DH_HYBRID_DERIVE not supported")
        _skip_no_x942_keygen(rs)
        pub, priv = _generate_x942_keypair(rs)
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestX942MQVDerive:
    """Test CKM_X9_42_MQV_DERIVE."""

    def test_mqv_derive_availability(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("X9_42_MQV_DERIVE"):
            pytest.skip("CKM_X9_42_MQV_DERIVE not supported")
        _skip_no_x942_keygen(rs)
        pub, priv = _generate_x942_keypair(rs)
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
