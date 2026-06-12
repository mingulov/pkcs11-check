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
from collections.abc import Callable
from ctypes import byref
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.pack import (
    LengthArg,
    PackedMechanism,
    PointerArg,
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    derive_key,
    destroy_quietly,
    encrypt_single,
    get_mechanism_info,
    read_attributes,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_VOID_PTR,
    CK_X9_42_DH1_DERIVE_PARAMS,
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
    CKA_SUBPRIME,
    CKA_SUBPRIME_BITS,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKD_SHA1_KDF_ASN1,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKK_X9_42_DH,
    CKM_AES_ECB,
    CKM_X9_42_DH_DERIVE,
    CKM_X9_42_DH_KEY_PAIR_GEN,
    CKM_X9_42_DH_PARAMETER_GEN,
    CKO_PRIVATE_KEY,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import classify_negative_rv, is_known_error, xfail_if_known_ckr

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

_X942_RFC5114_ALICE_PRIVATE = bytes.fromhex(
    "0102030405060708090a0b0c0d0e0f10"
    "1112131415161718191a1b1c1d1e1f20"
)
_X942_RFC5114_BOB_PUBLIC = bytes.fromhex(
    "17f5faa191eea8f9f132a9a12177057727fd0222da1944f3779146396a1ba94b"
    "8ac16ef5abab5482c21bcb179d4927d705a56e293c15e7dcbe186d153b6551"
    "3ae94447da0648d0cdba17cb014cf718b7fca9042f4179c3ffdb75789d4d4"
    "f3c3b73ae79c26a061b3c1ff591ea1a811c75130d295fdb4b70fbf398f4"
    "ff596b010654927606657a9c9c67fe288b0a6079009751d7fcff27a8ecc7"
    "58b4aeb8480eee1684f2fe82e6ac51e2c6003363c95bf8ca948af075296"
    "5cf8617627f20099fdf788098eb24dfd82d555e06ad71a9b7e4d2b97a8b"
    "735c68cbc6df76c75a51e6f017d501fdcc47e2643b4952a89c5384700f2"
    "7dffe3f64cc5cf566e823a1121b28"
)
_X942_RFC5114_EXPECTED_SECRET_32 = bytes.fromhex(
    "7c242567d649f58f68fd9650fe96a6e1"
    "8a70f17920dbdca3dd51101239b18788"
)

_X942_PARAM_PRIME_BITS = 2048
_X942_PARAM_SUBPRIME_BITS = 256
_X942_PARAM_SIZE_CANDIDATES = (
    (1024, 160),
    (_X942_PARAM_PRIME_BITS, _X942_PARAM_SUBPRIME_BITS),
)

_X942_PARAMETER_SIZE_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
)

_X942_PARAMETER_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_X942_KEYPAIR_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_X942_DERIVE_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_X942_INVALID_PEER_PUBLIC_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_X942_INVALID_OTHER_INFO_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_PARAM_INVALID,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _skip_no_x942_keygen(rs: Any) -> None:
    if not rs.has_mechanism("X9_42_DH_KEY_PAIR_GEN"):
        pytest.skip("CKM_X9_42_DH_KEY_PAIR_GEN not supported")


def _skip_no_x942_derive(rs: Any) -> None:
    if not rs.has_mechanism("X9_42_DH_DERIVE"):
        pytest.skip("CKM_X9_42_DH_DERIVE not supported")


def _generate_x942_keypair(
    rs: Any,
    *,
    prime: bytes = X942_PRIME_2048,
    base: bytes = X942_GEN,
    subprime: bytes = X942_SUBPRIME,
) -> tuple[int, int]:
    """Generate an X9.42 DH keypair using RFC 5114 parameters via raw C_GenerateKeyPair."""
    pub_tmpl = template(
        attr_ulong(CKA_CLASS, 0x00000002),  # CKO_PUBLIC_KEY
        attr_ulong(CKA_KEY_TYPE, CKK_X9_42_DH),
        attr_bytes(CKA_PRIME, prime),
        attr_bytes(CKA_BASE, base),
        attr_bytes(CKA_SUBPRIME, subprime),
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
    expect_rv(rv, CKR_OK)
    return pub_h.value, priv_h.value


def _generate_x942_params(
    raw: Any,
    sh: int,
    *,
    prime_bits: int = _X942_PARAM_PRIME_BITS,
    subprime_bits: int = _X942_PARAM_SUBPRIME_BITS,
) -> int:
    """Generate an X9.42 DH domain-parameter object."""
    tmpl = template(
        attr_ulong(CKA_PRIME_BITS, prime_bits),
        attr_ulong(CKA_SUBPRIME_BITS, subprime_bits),
        attr_bool(CKA_TOKEN, False),
    )
    dp_handle = CK_OBJECT_HANDLE(0)
    mech = mech_simple(CKM_X9_42_DH_PARAMETER_GEN)
    rv = raw.C_GenerateKey(
        sh,
        mech.byref(),
        tmpl.ptr,
        tmpl.count,
        byref(dp_handle),
    )
    expect_rv(rv, CKR_OK)
    return dp_handle.value


def _read_x942_params(
    raw: Any,
    sh: int,
    dp_handle: int,
    *,
    expected_prime_bits: int = _X942_PARAM_PRIME_BITS,
    expected_subprime_bits: int = _X942_PARAM_SUBPRIME_BITS,
) -> tuple[bytes, bytes, bytes]:
    attrs = read_attributes(
        raw,
        sh,
        dp_handle,
        [CKA_PRIME, CKA_BASE, CKA_SUBPRIME, CKA_PRIME_BITS, CKA_SUBPRIME_BITS],
    )
    prime = attrs[CKA_PRIME]
    base = attrs[CKA_BASE]
    subprime = attrs[CKA_SUBPRIME]
    prime_bits = attrs[CKA_PRIME_BITS]
    subprime_bits = attrs[CKA_SUBPRIME_BITS]

    assert isinstance(prime, bytes)
    assert isinstance(base, bytes)
    assert isinstance(subprime, bytes)
    assert prime_bits == expected_prime_bits
    assert subprime_bits == expected_subprime_bits
    assert len(prime) * 8 >= expected_prime_bits
    assert len(base) > 0
    assert len(subprime) * 8 >= expected_subprime_bits
    return prime, base, subprime


def _x942_param_size_candidates(rs: Any) -> tuple[tuple[int, int], ...]:
    slot_id = getattr(rs, "slot_id", None)
    if slot_id is None:
        return ((_X942_PARAM_PRIME_BITS, _X942_PARAM_SUBPRIME_BITS),)

    info = get_mechanism_info(rs.raw, slot_id, CKM_X9_42_DH_PARAMETER_GEN)
    min_key_size = int(info["min_key_size"])
    max_key_size = int(info["max_key_size"])
    candidates = tuple(
        (prime_bits, subprime_bits)
        for prime_bits, subprime_bits in _X942_PARAM_SIZE_CANDIDATES
        if (min_key_size == 0 or prime_bits >= min_key_size)
        and (max_key_size == 0 or prime_bits <= max_key_size)
    )
    if candidates:
        return candidates

    pytest.skip(
        "CKM_X9_42_DH_PARAMETER_GEN advertised, but mechanism info has no "
        "1024/160 or 2048/256 testable prime-size candidate"
    )


def _generate_x942_params_for_session(rs: Any) -> tuple[int, int, int]:
    last_size_reject: AssertionError | None = None
    for prime_bits, subprime_bits in _x942_param_size_candidates(rs):
        try:
            dp = _generate_x942_params(
                rs.raw,
                rs.sh,
                prime_bits=prime_bits,
                subprime_bits=subprime_bits,
            )
        except AssertionError as e:
            if is_known_error(e, _X942_PARAMETER_SIZE_REJECT_RVS):
                last_size_reject = e
                continue
            _skip_or_xfail_x942_param_gen_reject(e)
        return dp, prime_bits, subprime_bits

    if last_size_reject is not None:
        _skip_or_xfail_x942_param_gen_reject(last_size_reject)
    pytest.skip("No X9.42 DH parameter-generation size candidate available")


def _skip_or_xfail_x942_param_gen_reject(exc: AssertionError) -> NoReturn:
    if is_known_error(exc, _X942_PARAMETER_SIZE_REJECT_RVS):
        pytest.skip(
            "X9.42 DH 2048/256 parameter generation not supported by this module: "
            f"{exc}"
        )
    xfail_if_known_ckr(
        exc,
        _X942_PARAMETER_RUNTIME_REJECT_RVS,
        "X9_42_DH_PARAMETER_GEN advertised but parameter generation is not operational",
    )
    raise


def _xfail_if_x942_keypair_reject(exc: AssertionError) -> NoReturn:
    xfail_if_known_ckr(
        exc,
        _X942_KEYPAIR_RUNTIME_REJECT_RVS,
        "X9_42_DH_KEY_PAIR_GEN advertised but keypair generation from generated "
        "params is not operational",
    )
    raise


def _xfail_if_x942_derive_reject(exc: AssertionError) -> NoReturn:
    xfail_if_known_ckr(
        exc,
        _X942_DERIVE_RUNTIME_REJECT_RVS,
        "X9_42_DH_DERIVE advertised but derive from generated params is not operational",
    )
    raise


def _import_x942_private_key(
    raw: Any,
    sh: int,
    private_value: bytes,
) -> int:
    """Import an X9.42 DH private key for deterministic derive vectors."""
    return create_object(
        raw,
        sh,
        {
            CKA_CLASS: CKO_PRIVATE_KEY,
            CKA_KEY_TYPE: CKK_X9_42_DH,
            CKA_PRIME: X942_PRIME_2048,
            CKA_BASE: X942_GEN,
            CKA_SUBPRIME: X942_SUBPRIME,
            CKA_VALUE: private_value,
            CKA_DERIVE: True,
            CKA_TOKEN: False,
        },
    )


def _x942_setup_or_xfail(fn: Callable[[], int], label: str) -> int:
    try:
        return fn()
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _X942_DERIVE_RUNTIME_REJECT_RVS,
            f"{label}: X9.42 DH exact-vector setup is not operational",
        )
        raise


def _x942_derive_or_xfail(fn: Callable[[], int], label: str) -> int:
    try:
        return fn()
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _X942_DERIVE_RUNTIME_REJECT_RVS,
            f"{label}: X9.42 DH derive advertised but not operational",
        )
        raise


def _build_x942_derive_mech(
    public_data: bytes,
    kdf: int = CKD_NULL,
    *,
    other_info: bytes | None = None,
) -> PackedMechanism:
    """Build CKM_X9_42_DH_DERIVE mechanism with CK_X9_42_DH1_DERIVE_PARAMS."""
    keepalive: list[Any] = []

    pub_arr = (ctypes.c_ubyte * len(public_data))(*public_data)
    keepalive.append(pub_arr)

    params = CK_X9_42_DH1_DERIVE_PARAMS()
    params.kdf = kdf
    params.ulPublicDataLen = len(public_data)
    params.pPublicData = ctypes.cast(pub_arr, CK_VOID_PTR)
    if other_info is None:
        params.ulOtherInfoLen = 0
        params.pOtherInfo = None
    else:
        other_info_arr = (ctypes.c_ubyte * len(other_info))(*other_info)
        keepalive.append(other_info_arr)
        params.ulOtherInfoLen = len(other_info)
        params.pOtherInfo = ctypes.cast(other_info_arr, CK_VOID_PTR)
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

    def test_x942_derive_rejects_missing_peer_public_value(self, p11_raw_session: Any) -> None:
        """CKM_X9_42_DH_DERIVE must reject a missing DH1 derive parameter struct."""
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        _skip_no_x942_derive(rs)

        pub, priv = _generate_x942_keypair(rs)
        mech = mech_simple(CKM_X9_42_DH_DERIVE)
        derived = CK_OBJECT_HANDLE(0)
        attrs = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_AES),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_TOKEN, False),
        )
        try:
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                mech.byref(),
                priv,
                attrs.ptr,
                attrs.count,
                byref(derived),
            )
            classify_negative_rv(
                rv,
                (CKR_MECHANISM_PARAM_INVALID,),
                label="CKM_X9_42_DH_DERIVE missing peer public value",
            )
        finally:
            if derived.value:
                destroy_quietly(rs.raw, rs.sh, derived.value)
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_x942_derive_rejects_malformed_peer_public_value(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_X9_42_DH_DERIVE must reject a malformed peer public value."""
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        _skip_no_x942_derive(rs)

        pub, priv = _generate_x942_keypair(rs)
        mech = _build_x942_derive_mech(b"\x01")
        derived = CK_OBJECT_HANDLE(0)
        attrs = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_TOKEN, False),
        )
        try:
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                mech.byref(),
                priv,
                attrs.ptr,
                attrs.count,
                byref(derived),
            )
            classify_negative_rv(
                rv,
                _X942_INVALID_PEER_PUBLIC_RVS,
                label="CKM_X9_42_DH_DERIVE malformed peer public value",
            )
        finally:
            if derived.value:
                destroy_quietly(rs.raw, rs.sh, derived.value)
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_x942_derive_rejects_ckd_null_other_info(self, p11_raw_session: Any) -> None:
        """CKM_X9_42_DH_DERIVE CKD_NULL with OtherInfo must be rejected."""
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        _skip_no_x942_derive(rs)

        alice_pub, alice_priv = _generate_x942_keypair(rs)
        bob_pub, bob_priv = _generate_x942_keypair(rs)
        derived = CK_OBJECT_HANDLE(0)
        attrs = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_TOKEN, False),
        )
        try:
            bob_value = read_attributes(rs.raw, rs.sh, bob_pub, [CKA_VALUE])[CKA_VALUE]
            mech = _build_x942_derive_mech(
                bob_value,
                CKD_NULL,
                other_info=b"not allowed with CKD_NULL",
            )
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                mech.byref(),
                alice_priv,
                attrs.ptr,
                attrs.count,
                byref(derived),
            )
            classify_negative_rv(
                rv,
                _X942_INVALID_OTHER_INFO_RVS,
                label="CKM_X9_42_DH_DERIVE CKD_NULL with OtherInfo",
            )
        finally:
            if derived.value:
                destroy_quietly(rs.raw, rs.sh, derived.value)
            destroy_quietly(rs.raw, rs.sh, alice_pub)
            destroy_quietly(rs.raw, rs.sh, alice_priv)
            destroy_quietly(rs.raw, rs.sh, bob_pub)
            destroy_quietly(rs.raw, rs.sh, bob_priv)

    def test_x942_derive_rejects_asn1_kdf_missing_other_info(
        self,
        p11_raw_session: Any,
    ) -> None:
        """CKM_X9_42_DH_DERIVE CKD_SHA1_KDF_ASN1 missing OtherInfo must be rejected."""
        rs = p11_raw_session
        _skip_no_x942_keygen(rs)
        _skip_no_x942_derive(rs)

        alice_pub, alice_priv = _generate_x942_keypair(rs)
        bob_pub, bob_priv = _generate_x942_keypair(rs)
        derived = CK_OBJECT_HANDLE(0)
        attrs = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_TOKEN, False),
        )
        try:
            bob_value = read_attributes(rs.raw, rs.sh, bob_pub, [CKA_VALUE])[CKA_VALUE]
            mech = _build_x942_derive_mech(bob_value, CKD_SHA1_KDF_ASN1)
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                mech.byref(),
                alice_priv,
                attrs.ptr,
                attrs.count,
                byref(derived),
            )
            classify_negative_rv(
                rv,
                _X942_INVALID_OTHER_INFO_RVS,
                label="CKM_X9_42_DH_DERIVE CKD_SHA1_KDF_ASN1 missing OtherInfo",
            )
        finally:
            if derived.value:
                destroy_quietly(rs.raw, rs.sh, derived.value)
            destroy_quietly(rs.raw, rs.sh, alice_pub)
            destroy_quietly(rs.raw, rs.sh, alice_priv)
            destroy_quietly(rs.raw, rs.sh, bob_pub)
            destroy_quietly(rs.raw, rs.sh, bob_priv)

    def test_x942_dh_derive_rfc5114_exact_vector(self, p11_raw_session: Any) -> None:
        """CKM_X9_42_DH_DERIVE returns the expected RFC 5114 shared secret."""
        rs = p11_raw_session
        _skip_no_x942_derive(rs)

        priv = 0
        derived = 0
        try:
            priv = _x942_setup_or_xfail(
                lambda: _import_x942_private_key(
                    rs.raw,
                    rs.sh,
                    _X942_RFC5114_ALICE_PRIVATE,
                ),
                "CKM_X9_42_DH_DERIVE RFC 5114 vector",
            )
            derived = _x942_derive_or_xfail(
                lambda: derive_key(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_X9_42_DH_DERIVE,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                        CKA_VALUE_LEN: len(_X942_RFC5114_EXPECTED_SECRET_32),
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                        CKA_TOKEN: False,
                    },
                    mech_param=_build_x942_derive_mech(_X942_RFC5114_BOB_PUBLIC),
                ),
                "CKM_X9_42_DH_DERIVE RFC 5114 exact vector",
            )
            value = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
            assert value == _X942_RFC5114_EXPECTED_SECRET_32
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            if priv:
                destroy_quietly(rs.raw, rs.sh, priv)

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


@pytest.mark.slow
class TestX942DHParameterGen:
    """Test CKM_X9_42_DH_PARAMETER_GEN - on-token X9.42 DH parameter generation."""

    def test_generate_parameters(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("X9_42_DH_PARAMETER_GEN"):
            pytest.skip("CKM_X9_42_DH_PARAMETER_GEN not supported")

        dp, prime_bits, subprime_bits = _generate_x942_params_for_session(rs)
        try:
            assert dp != 0
            _read_x942_params(
                rs.raw,
                rs.sh,
                dp,
                expected_prime_bits=prime_bits,
                expected_subprime_bits=subprime_bits,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_generated_params_produce_valid_derive(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("X9_42_DH_PARAMETER_GEN"):
            pytest.skip("CKM_X9_42_DH_PARAMETER_GEN not supported")
        if not rs.has_mechanism("X9_42_DH_KEY_PAIR_GEN"):
            pytest.skip("CKM_X9_42_DH_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("X9_42_DH_DERIVE"):
            pytest.skip("CKM_X9_42_DH_DERIVE not supported")

        dp, prime_bits, subprime_bits = _generate_x942_params_for_session(rs)

        alice_pub = 0
        alice_priv = 0
        bob_pub = 0
        bob_priv = 0
        alice_shared = 0
        bob_shared = 0
        try:
            prime, base, subprime = _read_x942_params(
                rs.raw,
                rs.sh,
                dp,
                expected_prime_bits=prime_bits,
                expected_subprime_bits=subprime_bits,
            )
            try:
                alice_pub, alice_priv = _generate_x942_keypair(
                    rs,
                    prime=prime,
                    base=base,
                    subprime=subprime,
                )
                bob_pub, bob_priv = _generate_x942_keypair(
                    rs,
                    prime=prime,
                    base=base,
                    subprime=subprime,
                )
            except AssertionError as e:
                _xfail_if_x942_keypair_reject(e)

            alice_value = read_attributes(rs.raw, rs.sh, alice_pub, [CKA_VALUE])[CKA_VALUE]
            bob_value = read_attributes(rs.raw, rs.sh, bob_pub, [CKA_VALUE])[CKA_VALUE]
            assert alice_value != bob_value
            assert isinstance(alice_value, bytes)
            assert isinstance(bob_value, bytes)

            try:
                alice_shared = _x942_derive_aes(rs, alice_priv, bob_value)
                bob_shared = _x942_derive_aes(rs, bob_priv, alice_value)
            except AssertionError as e:
                _xfail_if_x942_derive_reject(e)

            va = read_attributes(rs.raw, rs.sh, alice_shared, [CKA_VALUE])[CKA_VALUE]
            vb = read_attributes(rs.raw, rs.sh, bob_shared, [CKA_VALUE])[CKA_VALUE]
            assert va == vb
        finally:
            for h in (alice_pub, alice_priv, bob_pub, bob_priv, alice_shared, bob_shared, dp):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)


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
