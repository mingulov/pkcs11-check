"""Tests for the complete DSA mechanism family.

Covers raw CKM_DSA, prehash variants (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-*),
and CKM_DSA_PARAMETER_GEN.

Note: CKM_DSA_KEY_PAIR_GEN is already tested in test_sign.py.

OASIS PKCS#11 v3.2 spec: DSA.
"""

from __future__ import annotations

import ctypes
import hashlib
from ctypes import byref
from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import (
    PackedMechanism,
    _mech_struct,
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    read_attributes,
    sign_multipart,
    sign_single,
    verify_multipart,
    verify_single,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_BYTE,
    CK_DSA_PARAMETER_GEN_PARAM,
    CK_OBJECT_HANDLE,
    CKA_BASE,
    CKA_PRIME,
    CKA_PRIME_BITS,
    CKA_SIGN,
    CKA_SUBPRIME,
    CKA_SUBPRIME_BITS,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM_DSA,
    CKM_DSA_FIPS_G_GEN,
    CKM_DSA_KEY_PAIR_GEN,
    CKM_DSA_PARAMETER_GEN,
    CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
    CKM_DSA_SHA1,
    CKM_DSA_SHA3_224,
    CKM_DSA_SHA3_256,
    CKM_DSA_SHA3_384,
    CKM_DSA_SHA3_512,
    CKM_DSA_SHA224,
    CKM_DSA_SHA256,
    CKM_DSA_SHA384,
    CKM_DSA_SHA512,
    CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
    CKM_SHA256,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._signature_policy import (
    signature_rejected_or_xfail,
    xfail_if_op_not_operational,
)
from pkcs11_check.testcases.conftest import (
    assert_correct,
    classify_negative_rv,
    is_known_error,
    xfail_if_known_ckr,
)

# Verification failure return values
_VERIFY_FAIL_RVS = {
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_FUNCTION_FAILED,
}

_DSA_PARAMETER_SIZE_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
)

_DSA_PARAMETER_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_BUFFER_TOO_SMALL,
)

# DSA parameter/key generation is heavy on several modules (10-32s per case
# on some modules); the whole file is keygen-bound. Marked slow so a basic run can skip
# it with -m "not slow"; it still runs in the full profile.
pytestmark = [pytest.mark.sign, pytest.mark.slow]

_DSA_KEYPAIR_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_DSA_PARAMETER_TEMPLATE_REJECT_RVS = (CKR_TEMPLATE_INCOMPLETE,)

# Prehash DSA variants.
_DSA_HASH_MECHS = [
    pytest.param("DSA_SHA1", CKM_DSA_SHA1, id="SHA1"),
    pytest.param("DSA_SHA224", CKM_DSA_SHA224, id="SHA224"),
    pytest.param("DSA_SHA256", CKM_DSA_SHA256, id="SHA256"),
    pytest.param("DSA_SHA384", CKM_DSA_SHA384, id="SHA384"),
    pytest.param("DSA_SHA512", CKM_DSA_SHA512, id="SHA512"),
    pytest.param("DSA_SHA3_224", CKM_DSA_SHA3_224, id="SHA3-224"),
    pytest.param("DSA_SHA3_256", CKM_DSA_SHA3_256, id="SHA3-256"),
    pytest.param("DSA_SHA3_384", CKM_DSA_SHA3_384, id="SHA3-384"),
    pytest.param("DSA_SHA3_512", CKM_DSA_SHA3_512, id="SHA3-512"),
]


def _dsa_parameter_gen_param_mech(
    mechanism: int,
    *,
    seed_len: int = 64,
    seed: bytes | None = None,
    index: int = 1,
    hash_mech: int = CKM_SHA256,
) -> PackedMechanism:
    """Pack CK_DSA_PARAMETER_GEN_PARAM with an owned mutable seed buffer."""
    if seed_len < 0:
        raise ValueError("seed_len must be non-negative")
    if seed is not None and len(seed) > seed_len:
        raise ValueError("seed does not fit in seed_len")

    seed_buf = (CK_BYTE * seed_len)()
    if seed:
        ctypes.memmove(seed_buf, seed, len(seed))

    params = CK_DSA_PARAMETER_GEN_PARAM()
    params.hash = hash_mech
    params.pSeed = ctypes.cast(seed_buf, ctypes.c_void_p)
    params.ulSeedLen = seed_len
    params.ulIndex = index

    packed = _mech_struct(mechanism, params, "dsa_parameter_gen_param")
    packed.add_buffer("seed", seed_buf, seed_len)
    return packed


def _generate_dsa_params(raw: Any, sh: int) -> int:
    """Generate DSA domain parameters using CKM_DSA_PARAMETER_GEN.

    Returns domain parameter object handle.
    """
    tmpl = template(
        attr_ulong(CKA_PRIME_BITS, 2048),
        attr_bool(CKA_TOKEN, False),
    )
    dp_handle = CK_OBJECT_HANDLE(0)
    mech = mech_simple(CKM_DSA_PARAMETER_GEN)
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(dp_handle))
    expect_rv(rv, CKR_OK)
    return dp_handle.value


def _generate_dsa_pq_params(raw: Any, sh: int, mechanism: int) -> tuple[int, PackedMechanism]:
    """Generate DSA p/q domain parameters using a FIPS 186-4 variant mechanism."""
    tmpl = template(
        attr_ulong(CKA_PRIME_BITS, 2048),
        attr_ulong(CKA_SUBPRIME_BITS, 256),
        attr_bool(CKA_TOKEN, False),
    )
    dp_handle = CK_OBJECT_HANDLE(0)
    mech = _dsa_parameter_gen_param_mech(mechanism)
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(dp_handle))
    expect_rv(rv, CKR_OK)
    return dp_handle.value, mech


def _assert_generated_dsa_pq_attrs(raw: Any, sh: int, dp_handle: int) -> tuple[bytes, bytes]:
    """Assert a FIPS 186-4 p/q-generation result contains the expected attributes."""
    attrs = read_attributes(
        raw,
        sh,
        dp_handle,
        [CKA_PRIME, CKA_SUBPRIME, CKA_PRIME_BITS, CKA_SUBPRIME_BITS],
    )
    prime = attrs[CKA_PRIME]
    subprime = attrs[CKA_SUBPRIME]
    prime_bits = attrs[CKA_PRIME_BITS]
    subprime_bits = attrs[CKA_SUBPRIME_BITS]

    assert isinstance(prime, bytes)
    assert isinstance(subprime, bytes)
    assert isinstance(prime_bits, int)
    assert isinstance(subprime_bits, int)
    assert_correct(
        actual=prime_bits,
        expected=2048,
        label="DSA parameter gen: CKA_PRIME_BITS readback",
        operation="C_GetAttributeValue",
        kind="metadata",
    )
    assert_correct(
        actual=subprime_bits,
        expected=256,
        label="DSA parameter gen: CKA_SUBPRIME_BITS readback",
        operation="C_GetAttributeValue",
        kind="metadata",
    )
    assert len(prime) > 0
    assert len(subprime) > 0
    return prime, subprime


def _dsa_returned_seed(mech: PackedMechanism) -> bytes:
    """Return the provider-written seed from a DSA p/q-generation mechanism."""
    assert isinstance(mech.params, CK_DSA_PARAMETER_GEN_PARAM)
    storage, capacity = mech.buffer_storage("seed")
    seed_len = int(mech.params.ulSeedLen)
    assert 0 < seed_len <= capacity
    return bytes(storage[:seed_len])


def _generate_dsa_base_from_pq(
    raw: Any,
    sh: int,
    *,
    prime: bytes,
    subprime: bytes,
    seed: bytes,
    index: int,
) -> int:
    """Generate DSA base g from p/q plus the seed returned by a p/q variant."""
    tmpl = template(
        attr_bytes(CKA_PRIME, prime),
        attr_bytes(CKA_SUBPRIME, subprime),
        attr_bool(CKA_TOKEN, False),
    )
    base_handle = CK_OBJECT_HANDLE(0)
    mech = _dsa_parameter_gen_param_mech(
        CKM_DSA_FIPS_G_GEN,
        seed_len=len(seed),
        seed=seed,
        index=index,
    )
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(base_handle))
    expect_rv(rv, CKR_OK)
    return base_handle.value


def _skip_or_xfail_dsa_param_gen_reject(exc: AssertionError) -> NoReturn:
    if is_known_error(exc, _DSA_PARAMETER_SIZE_REJECT_RVS):
        pytest.skip(f"DSA-2048 parameter generation not supported: {exc}")
    xfail_if_known_ckr(
        exc,
        _DSA_PARAMETER_RUNTIME_REJECT_RVS,
        "DSA_PARAMETER_GEN advertised but parameter generation is not operational",
    )
    raise


def _xfail_if_dsa_keypair_reject(exc: AssertionError) -> NoReturn:
    xfail_if_known_ckr(
        exc,
        _DSA_KEYPAIR_RUNTIME_REJECT_RVS,
        "DSA_KEY_PAIR_GEN advertised but keypair generation from generated params "
        "is not operational",
    )
    raise


def _gen_dsa_keypair_from_params(
    raw: Any,
    sh: int,
    dp_handle: int,
) -> tuple[int, int]:
    """Generate a DSA keypair from domain parameters object.

    Reads PRIME, SUBPRIME, BASE from dp_handle, then calls C_GenerateKeyPair.
    Returns (pub_handle, priv_handle).
    """
    dp_attrs = read_attributes(
        raw,
        sh,
        dp_handle,
        [CKA_PRIME, CKA_SUBPRIME, CKA_BASE],
    )
    prime = dp_attrs[CKA_PRIME]
    subprime = dp_attrs[CKA_SUBPRIME]
    base = dp_attrs[CKA_BASE]

    assert isinstance(prime, bytes)
    assert isinstance(subprime, bytes)
    assert isinstance(base, bytes)

    pub_tmpl = template(
        attr_bytes(CKA_PRIME, prime),
        attr_bytes(CKA_SUBPRIME, subprime),
        attr_bytes(CKA_BASE, base),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_VERIFY, True),
    )
    priv_tmpl = template(
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SIGN, True),
    )
    mech = mech_simple(CKM_DSA_KEY_PAIR_GEN)
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
    expect_rv(rv, CKR_OK)
    return pub_h.value, priv_h.value


def _generate_dsa_keypair(
    rs: Any,
) -> tuple[int, int, int]:
    """Generate DSA domain parameters and keypair.

    Returns (dp_handle, public_key_handle, private_key_handle).
    Skips the test if DSA param/key generation is not supported.
    """
    if not rs.has_mechanism("DSA_PARAMETER_GEN"):
        pytest.skip("CKM_DSA_PARAMETER_GEN not supported for DSA setup")
    try:
        dp_handle = _generate_dsa_params(rs.raw, rs.sh)
    except AssertionError as e:
        _skip_or_xfail_dsa_param_gen_reject(e)
    if not rs.has_mechanism("DSA_KEY_PAIR_GEN"):
        destroy_quietly(rs.raw, rs.sh, dp_handle)
        pytest.skip("CKM_DSA_KEY_PAIR_GEN not supported for DSA setup")
    try:
        pub, priv = _gen_dsa_keypair_from_params(rs.raw, rs.sh, dp_handle)
    except AssertionError as e:
        destroy_quietly(rs.raw, rs.sh, dp_handle)
        _xfail_if_dsa_keypair_reject(e)
    return dp_handle, pub, priv


def _dsa_sign_or_xfail(rs: Any, priv: int, mechanism: int, data: bytes, label: str) -> bytes:
    try:
        return sign_single(rs.raw, rs.sh, priv, mechanism, data)
    except AssertionError as exc:
        xfail_if_op_not_operational(exc, label)


def _dsa_sign_multipart_or_xfail(
    rs: Any,
    priv: int,
    mechanism: int,
    chunks: tuple[bytes, ...],
    label: str,
) -> bytes:
    try:
        return sign_multipart(rs.raw, rs.sh, priv, mechanism, chunks)
    except AssertionError as exc:
        xfail_if_op_not_operational(exc, label)


def _dsa_verify_or_xfail(
    rs: Any,
    pub: int,
    mechanism: int,
    data: bytes,
    signature: bytes,
    label: str,
) -> bool:
    try:
        return verify_single(rs.raw, rs.sh, pub, mechanism, data, signature)
    except AssertionError as exc:
        xfail_if_op_not_operational(exc, label)


def _dsa_verify_multipart_or_xfail(
    rs: Any,
    pub: int,
    mechanism: int,
    chunks: tuple[bytes, ...],
    signature: bytes,
    label: str,
) -> bool:
    try:
        return verify_multipart(rs.raw, rs.sh, pub, mechanism, chunks, signature)
    except AssertionError as exc:
        xfail_if_op_not_operational(exc, label)


def _dsa_invalid_verify_rejected_or_xfail(
    rs: Any,
    pub: int,
    mechanism: int,
    data: bytes,
    signature: bytes,
    label: str,
) -> bool:
    try:
        return verify_single(rs.raw, rs.sh, pub, mechanism, data, signature)
    except AssertionError as exc:
        return signature_rejected_or_xfail(exc, label)


class TestDSARaw:
    """Tests for raw CKM_DSA with pre-hashed data."""

    def test_raw_dsa_sign_verify(self, p11_module_session: Any) -> None:
        """Raw DSA sign/verify with a SHA-1-sized digest (20 bytes)."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            digest = hashlib.sha1(b"raw DSA test data", usedforsecurity=False).digest()  # noqa: S324
            assert len(digest) == 20

            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            assert len(sig) > 0

            result = verify_single(rs.raw, rs.sh, pub, CKM_DSA, digest, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_wrong_digest_fails(self, p11_module_session: Any) -> None:
        """Raw DSA verification with wrong digest must fail."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            digest = hashlib.sha1(b"original data", usedforsecurity=False).digest()  # noqa: S324
            wrong_digest = hashlib.sha1(b"tampered data", usedforsecurity=False).digest()  # noqa: S324

            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            result = verify_single(rs.raw, rs.sh, pub, CKM_DSA, wrong_digest, sig)
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_wrong_signature_length_fails(self, p11_module_session: Any) -> None:
        """Raw DSA verification with a truncated signature must fail."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            digest = hashlib.sha1(b"wrong signature length", usedforsecurity=False).digest()  # noqa: S324
            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            assert len(sig) > 1

            truncated_sig = sig[:-1]
            result = _dsa_invalid_verify_rejected_or_xfail(
                rs,
                pub,
                CKM_DSA,
                digest,
                truncated_sig,
                "CKM_DSA wrong-length signature",
            )
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_overlong_signature_length_fails(self, p11_module_session: Any) -> None:
        """Raw DSA verification with an overlong signature must fail."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            digest = hashlib.sha1(b"overlong signature length", usedforsecurity=False).digest()  # noqa: S324
            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            assert len(sig) > 0

            overlong_sig = sig + b"\x00"
            result = _dsa_invalid_verify_rejected_or_xfail(
                rs,
                pub,
                CKM_DSA,
                digest,
                overlong_sig,
                "CKM_DSA overlong signature",
            )
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_nondeterministic(self, p11_module_session: Any) -> None:
        """Raw DSA signatures for the same digest should differ (random k)."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            digest = hashlib.sha1(b"nonce test", usedforsecurity=False).digest()  # noqa: S324

            sig1 = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            sig2 = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            if sig1 == sig2:
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_DSA:sign nonce uniqueness",
                    operation="C_Sign",
                    mechanism="CKM_DSA",
                    summary="two DSA signatures of the same digest are identical -- "
                    "nonce (k) reuse leaks the private key",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_wrong_length_digest(self, p11_module_session: Any) -> None:
        """Raw DSA with wrong-length digest should fail per spec."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            # 7 bytes is too short for any valid subprime size
            bad_digest = b"\x00" * 7

            # Sign with wrong-length digest - must be rejected
            mech = mech_simple(CKM_DSA)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            if rv != CKR_OK:
                # SignInit itself rejected it -- acceptable
                return

            in_buf = (ctypes.c_ubyte * len(bad_digest))(*bad_digest)
            out_len = ctypes.c_ulong(0)
            rv = rs.raw.C_Sign(rs.sh, in_buf, len(bad_digest), None, byref(out_len))
            if rv == CKR_OK and out_len.value > 0:
                out_buf = (ctypes.c_ubyte * out_len.value)()
                rv = rs.raw.C_Sign(
                    rs.sh,
                    in_buf,
                    len(bad_digest),
                    out_buf,
                    byref(out_len),
                )

            classify_negative_rv(
                rv,
                (CKR_DATA_LEN_RANGE,),
                label="CKM_DSA wrong-length digest",
                kind="crypto",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_raw_dsa_wrong_length_verify_digest(self, p11_module_session: Any) -> None:
        """Raw DSA verification with wrong-length digest should fail per spec."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA"):
            pytest.skip("CKM_DSA not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            digest = hashlib.sha1(  # noqa: S324
                b"raw DSA verify length baseline",
                usedforsecurity=False,
            ).digest()
            sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
            bad_digest = b"\x00" * 7

            mech = mech_simple(CKM_DSA)
            rv = rs.raw.C_VerifyInit(rs.sh, mech.byref(), pub)
            if rv != CKR_OK:
                return

            in_buf = (ctypes.c_ubyte * len(bad_digest))(*bad_digest)
            sig_buf = (ctypes.c_ubyte * len(sig))(*sig)
            rv = rs.raw.C_Verify(rs.sh, in_buf, len(bad_digest), sig_buf, len(sig))

            classify_negative_rv(
                rv,
                (CKR_DATA_LEN_RANGE,),
                label="CKM_DSA wrong-length verify digest",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)


class TestDSAPrehash:
    """Tests for prehash DSA variants (SHA-1, SHA-224, SHA-384, SHA-512, SHA3-*)."""

    def _multipart_sign_verify_roundtrip(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            chunks = (
                b"DSA prehash multipart ",
                b"sign/verify ",
                b"test data",
            )
            sig = _dsa_sign_multipart_or_xfail(
                rs,
                priv,
                mechanism,
                chunks,
                f"CKM_{mech_name_str} multipart sign",
            )
            assert len(sig) > 0

            result = _dsa_verify_multipart_or_xfail(
                rs,
                pub,
                mechanism,
                chunks,
                sig,
                f"CKM_{mech_name_str} multipart verify",
            )
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    def _wrong_signature_lengths_fail(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            data = b"DSA prehash wrong signature length"
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")
            assert len(sig) > 1

            for wrong_sig, label, case_name in (
                (
                    sig[:-1],
                    f"CKM_{mech_name_str} wrong-length signature",
                    "wrong-length",
                ),
                (
                    sig + b"\x00",
                    f"CKM_{mech_name_str} overlong signature",
                    "overlong",
                ),
            ):
                result = _dsa_invalid_verify_rejected_or_xfail(
                    rs,
                    pub,
                    mechanism,
                    data,
                    wrong_sig,
                    label,
                )
                if result is True:
                    classify(
                        "accepted_invalid",
                        kind="crypto",
                        label=f"CKM_{mech_name_str} {case_name} signature",
                        operation="C_Verify",
                        mechanism=f"CKM_{mech_name_str}",
                        summary=f"CKM_{mech_name_str} accepted {case_name} signature",
                    )
                assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_multipart_sign_verify_roundtrip(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA multipart sign and verify should roundtrip."""
        self._multipart_sign_verify_roundtrip(p11_module_session, mech_name_str, mechanism)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_sign_verify_roundtrip(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Sign and verify with a prehash DSA mechanism."""
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            data = b"DSA prehash sign/verify roundtrip test data"
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")
            assert len(sig) > 0

            result = _dsa_verify_or_xfail(rs, pub, mechanism, data, sig, f"CKM_{mech_name_str}")
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_tampered_data_fails(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA verification with tampered data must fail."""
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            data = b"original prehash data"
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")

            tampered = b"tampered prehash data"
            result = _dsa_invalid_verify_rejected_or_xfail(
                rs,
                pub,
                mechanism,
                tampered,
                sig,
                f"CKM_{mech_name_str}",
            )
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_tampered_signature_fails(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA verification with tampered signature must fail."""
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            data = b"signature tamper test"
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")

            # Flip a byte in the signature
            sig_arr = bytearray(sig)
            sig_arr[len(sig_arr) // 2] ^= 0xFF
            tampered_sig = bytes(sig_arr)

            result = _dsa_invalid_verify_rejected_or_xfail(
                rs,
                pub,
                mechanism,
                data,
                tampered_sig,
                f"CKM_{mech_name_str}",
            )
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_wrong_signature_lengths_fail(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA verification with wrong-length signatures must fail."""
        self._wrong_signature_lengths_fail(p11_module_session, mech_name_str, mechanism)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_empty_data(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA sign/verify with empty data should work (hash of empty)."""
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            data = b""
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")
            assert len(sig) > 0

            result = _dsa_verify_or_xfail(rs, pub, mechanism, data, sig, f"CKM_{mech_name_str}")
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

    @pytest.mark.parametrize(("mech_name_str", "mechanism"), _DSA_HASH_MECHS)
    def test_large_data(
        self,
        p11_module_session: Any,
        mech_name_str: str,
        mechanism: int,
    ) -> None:
        """Prehash DSA sign/verify with large data (10 KiB)."""
        rs = p11_module_session
        if not rs.has_mechanism(mech_name_str):
            pytest.skip(f"CKM_{mech_name_str} not supported")

        dp, pub, priv = _generate_dsa_keypair(rs)
        try:
            data = b"A" * 10240
            sig = _dsa_sign_or_xfail(rs, priv, mechanism, data, f"CKM_{mech_name_str}")
            assert len(sig) > 0

            result = _dsa_verify_or_xfail(rs, pub, mechanism, data, sig, f"CKM_{mech_name_str}")
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)


class TestDSAParameterGen:
    """Tests for DSA domain-parameter generation mechanisms."""

    def test_parameter_gen_rejects_missing_prime_bits(self, p11_module_session: Any) -> None:
        """CKM_DSA_PARAMETER_GEN requires CKA_PRIME_BITS in the template."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        tmpl = template(attr_bool(CKA_TOKEN, False))
        dp_handle = CK_OBJECT_HANDLE(0)
        mech = mech_simple(CKM_DSA_PARAMETER_GEN)
        try:
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(dp_handle),
            )
            classify_negative_rv(
                rv,
                _DSA_PARAMETER_TEMPLATE_REJECT_RVS,
                label="CKM_DSA_PARAMETER_GEN missing CKA_PRIME_BITS",
            )
        finally:
            if dp_handle.value:
                destroy_quietly(rs.raw, rs.sh, dp_handle.value)

    def test_parameter_gen(self, p11_module_session: Any) -> None:
        """Generate DSA domain parameters using CKM_DSA_PARAMETER_GEN."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        try:
            dp = _generate_dsa_params(rs.raw, rs.sh)
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            assert dp != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_probabilistic_parameter_gen_returns_pq(self, p11_module_session: Any) -> None:
        """CKM_DSA_PROBABILISTIC_PARAMETER_GEN generates p/q and returns a seed."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_PROBABILISTIC_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PROBABILISTIC_PARAMETER_GEN not supported")

        try:
            dp, mech = _generate_dsa_pq_params(
                rs.raw,
                rs.sh,
                CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
            )
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            _assert_generated_dsa_pq_attrs(rs.raw, rs.sh, dp)
            assert len(_dsa_returned_seed(mech)) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_shawe_taylor_parameter_gen_returns_pq(self, p11_module_session: Any) -> None:
        """CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN generates p/q and returns a seed."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_SHAWE_TAYLOR_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN not supported")

        try:
            dp, mech = _generate_dsa_pq_params(
                rs.raw,
                rs.sh,
                CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
            )
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            _assert_generated_dsa_pq_attrs(rs.raw, rs.sh, dp)
            assert len(_dsa_returned_seed(mech)) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_fips_g_gen_uses_generated_seed_and_pq(self, p11_module_session: Any) -> None:
        """CKM_DSA_FIPS_G_GEN generates g from generated p/q plus returned seed."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_FIPS_G_GEN"):
            pytest.skip("CKM_DSA_FIPS_G_GEN not supported")
        if not rs.has_mechanism("DSA_PROBABILISTIC_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PROBABILISTIC_PARAMETER_GEN not supported for setup")

        try:
            dp, mech = _generate_dsa_pq_params(
                rs.raw,
                rs.sh,
                CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
            )
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            prime, subprime = _assert_generated_dsa_pq_attrs(rs.raw, rs.sh, dp)
            seed = _dsa_returned_seed(mech)
            try:
                base_dp = _generate_dsa_base_from_pq(
                    rs.raw,
                    rs.sh,
                    prime=prime,
                    subprime=subprime,
                    seed=seed,
                    index=1,
                )
            except AssertionError as e:
                _skip_or_xfail_dsa_param_gen_reject(e)

            try:
                attrs = read_attributes(rs.raw, rs.sh, base_dp, [CKA_BASE])
                base = attrs[CKA_BASE]
                assert isinstance(base, bytes)
                assert len(base) > 0
            finally:
                destroy_quietly(rs.raw, rs.sh, base_dp)
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_parameter_gen_and_keypair(self, p11_module_session: Any) -> None:
        """Generate DSA parameters, then use them for keypair generation."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        try:
            dp = _generate_dsa_params(rs.raw, rs.sh)
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            if not rs.has_mechanism("DSA_KEY_PAIR_GEN"):
                pytest.skip("CKM_DSA_KEY_PAIR_GEN not supported")
            try:
                pub, priv = _gen_dsa_keypair_from_params(rs.raw, rs.sh, dp)
            except AssertionError as e:
                _xfail_if_dsa_keypair_reject(e)

            try:
                assert pub != 0
                assert priv != 0
            finally:
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)

    def test_parameter_gen_sign_verify(self, p11_module_session: Any) -> None:
        """Generate DSA params, keypair, then sign and verify."""
        rs = p11_module_session
        if not rs.has_mechanism("DSA_PARAMETER_GEN"):
            pytest.skip("CKM_DSA_PARAMETER_GEN not supported")

        # Need a signing mechanism too
        has_raw = rs.has_mechanism("DSA")
        has_sha256 = rs.has_mechanism("DSA_SHA256")
        if not has_raw and not has_sha256:
            pytest.skip("No DSA signing mechanism available")

        try:
            dp = _generate_dsa_params(rs.raw, rs.sh)
        except AssertionError as e:
            _skip_or_xfail_dsa_param_gen_reject(e)

        try:
            if not rs.has_mechanism("DSA_KEY_PAIR_GEN"):
                pytest.skip("CKM_DSA_KEY_PAIR_GEN not supported")
            try:
                pub, priv = _gen_dsa_keypair_from_params(rs.raw, rs.sh, dp)
            except AssertionError as e:
                _xfail_if_dsa_keypair_reject(e)

            try:
                if has_raw:
                    digest = hashlib.sha1(b"param gen sign test", usedforsecurity=False).digest()  # noqa: S324
                    sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA, digest)
                    result = verify_single(rs.raw, rs.sh, pub, CKM_DSA, digest, sig)
                else:
                    data = b"param gen sign test"
                    sig = sign_single(rs.raw, rs.sh, priv, CKM_DSA_SHA256, data)
                    result = verify_single(
                        rs.raw,
                        rs.sh,
                        pub,
                        CKM_DSA_SHA256,
                        data,
                        sig,
                    )
                assert result is True
            finally:
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
        finally:
            destroy_quietly(rs.raw, rs.sh, dp)
