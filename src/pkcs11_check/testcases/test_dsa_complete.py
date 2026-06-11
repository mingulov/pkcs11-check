"""Tests for the complete DSA mechanism family.

Covers raw CKM_DSA, prehash variants (SHA-1, SHA-384, SHA-512, SHA3-*),
and CKM_DSA_PARAMETER_GEN.

Note: CKM_DSA_KEY_PAIR_GEN and CKM_DSA_SHA256 are already tested in
test_sign.py and test_wycheproof_dsa.py.

OASIS spec: dsa.md
"""

from __future__ import annotations

import ctypes
import hashlib
from ctypes import byref
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.pack import (
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_BASE,
    CKA_PRIME,
    CKA_PRIME_BITS,
    CKA_SIGN,
    CKA_SUBPRIME,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM_DSA,
    CKM_DSA_KEY_PAIR_GEN,
    CKM_DSA_PARAMETER_GEN,
    CKM_DSA_SHA1,
    CKM_DSA_SHA3_224,
    CKM_DSA_SHA3_256,
    CKM_DSA_SHA3_384,
    CKM_DSA_SHA3_512,
    CKM_DSA_SHA256,
    CKM_DSA_SHA384,
    CKM_DSA_SHA512,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
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
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr

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
)

# DSA parameter/key generation is heavy on several providers (10-32s per case
# on NSS); the whole file is keygen-bound. Marked slow so a basic run can skip
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

# Prehash DSA variants (excluding DSA_SHA256 which is tested elsewhere)
_DSA_HASH_MECHS = [
    pytest.param("DSA_SHA1", CKM_DSA_SHA1, id="SHA1"),
    pytest.param("DSA_SHA384", CKM_DSA_SHA384, id="SHA384"),
    pytest.param("DSA_SHA512", CKM_DSA_SHA512, id="SHA512"),
    pytest.param("DSA_SHA3_224", CKM_DSA_SHA3_224, id="SHA3-224"),
    pytest.param("DSA_SHA3_256", CKM_DSA_SHA3_256, id="SHA3-256"),
    pytest.param("DSA_SHA3_384", CKM_DSA_SHA3_384, id="SHA3-384"),
    pytest.param("DSA_SHA3_512", CKM_DSA_SHA3_512, id="SHA3-512"),
]


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
            assert sig1 != sig2
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

            rv_int = rv
            if rv_int == CKR_OK:
                # Module accepted wrong-length digest - non-standard
                pytest.xfail(
                    "Module accepted wrong-length digest for CKM_DSA - "
                    "spec requires CKR_DATA_LEN_RANGE"
                )
            # Any rejection is acceptable
            assert rv_int in {
                CKR_DATA_LEN_RANGE,
                CKR_MECHANISM_INVALID,
                CKR_FUNCTION_FAILED,
                CKR_ARGUMENTS_BAD,
                CKR_GENERAL_ERROR,
            }, f"Unexpected CKR: {ckr_name(rv_int)}"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)


class TestDSAPrehash:
    """Tests for prehash DSA variants (SHA-1, SHA-384, SHA-512, SHA3-*)."""

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
            sig = sign_single(rs.raw, rs.sh, priv, mechanism, data)
            assert len(sig) > 0

            result = verify_single(rs.raw, rs.sh, pub, mechanism, data, sig)
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
            sig = sign_single(rs.raw, rs.sh, priv, mechanism, data)

            tampered = b"tampered prehash data"
            result = verify_single(rs.raw, rs.sh, pub, mechanism, tampered, sig)
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
            sig = sign_single(rs.raw, rs.sh, priv, mechanism, data)

            # Flip a byte in the signature
            sig_arr = bytearray(sig)
            sig_arr[len(sig_arr) // 2] ^= 0xFF
            tampered_sig = bytes(sig_arr)

            result = verify_single(rs.raw, rs.sh, pub, mechanism, data, tampered_sig)
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)

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
            sig = sign_single(rs.raw, rs.sh, priv, mechanism, data)
            assert len(sig) > 0

            result = verify_single(rs.raw, rs.sh, pub, mechanism, data, sig)
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
            sig = sign_single(rs.raw, rs.sh, priv, mechanism, data)
            assert len(sig) > 0

            result = verify_single(rs.raw, rs.sh, pub, mechanism, data, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, dp)


class TestDSAParameterGen:
    """Tests for CKM_DSA_PARAMETER_GEN."""

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
