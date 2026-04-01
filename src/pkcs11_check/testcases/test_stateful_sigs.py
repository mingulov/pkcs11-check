"""Stateful hash-based signature tests - HSS, XMSS, XMSS^MT (PKCS#11 v3.2).

Tests three stateful hash-based signature families per OASIS PKCS#11 v3.2:
- CKM_HSS_KEY_PAIR_GEN + CKM_HSS - Hierarchical Signature Scheme (RFC 8554)
- CKM_XMSS_KEY_PAIR_GEN + CKM_XMSS - eXtended Merkle Signature Scheme (RFC 8391)
- CKM_XMSSMT_KEY_PAIR_GEN + CKM_XMSSMT - XMSS Multi-Tree (RFC 8391)

IMPORTANT: These are stateful signatures - each signing operation consumes a
one-time key from a finite pool.  Tests sign minimally to avoid exhaustion.
Key generation can be very slow (minutes for large trees); smallest parameter
sets are used throughout.

All tests require PKCS#11 v3.2 interface.  Auto-skips on v3.1 and earlier.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    attr_array,
    attr_bool,
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
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_HSS_LEVELS,
    CKA_HSS_LMOTS_TYPES,
    CKA_HSS_LMS_TYPES,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_HSS,
    CKK_XMSS,
    CKK_XMSSMT,
    CKM_HSS,
    CKM_HSS_KEY_PAIR_GEN,
    CKM_XMSS,
    CKM_XMSS_KEY_PAIR_GEN,
    CKM_XMSSMT,
    CKM_XMSSMT_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKR_OK,
)

pytestmark = [pytest.mark.pqc]

_MESSAGE = b"stateful hash signature test message 2026"

# HSS LMS/LMOTS parameter values (from RFC 8554 / NIST SP 800-208).
# Use the smallest tree for fast keygen.
_LMS_SHA256_M32_H5 = 0x05  # LMS_SHA256_M32_H5: height 5, 32 signatures
_LMOTS_SHA256_N32_W8 = 0x04  # LMOTS_SHA256_N32_W8: Winternitz w=8

# XMSS parameter set OIDs (NIST SP 800-208, Table 11).
_XMSS_SHA2_10_256 = 0x00000001  # XMSS-SHA2_10_256: height 10

# XMSSMT parameter set OIDs (NIST SP 800-208, Table 12).
_XMSSMT_SHA2_20_2_256 = 0x00000001  # XMSSMT-SHA2_20/2_256

# Common keygen errors for stateful sigs - modules may reject templates.
_KEYGEN_CKR_NAMES = (
    "CKR_MECHANISM_INVALID",
    "CKR_FUNCTION_FAILED",
    "CKR_DEVICE_ERROR",
    "CKR_TEMPLATE_INCOMPLETE",
    "CKR_TEMPLATE_INCONSISTENT",
)

_SIGN_CKR_NAMES = (
    "CKR_MECHANISM_INVALID",
    "CKR_FUNCTION_FAILED",
    "CKR_DEVICE_ERROR",
)


def _skip_if_no(rs: Any, mech_name: str) -> None:
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"CKM_{mech_name} not supported by module")


def _destroy_pair(rs: Any, pub: int, priv: int) -> None:
    """Destroy a key pair, ignoring errors."""
    destroy_quietly(rs.raw, rs.sh, pub)
    destroy_quietly(rs.raw, rs.sh, priv)


def _generate_hss_keypair(rs: Any) -> tuple[int, int]:
    """Generate an HSS key pair with the smallest parameter set."""
    pub_tmpl = template(
        attr_bool(CKA_VERIFY, True),
        attr_bool(CKA_TOKEN, False),
    )
    priv_tmpl = template(
        attr_bool(CKA_SIGN, True),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, True),
        attr_bool(CKA_EXTRACTABLE, False),
        attr_ulong(CKA_HSS_LEVELS, 1),
        attr_array(CKA_HSS_LMS_TYPES, [_LMS_SHA256_M32_H5]),
        attr_array(CKA_HSS_LMOTS_TYPES, [_LMOTS_SHA256_N32_W8]),
    )
    mech = mech_simple(CKM_HSS_KEY_PAIR_GEN)
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


def _generate_xmss_keypair(rs: Any) -> tuple[int, int]:
    """Generate an XMSS key pair with XMSS-SHA2_10_256 (smallest)."""
    pub_tmpl = template(
        attr_bool(CKA_VERIFY, True),
        attr_ulong(CKA_PARAMETER_SET, _XMSS_SHA2_10_256),
        attr_bool(CKA_TOKEN, False),
    )
    priv_tmpl = template(
        attr_bool(CKA_SIGN, True),
        attr_ulong(CKA_PARAMETER_SET, _XMSS_SHA2_10_256),
        attr_bool(CKA_SENSITIVE, True),
        attr_bool(CKA_EXTRACTABLE, False),
        attr_bool(CKA_TOKEN, False),
    )
    mech = mech_simple(CKM_XMSS_KEY_PAIR_GEN)
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


def _generate_xmssmt_keypair(rs: Any) -> tuple[int, int]:
    """Generate an XMSS^MT key pair with XMSSMT-SHA2_20/2_256 (smallest)."""
    pub_tmpl = template(
        attr_bool(CKA_VERIFY, True),
        attr_ulong(CKA_PARAMETER_SET, _XMSSMT_SHA2_20_2_256),
        attr_bool(CKA_TOKEN, False),
    )
    priv_tmpl = template(
        attr_bool(CKA_SIGN, True),
        attr_ulong(CKA_PARAMETER_SET, _XMSSMT_SHA2_20_2_256),
        attr_bool(CKA_SENSITIVE, True),
        attr_bool(CKA_EXTRACTABLE, False),
        attr_bool(CKA_TOKEN, False),
    )
    mech = mech_simple(CKM_XMSSMT_KEY_PAIR_GEN)
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


def _try_keygen(gen_fn: Any, rs: Any, name: str) -> tuple[int, int]:
    """Try key generation, xfail if module rejects."""
    try:
        return gen_fn(rs)
    except AssertionError as exc:
        exc_msg = str(exc)
        if any(n in exc_msg for n in _KEYGEN_CKR_NAMES):
            pytest.xfail(f"{name} key generation failed: {exc_msg}")
        raise


def _try_sign(rs: Any, priv: int, mech: int, name: str) -> bytes:
    """Try signing, xfail if module rejects."""
    try:
        return sign_single(rs.raw, rs.sh, priv, mech, _MESSAGE)
    except AssertionError as exc:
        exc_msg = str(exc)
        if any(n in exc_msg for n in _SIGN_CKR_NAMES):
            pytest.xfail(f"{name} sign failed: {exc_msg}")
        raise


# ---------------------------------------------------------------------------
# HSS tests
# ---------------------------------------------------------------------------


class TestHSSKeyGeneration:
    """CKM_HSS_KEY_PAIR_GEN - HSS key generation (RFC 8554)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_HSS_KEY_PAIR_GEN is advertised by the module."""
        _skip_if_no(p11_raw_session, "HSS_KEY_PAIR_GEN")

    def test_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate an HSS key pair."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            assert pub != 0
            assert priv != 0
        finally:
            _destroy_pair(rs, pub, priv)

    def test_keypair_key_type(self, p11_raw_session: Any) -> None:
        """HSS keys report CKK_HSS key type."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])
            assert pub_attrs[CKA_KEY_TYPE] == CKK_HSS
            assert priv_attrs[CKA_KEY_TYPE] == CKK_HSS
        finally:
            _destroy_pair(rs, pub, priv)

    def test_keypair_classes(self, p11_raw_session: Any) -> None:
        """HSS public key is PUBLIC_KEY, private is PRIVATE_KEY."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_CLASS])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_CLASS])
            assert pub_attrs[CKA_CLASS] == CKO_PUBLIC_KEY
            assert priv_attrs[CKA_CLASS] == CKO_PRIVATE_KEY
        finally:
            _destroy_pair(rs, pub, priv)

    def test_private_key_attributes(self, p11_raw_session: Any) -> None:
        """HSS private key MUST be SENSITIVE, not EXTRACTABLE per spec."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_SENSITIVE, CKA_EXTRACTABLE])
            assert priv_attrs[CKA_SENSITIVE] is True
            assert priv_attrs[CKA_EXTRACTABLE] is False
        finally:
            _destroy_pair(rs, pub, priv)


class TestHSSSignVerify:
    """CKM_HSS - HSS sign/verify (RFC 8554)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_HSS is advertised by the module."""
        _skip_if_no(p11_raw_session, "HSS")

    def test_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """HSS sign + verify round-trip (single signature)."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS")
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            sig = _try_sign(rs, priv, CKM_HSS, "HSS")
            assert isinstance(sig, bytes) and len(sig) > 0
            assert verify_single(rs.raw, rs.sh, pub, CKM_HSS, _MESSAGE, sig) is True
        finally:
            _destroy_pair(rs, pub, priv)

    def test_tampered_message_fails(self, p11_raw_session: Any) -> None:
        """Tampered message must fail HSS verification."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS")
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            sig = _try_sign(rs, priv, CKM_HSS, "HSS")
            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            result = verify_single(rs.raw, rs.sh, pub, CKM_HSS, tampered, sig)
            assert not result, "Tampered message should fail HSS verification"
        except AssertionError as exc:
            exc_msg = str(exc)
            if "CKR_SIGNATURE_INVALID" in exc_msg:
                pass  # Correct PKCS#11 behavior
            elif "CKR_DEVICE_ERROR" in exc_msg:
                pytest.xfail("Module returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID")
            else:
                raise
        finally:
            _destroy_pair(rs, pub, priv)


# ---------------------------------------------------------------------------
# XMSS tests
# ---------------------------------------------------------------------------


class TestXMSSKeyGeneration:
    """CKM_XMSS_KEY_PAIR_GEN - XMSS key generation (RFC 8391)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_XMSS_KEY_PAIR_GEN is advertised by the module."""
        _skip_if_no(p11_raw_session, "XMSS_KEY_PAIR_GEN")

    def test_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate an XMSS key pair."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            assert pub != 0
            assert priv != 0
        finally:
            _destroy_pair(rs, pub, priv)

    def test_keypair_key_type(self, p11_raw_session: Any) -> None:
        """XMSS keys report CKK_XMSS key type."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])
            assert pub_attrs[CKA_KEY_TYPE] == CKK_XMSS
            assert priv_attrs[CKA_KEY_TYPE] == CKK_XMSS
        finally:
            _destroy_pair(rs, pub, priv)

    def test_keypair_classes(self, p11_raw_session: Any) -> None:
        """XMSS public key is PUBLIC_KEY, private is PRIVATE_KEY."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_CLASS])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_CLASS])
            assert pub_attrs[CKA_CLASS] == CKO_PUBLIC_KEY
            assert priv_attrs[CKA_CLASS] == CKO_PRIVATE_KEY
        finally:
            _destroy_pair(rs, pub, priv)

    def test_private_key_attributes(self, p11_raw_session: Any) -> None:
        """XMSS private key MUST be SENSITIVE, not EXTRACTABLE per spec."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_SENSITIVE, CKA_EXTRACTABLE])
            assert priv_attrs[CKA_SENSITIVE] is True
            assert priv_attrs[CKA_EXTRACTABLE] is False
        finally:
            _destroy_pair(rs, pub, priv)


class TestXMSSSignVerify:
    """CKM_XMSS - XMSS sign/verify (RFC 8391)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_XMSS is advertised by the module."""
        _skip_if_no(p11_raw_session, "XMSS")

    def test_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """XMSS sign + verify round-trip (single signature)."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS")
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            sig = _try_sign(rs, priv, CKM_XMSS, "XMSS")
            assert isinstance(sig, bytes) and len(sig) > 0
            assert verify_single(rs.raw, rs.sh, pub, CKM_XMSS, _MESSAGE, sig) is True
        finally:
            _destroy_pair(rs, pub, priv)

    def test_tampered_message_fails(self, p11_raw_session: Any) -> None:
        """Tampered message must fail XMSS verification."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSS")
        _skip_if_no(rs, "XMSS_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmss_keypair, rs, "XMSS")
        try:
            sig = _try_sign(rs, priv, CKM_XMSS, "XMSS")
            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            result = verify_single(rs.raw, rs.sh, pub, CKM_XMSS, tampered, sig)
            assert not result, "Tampered message should fail XMSS verification"
        except AssertionError as exc:
            exc_msg = str(exc)
            if "CKR_SIGNATURE_INVALID" in exc_msg:
                pass  # Correct PKCS#11 behavior
            elif "CKR_DEVICE_ERROR" in exc_msg:
                pytest.xfail("Module returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID")
            else:
                raise
        finally:
            _destroy_pair(rs, pub, priv)


# ---------------------------------------------------------------------------
# XMSS^MT tests
# ---------------------------------------------------------------------------


class TestXMSSMTKeyGeneration:
    """CKM_XMSSMT_KEY_PAIR_GEN - XMSS^MT key generation (RFC 8391)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_XMSSMT_KEY_PAIR_GEN is advertised by the module."""
        _skip_if_no(p11_raw_session, "XMSSMT_KEY_PAIR_GEN")

    def test_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate an XMSS^MT key pair."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            assert pub != 0
            assert priv != 0
        finally:
            _destroy_pair(rs, pub, priv)

    def test_keypair_key_type(self, p11_raw_session: Any) -> None:
        """XMSS^MT keys report CKK_XMSSMT key type."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])
            assert pub_attrs[CKA_KEY_TYPE] == CKK_XMSSMT
            assert priv_attrs[CKA_KEY_TYPE] == CKK_XMSSMT
        finally:
            _destroy_pair(rs, pub, priv)

    def test_keypair_classes(self, p11_raw_session: Any) -> None:
        """XMSS^MT public key is PUBLIC_KEY, private is PRIVATE_KEY."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            pub_attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_CLASS])
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_CLASS])
            assert pub_attrs[CKA_CLASS] == CKO_PUBLIC_KEY
            assert priv_attrs[CKA_CLASS] == CKO_PRIVATE_KEY
        finally:
            _destroy_pair(rs, pub, priv)

    def test_private_key_attributes(self, p11_raw_session: Any) -> None:
        """XMSS^MT private key MUST be SENSITIVE, not EXTRACTABLE per spec."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            priv_attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_SENSITIVE, CKA_EXTRACTABLE])
            assert priv_attrs[CKA_SENSITIVE] is True
            assert priv_attrs[CKA_EXTRACTABLE] is False
        finally:
            _destroy_pair(rs, pub, priv)


class TestXMSSMTSignVerify:
    """CKM_XMSSMT - XMSS^MT sign/verify (RFC 8391)."""

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_XMSSMT is advertised by the module."""
        _skip_if_no(p11_raw_session, "XMSSMT")

    def test_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """XMSS^MT sign + verify round-trip (single signature)."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT")
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            sig = _try_sign(rs, priv, CKM_XMSSMT, "XMSS^MT")
            assert isinstance(sig, bytes) and len(sig) > 0
            assert verify_single(rs.raw, rs.sh, pub, CKM_XMSSMT, _MESSAGE, sig) is True
        finally:
            _destroy_pair(rs, pub, priv)

    def test_tampered_message_fails(self, p11_raw_session: Any) -> None:
        """Tampered message must fail XMSS^MT verification."""
        rs = p11_raw_session
        _skip_if_no(rs, "XMSSMT")
        _skip_if_no(rs, "XMSSMT_KEY_PAIR_GEN")
        pub, priv = _try_keygen(_generate_xmssmt_keypair, rs, "XMSS^MT")
        try:
            sig = _try_sign(rs, priv, CKM_XMSSMT, "XMSS^MT")
            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            result = verify_single(rs.raw, rs.sh, pub, CKM_XMSSMT, tampered, sig)
            assert not result, "Tampered message should fail XMSS^MT verification"
        except AssertionError as exc:
            exc_msg = str(exc)
            if "CKR_SIGNATURE_INVALID" in exc_msg:
                pass  # Correct PKCS#11 behavior
            elif "CKR_DEVICE_ERROR" in exc_msg:
                pytest.xfail("Module returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID")
            else:
                raise
        finally:
            _destroy_pair(rs, pub, priv)
