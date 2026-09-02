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

from pkcs11_check.classification import classify
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
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_KEY_EXHAUSTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_SIGNATURE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    assert_correct,
    is_known_error,
    reject_or_classify,
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
_KEYGEN_ERROR_RVS = (
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_SIGN_ERROR_RVS = (
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
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
        result: tuple[int, int] = gen_fn(rs)
        return result
    except AssertionError as exc:
        if is_known_error(exc, _KEYGEN_ERROR_RVS):
            classify(
                "not_operational",
                kind="crypto",
                label=f"{name}:C_GenerateKeyPair",
                operation="C_GenerateKeyPair",
                summary=f"{name} key generation failed: {exc}",
            )
        raise


def _try_sign(rs: Any, priv: int, mech: int, name: str) -> bytes:
    """Try signing, xfail if module rejects."""
    try:
        return sign_single(rs.raw, rs.sh, priv, mech, _MESSAGE)
    except AssertionError as exc:
        if is_known_error(exc, _SIGN_ERROR_RVS):
            classify(
                "not_operational",
                kind="crypto",
                label=f"{name}:C_Sign",
                operation="C_Sign",
                summary=f"{name} sign failed: {exc}",
            )
        raise


def _handle_tampered_verify_error(exc: BaseException) -> None:
    """Accept signature-invalid and expose provider-specific substitute CKRs."""
    if is_known_error(exc, {CKR_SIGNATURE_INVALID}):
        return
    if is_known_error(exc, {CKR_DEVICE_ERROR}):
        classify(
            "nonspec_reject",
            kind="crypto",
            label="tampered-signature verify",
            operation="C_Verify",
            expected=[CKR_SIGNATURE_INVALID],
            actual=CKR_DEVICE_ERROR,
            summary="Module returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID",
        )
    raise exc


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
            assert_correct(
                actual=pub_attrs[CKA_KEY_TYPE],
                expected=CKK_HSS,
                label="HSS:public CKA_KEY_TYPE readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
            assert_correct(
                actual=priv_attrs[CKA_KEY_TYPE],
                expected=CKK_HSS,
                label="HSS:private CKA_KEY_TYPE readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
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
            assert_correct(
                actual=pub_attrs[CKA_CLASS],
                expected=CKO_PUBLIC_KEY,
                label="HSS:public CKA_CLASS readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
            assert_correct(
                actual=priv_attrs[CKA_CLASS],
                expected=CKO_PRIVATE_KEY,
                label="HSS:private CKA_CLASS readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
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
            _handle_tampered_verify_error(exc)
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
            assert_correct(
                actual=pub_attrs[CKA_KEY_TYPE],
                expected=CKK_XMSS,
                label="XMSS:public CKA_KEY_TYPE readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
            assert_correct(
                actual=priv_attrs[CKA_KEY_TYPE],
                expected=CKK_XMSS,
                label="XMSS:private CKA_KEY_TYPE readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
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
            assert_correct(
                actual=pub_attrs[CKA_CLASS],
                expected=CKO_PUBLIC_KEY,
                label="XMSS:public CKA_CLASS readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
            assert_correct(
                actual=priv_attrs[CKA_CLASS],
                expected=CKO_PRIVATE_KEY,
                label="XMSS:private CKA_CLASS readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
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
            _handle_tampered_verify_error(exc)
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
            assert_correct(
                actual=pub_attrs[CKA_KEY_TYPE],
                expected=CKK_XMSSMT,
                label="XMSSMT:public CKA_KEY_TYPE readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
            assert_correct(
                actual=priv_attrs[CKA_KEY_TYPE],
                expected=CKK_XMSSMT,
                label="XMSSMT:private CKA_KEY_TYPE readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
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
            assert_correct(
                actual=pub_attrs[CKA_CLASS],
                expected=CKO_PUBLIC_KEY,
                label="XMSSMT:public CKA_CLASS readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
            assert_correct(
                actual=priv_attrs[CKA_CLASS],
                expected=CKO_PRIVATE_KEY,
                label="XMSSMT:private CKA_CLASS readback",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
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
            _handle_tampered_verify_error(exc)
        finally:
            _destroy_pair(rs, pub, priv)


# ---------------------------------------------------------------------------
# Key-pool exhaustion (stress)
# ---------------------------------------------------------------------------

# Spec-recognised CKR codes for "the stateful key has been exhausted".
# CKR_KEY_EXHAUSTED is the PKCS#11 v3.2 specific code; some modules also
# return CKR_DEVICE_ERROR or CKR_FUNCTION_FAILED.  All three are acceptable.
# What's *not* acceptable: CKR_OK (silent leaf reuse — security gap) or
# a segfault.
_EXHAUSTION_OK_RVS: frozenset[int] = frozenset(
    {
        int(CKR_KEY_EXHAUSTED),
        int(CKR_DEVICE_ERROR),
        int(CKR_FUNCTION_FAILED),
        int(CKR_KEY_HANDLE_INVALID),  # Module destroys key handle on exhaustion
    }
)


@pytest.mark.stress
class TestHSSKeyExhaustion:
    """Sign past the leaf budget — verify the module returns CKR_KEY_EXHAUSTED.

    HSS with single-level LMS_SHA256_M32_H5 has 2^5 = 32 one-time keys.
    Signing 33 times must return a key-exhausted error on attempt #33,
    not silently re-use a leaf (which would be a security gap) and not
    segfault.

    Marked @stress because 32+ HSS signatures can take 10-60 seconds
    depending on module.
    """

    def test_hss_sign_past_leaf_budget_returns_key_exhausted(self, p11_raw_session: Any) -> None:
        """Sign 33 times on a 32-leaf HSS key; the 33rd attempt must error."""
        rs = p11_raw_session
        _skip_if_no(rs, "HSS")
        _skip_if_no(rs, "HSS_KEY_PAIR_GEN")

        pub, priv = _try_keygen(_generate_hss_keypair, rs, "HSS")
        try:
            # Sign all 32 leaves
            for i in range(32):
                try:
                    sig = sign_single(rs.raw, rs.sh, priv, CKM_HSS, _MESSAGE)
                except AssertionError as exc:
                    rv = getattr(exc, "rv", None)
                    # If module exhausts earlier than expected (e.g. 16-leaf
                    # internal limit), still observe the spec-compliant CKR.
                    if rv in _EXHAUSTION_OK_RVS:
                        classify(
                            "honest_deviation",
                            kind="lifecycle",
                            label="CKM_HSS:early key exhaustion",
                            operation="C_Sign",
                            mechanism="CKM_HSS",
                            summary=(
                                f"Module exhausted HSS key at signature #{i + 1} "
                                f"(expected at #33): {exc}.  This is the "
                                f"spec-compliant return code; module may use a "
                                f"smaller leaf budget than RFC 8554 LMS_SHA256_M32_H5."
                            ),
                        )
                    raise
                assert isinstance(sig, bytes) and len(sig) > 0

            # 33rd signature attempt: must reject (CKR_KEY_EXHAUSTED or a
            # spec-compatible alternative).  Must NOT succeed silently — that
            # would mean one-time-key reuse, a security gap (RFC 8554 Sec.6.3).
            # 3-way: success (over-budget sign accepted) -> fail; spec-compatible
            # reject -> pass; any other clean reject -> xfail.
            caught: BaseException | None = None
            try:
                sign_single(rs.raw, rs.sh, priv, CKM_HSS, _MESSAGE)
            except AssertionError as exc:
                caught = exc
            reject_or_classify(
                caught,
                tuple(_EXHAUSTION_OK_RVS),
                label="33rd C_Sign on a 32-leaf HSS key (one-time-key reuse past the "
                "leaf budget is a security gap; RFC 8554 Sec.6.3 requires CKR_KEY_EXHAUSTED)",
            )
        finally:
            _destroy_pair(rs, pub, priv)
