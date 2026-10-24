"""Tests for EC key generation and ECDSA across multiple curves.

Parametrized tests for P-224, P-256, P-384, P-521, plus subgroup-order legs
for curves whose order and field octet widths differ (QC5c).
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from pkcs11_check.classification import fail_as, record_as, xfail_as
from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_ec_keypair,
    read_attributes,
    sign_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKF_SIGN,
    CKK_EC,
    CKM_ECDSA,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._ec_export import (
    assert_exact_dss_width_or_classify,
    parse_raw_dss_or_classify,
    read_ec_public_key_or_xfail,
)
from pkcs11_check.testcases.conftest import (
    EC_CURVE_UNSUPPORTED_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    assert_correct,
    is_known_error,
    route_in_range_not_operational,
    skip_unless_capability,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.crossverify

# Unambiguous "advertised ECDSA sign is not operational" codes -> xfail (flag for
# investigation). Deliberately NARROW: only FUNCTION_NOT_SUPPORTED (function/mech
# absent) and FUNCTION_FAILED. CKR_GENERAL_ERROR / CKR_DEVICE_ERROR are NOT here --
# they are catch-alls that may mask a real signing failure (some modules return
# DEVICE_ERROR on a crypto/OpenSSL failure), so they stay a hard FAIL to be
# investigated rather than quietly downgraded. A WRONG signature is independently
# caught by the software verify below (crypto break -> fail).
_ECDSA_SIGN_REJECT_RVS = (
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
)

_EC_CURVES = [
    ("secp224r1", 28, ec.SECP224R1(), hashes.SHA224()),
    ("secp256r1", 32, ec.SECP256R1(), hashes.SHA256()),
    ("secp256k1", 32, ec.SECP256K1(), hashes.SHA256()),
    ("secp384r1", 48, ec.SECP384R1(), hashes.SHA384()),
    ("secp521r1", 66, ec.SECP521R1(), hashes.SHA512()),
]


def _try_gen_ec(rs: Any, curve_name: str) -> tuple[int, int]:
    """Generate EC keypair, skip if curve unsupported."""
    curve_oid = encode_named_curve_parameters(curve_name)
    try:
        return gen_ec_keypair(rs.raw, rs.sh, curve_oid)
    except CkrAssertionError as exc:
        if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
            pytest.skip(f"Curve {curve_name} not supported by module")
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            f"EC key generation advertised but {curve_name} keygen is not operational",
        )
        raise


# ---------------------------------------------------------------------------
# Subgroup-order fixtures (QC5c, issue #57.3)
# ---------------------------------------------------------------------------
# The trusted subgroup order n is stored SEPARATELY from the field/coordinate
# size: they differ on every fixture curve (sect409k1: field 52 bytes, order
# 51; secp160r1: field 20, order 21; secp224k1: field 28, order 29), so one
# must never be derived from the other. Signature half-lengths come from the
# order width (PKCS#11 v3.2 section 6.3.1: 2*nLen, nLen in octets of n);
# SEC1 point parsing uses the field width. Domain parameters below were
# transcribed from the cited SECG documents and cross-checked field-by-field
# against OpenSSL explicit parameters plus on-curve and n*G == O checks.


@dataclass(frozen=True)
class _PrimeField:
    p: int
    a: int
    b: int


@dataclass(frozen=True)
class _BinaryField:
    m: int
    k: int  # Reduction trinomial f(x) = x**m + x**k + 1.
    a: int
    b: int


@dataclass(frozen=True)
class _SubgroupCurve:
    name: str
    field: _PrimeField | _BinaryField
    gx: int
    gy: int
    order: int
    field_width: int
    order_width: int
    hash_name: str
    sec2_ref: str


_SUBGROUP_ORDER_CURVES: tuple[_SubgroupCurve, ...] = (
    _SubgroupCurve(
        name="secp160r1",
        field=_PrimeField(
            p=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", 16),
            a=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", 16),
            b=int("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", 16),
        ),
        gx=int("4A96B5688EF573284664698968C38BB913CBFC82", 16),
        gy=int("23A628553168947D59DCC912042351377AC5FB32", 16),
        order=int("0100000000000000000001F4C8F927AED3CA752257", 16),
        field_width=20,
        order_width=21,
        hash_name="sha256",
        sec2_ref="SECG SEC 2 v1.0, section 2.4.2",
    ),
    _SubgroupCurve(
        name="secp224k1",
        field=_PrimeField(
            p=int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D", 16),
            a=0,
            b=5,
        ),
        gx=int("A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C", 16),
        gy=int("7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5", 16),
        order=int("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7", 16),
        field_width=28,
        order_width=29,
        hash_name="sha256",
        sec2_ref="SECG SEC 2 v2.0, section 2.3.1",
    ),
    _SubgroupCurve(
        name="sect409k1",
        field=_BinaryField(
            m=409,
            k=87,
            a=0,
            b=1,
        ),
        gx=int(
            "0060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8"
            "F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE9023746",
            16,
        ),
        gy=int(
            "01E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165"
            "E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B",
            16,
        ),
        order=int(
            "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA"
            "20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF",
            16,
        ),
        field_width=52,
        order_width=51,
        hash_name="sha384",
        sec2_ref="SECG SEC 2 v2.0, section 3.6.1",
    ),
)


def _order_octet_length(order: int) -> int:
    """Return ceil(order.bit_length()/8), the nLen of section 6.3.1."""
    return (order.bit_length() + 7) // 8


def _prime_add(
    p: int,
    a: int,
    p1: tuple[int, int] | None,
    p2: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        s = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        s = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (s * s - x1 - x2) % p
    return (x3, (s * (x1 - x3) - y1) % p)


def _prime_mul(p: int, a: int, k: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    acc: tuple[int, int] | None = None
    while k:
        if k & 1:
            acc = _prime_add(p, a, acc, point)
        point = _prime_add(p, a, point, point)
        k >>= 1
    return acc


def _gf2m_mul(a: int, b: int, m: int, k: int) -> int:
    res = 0
    while b:
        if b & 1:
            res ^= a
        a <<= 1
        b >>= 1
    mod = (1 << m) | (1 << k) | 1
    top = res.bit_length()
    while top > m:
        res ^= mod << (top - m - 1)
        top = res.bit_length()
    return res


def _gf2m_inv(a: int, m: int, k: int) -> int:
    mod = (1 << m) | (1 << k) | 1
    u, v = a, mod
    g1, g2 = 1, 0
    while u:
        j = u.bit_length() - v.bit_length()
        if j < 0:
            u, v = v, u
            g1, g2 = g2, g1
            j = -j
        u ^= v << j
        g1 ^= g2 << j
    return g2


def _binary_add(
    m: int,
    k: int,
    a: int,
    p1: tuple[int, int] | None,
    p2: tuple[int, int] | None,
) -> tuple[int, int] | None:
    """Affine add on y^2 + xy = x^3 + ax^2 + b over GF(2**m)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if y1 != y2 or x1 == 0:
            return None
        lam = x1 ^ _gf2m_mul(y1, _gf2m_inv(x1, m, k), m, k)
        x3 = _gf2m_mul(lam, lam, m, k) ^ lam ^ a
    else:
        lam = _gf2m_mul(y1 ^ y2, _gf2m_inv(x1 ^ x2, m, k), m, k)
        x3 = _gf2m_mul(lam, lam, m, k) ^ lam ^ x1 ^ x2 ^ a
    y3 = _gf2m_mul(lam, x1 ^ x3, m, k) ^ x3 ^ y1
    return (x3, y3)


def _binary_mul(
    m: int, k: int, a: int, n: int, point: tuple[int, int] | None
) -> tuple[int, int] | None:
    acc: tuple[int, int] | None = None
    while n:
        if n & 1:
            acc = _binary_add(m, k, a, acc, point)
        point = _binary_add(m, k, a, point, point)
        n >>= 1
    return acc


def _subgroup_on_curve(curve: _SubgroupCurve, x: int, y: int) -> bool:
    if isinstance(curve.field, _PrimeField):
        p, a, b = curve.field.p, curve.field.a, curve.field.b
        return (y * y - (x * x * x + a * x + b)) % p == 0
    f = curve.field
    lhs = _gf2m_mul(y, y, f.m, f.k) ^ _gf2m_mul(x, y, f.m, f.k)
    x2 = _gf2m_mul(x, x, f.m, f.k)
    rhs = _gf2m_mul(x2, x, f.m, f.k) ^ _gf2m_mul(f.a, x2, f.m, f.k) ^ f.b
    return lhs == rhs


def _ecdsa_truncate(digest: bytes, order: int) -> int:
    """Leftmost bit_length(order) bits of the digest (FIPS 186-5 section 6.4)."""
    excess = 8 * len(digest) - order.bit_length()
    z = int.from_bytes(digest, "big")
    return z >> excess if excess > 0 else z


def _ecdsa_verify_subgroup(
    curve: _SubgroupCurve, qx: int, qy: int, digest: bytes, r: int, s: int
) -> bool:
    """Independently verify an ECDSA signature (pure Python, no provider)."""
    n = curve.order
    if not (0 < r < n and 0 < s < n):
        return False
    z = _ecdsa_truncate(digest, n)
    w = pow(s, -1, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    if isinstance(curve.field, _PrimeField):
        g1 = _prime_mul(curve.field.p, curve.field.a, u1, (curve.gx, curve.gy))
        g2 = _prime_mul(curve.field.p, curve.field.a, u2, (qx, qy))
        point = _prime_add(curve.field.p, curve.field.a, g1, g2)
    else:
        f = curve.field
        g1 = _binary_mul(f.m, f.k, f.a, u1, (curve.gx, curve.gy))
        g2 = _binary_mul(f.m, f.k, f.a, u2, (qx, qy))
        point = _binary_add(f.m, f.k, f.a, g1, g2)
    if point is None:
        return False
    return point[0] % n == r


def _parse_subgroup_point(data: bytes, curve: _SubgroupCurve) -> tuple[int, int]:
    """Parse an uncompressed SEC1 point sized by FIELD width (never the order).

    Exact-length raw uncompressed SEC1 is recognized before DER because a
    valid raw coordinate may also look like a DER length; other inputs must
    be a strict DER OCTET STRING wrapping uncompressed SEC1. Compressed
    points are not decoded (ValueError -> the caller xfails visibly).
    """
    expected_raw_len = 1 + 2 * curve.field_width
    candidate = data
    if not (len(data) == expected_raw_len and data.startswith(b"\x04")):
        candidate = decode_ec_point(data)
    if len(candidate) != expected_raw_len or not candidate.startswith(b"\x04"):
        raise ValueError(
            f"expected {expected_raw_len}-byte uncompressed SEC1 for {curve.name}, "
            f"got {len(candidate)} bytes"
        )
    w = curve.field_width
    return (
        int.from_bytes(candidate[1 : 1 + w], "big"),
        int.from_bytes(candidate[1 + w :], "big"),
    )


def _read_subgroup_point_or_xfail(
    rs: Any,
    handle: int,
    curve: _SubgroupCurve,
    *,
    label: str = "EC public key",
) -> tuple[int, int]:
    """Read and validate a CKA_EC_POINT for a subgroup-order curve.

    Unavailable or undecodable representations xfail (the independent check
    cannot run). A structurally valid point that is not on the expected
    curve is a hard cryptographic failure.
    """
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_EC_POINT])
    except CkrAssertionError as exc:
        if exc.rv in (int(CKR_ATTRIBUTE_SENSITIVE), int(CKR_ATTRIBUTE_TYPE_INVALID)):
            xfail_as(
                "not_operational",
                kind="metadata",
                label=label,
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                actual=exc.rv,
                summary=f"{label}: cannot read CKA_EC_POINT: {exc}",
                detail={
                    "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                    "curve": curve.name,
                },
            )
        raise

    if CKA_EC_POINT in attrs:
        ec_point = attrs[CKA_EC_POINT]
    else:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=f"{label}: CKA_EC_POINT attribute unavailable",
            detail={
                "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                "curve": curve.name,
            },
        )

    if not isinstance(ec_point, bytes) or not ec_point:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=f"{label}: CKA_EC_POINT is missing or not bytes: {ec_point!r}",
            detail={
                "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                "curve": curve.name,
            },
        )

    try:
        x, y = _parse_subgroup_point(ec_point, curve)
    except ValueError as exc:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=f"{label}: cannot decode CKA_EC_POINT: {exc}",
            detail={
                "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                "curve": curve.name,
            },
        )
    # Coordinate ranges BEFORE the equation check (SEC 1 sections 2.3.4 and
    # 2.3.6): field arithmetic silently reduces out-of-range representations
    # (e.g. a 410-bit binary-field x aliases its reduced value), so an
    # equation-only check accepts coordinates the standard requires rejected.
    field = curve.field
    if isinstance(field, _PrimeField):
        limit = field.p
        bound = "p"
    else:
        limit = 1 << field.m
        bound = "2**m"
    for name, value in (("x", x), ("y", y)):
        if not 0 <= value < limit:
            fail_as(
                "wrong_result",
                kind="crypto",
                label=label,
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                summary=(
                    f"{label}: provider returned a {curve.name} CKA_EC_POINT with "
                    f"{name}-coordinate outside [0, {bound})"
                ),
                detail={
                    "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                    "curve": curve.name,
                    "coordinate": name,
                },
            )
    if not _subgroup_on_curve(curve, x, y):
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=f"{label}: provider returned an off-curve CKA_EC_POINT for {curve.name}",
            detail={
                "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
                "curve": curve.name,
            },
        )
    return (x, y)


class TestECKeygen:
    @pytest.mark.parametrize(
        "curve_name,_,__,___",
        _EC_CURVES,
        ids=["P-224", "P-256", "secp256k1", "P-384", "P-521"],
    )
    def test_ec_keygen(
        self, p11_raw_session: Any, curve_name: str, _: int, __: Any, ___: Any
    ) -> None:
        """Generate EC key pair on the given curve."""
        rs = p11_raw_session
        pub, priv = _try_gen_ec(rs, curve_name)
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize(
        "curve_name,_,__,___",
        _EC_CURVES,
        ids=["P-224", "P-256", "secp256k1", "P-384", "P-521"],
    )
    def test_ec_key_type(
        self, p11_raw_session: Any, curve_name: str, _: int, __: Any, ___: Any
    ) -> None:
        """EC key pair should have EC key type."""
        rs = p11_raw_session
        pub, priv = _try_gen_ec(rs, curve_name)
        try:
            attrs_pub = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])
            attrs_priv = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])
            pub_type = attr_or_record(
                attrs_pub,
                CKA_KEY_TYPE,
                inherit_mechanism=False,
                label=f"CKA_KEY_TYPE:{curve_name}-public-key",
            )
            priv_type = attr_or_record(
                attrs_priv,
                CKA_KEY_TYPE,
                inherit_mechanism=False,
                label=f"CKA_KEY_TYPE:{curve_name}-private-key",
            )
            contradictions = [
                (label, value)
                for label, value in (
                    (f"CKA_KEY_TYPE:{curve_name}-public-key", pub_type),
                    (f"CKA_KEY_TYPE:{curve_name}-private-key", priv_type),
                )
                if value is not MISSING_ATTRIBUTE and value != CKK_EC
            ]
            for label, value in contradictions[:-1]:
                record_as(
                    "self_contradiction",
                    kind="metadata",
                    label=label,
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    summary=f"{label}: expected CKK_EC, got {value!r}",
                )
            if contradictions:
                label, value = contradictions[-1]
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label=label,
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    summary=f"{label}: expected CKK_EC, got {value!r}",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECDSACrossVerify:
    @pytest.mark.parametrize(
        "curve_name,coord_size,crypto_curve,hash_algo",
        _EC_CURVES,
        ids=["P-224", "P-256", "secp256k1", "P-384", "P-521"],
    )
    def test_ecdsa_sign_p11_verify_crypto(
        self,
        p11_raw_session: Any,
        curve_name: str,
        coord_size: int,
        crypto_curve: ec.EllipticCurve,
        hash_algo: hashes.HashAlgorithm,
    ) -> None:
        """ECDSA sign with PKCS#11, verify with cryptography."""
        rs = p11_raw_session
        skip_unless_capability(rs, CKM_ECDSA, operation=CKF_SIGN)

        hash_fns = {28: hashlib.sha224, 32: hashlib.sha256, 48: hashlib.sha384, 66: hashlib.sha512}

        pub, priv = _try_gen_ec(rs, curve_name)
        try:
            data = f"ECDSA {curve_name} cross-verify".encode()
            digest = hash_fns[coord_size](data).digest()

            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            except CkrAssertionError as exc:
                # The gate above proved CKM_ECDSA C_Sign is advertised IN_RANGE; a clean
                # capability-ish refusal here is an advertised-then-refused contradiction.
                # Tag it as the IN_RANGE not_operational xfail (recorded for investigation,
                # not hidden); other reject codes fall through to the existing handler.
                try:
                    route_in_range_not_operational(
                        exc,
                        label="ECDSA sign",
                        mechanism="CKM_ECDSA",
                        key_size=None,
                        operation="C_Sign",
                    )
                except CkrAssertionError:
                    # audit-ok: route re-raised a non-in-range code; handled just below
                    pass
                xfail_if_known_ckr(exc, _ECDSA_SIGN_REJECT_RVS, "ECDSA sign not operational")
                raise

            pub_crypto = read_ec_public_key_or_xfail(
                rs,
                pub,
                crypto_curve,
                label=f"ECDSA {curve_name} public key",
            )

            half = len(sig) // 2
            r = int.from_bytes(sig[:half], "big")
            s = int.from_bytes(sig[half:], "big")
            der_sig = encode_dss_signature(r, s)

            pub_crypto.verify(der_sig, data, ec.ECDSA(hash_algo))
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECDSASubgroupOrder:
    """ECDSA width and independent verification where order != field (QC5c).

    Issue #57.3: a token sized sect409k1 signatures from the field (104
    bytes) instead of the subgroup order (2*51 = 102). Every leg below
    splits and validates signatures with the trusted ORDER width while
    point parsing uses the FIELD width; the two are stored separately and
    cross-checked, never derived from each other. Curves the module does
    not support are visible skips, never fabricated coverage.
    """

    @pytest.mark.parametrize(
        "curve", _SUBGROUP_ORDER_CURVES, ids=[c.name for c in _SUBGROUP_ORDER_CURVES]
    )
    def test_order_width_crosscheck(self, curve: _SubgroupCurve) -> None:
        """Trusted order width equals ceil(order.bit_length()/8) (no provider)."""
        assert_correct(
            actual=curve.order_width,
            expected=_order_octet_length(curve.order),
            label=f"subgroup order width {curve.name}",
            kind="metadata",
            inherit_mechanism=False,
        )

    @pytest.mark.parametrize(
        "curve", _SUBGROUP_ORDER_CURVES, ids=[c.name for c in _SUBGROUP_ORDER_CURVES]
    )
    def test_sign_width_is_two_order_len(self, p11_raw_session: Any, curve: _SubgroupCurve) -> None:
        """Token ECDSA signatures are exactly 2*order_width bytes (fail otherwise)."""
        assert_correct(
            actual=curve.order_width,
            expected=_order_octet_length(curve.order),
            label=f"subgroup order width {curve.name}",
            kind="metadata",
            inherit_mechanism=False,
        )
        rs = p11_raw_session
        skip_unless_capability(rs, CKM_ECDSA, operation=CKF_SIGN)

        pub, priv = _try_gen_ec(rs, curve.name)
        try:
            data = f"ECDSA {curve.name} subgroup-order cross-verify".encode()
            digest = hashlib.new(curve.hash_name, data).digest()
            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            except CkrAssertionError as exc:
                # Same advertised-then-refused routing as TestECDSACrossVerify:
                # IN_RANGE refusal -> not_operational xfail; a narrow
                # sign-reject set xfails; anything else (a real signing
                # failure) stays a hard failure.
                try:
                    route_in_range_not_operational(
                        exc,
                        label="ECDSA sign",
                        mechanism="CKM_ECDSA",
                        key_size=None,
                        operation="C_Sign",
                    )
                except CkrAssertionError:
                    # audit-ok: route re-raised a non-in-range code; handled just below
                    pass
                xfail_if_known_ckr(exc, _ECDSA_SIGN_REJECT_RVS, "ECDSA sign not operational")
                raise
            # Width gate first: token-created output must be exactly
            # 2*order_width even when it is a well-formed DER signature (the
            # parser below leniently xfails DER, which must not leak into
            # this leg).
            assert_exact_dss_width_or_classify(
                sig,
                half_len=curve.order_width,
                label=f"CKM_ECDSA:sign {curve.name} subgroup-order width",
                operation="C_Sign",
                mechanism="CKM_ECDSA",
            )
            parse_raw_dss_or_classify(
                sig,
                half_len=curve.order_width,
                order=curve.order,
                label=f"CKM_ECDSA:sign {curve.name} subgroup-order width",
                operation="C_Sign",
                mechanism="CKM_ECDSA",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize(
        "curve", _SUBGROUP_ORDER_CURVES, ids=[c.name for c in _SUBGROUP_ORDER_CURVES]
    )
    def test_token_signature_verifies_independently(
        self, p11_raw_session: Any, curve: _SubgroupCurve
    ) -> None:
        """Token signatures verify under the independent pure-Python verifier."""
        assert_correct(
            actual=curve.order_width,
            expected=_order_octet_length(curve.order),
            label=f"subgroup order width {curve.name}",
            kind="metadata",
            inherit_mechanism=False,
        )
        rs = p11_raw_session
        skip_unless_capability(rs, CKM_ECDSA, operation=CKF_SIGN)

        pub, priv = _try_gen_ec(rs, curve.name)
        try:
            data = f"ECDSA {curve.name} subgroup-order cross-verify".encode()
            digest = hashlib.new(curve.hash_name, data).digest()
            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            except CkrAssertionError as exc:
                try:
                    route_in_range_not_operational(
                        exc,
                        label="ECDSA sign",
                        mechanism="CKM_ECDSA",
                        key_size=None,
                        operation="C_Sign",
                    )
                except CkrAssertionError:
                    # audit-ok: route re-raised a non-in-range code; handled just below
                    pass
                xfail_if_known_ckr(exc, _ECDSA_SIGN_REJECT_RVS, "ECDSA sign not operational")
                raise
            r, s = parse_raw_dss_or_classify(
                sig,
                half_len=curve.order_width,
                order=curve.order,
                label=f"CKM_ECDSA:sign {curve.name} subgroup-order stimulus",
                operation="C_Sign",
                mechanism="CKM_ECDSA",
            )
            qx, qy = _read_subgroup_point_or_xfail(
                rs, pub, curve, label=f"ECDSA {curve.name} public key"
            )
            if not _ecdsa_verify_subgroup(curve, qx, qy, digest, r, s):
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label=f"CKM_ECDSA:sign {curve.name} independent verify",
                    operation="C_Sign",
                    mechanism="CKM_ECDSA",
                    summary=(
                        f"Token ECDSA signature on {curve.name} does not verify independently"
                    ),
                    detail={
                        "digest_length": len(digest),
                        "signature_length": len(sig),
                        "curve": curve.name,
                    },
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
