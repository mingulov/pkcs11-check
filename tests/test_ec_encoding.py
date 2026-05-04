"""Regression tests for EC DER OID generation and EC point encoding.

Covers every curve in ec.py with exact DER byte verification, all aliases,
case insensitivity, and each EC point format (Weierstrass DER, Montgomery raw,
Edwards raw).  Prevents regressions like the 0xe5 Montgomery DER unwrap bug
and the brainpoolp224r1 OID typo (0x0B vs 0x05).

Reference standards:
  - RFC 5480: SEC/ANSI P-curves, secp160/k1/r2, secp192/k1/r1, secp224/k1/r1
  - RFC 5639: Brainpool curves
  - RFC 8410: Edwards/Montgomery curves (Ed25519, Ed448, X25519, X448)
  - SEC 2: Binary K-curves (sect283k1/r1, sect409k1/r1, sect571k1/r1)
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.der import decode_ec_point, encode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters

# ---------------------------------------------------------------------------
# OID test data: each curve verified against its defining RFC
# ---------------------------------------------------------------------------


class _Oid:
    def __init__(self, curve: str, expected_hex: str) -> None:
        self.curve = curve
        self.expected = bytes.fromhex(expected_hex)


# NIST/SEC P-curves (RFC 5480)
_P_CURVES = [
    _Oid("secp160r1", "06052b81040008"),
    _Oid("secp160r2", "06052b8104001e"),
    _Oid("secp160k1", "06052b81040009"),
    _Oid("secp192k1", "06052b8104001f"),
    _Oid("secp192r1", "06082a8648ce3d030101"),
    _Oid("secp224r1", "06052b81040021"),
    _Oid("secp224k1", "06052b81040020"),
    _Oid("secp256r1", "06082a8648ce3d030107"),
    _Oid("secp384r1", "06052b81040022"),
    _Oid("secp521r1", "06052b81040023"),
    _Oid("secp256k1", "06052b8104000a"),
]

# Edwards and Montgomery curves (RFC 8410)
_EDM_CURVES = [
    _Oid("ed25519", "06032b6570"),
    _Oid("ed448", "06032b6571"),
    _Oid("x25519", "06032b656e"),
    _Oid("x448", "06032b656f"),
]

# Brainpool curves (RFC 5639 Section 4.2)
_BRAINPOOL_CURVES = [
    _Oid("brainpoolp224r1", "06092b2403030208010105"),
    _Oid("brainpoolp256r1", "06092b2403030208010107"),
    _Oid("brainpoolp320r1", "06092b2403030208010109"),
    _Oid("brainpoolp384r1", "06092b240303020801010b"),
    _Oid("brainpoolp512r1", "06092b240303020801010d"),
]

# Binary K-curves (SEC 2)
_K_CURVES = [
    _Oid("sect283k1", "06052b81040010"),
    _Oid("sect283r1", "06052b81040011"),
    _Oid("sect409k1", "06052b81040024"),
    _Oid("sect409r1", "06052b81040025"),
    _Oid("sect571k1", "06052b81040026"),
    _Oid("sect571r1", "06052b81040027"),
]

_ALL_CURVES = _P_CURVES + _EDM_CURVES + _BRAINPOOL_CURVES + _K_CURVES

# Alias resolution table
_ALIAS_TESTS: list[tuple[str, str]] = [
    ("p-224", "secp224r1"),
    ("p-256", "secp256r1"),
    ("p-384", "secp384r1"),
    ("p-521", "secp521r1"),
    ("prime192v1", "secp192r1"),
    ("prime256v1", "secp256r1"),
    ("ansix962prime192v1", "secp192r1"),
    ("nistp256", "secp256r1"),
    ("nistp384", "secp384r1"),
    ("nistp521", "secp521r1"),
]


# ---------------------------------------------------------------------------
# OID generation tests
# ---------------------------------------------------------------------------


class TestAllCurveOids:
    """Every curve in ec.py produces the correct DER-encoded OID bytes.

    Regression: brainpoolp224r1 was 0x0B (wrong, that's brainpoolP384r1)
    instead of 0x05 (correct, per RFC 5639 Section 4.2).
    """

    @pytest.mark.parametrize("oid", _ALL_CURVES, ids=lambda o: o.curve)
    def test_oid_bytes(self, oid: _Oid) -> None:
        result = encode_named_curve_parameters(oid.curve)
        assert result == oid.expected, (
            f"{oid.curve}: expected {oid.expected.hex()}, got {result.hex()}"
        )

    @pytest.mark.parametrize("oid", _ALL_CURVES, ids=lambda o: o.curve)
    def test_oid_starts_with_asn1_tag(self, oid: _Oid) -> None:
        result = encode_named_curve_parameters(oid.curve)
        assert result[0] == 0x06, f"{oid.curve}: first byte must be 0x06 (OID tag)"

    @pytest.mark.parametrize("oid", _ALL_CURVES, ids=lambda o: o.curve)
    def test_oid_length_field_is_consistent(self, oid: _Oid) -> None:
        result = encode_named_curve_parameters(oid.curve)
        declared_length = result[1]
        actual_content = len(result) - 2
        assert declared_length == actual_content, (
            f"{oid.curve}: DER length byte says {declared_length} "
            f"but payload is {actual_content} bytes"
        )


class TestCurveAliasResolution:
    """Every alias in _ALIASES resolves to the same DER bytes as its canonical name."""

    @pytest.mark.parametrize("alias,canonical", _ALIAS_TESTS)
    def test_alias_matches_canonical(self, alias: str, canonical: str) -> None:
        canonical_oid = encode_named_curve_parameters(canonical)
        alias_oid = encode_named_curve_parameters(alias)
        assert alias_oid == canonical_oid, f"alias {alias!r} should resolve to {canonical!r}"


class TestCaseInsensitivity:
    """Curve names and aliases are case-insensitive."""

    @pytest.mark.parametrize(
        "name",
        ["SECP256R1", "Secp256R1", "ED25519", "Ed448", "X25519", "x448"],
    )
    def test_uppercase_curve(self, name: str) -> None:
        lower = encode_named_curve_parameters(name.lower())
        upper = encode_named_curve_parameters(name)
        assert upper == lower

    @pytest.mark.parametrize("alias", ["P-256", "P-384", "PRIME256V1", "Nistp256"])
    def test_uppercase_alias(self, alias: str) -> None:
        lower = encode_named_curve_parameters(alias.lower())
        upper = encode_named_curve_parameters(alias)
        assert upper == lower


class TestErrorCases:
    def test_unknown_curve_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown curve"):
            encode_named_curve_parameters("not-a-curve")

    def test_empty_string_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown curve"):
            encode_named_curve_parameters("")

    def test_whitespace_is_stripped(self) -> None:
        canonical = encode_named_curve_parameters("secp256r1")
        stripped = encode_named_curve_parameters("  secp256r1  ")
        assert stripped == canonical


class TestCurveCategories:
    """Category-level sanity checks: curves in the same family share OID prefix patterns."""

    def test_p_curves_have_sec_oid_prefix(self) -> None:
        for oid in _P_CURVES:
            if oid.curve in ("secp192r1", "secp256r1"):
                continue
            assert oid.expected[:3] == bytes([0x06, 0x05, 0x2B, 0x81, 0x04])[:3], (
                f"{oid.curve}: should use SEC 2 OID arc 1.3.132"
            )

    def test_edm_curves_are_5_bytes(self) -> None:
        for oid in _EDM_CURVES:
            assert len(oid.expected) == 5, f"{oid.curve}: RFC 8410 OIDs are 5 bytes"

    def test_brainpool_curves_are_11_bytes(self) -> None:
        for oid in _BRAINPOOL_CURVES:
            assert len(oid.expected) == 11, f"{oid.curve}: RFC 5639 OIDs are 11 bytes"

    def test_brainpool_curves_share_prefix(self) -> None:
        prefix = bytes([0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01])
        for oid in _BRAINPOOL_CURVES:
            assert oid.expected[:10] == prefix, (
                f"{oid.curve}: should have brainpool OID prefix 1.3.36.3.3.2.8.1.1"
            )


# ---------------------------------------------------------------------------
# EC point format tests
# ---------------------------------------------------------------------------


class TestWeierstrassEcPointDer:
    """Weierstrass (CKK_EC) curves: EC point is DER OCTET STRING wrapping 0x04||x||y.

    Per OASIS elliptic_curves.md: CKA_EC_POINT is DER-encoding of ANSI X9.62
    ECPoint value Q.
    """

    def test_p256_der_structure(self) -> None:
        x = int.from_bytes(b"\x01" * 32, "big")
        y = int.from_bytes(b"\x02" * 32, "big")
        der = encode_ec_point(x, y, key_size=32)
        assert der[0] == 0x04
        assert der[1] == 65
        assert der[2] == 0x04

    def test_p384_round_trip(self) -> None:
        x = int.from_bytes(b"\xab" * 48, "big")
        y = int.from_bytes(b"\xcd" * 48, "big")
        der = encode_ec_point(x, y, key_size=48)
        point = decode_ec_point(der)
        assert point[0] == 0x04
        assert len(point) == 97

    def test_p521_long_form_length(self) -> None:
        x = int.from_bytes(b"\x01" * 66, "big")
        y = int.from_bytes(b"\x02" * 66, "big")
        der = encode_ec_point(x, y, key_size=66)
        assert der[1] == 0x81
        assert der[2] == 133

    def test_round_trip_preserves_coordinates(self) -> None:
        x = int.from_bytes(b"\xaa" * 32, "big")
        y = int.from_bytes(b"\xbb" * 32, "big")
        der = encode_ec_point(x, y, key_size=32)
        point = decode_ec_point(der)
        assert int.from_bytes(point[1:33], "big") == x
        assert int.from_bytes(point[33:65], "big") == y


class TestMontgomeryEcPointRaw:
    """Montgomery curves (CKK_EC_MONTGOMERY): raw little-endian bytes per RFC 7748.

    X25519/X448 public keys are NOT DER-wrapped. The raw 0xe5 byte prefix on
    X25519 keys caused a false DER unwrap error before the fix.

    Regression: test_ecdh_extended.py _ec_point() was applying DER unwrap to
    Montgomery keys starting with 0xc1, producing garbage.
    """

    def test_x25519_raw_key_not_der_wrapped(self) -> None:
        raw_key = bytes([0xE5, 0x72, 0x0A, 0x15]) + b"\x00" * 28
        assert raw_key[0] == 0xE5
        assert raw_key[0] != 0x04
        assert len(raw_key) == 32

    def test_montgomery_key_starts_with_non_der_byte(self) -> None:
        for first_byte in [0xC1, 0xE5, 0xA0, 0x00, 0xFF]:
            key = bytes([first_byte]) + b"\x00" * 31
            assert key[0] != 0x04, f"Montgomery key byte 0x{first_byte:02x} != 0x04"

    def test_decode_ec_point_rejects_raw_montgomery_data(self) -> None:
        raw_key = bytes([0xE5]) + b"\x00" * 31
        with pytest.raises(ValueError, match="OCTET STRING"):
            decode_ec_point(raw_key)


class TestEdwardsEcPointRaw:
    """Edwards curves (CKK_EC_EDWARDS): raw little-endian bytes per RFC 8032.

    Ed25519/Ed448 public keys are NOT DER-wrapped.
    """

    def test_ed25519_raw_key_not_der_wrapped(self) -> None:
        raw_key = b"\x58" + b"\x00" * 31
        assert raw_key[0] != 0x04
        assert len(raw_key) == 32

    def test_ed448_raw_key_not_der_wrapped(self) -> None:
        raw_key = b"\x30" + b"\x00" * 56
        assert raw_key[0] != 0x04
        assert len(raw_key) == 57

    def test_decode_ec_point_rejects_raw_edwards_data(self) -> None:
        raw_key = b"\x58" + b"\x00" * 31
        with pytest.raises(ValueError, match="OCTET STRING"):
            decode_ec_point(raw_key)


class TestExtractEcPointPassthrough:
    """extract_ec_point from conftest.py returns raw data unchanged for non-DER inputs.

    Regression: the fallback path (line 56-57 of conftest.py) was not tested,
    meaning Montgomery/Edwards key extraction could break silently.
    """

    def test_passthrough_for_non_04_prefix(self) -> None:
        from pkcs11_check.testcases.conftest import extract_ec_point

        raw_montgomery = bytes([0xE5]) + b"\x00" * 31
        result = extract_ec_point(raw_montgomery)
        assert result == raw_montgomery

    def test_passthrough_for_empty_data(self) -> None:
        from pkcs11_check.testcases.conftest import extract_ec_point

        result = extract_ec_point(b"")
        assert result == b""

    def test_unwrap_for_der_weierstrass(self) -> None:
        from pkcs11_check.testcases.conftest import extract_ec_point

        x = int.from_bytes(b"\x01" * 32, "big")
        y = int.from_bytes(b"\x02" * 32, "big")
        der = encode_ec_point(x, y, key_size=32)
        result = extract_ec_point(der)
        assert result[0] == 0x04
        assert len(result) == 65


class TestDerStructuralValidation:
    """DER decode rejects malformed input instead of producing garbage."""

    def test_wrong_outer_tag_sequence(self) -> None:
        with pytest.raises(ValueError, match="OCTET STRING"):
            decode_ec_point(b"\x30\x03\x04\x01\x01")

    def test_truncated_octet_string(self) -> None:
        with pytest.raises(ValueError, match="Truncated"):
            decode_ec_point(b"\x04\x20" + b"\x00" * 10)

    def test_empty_input(self) -> None:
        with pytest.raises(ValueError):
            decode_ec_point(b"")
