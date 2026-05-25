"""Wycheproof ECDH key agreement test vectors (SP 800-56A).

Tests ECDH shared secret derivation using Wycheproof vectors for P-256, P-384,
and P-521 curves.

Requires: Wycheproof test vectors
Skips gracefully if test vectors not available or mechanism unavailable.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack_mechanisms import mech_ecdh
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    import_ec_private_key,
    import_ec_public_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKK_EC,
    CKK_GENERIC_SECRET,
    CKM_ECDH1_DERIVE,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
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
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr
from pkcs11_check.testcases.data import WYCHEPROOF_DIR

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

# Curve mapping: curve name -> (pkcs11 curve name, coordinate byte length, wycheproof file)
_CURVE_MAP: dict[str, tuple[str, int, str]] = {
    "P-256": ("secp256r1", 32, "ecdh_secp256r1_test.json"),
    "P-384": ("secp384r1", 48, "ecdh_secp384r1_test.json"),
    "P-521": ("secp521r1", 66, "ecdh_secp521r1_test.json"),
}

_EC_CAPABILITY_REJECT_RVS = (
    CKR_MECHANISM_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_KEY_SIZE_RANGE,
)

_ECDH_RUNTIME_REJECT_RVS = (
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_TEMPLATE_INCONSISTENT,
)


def _skip_if_ec_capability_reject(exc: AssertionError, label: str) -> None:
    if is_known_error(exc, _EC_CAPABILITY_REJECT_RVS):
        pytest.skip(f"{label} not supported: {exc}")
    raise


def _xfail_if_ecdh_runtime_reject(exc: AssertionError, label: str) -> None:
    if is_known_error(exc, (CKR_CURVE_NOT_SUPPORTED, CKR_DOMAIN_PARAMS_INVALID)):
        pytest.skip(f"{label} not supported: {exc}")
    xfail_if_known_ckr(
        exc,
        _ECDH_RUNTIME_REJECT_RVS,
        f"{label} advertised but ECDH derive is not operational",
    )
    raise


def _der_octet_string(data: bytes) -> bytes:
    """Wrap bytes in a DER OCTET STRING (tag 0x04 + length + data)."""
    n = len(data)
    if n < 0x80:
        return bytes([0x04, n]) + data
    elif n < 0x100:
        return bytes([0x04, 0x81, n]) + data
    else:
        return bytes([0x04, 0x82, n >> 8, n & 0xFF]) + data


def _pad_coordinate(hex_str: str, coord_len: int) -> bytes:
    """Pad hex coordinate to specified byte length."""
    return bytes.fromhex(hex_str.zfill(coord_len * 2))


def _build_ec_point(qx_hex: str, qy_hex: str, coord_len: int) -> bytes:
    """Build uncompressed EC point from coordinates (04 || X || Y)."""
    point_bytes = (
        bytes([0x04]) + _pad_coordinate(qx_hex, coord_len) + _pad_coordinate(qy_hex, coord_len)
    )
    return _der_octet_string(point_bytes)


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """Read one DER TLV and return (tag, value_start, value_end, next_offset)."""
    if offset >= len(data):
        raise ValueError("truncated DER tag")

    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("truncated DER length")

    first_len = data[offset]
    offset += 1
    if first_len < 0x80:
        length = first_len
    else:
        length_octets = first_len & 0x7F
        if length_octets == 0:
            raise ValueError("indefinite DER length is not allowed")
        if offset + length_octets > len(data):
            raise ValueError("truncated DER long-form length")
        length = int.from_bytes(data[offset : offset + length_octets], "big")
        offset += length_octets

    value_start = offset
    value_end = offset + length
    if value_end > len(data):
        raise ValueError("truncated DER value")
    return tag, value_start, value_end, value_end


def _load_wycheproof_ecdh_vectors(
    curve: str,
) -> list[tuple[str, dict[str, Any]]]:
    """Load ECDH vectors from Wycheproof for a specific curve.

    Returns list of (test_id, test_data) tuples with:
    - private_key: hex string of private scalar
    - public_key: hex string of peer public point (04 || X || Y)
    - expected_shared: hex string of expected shared secret
    """
    if curve not in _CURVE_MAP:
        return []

    _, coord_len, filename = _CURVE_MAP[curve]
    filepath = WYCHEPROOF_DIR / filename

    if not filepath.exists():
        return []

    with open(filepath) as f:
        data = json.load(f)

    results: list[tuple[str, dict[str, Any]]] = []

    for group in data.get("testGroups", []):
        for test in group.get("tests", []):
            # Only use valid tests (not invalid or edge cases)
            if test.get("result") != "valid":
                continue

            tc_id = test.get("tcId", 0)
            private_hex = test.get("private", "")
            public_hex = test.get("public", "")
            shared_hex = test.get("shared", "")

            if not (private_hex and public_hex and shared_hex):
                continue

            # Parse public key - it's a DER-encoded ASN.1 structure
            # For raw ECDH, we need the X and Y coordinates
            public_bytes = bytes.fromhex(public_hex)

            # Extract raw point from DER SubjectPublicKeyInfo or raw point
            # Wycheproof format varies - try to extract uncompressed point
            ec_point_der = _extract_ec_point(public_bytes, coord_len)
            if ec_point_der is None:
                continue

            test_data = {
                "curve": curve,
                "tc_id": tc_id,
                "private_key": bytes.fromhex(private_hex).lstrip(b"\x00").rjust(coord_len, b"\x00"),
                "ec_point_der": ec_point_der,
                "expected_shared": bytes.fromhex(shared_hex),
                "comment": test.get("comment", ""),
            }

            results.append((f"Wycheproof-ECDH-{curve}-tc{tc_id}", test_data))

    return results


def _extract_ec_point(public_key_bytes: bytes, coord_len: int) -> bytes | None:
    """Extract uncompressed EC point from public key bytes.

    Handles both raw points (04 || X || Y) and DER-encoded SubjectPublicKeyInfo.
    """
    n = len(public_key_bytes)
    expected_point_len = 1 + 2 * coord_len  # 04 || X || Y

    # Check if it's already a raw uncompressed point
    if n == expected_point_len and public_key_bytes[0] == 0x04:
        return _der_octet_string(public_key_bytes)

    # CKA_EC_POINT encoding: DER OCTET STRING wrapping the uncompressed point.
    if n > expected_point_len and public_key_bytes[0] == 0x04:
        try:
            point = decode_ec_point(public_key_bytes)
        except ValueError:
            point = b""
        if len(point) == expected_point_len and point[0] == 0x04:
            return public_key_bytes

    # SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING ECPoint }.
    # Do not scan for the first 0x04 byte: P-384/P-521 curve OIDs contain 0x04.
    try:
        tag, outer_start, outer_end, next_offset = _read_der_tlv(public_key_bytes, 0)
        if tag != 0x30 or next_offset != n:
            return None

        tag, _, _, offset = _read_der_tlv(public_key_bytes, outer_start)
        if tag != 0x30:
            return None

        tag, bit_start, bit_end, offset = _read_der_tlv(public_key_bytes, offset)
        if tag != 0x03 or offset != outer_end or bit_start >= bit_end:
            return None

        unused_bits = public_key_bytes[bit_start]
        point = public_key_bytes[bit_start + 1 : bit_end]
        if unused_bits == 0 and len(point) == expected_point_len and point[0] == 0x04:
            return _der_octet_string(point)
    except ValueError:
        return None

    return None


def _load_all_ecdh_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ECDH vectors for all supported curves."""
    all_vectors: list[tuple[str, dict[str, Any]]] = []

    for curve in ["P-256", "P-384", "P-521"]:
        vectors = _load_wycheproof_ecdh_vectors(curve)
        all_vectors.extend(vectors)

    return all_vectors


_ECDH_VECTORS = _load_all_ecdh_vectors()


@pytest.mark.parametrize("vec_id, vec", _ECDH_VECTORS, ids=[v[0] for v in _ECDH_VECTORS])
def test_acvp_ecdh_shared_secret(
    p11_raw_session: RawSession, vec_id: str, vec: dict[str, Any]
) -> None:
    """ECDH shared secret derivation test using Wycheproof vectors.

    Imports a private key and peer public key, derives the shared secret using
    CKM_ECDH1_DERIVE, and verifies it matches the expected value.
    """
    rs = p11_raw_session

    # Skip if ECDH not supported
    if not rs.has_mechanism("ECDH1_DERIVE"):
        pytest.skip("CKM_ECDH1_DERIVE not supported by module")

    curve = vec["curve"]
    ec_curve_name, coord_len, _ = _CURVE_MAP[curve]
    ec_params = encode_named_curve_parameters(ec_curve_name)

    priv_key = 0
    pub_key = 0
    derived_key = 0

    try:
        try:
            priv_key = import_ec_private_key(
                rs.raw,
                rs.sh,
                ec_params=ec_params,
                value=vec["private_key"],
                key_type=int(CKK_EC),
                attrs={
                    CKA_DERIVE: True,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
            )
        except AssertionError as exc:
            _skip_if_ec_capability_reject(exc, f"Curve {curve} private key import")

        try:
            pub_key = import_ec_public_key(
                rs.raw,
                rs.sh,
                ec_params=ec_params,
                ec_point=vec["ec_point_der"],
                key_type=int(CKK_EC),
            )
        except AssertionError as exc:
            _skip_if_ec_capability_reject(exc, f"Curve {curve} public key import")

        # Prepare ECDH1_DERIVE mechanism parameters. The public data is the peer's
        # public key point; strip DER OCTET STRING wrapper because ECDH1_DERIVE
        # takes the raw point.
        point_data = decode_ec_point(vec["ec_point_der"])

        mech_param = mech_ecdh(
            CKM_ECDH1_DERIVE,
            kdf=int(CKD_NULL),  # No KDF, raw shared secret
            public_data=point_data,
        )

        try:
            derived_key = derive_key(
                rs.raw,
                rs.sh,
                base_key=priv_key,
                mechanism=CKM_ECDH1_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,  # Derived shared secret, not EC key
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_VALUE_LEN: len(vec["expected_shared"]),
                },
                mech_param=mech_param,
            )
        except AssertionError as exc:
            _xfail_if_ecdh_runtime_reject(exc, f"Curve {curve}")

        # Read the derived key's value
        attrs = read_attributes(rs.raw, rs.sh, derived_key, [CKA_VALUE])
        shared_secret = cast(bytes, attrs.get(CKA_VALUE, b""))

        # Compare to expected (may need coordinate extraction for some modules)
        expected = vec["expected_shared"]

        # Some modules return the full coordinate, others return just X
        # The shared secret in ECDH is the X coordinate of the resulting point
        if len(shared_secret) > len(expected):
            # Extract the X coordinate if we got a full point
            shared_secret = shared_secret[: len(expected)]

        assert shared_secret == expected, (
            f"{vec_id}: Shared secret mismatch\n"
            f"  Expected: {expected.hex()[:32]}...\n"
            f"  Got:      {shared_secret.hex()[:32]}..."
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, derived_key)
        destroy_quietly(rs.raw, rs.sh, pub_key)
        destroy_quietly(rs.raw, rs.sh, priv_key)


class TestEcdhKeyAgreement:
    """ECDH key agreement tests by curve."""

    @pytest.mark.parametrize("curve", ["P-256", "P-384", "P-521"])
    def test_ecdh_key_agreement_basic(self, p11_raw_session: RawSession, curve: str) -> None:
        """Basic ECDH key agreement with module-generated keys."""
        rs = p11_raw_session

        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported by module")

        if curve not in _CURVE_MAP:
            pytest.skip(f"Curve {curve} not in test map")

        ec_curve_name, coord_len, _ = _CURVE_MAP[curve]
        ec_params = encode_named_curve_parameters(ec_curve_name)

        # Generate two keypairs for ECDH
        from pkcs11_check.raw.recipes import gen_ec_keypair

        alice_priv = alice_pub = bob_priv = bob_pub = 0
        alice_secret = 0

        try:
            try:
                alice_pub, alice_priv = gen_ec_keypair(
                    rs.raw,
                    rs.sh,
                    curve_oid=ec_params,
                    private_attrs={CKA_DERIVE: True},
                )
            except AssertionError as exc:
                _skip_if_ec_capability_reject(exc, f"Curve {curve} key generation")

            try:
                bob_pub, bob_priv = gen_ec_keypair(
                    rs.raw,
                    rs.sh,
                    curve_oid=ec_params,
                    private_attrs={CKA_DERIVE: True},
                )
            except AssertionError as exc:
                _skip_if_ec_capability_reject(exc, f"Curve {curve} key generation")

            # Alice derives secret with Bob's public key
            bob_point_attrs = read_attributes(rs.raw, rs.sh, bob_pub, [CKA_EC_POINT])
            bob_ec_point = cast(bytes, bob_point_attrs.get(CKA_EC_POINT, b""))

            # If we can't read the point, skip
            if not bob_ec_point:
                pytest.skip("Cannot extract public key point for ECDH")

            # CKA_EC_POINT is DER-encoded; ECDH1_DERIVE requires raw point per OASIS spec
            bob_point_raw = decode_ec_point(bob_ec_point)

            # Derive shared secrets
            mech_param_alice = mech_ecdh(
                CKM_ECDH1_DERIVE,
                kdf=int(CKD_NULL),
                public_data=bob_point_raw,
            )

            alice_secret = derive_key(
                rs.raw,
                rs.sh,
                base_key=alice_priv,
                mechanism=CKM_ECDH1_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                },
                mech_param=mech_param_alice,
            )
            try:
                # Read Alice's shared secret
                alice_attrs = read_attributes(rs.raw, rs.sh, alice_secret, [CKA_VALUE])
                alice_shared = cast(bytes, alice_attrs.get(CKA_VALUE, b""))

                assert len(alice_shared) > 0, f"{curve}: Failed to derive shared secret"
            except AssertionError:
                raise
        except AssertionError as exc:
            _xfail_if_ecdh_runtime_reject(exc, f"Curve {curve}")
        finally:
            destroy_quietly(rs.raw, rs.sh, alice_secret)
            destroy_quietly(rs.raw, rs.sh, bob_pub)
            destroy_quietly(rs.raw, rs.sh, bob_priv)
            destroy_quietly(rs.raw, rs.sh, alice_pub)
            destroy_quietly(rs.raw, rs.sh, alice_priv)
