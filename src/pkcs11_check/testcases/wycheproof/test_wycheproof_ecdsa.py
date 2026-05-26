"""Wycheproof ECDSA vectors - broad curve and hash coverage.

The base Wycheproof module covers a small core subset.
This file adds the remaining DER and P1363-encoded verification vectors
that can run through the existing raw `CKM_ECDSA` mechanism path.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, NoReturn

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    generate_random,
    import_ec_public_key,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKM_ECDSA,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["ECDSA"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Module-level cache of curves that failed C_CreateObject with a domain/curve error.
# Avoids thousands of redundant probe calls when a module does not support a curve.
_UNSUPPORTED_CURVES: set[str] = set()

_CURVE_UNSUPPORTED_CKRS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

_EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
)

_ECDSA_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)


class _ShakeHash:
    """Wrapper to make SHAKE hashes compatible with the hashlib .digest() API.

    SHAKE produces variable-length output, so .digest(length) is required.
    This wrapper binds the output length at construction time.
    """

    def __init__(self, shake_fn: Any, output_len: int, data: bytes = b"") -> None:
        self._h = shake_fn(data)
        self._output_len = output_len

    def digest(self) -> bytes:
        return self._h.digest(self._output_len)  # type: ignore[no-any-return]


def _shake128(output_len: int) -> Any:
    """Return a SHAKE-128 hash factory with fixed output length."""

    def factory(data: bytes = b"") -> _ShakeHash:
        return _ShakeHash(hashlib.shake_128, output_len, data)

    return factory


def _shake256(output_len: int) -> Any:
    """Return a SHAKE-256 hash factory with fixed output length."""

    def factory(data: bytes = b"") -> _ShakeHash:
        return _ShakeHash(hashlib.shake_256, output_len, data)

    return factory


# Curve config: (filename, curve_name, coord_size, hash_fn)
_ECDSA_CONFIGS = [
    ("ecdsa_brainpoolP224r1_sha224_test.json", "brainpoolp224r1", 28, hashlib.sha224, False),
    ("ecdsa_brainpoolP224r1_sha224_p1363_test.json", "brainpoolp224r1", 28, hashlib.sha224, True),
    ("ecdsa_brainpoolP224r1_sha3_224_test.json", "brainpoolp224r1", 28, hashlib.sha3_224, False),
    ("ecdsa_brainpoolP256r1_sha256_test.json", "brainpoolp256r1", 32, hashlib.sha256, False),
    ("ecdsa_brainpoolP256r1_sha256_p1363_test.json", "brainpoolp256r1", 32, hashlib.sha256, True),
    ("ecdsa_brainpoolP256r1_sha3_256_test.json", "brainpoolp256r1", 32, hashlib.sha3_256, False),
    ("ecdsa_brainpoolP320r1_sha384_test.json", "brainpoolp320r1", 40, hashlib.sha384, False),
    ("ecdsa_brainpoolP320r1_sha384_p1363_test.json", "brainpoolp320r1", 40, hashlib.sha384, True),
    ("ecdsa_brainpoolP320r1_sha3_384_test.json", "brainpoolp320r1", 40, hashlib.sha3_384, False),
    ("ecdsa_brainpoolP384r1_sha384_test.json", "brainpoolp384r1", 48, hashlib.sha384, False),
    ("ecdsa_brainpoolP384r1_sha384_p1363_test.json", "brainpoolp384r1", 48, hashlib.sha384, True),
    ("ecdsa_brainpoolP384r1_sha3_384_test.json", "brainpoolp384r1", 48, hashlib.sha3_384, False),
    ("ecdsa_brainpoolP512r1_sha512_test.json", "brainpoolp512r1", 64, hashlib.sha512, False),
    ("ecdsa_brainpoolP512r1_sha512_p1363_test.json", "brainpoolp512r1", 64, hashlib.sha512, True),
    ("ecdsa_brainpoolP512r1_sha3_512_test.json", "brainpoolp512r1", 64, hashlib.sha3_512, False),
    ("ecdsa_secp160k1_sha256_test.json", "secp160k1", 21, hashlib.sha256, False),
    ("ecdsa_secp160k1_sha256_p1363_test.json", "secp160k1", 21, hashlib.sha256, True),
    ("ecdsa_secp160r1_sha256_test.json", "secp160r1", 21, hashlib.sha256, False),
    ("ecdsa_secp160r1_sha256_p1363_test.json", "secp160r1", 21, hashlib.sha256, True),
    ("ecdsa_secp160r2_sha256_test.json", "secp160r2", 21, hashlib.sha256, False),
    ("ecdsa_secp160r2_sha256_p1363_test.json", "secp160r2", 21, hashlib.sha256, True),
    ("ecdsa_secp192k1_sha256_test.json", "secp192k1", 24, hashlib.sha256, False),
    ("ecdsa_secp192k1_sha256_p1363_test.json", "secp192k1", 24, hashlib.sha256, True),
    ("ecdsa_secp192r1_sha256_test.json", "secp192r1", 24, hashlib.sha256, False),
    ("ecdsa_secp192r1_sha256_p1363_test.json", "secp192r1", 24, hashlib.sha256, True),
    ("ecdsa_secp224k1_sha224_test.json", "secp224k1", 29, hashlib.sha224, False),
    ("ecdsa_secp224k1_sha224_p1363_test.json", "secp224k1", 29, hashlib.sha224, True),
    ("ecdsa_secp224k1_sha256_test.json", "secp224k1", 29, hashlib.sha256, False),
    ("ecdsa_secp224k1_sha256_p1363_test.json", "secp224k1", 29, hashlib.sha256, True),
    ("ecdsa_secp224r1_sha224_test.json", "secp224r1", 28, hashlib.sha224, False),
    ("ecdsa_secp224r1_sha224_p1363_test.json", "secp224r1", 28, hashlib.sha224, True),
    ("ecdsa_secp224r1_sha256_test.json", "secp224r1", 28, hashlib.sha256, False),
    ("ecdsa_secp224r1_sha256_p1363_test.json", "secp224r1", 28, hashlib.sha256, True),
    ("ecdsa_secp224r1_sha512_test.json", "secp224r1", 28, hashlib.sha512, False),
    ("ecdsa_secp224r1_sha512_p1363_test.json", "secp224r1", 28, hashlib.sha512, True),
    ("ecdsa_secp224r1_sha3_224_test.json", "secp224r1", 28, hashlib.sha3_224, False),
    ("ecdsa_secp224r1_sha3_256_test.json", "secp224r1", 28, hashlib.sha3_256, False),
    ("ecdsa_secp224r1_sha3_512_test.json", "secp224r1", 28, hashlib.sha3_512, False),
    ("ecdsa_secp224r1_shake128_test.json", "secp224r1", 28, _shake128(28), False),
    ("ecdsa_secp224r1_shake128_p1363_test.json", "secp224r1", 28, _shake128(28), True),
    ("ecdsa_secp256k1_sha256_test.json", "secp256k1", 32, hashlib.sha256, False),
    ("ecdsa_secp256k1_sha256_p1363_test.json", "secp256k1", 32, hashlib.sha256, True),
    ("ecdsa_secp256k1_sha256_bitcoin_test.json", "secp256k1", 32, hashlib.sha256, False),
    ("ecdsa_secp256k1_sha512_test.json", "secp256k1", 32, hashlib.sha512, False),
    ("ecdsa_secp256k1_sha512_p1363_test.json", "secp256k1", 32, hashlib.sha512, True),
    ("ecdsa_secp256k1_sha3_256_test.json", "secp256k1", 32, hashlib.sha3_256, False),
    ("ecdsa_secp256k1_sha3_512_test.json", "secp256k1", 32, hashlib.sha3_512, False),
    ("ecdsa_secp256k1_shake128_test.json", "secp256k1", 32, _shake128(32), False),
    ("ecdsa_secp256k1_shake128_p1363_test.json", "secp256k1", 32, _shake128(32), True),
    ("ecdsa_secp256k1_shake256_test.json", "secp256k1", 32, _shake256(32), False),
    ("ecdsa_secp256k1_shake256_p1363_test.json", "secp256k1", 32, _shake256(32), True),
    ("ecdsa_secp256r1_sha512_test.json", "secp256r1", 32, hashlib.sha512, False),
    ("ecdsa_secp256r1_sha512_p1363_test.json", "secp256r1", 32, hashlib.sha512, True),
    ("ecdsa_secp256r1_sha256_p1363_test.json", "secp256r1", 32, hashlib.sha256, True),
    ("ecdsa_secp256r1_sha3_256_test.json", "secp256r1", 32, hashlib.sha3_256, False),
    ("ecdsa_secp256r1_sha3_512_test.json", "secp256r1", 32, hashlib.sha3_512, False),
    ("ecdsa_secp256r1_shake128_test.json", "secp256r1", 32, _shake128(32), False),
    ("ecdsa_secp256r1_shake128_p1363_test.json", "secp256r1", 32, _shake128(32), True),
    ("ecdsa_secp384r1_sha256_test.json", "secp384r1", 48, hashlib.sha256, False),
    ("ecdsa_secp384r1_sha384_p1363_test.json", "secp384r1", 48, hashlib.sha384, True),
    ("ecdsa_secp384r1_sha512_test.json", "secp384r1", 48, hashlib.sha512, False),
    ("ecdsa_secp384r1_sha512_p1363_test.json", "secp384r1", 48, hashlib.sha512, True),
    ("ecdsa_secp384r1_sha3_384_test.json", "secp384r1", 48, hashlib.sha3_384, False),
    ("ecdsa_secp384r1_sha3_512_test.json", "secp384r1", 48, hashlib.sha3_512, False),
    ("ecdsa_secp384r1_shake256_test.json", "secp384r1", 48, _shake256(48), False),
    ("ecdsa_secp384r1_shake256_p1363_test.json", "secp384r1", 48, _shake256(48), True),
    ("ecdsa_secp521r1_sha512_test.json", "secp521r1", 66, hashlib.sha512, False),
    ("ecdsa_secp521r1_sha512_p1363_test.json", "secp521r1", 66, hashlib.sha512, True),
    ("ecdsa_secp521r1_sha3_512_test.json", "secp521r1", 66, hashlib.sha3_512, False),
    ("ecdsa_secp521r1_shake256_test.json", "secp521r1", 66, _shake256(66), False),
    ("ecdsa_secp521r1_shake256_p1363_test.json", "secp521r1", 66, _shake256(66), True),
]


def _raw_ecdsa_signature(test: dict[str, Any]) -> bytes:
    """Return the PKCS#11-visible raw ECDSA r||s signature."""
    sig_bytes = bytes.fromhex(test["sig"])
    coord_size = test["_coord_size"]
    if test["_is_p1363"]:
        return sig_bytes
    r_int, s_int = decode_dss_signature(sig_bytes)
    return r_int.to_bytes(coord_size, "big") + s_int.to_bytes(coord_size, "big")


def _pkcs11_ecdsa_fingerprint(test: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes] | None:
    """Return PKCS#11-visible ECDSA verify inputs for duplicate detection."""
    try:
        pub_key_info = test["_group"].get("publicKey", {})
        return (
            encode_named_curve_parameters(test["_curve"]),
            bytes.fromhex(pub_key_info.get("uncompressed", "")),
            test["_hash_fn"](bytes.fromhex(test["msg"])).digest(),
            _raw_ecdsa_signature(test),
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def _canonical_duplicate_id(entries: list[tuple[str, dict[str, Any]]]) -> str:
    """Choose the most PKCS#11-meaningful representative for duplicate vectors."""
    for preferred in ("valid", "acceptable"):
        for vec_id, test in entries:
            if test["result"] == preferred:
                return vec_id
    return entries[0][0]


def _mark_pkcs11_duplicate_vectors(vectors: list[tuple[str, dict[str, Any]]]) -> None:
    groups: dict[tuple[bytes, bytes, bytes, bytes], list[tuple[str, dict[str, Any]]]] = {}
    for vec_id, test in vectors:
        fingerprint = _pkcs11_ecdsa_fingerprint(test)
        if fingerprint is not None:
            groups.setdefault(fingerprint, []).append((vec_id, test))
    for entries in groups.values():
        if len(entries) < 2:
            continue
        duplicate_of = _canonical_duplicate_id(entries)
        for vec_id, test in entries:
            if vec_id != duplicate_of:
                test["_pkcs11_duplicate_of"] = duplicate_of


def _load_ecdsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    vectors = []
    for filename, curve, coord_size, hash_fn, is_p1363 in _ECDSA_CONFIGS:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_curve"] = curve
                test["_coord_size"] = coord_size
                test["_hash_fn"] = hash_fn
                test["_file"] = filename
                test["_is_p1363"] = is_p1363
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    _mark_pkcs11_duplicate_vectors(vectors)
    return vectors


_ALL_ECDSA = _load_ecdsa_vectors()


def _xfail_if_ecdsa_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised ECDSA verify runtime rejects as findings."""
    xfail_if_known_ckr(
        exc,
        _ECDSA_RUNTIME_REJECT_CKRS,
        f"{label}: advertised ECDSA verify is not operational",
    )
    raise exc


@pytest.mark.parametrize("vec_id,vec", _ALL_ECDSA, ids=[v[0] for v in _ALL_ECDSA])
def test_ecdsa_wycheproof(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ECDSA signature verification from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("ECDSA"):
        pytest.skip("ECDSA not supported")

    if duplicate_of := vec.get("_pkcs11_duplicate_of"):
        pytest.skip(f"Duplicate PKCS#11 ECDSA operation input; covered by {duplicate_of}")

    msg = bytes.fromhex(vec["msg"])
    result = vec["result"]
    group = vec["_group"]
    curve = vec["_curve"]
    hash_fn = vec["_hash_fn"]

    pub_key_info = group.get("publicKey", {})
    uncompressed_hex = pub_key_info.get("uncompressed", "")
    if not uncompressed_hex:
        pytest.skip("No uncompressed point")

    uncompressed = bytes.fromhex(uncompressed_hex)

    # DER OCTET STRING wrapper
    if len(uncompressed) < 128:
        ec_point_der = bytes([0x04, len(uncompressed)]) + uncompressed
    else:
        ec_point_der = bytes([0x04, 0x81, len(uncompressed)]) + uncompressed

    try:
        ec_params = encode_named_curve_parameters(curve)
    except (ValueError, KeyError, LookupError):
        pytest.skip(f"No EC params for curve {curve}")

    if curve in _UNSUPPORTED_CURVES:
        pytest.skip(f"Curve {curve} not supported (cached)")

    try:
        pub_key = import_ec_public_key(
            rs.raw,
            rs.sh,
            ec_params=ec_params,
            ec_point=ec_point_der,
            attrs={CKA_VERIFY: True},
        )
    except AssertionError as exc:
        if is_known_error(exc, _CURVE_UNSUPPORTED_CKRS):
            _UNSUPPORTED_CURVES.add(curve)
            pytest.skip(f"Cannot import EC key for {curve}: {exc}")
        if is_known_error(exc, _EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS):
            pytest.skip(f"Cannot import EC key for {curve}: {exc}")
        raise

    try:
        raw_sig = _raw_ecdsa_signature(vec)
    except (ValueError, OverflowError) as exc:
        if result == "invalid":
            return
        pytest.fail(f"Cannot decode valid DER sig for {vec_id}: {exc}")

    digest = hash_fn(msg).digest()

    try:
        verified = verify_single(rs.raw, rs.sh, pub_key, CKM_ECDSA, digest, raw_sig)
        if result == "invalid":
            if verified:
                pytest.fail(f"Invalid ECDSA sig {vec_id} accepted by module")
            return
        if result == "valid" and not verified:
            pytest.fail(f"Valid ECDSA sig {vec_id} rejected by module")
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_ecdsa_runtime_reject(exc, vec_id)
            pytest.fail(f"Valid ECDSA sig {vec_id} rejected: {exc}")
        signature_rejected_or_xfail(exc, vec_id)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)
