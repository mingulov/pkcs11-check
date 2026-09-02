"""Wycheproof ECDSA vectors - broad curve and hash coverage.

The base Wycheproof module covers a small core subset.
This file adds the remaining DER and P1363-encoded verification vectors
that can run through the existing raw `CKM_ECDSA` mechanism path.
"""

from __future__ import annotations

import hashlib
from typing import Any, NoReturn

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pkcs11_check.classification import classify, set_params
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    generate_random,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKM_ECDSA,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE,
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
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import (
    ec_public_key_binding_defect,
    import_ec_public_key_negotiated,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["ECDSA"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402

# Module-level cache of curves that failed C_CreateObject with a domain/curve error.
# Avoids thousands of redundant probe calls when a module does not support a curve.
_UNSUPPORTED_CURVES: set[str] = set()

# Per-curve effect-check result: None = curve binding verified coherent; str = defect
# reason (silent rebind / incoherent object). Checked once per curve per process; a
# defective curve's vectors skip BEFORE import so a bounded object store is not
# flooded with broken objects (some modules have bounded object stores that can
# overflow with CKR_DEVICE_MEMORY).
_CURVE_BINDING_DEFECTS: dict[str, str | None] = {}

_CURVE_UNSUPPORTED_CKRS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

_EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS = (
    # advertised-but-not-operational: a KMS bridge rejects external EC public-key
    # import (C_CreateObject) with a clean generic CKR -> xfail, not a raw failure.
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
)

_ECDSA_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_INVALID,
    # PKCS#11 §2.3.1: CKM_ECDSA must accept any hash length (truncating to the
    # group order); a module pinning the digest length (some modules pin to a
    # fixed size such as 32B) cleanly rejects valid longer digests -> recorded
    # deviation, not hard fail.
    CKR_DATA_LEN_RANGE,
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
    ("ecdsa_secp521r1_shake256_test.json", "secp521r1", 66, _shake256(64), False),
    ("ecdsa_secp521r1_shake256_p1363_test.json", "secp521r1", 66, _shake256(64), True),
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


def _is_pkcs11_short_signature_size_vector(test: dict[str, Any]) -> bool:
    """Return whether a fixed-width P1363 size reject is not PKCS#11-neutral."""
    if not test.get("_is_p1363"):
        return False
    if test.get("result") != "invalid":
        return False
    if "SignatureSize" not in test.get("flags", ()):
        return False
    try:
        sig_len = len(bytes.fromhex(test["sig"]))
        coord_size = int(test["_coord_size"])
    except (KeyError, TypeError, ValueError):
        return False
    return sig_len > 0 and sig_len % 2 == 0 and sig_len < 2 * coord_size


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
        data = load_json_cached(path)
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
def test_ecdsa_wycheproof(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ECDSA signature verification from Wycheproof vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("ECDSA"):
        pytest.skip("ECDSA not supported")

    if duplicate_of := vec.get("_pkcs11_duplicate_of"):
        pytest.skip(f"Duplicate PKCS#11 ECDSA operation input; covered by {duplicate_of}")

    if _is_pkcs11_short_signature_size_vector(vec):
        pytest.skip("Wycheproof short ECDSA signature-size vector is not PKCS#11-neutral")

    msg = bytes.fromhex(vec["msg"])
    result = vec["result"]
    group = vec["_group"]
    curve = vec["_curve"]
    set_params({"curve": curve})
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

    if defect := _CURVE_BINDING_DEFECTS.get(curve):
        pytest.skip(f"Curve {curve} not honored by module (already reported): {defect}")

    # Decode the signature BEFORE importing the key: this path returns/fails
    # without reaching the destroying try/finally, so an already-imported key
    # would leak — fatal on modules with a bounded object store.
    try:
        raw_sig = _raw_ecdsa_signature(vec)
    except (ValueError, OverflowError) as exc:
        if result == "invalid":
            return
        classify(
            "not_operational",
            label="ECDSA:DER-decode",
            summary=f"Cannot decode valid DER sig for {vec_id}: {exc}",
        )

    digest = hash_fn(msg).digest()

    try:
        pub_key = import_ec_public_key_negotiated(
            rs,
            ec_params=ec_params,
            ec_point=ec_point_der,
            attrs={CKA_VERIFY: True},
            purpose=f"wycheproof ECDSA {curve} public key import",
        )
    except AssertionError as exc:
        if is_known_error(exc, _CURVE_UNSUPPORTED_CKRS):
            # Genuine capability absence: this specific curve is not supported
            # (CKR_CURVE_NOT_SUPPORTED / CKR_DOMAIN_PARAMS_INVALID). Skip stays.
            _UNSUPPORTED_CURVES.add(curve)
            pytest.skip(f"Cannot import EC key for {curve}: {exc}")
        if isinstance(exc, CkrAssertionError) and is_known_error(
            exc, _EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS
        ):
            # ECDSA is advertised (has_mechanism gate passed above) and the
            # negotiated import is exhausted -> "advertised but not operational"
            # -> xfail per the classification model (not skip).
            # May include curve-capability rejects expressed as generic CKRs --
            # recorded as xfail, not hidden.
            classify(
                "not_operational",
                label="ECDSA:key-import",
                summary=not_operational_reason("ECDSA:key-import", f"{curve}: {ckr_name(exc.rv)}"),
            )
        raise

    if curve not in _CURVE_BINDING_DEFECTS:
        defect = ec_public_key_binding_defect(rs, pub_key, ec_params)
        _CURVE_BINDING_DEFECTS[curve] = defect
        if defect:
            destroy_quietly(rs.raw, rs.sh, pub_key)
            classify(
                "self_contradiction",
                kind="lifecycle",
                label=f"EC import coherence {curve}",
                operation="C_CreateObject",
                summary=(
                    f"{curve}: C_CreateObject returned CKR_OK but the object is not "
                    f"honored (lifecycle self-contradiction): {defect}"
                ),
            )
    if defect := _CURVE_BINDING_DEFECTS[curve]:
        destroy_quietly(rs.raw, rs.sh, pub_key)
        pytest.skip(f"Curve {curve} not honored by module (already reported): {defect}")

    try:
        verified = verify_single(rs.raw, rs.sh, pub_key, CKM_ECDSA, digest, raw_sig)
        if result == "invalid":
            if verified:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="ECDSA",
                    summary=f"Invalid ECDSA sig {vec_id} accepted by module",
                )
            return
        if result == "valid" and not verified:
            classify(
                "wrong_result",
                kind="crypto",
                label="ECDSA",
                summary=f"Valid ECDSA sig {vec_id} rejected by module",
            )
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_ecdsa_runtime_reject(exc, vec_id)
        signature_rejected_or_xfail(exc, vec_id)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)
