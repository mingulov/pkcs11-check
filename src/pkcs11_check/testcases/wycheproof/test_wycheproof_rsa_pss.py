"""Wycheproof RSA-PSS signature verification vectors.

Tests RSA-PSS (PKCS#1 v2.1) across key sizes 2048/3072/4096 with
SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 and varying salt lengths.
"""

from __future__ import annotations

import json
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.pack import mech_pss
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    generate_random,
    import_rsa_public_key,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA3_224,
    CKG_MGF1_SHA3_256,
    CKG_MGF1_SHA3_384,
    CKG_MGF1_SHA3_512,
    CKG_MGF1_SHA224,
    CKG_MGF1_SHA256,
    CKG_MGF1_SHA384,
    CKG_MGF1_SHA512,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA3_224,
    CKM_SHA3_224_RSA_PKCS_PSS,
    CKM_SHA3_256,
    CKM_SHA3_256_RSA_PKCS_PSS,
    CKM_SHA3_384,
    CKM_SHA3_384_RSA_PKCS_PSS,
    CKM_SHA3_512,
    CKM_SHA3_512_RSA_PKCS_PSS,
    CKM_SHA224,
    CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr
from pkcs11_check.testcases.wycheproof._key_decoders import pkcs11_bigint_from_hex

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Cache of RSA key sizes (in bits) that the module rejected on import.
# Populated on first failure; subsequent tests with the same key size skip
# immediately without attempting another C_CreateObject probe.
_UNSUPPORTED_RSA_KEY_SIZES: set[int] = set()

_RSA_PUBLIC_IMPORT_UNSUPPORTED_CKRS = (
    CKR_KEY_SIZE_RANGE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
)

_RSA_PSS_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_RsaPssFingerprint = tuple[int, int, int, int, bytes, bytes, bytes, bytes]


def _pkcs11_rsa_pss_fingerprint(test: dict[str, Any]) -> _RsaPssFingerprint | None:
    """Return PKCS#11-visible RSA-PSS verify inputs for duplicate detection."""
    try:
        public_key = test["_group"].get("publicKey", {})
        return (
            int(test["_mechanism"]),
            int(test["_hash_mech"]),
            int(test["_mgf"]),
            int(test["_sLen"]),
            pkcs11_bigint_from_hex(public_key.get("modulus", "")),
            pkcs11_bigint_from_hex(public_key.get("publicExponent", "")),
            bytes.fromhex(test["msg"]),
            bytes.fromhex(test["sig"]),
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
    groups: dict[_RsaPssFingerprint, list[tuple[str, dict[str, Any]]]] = {}
    for vec_id, test in vectors:
        fingerprint = _pkcs11_rsa_pss_fingerprint(test)
        if fingerprint is not None:
            groups.setdefault(fingerprint, []).append((vec_id, test))
    for entries in groups.values():
        if len(entries) < 2:
            continue
        duplicate_of = _canonical_duplicate_id(entries)
        for vec_id, test in entries:
            if vec_id != duplicate_of:
                test["_pkcs11_duplicate_of"] = duplicate_of


# Map hash names to PKCS#11 mechanisms and hash mechanisms for PSS params
_SHA_MECHANISMS: dict[str, int] = {
    "SHA-1": CKM_SHA1_RSA_PKCS_PSS,
    "SHA-224": CKM_SHA224_RSA_PKCS_PSS,
    "SHA-256": CKM_SHA256_RSA_PKCS_PSS,
    "SHA-384": CKM_SHA384_RSA_PKCS_PSS,
    "SHA-512": CKM_SHA512_RSA_PKCS_PSS,
    "SHA3-224": CKM_SHA3_224_RSA_PKCS_PSS,
    "SHA3-256": CKM_SHA3_256_RSA_PKCS_PSS,
    "SHA3-384": CKM_SHA3_384_RSA_PKCS_PSS,
    "SHA3-512": CKM_SHA3_512_RSA_PKCS_PSS,
}

_SHA_HASH_MECHS: dict[str, int] = {
    "SHA-1": CKM_SHA_1,
    "SHA-224": CKM_SHA224,
    "SHA-256": CKM_SHA256,
    "SHA-384": CKM_SHA384,
    "SHA-512": CKM_SHA512,
    "SHA3-224": CKM_SHA3_224,
    "SHA3-256": CKM_SHA3_256,
    "SHA3-384": CKM_SHA3_384,
    "SHA3-512": CKM_SHA3_512,
}

_SHA_MGFS: dict[str, int] = {
    "SHA-1": CKG_MGF1_SHA1,
    "SHA-224": CKG_MGF1_SHA224,
    "SHA-256": CKG_MGF1_SHA256,
    "SHA-384": CKG_MGF1_SHA384,
    "SHA-512": CKG_MGF1_SHA512,
    "SHA3-224": CKG_MGF1_SHA3_224,
    "SHA3-256": CKG_MGF1_SHA3_256,
    "SHA3-384": CKG_MGF1_SHA3_384,
    "SHA3-512": CKG_MGF1_SHA3_512,
}

# Mechanism display names for availability checking
_MECH_DISPLAY: dict[int, str] = {
    CKM_SHA1_RSA_PKCS_PSS: "SHA1_RSA_PKCS_PSS",
    CKM_SHA224_RSA_PKCS_PSS: "SHA224_RSA_PKCS_PSS",
    CKM_SHA256_RSA_PKCS_PSS: "SHA256_RSA_PKCS_PSS",
    CKM_SHA384_RSA_PKCS_PSS: "SHA384_RSA_PKCS_PSS",
    CKM_SHA512_RSA_PKCS_PSS: "SHA512_RSA_PKCS_PSS",
    CKM_SHA3_224_RSA_PKCS_PSS: "SHA3_224_RSA_PKCS_PSS",
    CKM_SHA3_256_RSA_PKCS_PSS: "SHA3_256_RSA_PKCS_PSS",
    CKM_SHA3_384_RSA_PKCS_PSS: "SHA3_384_RSA_PKCS_PSS",
    CKM_SHA3_512_RSA_PKCS_PSS: "SHA3_512_RSA_PKCS_PSS",
}

# RSA-PSS vector files - standard and parameterized variants that map to
# the existing PKCS#11 PSS mechanism family.
_PSS_FILES = sorted(
    f.name
    for f in WYCHEPROOF_DIR.glob("rsa_pss_*_test.json")
    if f.exists() and "shake" not in f.name
)


def _load_pss_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load all standard RSA-PSS vectors."""
    vectors = []
    for filename in _PSS_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "")
            mgf_sha = group.get("mgfSha", sha)
            mechanism = _SHA_MECHANISMS.get(sha)
            hash_mech = _SHA_HASH_MECHS.get(sha)
            mgf = _SHA_MGFS.get(mgf_sha)
            if mechanism is None or hash_mech is None or mgf is None:
                continue
            s_len = group.get("sLen", 0)
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_mechanism"] = mechanism
                test["_sLen"] = s_len
                test["_sha"] = sha
                test["_mgf_sha"] = mgf_sha
                test["_hash_mech"] = hash_mech
                test["_mgf"] = mgf
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    _mark_pkcs11_duplicate_vectors(vectors)
    return vectors


_ALL_PSS_VECTORS = _load_pss_vectors()


def _xfail_if_rsa_pss_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised RSA-PSS parameter/runtime rejects as findings."""
    xfail_if_known_ckr(
        exc,
        _RSA_PSS_RUNTIME_REJECT_CKRS,
        f"{label}: advertised RSA-PSS parameters are not operational",
    )
    raise exc


@pytest.mark.parametrize("vec_id,vec", _ALL_PSS_VECTORS, ids=[v[0] for v in _ALL_PSS_VECTORS])
def test_rsa_pss(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA-PSS signature verification from Wycheproof vectors."""
    rs = p11_raw_session
    mechanism = vec["_mechanism"]
    name = _MECH_DISPLAY.get(mechanism, "RSA_PKCS_PSS")
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")

    if duplicate_of := vec.get("_pkcs11_duplicate_of"):
        pytest.skip(f"Duplicate PKCS#11 RSA-PSS operation input; covered by {duplicate_of}")

    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    mechanism = vec["_mechanism"]
    group = vec["_group"]
    s_len = vec["_sLen"]
    hash_mech = vec["_hash_mech"]
    mgf = vec["_mgf"]

    pk = group.get("publicKey", {})
    modulus_hex = pk.get("modulus", "")
    exp_hex = pk.get("publicExponent", "")
    if not modulus_hex or not exp_hex:
        pytest.skip("No RSA public key in vector group")

    modulus = pkcs11_bigint_from_hex(modulus_hex)
    exponent = pkcs11_bigint_from_hex(exp_hex)
    key_bits = len(modulus) * 8

    if key_bits in _UNSUPPORTED_RSA_KEY_SIZES:
        pytest.skip(f"RSA {key_bits}-bit keys not supported (cached)")

    try:
        pub_key = import_rsa_public_key(
            rs.raw,
            rs.sh,
            n=modulus,
            e=exponent,
            attrs={CKA_VERIFY: True},
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        # Only cache permanent key-size rejections, not transient errors.
        if is_known_error(exc, _RSA_PUBLIC_IMPORT_UNSUPPORTED_CKRS):
            _UNSUPPORTED_RSA_KEY_SIZES.add(key_bits)
        pytest.skip(f"Cannot import RSA {key_bits}-bit public key: {exc_msg}")

    # Build PSS params
    pss_param = mech_pss(mechanism, hash_mech=hash_mech, mgf=mgf, salt_len=s_len)

    try:
        verified = verify_single(rs.raw, rs.sh, pub_key, mechanism, msg, sig, mech_param=pss_param)
        if result == "invalid":
            if verified:
                pytest.fail(f"Invalid RSA-PSS sig {vec_id} accepted by module")
            return
        if result == "valid" and not verified:
            pytest.fail(f"Valid RSA-PSS sig {vec_id} rejected by module")
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_rsa_pss_runtime_reject(exc, vec_id)
            sha = vec.get("_sha", "unknown")
            mgf_sha = vec.get("_mgf_sha", "unknown")
            flags = vec.get("flags", [])
            flags_str = ", ".join(flags) if flags else "none"
            pytest.fail(
                f"Valid RSA-PSS sig {vec_id} rejected (sLen={s_len}, "
                f"sha={sha}, mgf={mgf_sha}, flags=[{flags_str}]): {exc}"
            )
        signature_rejected_or_xfail(exc, vec_id)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)
