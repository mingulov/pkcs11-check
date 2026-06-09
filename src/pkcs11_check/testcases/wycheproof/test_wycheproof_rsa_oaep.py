"""Wycheproof RSA-OAEP decryption vectors.

Tests RSA-OAEP across key sizes 2048/3072/4096 with various hash
and MGF combinations. Imports RSA private key, decrypts ciphertext,
compares against expected plaintext.
"""

from __future__ import annotations

import json
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.pack import mech_oaep
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    import_rsa_private_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA224,
    CKG_MGF1_SHA256,
    CKG_MGF1_SHA384,
    CKG_MGF1_SHA512,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA512_224,
    CKM_SHA512_256,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr
from pkcs11_check.testcases.wycheproof._key_decoders import pkcs11_bigint_from_hex

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Cache of RSA key sizes (in bits) that the module rejected on import.
# Populated on first failure; subsequent tests with the same key size skip
# immediately without attempting another C_CreateObject probe.
_UNSUPPORTED_RSA_KEY_SIZES: set[int] = set()

_RSA_PRIVATE_IMPORT_UNSUPPORTED_CKRS = (
    CKR_KEY_SIZE_RANGE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
)

_RSA_OAEP_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

# Map Wycheproof sha names to PKCS#11 hash mechanisms and MGFs for OAEP params
_SHA_HASH_MECHS: dict[str, int] = {
    "SHA-1": CKM_SHA_1,
    "SHA-224": CKM_SHA224,
    "SHA-256": CKM_SHA256,
    "SHA-384": CKM_SHA384,
    "SHA-512": CKM_SHA512,
    # Truncated SHA-512 OAEP hashAlg. PKCS#11 has no CKG_MGF1_SHA512_224/256,
    # so only vectors whose MGF hash *does* have a constant (e.g. mgf1sha1)
    # are runnable; the rest skip cleanly via the param-mapping guard below.
    "SHA-512/224": CKM_SHA512_224,
    "SHA-512/256": CKM_SHA512_256,
}

_SHA_MGFS: dict[str, int] = {
    "SHA-1": CKG_MGF1_SHA1,
    "SHA-224": CKG_MGF1_SHA224,
    "SHA-256": CKG_MGF1_SHA256,
    "SHA-384": CKG_MGF1_SHA384,
    "SHA-512": CKG_MGF1_SHA512,
}

# RSA-OAEP files - same hash and mixed hash/MGF combinations
_OAEP_FILES = [
    # Same hash/MGF
    "rsa_oaep_2048_sha1_mgf1sha1_test.json",
    "rsa_oaep_2048_sha224_mgf1sha224_test.json",
    "rsa_oaep_2048_sha256_mgf1sha256_test.json",
    "rsa_oaep_2048_sha384_mgf1sha384_test.json",
    "rsa_oaep_2048_sha512_mgf1sha512_test.json",
    "rsa_oaep_3072_sha256_mgf1sha256_test.json",
    "rsa_oaep_3072_sha512_mgf1sha512_test.json",
    "rsa_oaep_4096_sha256_mgf1sha256_test.json",
    "rsa_oaep_4096_sha512_mgf1sha512_test.json",
    # Mixed hash/MGF (hash != mgfSha)
    "rsa_oaep_2048_sha224_mgf1sha1_test.json",
    "rsa_oaep_2048_sha256_mgf1sha1_test.json",
    "rsa_oaep_2048_sha384_mgf1sha1_test.json",
    "rsa_oaep_2048_sha512_mgf1sha1_test.json",
    "rsa_oaep_3072_sha256_mgf1sha1_test.json",
    "rsa_oaep_3072_sha512_mgf1sha1_test.json",
    "rsa_oaep_4096_sha256_mgf1sha1_test.json",
    "rsa_oaep_4096_sha512_mgf1sha1_test.json",
    # Truncated SHA-512 hashAlg (mgf1sha1 runs; mgf1sha512_224/256 skip --
    # PKCS#11 has no CKG_MGF1_SHA512_224/256 to express those MGFs)
    "rsa_oaep_2048_sha512_224_mgf1sha1_test.json",
    "rsa_oaep_2048_sha512_224_mgf1sha512_224_test.json",
    "rsa_oaep_3072_sha512_256_mgf1sha1_test.json",
    "rsa_oaep_3072_sha512_256_mgf1sha512_256_test.json",
    "rsa_three_primes_oaep_2048_sha1_mgf1sha1_test.json",
    "rsa_three_primes_oaep_3072_sha224_mgf1sha224_test.json",
    "rsa_three_primes_oaep_4096_sha256_mgf1sha256_test.json",
    # Misc - various parameter combinations in one file
    "rsa_oaep_misc_test.json",
]


# PKCS#11-visible OAEP decryption inputs: (modulus, ciphertext, hashAlg,
# mgf, label). Two vectors that differ only in fields PKCS#11 cannot see drive
# the identical C_Decrypt and are deduplicated (see sibling wycheproof tests).
_OaepFingerprint = tuple[bytes, bytes, str, str, bytes]


def _pkcs11_oaep_fingerprint(test: dict[str, Any]) -> _OaepFingerprint | None:
    """Return PKCS#11-visible RSA-OAEP decrypt inputs for duplicate detection."""
    try:
        pk = test["_group"].get("privateKey", {})
        return (
            pkcs11_bigint_from_hex(pk.get("modulus", "")),
            bytes.fromhex(test["ct"]),
            str(test["_sha"]),
            str(test["_mgfSha"]),
            bytes.fromhex(test.get("label", "")),
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
    groups: dict[_OaepFingerprint, list[tuple[str, dict[str, Any]]]] = {}
    for vec_id, test in vectors:
        fingerprint = _pkcs11_oaep_fingerprint(test)
        if fingerprint is not None:
            groups.setdefault(fingerprint, []).append((vec_id, test))
    for entries in groups.values():
        if len(entries) < 2:
            continue
        duplicate_of = _canonical_duplicate_id(entries)
        for vec_id, test in entries:
            if vec_id != duplicate_of:
                test["_pkcs11_duplicate_of"] = duplicate_of


def _load_oaep_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA-OAEP vectors - decryption tests with private key."""
    vectors = []
    for filename in _OAEP_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "SHA-1")
            mgf_sha = group.get("mgfSha", sha)
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_file"] = filename
                test["_sha"] = sha
                test["_mgfSha"] = mgf_sha
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    _mark_pkcs11_duplicate_vectors(vectors)
    return vectors


_ALL_OAEP_VECTORS = _load_oaep_vectors()


def _xfail_if_rsa_oaep_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised RSA-OAEP parameter/runtime rejects as findings."""
    xfail_if_known_ckr(
        exc,
        _RSA_OAEP_RUNTIME_REJECT_CKRS,
        f"{label}: advertised RSA-OAEP parameters are not operational",
    )
    raise exc


def _skip_or_xfail_rsa_oaep_private_import_reject(
    exc: AssertionError,
    key_bits: int,
) -> NoReturn:
    """Classify RSA private-key import rejects before Wycheproof OAEP decrypt."""
    if is_known_error(exc, _RSA_PRIVATE_IMPORT_UNSUPPORTED_CKRS):
        _UNSUPPORTED_RSA_KEY_SIZES.add(key_bits)
        pytest.skip(f"Cannot import RSA {key_bits}-bit private key for OAEP: {exc}")
    xfail_if_known_ckr(
        exc,
        _RSA_OAEP_RUNTIME_REJECT_CKRS,
        f"RSA private-key import is not operational for OAEP ({key_bits}-bit)",
    )
    raise exc


@pytest.mark.parametrize("vec_id,vec", _ALL_OAEP_VECTORS, ids=[v[0] for v in _ALL_OAEP_VECTORS])
def test_rsa_oaep(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA-OAEP decryption from Wycheproof vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("RSA_PKCS_OAEP"):
        pytest.skip("RSA_PKCS_OAEP not supported")

    if duplicate_of := vec.get("_pkcs11_duplicate_of"):
        pytest.skip(f"Duplicate PKCS#11 RSA-OAEP operation input; covered by {duplicate_of}")

    ct = bytes.fromhex(vec["ct"])
    msg_expected = bytes.fromhex(vec["msg"])
    result = vec["result"]
    group = vec["_group"]
    sha = vec["_sha"]
    mgf_sha = vec["_mgfSha"]
    label = bytes.fromhex(vec.get("label", ""))

    # Build OAEP params
    hash_mech = _SHA_HASH_MECHS.get(sha)
    mgf = _SHA_MGFS.get(mgf_sha)
    if hash_mech is None or mgf is None:
        pytest.skip(f"No OAEP param mapping for sha={sha} mgfSha={mgf_sha}")

    oaep_param = mech_oaep(
        CKM_RSA_PKCS_OAEP,
        hash_mech=hash_mech,
        mgf=mgf,
        source_data=label if label else None,
    )

    pk = group.get("privateKey", {})
    modulus_hex = pk.get("modulus", "")
    exp_hex = pk.get("publicExponent", "")
    priv_exp_hex = pk.get("privateExponent", "")
    if not modulus_hex or not priv_exp_hex:
        pytest.skip("No RSA private key in vector group")

    modulus = pkcs11_bigint_from_hex(modulus_hex)
    pub_exponent = pkcs11_bigint_from_hex(exp_hex)
    priv_exponent = pkcs11_bigint_from_hex(priv_exp_hex)
    prime1 = pkcs11_bigint_from_hex(pk.get("prime1", ""))
    prime2 = pkcs11_bigint_from_hex(pk.get("prime2", ""))
    exp1 = pkcs11_bigint_from_hex(pk.get("exponent1", ""))
    exp2 = pkcs11_bigint_from_hex(pk.get("exponent2", ""))
    coefficient = pkcs11_bigint_from_hex(pk.get("coefficient", ""))
    key_bits = len(modulus) * 8

    if key_bits in _UNSUPPORTED_RSA_KEY_SIZES:
        pytest.skip(f"RSA {key_bits}-bit keys not supported (cached)")

    try:
        priv_key = import_rsa_private_key(
            rs.raw,
            rs.sh,
            n=modulus,
            e=pub_exponent,
            d=priv_exponent,
            p=prime1,
            q=prime2,
            dmp1=exp1,
            dmq1=exp2,
            iqmp=coefficient,
            attrs={CKA_DECRYPT: True},
        )
    except AssertionError as exc:
        _skip_or_xfail_rsa_oaep_private_import_reject(exc, key_bits)

    plaintext = None
    try:
        plaintext = decrypt_single(
            rs.raw,
            rs.sh,
            priv_key,
            CKM_RSA_PKCS_OAEP,
            ct,
            mech_param=oaep_param,
        )
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_rsa_oaep_runtime_reject(exc, vec_id)
            sha = vec.get("_sha", "unknown")
            mgf_sha = vec.get("_mgfSha", "unknown")
            pytest.fail(
                f"Valid RSA-OAEP ciphertext {vec_id} failed to decrypt "
                f"(sha={sha}, mgf={mgf_sha}): {exc}"
            )
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)

    if result == "valid" and plaintext is not None:
        assert plaintext == msg_expected
    if result == "invalid" and plaintext is not None:
        pytest.fail(f"RSA-OAEP decrypt {vec_id} accepted invalid ciphertext")
