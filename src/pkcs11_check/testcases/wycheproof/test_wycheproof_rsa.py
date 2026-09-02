"""Wycheproof RSA signature verification vectors - all key sizes and hashes.

Auto-discovers RSA signature vector files from the Wycheproof submodule.
Each file produces a parametrized test class.
"""

from __future__ import annotations

from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify, set_params
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    generate_random,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKM_SHA3_224_RSA_PKCS,
    CKM_SHA3_256_RSA_PKCS,
    CKM_SHA3_384_RSA_PKCS,
    CKM_SHA3_512_RSA_PKCS,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import (
    import_rsa_public_key_negotiated,
    is_known_error,
)
from pkcs11_check.testcases.wycheproof._key_decoders import pkcs11_bigint_from_hex

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402

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

_RsaFingerprint = tuple[int, bytes, bytes, bytes, bytes]


def _pkcs11_rsa_fingerprint(test: dict[str, Any]) -> _RsaFingerprint | None:
    """Return PKCS#11-visible RSA PKCS#1 verify inputs for duplicate detection."""
    try:
        public_key = test["_group"].get("publicKey", test["_group"].get("privateKey", {}))
        return (
            int(test["_mechanism"]),
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
    groups: dict[_RsaFingerprint, list[tuple[str, dict[str, Any]]]] = {}
    for vec_id, test in vectors:
        fingerprint = _pkcs11_rsa_fingerprint(test)
        if fingerprint is not None:
            groups.setdefault(fingerprint, []).append((vec_id, test))
    for entries in groups.values():
        if len(entries) < 2:
            continue
        duplicate_of = _canonical_duplicate_id(entries)
        for vec_id, test in entries:
            if vec_id != duplicate_of:
                test["_pkcs11_duplicate_of"] = duplicate_of


def _classify_valid_verify_reject(
    exc: AssertionError,
    *,
    label: str,
    summary: str,
    source: str | None = None,
    vector_id: str | None = None,
) -> NoReturn:
    """Route a valid-vector verify reject without catching harness failures."""
    if not isinstance(exc, CkrAssertionError):
        raise exc
    # Signature rejects are an advertised-but-not-operational valid-vector
    # deviation. Other defined CKRs remain visible through the strict helper.
    if not signature_rejected_or_xfail(exc, label):
        classify(
            "not_operational",
            label=label,
            summary=summary,
            source=source,
            vector_id=vector_id,
        )
    raise exc


# Mechanism display names for availability checking
_MECH_DISPLAY: dict[int, str] = {
    CKM_SHA224_RSA_PKCS: "SHA224_RSA_PKCS",
    CKM_SHA256_RSA_PKCS: "SHA256_RSA_PKCS",
    CKM_SHA384_RSA_PKCS: "SHA384_RSA_PKCS",
    CKM_SHA512_RSA_PKCS: "SHA512_RSA_PKCS",
    CKM_SHA3_224_RSA_PKCS: "SHA3_224_RSA_PKCS",
    CKM_SHA3_256_RSA_PKCS: "SHA3_256_RSA_PKCS",
    CKM_SHA3_384_RSA_PKCS: "SHA3_384_RSA_PKCS",
    CKM_SHA3_512_RSA_PKCS: "SHA3_512_RSA_PKCS",
}

# Map hash names to PKCS#11 mechanisms
_RSA_HASH_MECHANISMS: dict[str, int] = {
    "SHA-224": CKM_SHA224_RSA_PKCS,
    "SHA-256": CKM_SHA256_RSA_PKCS,
    "SHA-384": CKM_SHA384_RSA_PKCS,
    "SHA-512": CKM_SHA512_RSA_PKCS,
    # SHA-3 (PKCS#11 v3.0+)
    "SHA3-224": CKM_SHA3_224_RSA_PKCS,
    "SHA3-256": CKM_SHA3_256_RSA_PKCS,
    "SHA3-384": CKM_SHA3_384_RSA_PKCS,
    "SHA3-512": CKM_SHA3_512_RSA_PKCS,
}

# All RSA signature vector files we want to test
_RSA_SIG_FILES = [
    "rsa_pkcs1_1024_sig_gen_test.json",
    "rsa_pkcs1_1536_sig_gen_test.json",
    "rsa_pkcs1_2048_sig_gen_test.json",
    "rsa_pkcs1_3072_sig_gen_test.json",
    "rsa_pkcs1_4096_sig_gen_test.json",
    "rsa_signature_2048_sha224_test.json",
    "rsa_signature_2048_sha256_test.json",
    "rsa_signature_2048_sha384_test.json",
    "rsa_signature_2048_sha512_test.json",
    "rsa_signature_2048_sha512_224_test.json",
    "rsa_signature_2048_sha512_256_test.json",
    "rsa_signature_3072_sha256_test.json",
    "rsa_signature_3072_sha384_test.json",
    "rsa_signature_3072_sha512_test.json",
    "rsa_signature_3072_sha512_256_test.json",
    "rsa_signature_4096_sha256_test.json",
    "rsa_signature_4096_sha384_test.json",
    "rsa_signature_4096_sha512_test.json",
    "rsa_signature_4096_sha512_256_test.json",
    # 8192-bit RSA (large key, slow)
    "rsa_signature_8192_sha256_test.json",
    "rsa_signature_8192_sha384_test.json",
    "rsa_signature_8192_sha512_test.json",
    # SHA-3 variants (PKCS#11 v3.0+)
    "rsa_signature_2048_sha3_224_test.json",
    "rsa_signature_2048_sha3_256_test.json",
    "rsa_signature_2048_sha3_384_test.json",
    "rsa_signature_2048_sha3_512_test.json",
    "rsa_signature_3072_sha3_256_test.json",
    "rsa_signature_3072_sha3_384_test.json",
    "rsa_signature_3072_sha3_512_test.json",
]


def _load_all_rsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load all RSA vectors with file name as identifier."""
    vectors = []
    for filename in _RSA_SIG_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        data = load_json_cached(path)
        for group in data["testGroups"]:
            sha = group.get("sha", "SHA-256")
            mechanism = _RSA_HASH_MECHANISMS.get(sha)
            if mechanism is None:
                continue
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_mechanism"] = mechanism
                test["_file"] = filename
                vectors.append((f"{filename}:tc{test['tcId']}-{test['result']}", test))
    _mark_pkcs11_duplicate_vectors(vectors)
    return vectors


_ALL_RSA_VECTORS = _load_all_rsa_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_RSA_VECTORS, ids=[v[0] for v in _ALL_RSA_VECTORS])
def test_rsa_wycheproof(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA PKCS#1 v1.5 signature verification from Wycheproof vectors."""
    rs = p11_module_session
    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    mechanism = vec["_mechanism"]
    group = vec["_group"]

    # Check mechanism availability
    mech_display = _MECH_DISPLAY.get(mechanism, f"0x{mechanism:08x}")
    if not rs.has_mechanism(mech_display):
        pytest.skip(f"{mech_display} not supported by module")

    if duplicate_of := vec.get("_pkcs11_duplicate_of"):
        pytest.skip(f"Duplicate PKCS#11 RSA operation input; covered by {duplicate_of}")

    pk = group.get("publicKey", group.get("privateKey", {}))
    modulus_hex = pk.get("modulus", "")
    exp_hex = pk.get("publicExponent", "")
    if not modulus_hex or not exp_hex:
        pytest.skip("No RSA public key in vector group")

    modulus = pkcs11_bigint_from_hex(modulus_hex)
    exponent = pkcs11_bigint_from_hex(exp_hex)
    key_bits = len(modulus) * 8
    set_params({"rsa_bits": str(key_bits), "hash": str(group.get("sha", ""))})

    if key_bits in _UNSUPPORTED_RSA_KEY_SIZES:
        classify(
            "not_operational",
            summary=not_operational_reason(
                f"{mech_display}:key-import",
                f"RSA {key_bits}-bit key import refused (cached)",
            ),
        )

    try:
        pub_key = import_rsa_public_key_negotiated(
            rs,
            n=modulus,
            e=exponent,
            attrs={CKA_VERIFY: True},
        )
    except CkrAssertionError as exc:
        # Only cache permanent key-size rejections, not transient errors.
        if is_known_error(exc, _RSA_PUBLIC_IMPORT_UNSUPPORTED_CKRS):
            _UNSUPPORTED_RSA_KEY_SIZES.add(key_bits)
            classify(
                "not_operational",
                summary=not_operational_reason(
                    f"{mech_display}:key-import",
                    f"RSA {key_bits}-bit: {ckr_name(exc.rv)}",
                ),
            )
        raise

    try:
        verified = verify_single(rs.raw, rs.sh, pub_key, mechanism, msg, sig)
        if result == "invalid":
            if verified:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label=vec_id,
                    summary=f"Invalid RSA sig {vec_id} accepted by module",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            return
        if result == "valid" and not verified:
            classify(
                "wrong_result",
                kind="crypto",
                label=vec_id,
                summary=f"Valid RSA sig {vec_id} rejected by module",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
    except CkrAssertionError as exc:
        if result == "valid":
            _classify_valid_verify_reject(
                exc,
                label=vec_id,
                summary=f"Valid RSA sig {vec_id} rejected: {exc}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        signature_rejected_or_xfail(exc, vec_id)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)
