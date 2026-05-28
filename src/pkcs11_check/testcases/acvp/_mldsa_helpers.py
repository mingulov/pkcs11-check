"""ML-DSA ACVP test helpers - shared utilities for ML-DSA ACVP tests.

This module contains helper functions for loading and processing
NIST ACVP ML-DSA test vectors (FIPS 204).
"""

from __future__ import annotations

import json
from typing import Any

from pkcs11_check.raw.types_std import (
    CKM,
    CKM_HASH_ML_DSA_SHA3_224,
    CKM_HASH_ML_DSA_SHA3_256,
    CKM_HASH_ML_DSA_SHA3_384,
    CKM_HASH_ML_DSA_SHA3_512,
    CKM_HASH_ML_DSA_SHA224,
    CKM_HASH_ML_DSA_SHA256,
    CKM_HASH_ML_DSA_SHA384,
    CKM_HASH_ML_DSA_SHA512,
    CKM_HASH_ML_DSA_SHAKE128,
    CKM_HASH_ML_DSA_SHAKE256,
    CKM_ML_DSA,
    CKP_ML_DSA_44,
    CKP_ML_DSA_65,
    CKP_ML_DSA_87,
)
from pkcs11_check.testcases.acvp._duplicates import mark_duplicate_pkcs11_inputs
from pkcs11_check.testcases.acvp.acvp_loader import load_acvp_vectors
from pkcs11_check.testcases.data import ACVP_DIR

# Parameter set mapping
_ML_DSA_PARAM_MAP: dict[str, int] = {
    "ML-DSA-44": int(CKP_ML_DSA_44),
    "ML-DSA-65": int(CKP_ML_DSA_65),
    "ML-DSA-87": int(CKP_ML_DSA_87),
}

# Pre-hash to hash-specific ML-DSA mechanism mapping
# Per OASIS PKCS#11 v3.2 spec and FIPS 204, only these hash functions
# are valid for Hash-ML-DSA. SHA-512/224 and SHA-512/256 are NOT supported.
_SUPPORTED_MLDSA_HASH_ALGS: frozenset[str] = frozenset(
    {
        "SHA2-224",
        "SHA2-256",
        "SHA2-384",
        "SHA2-512",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "SHAKE-128",
        "SHAKE-256",
        "none",  # ACVP uses "none" for non-prehashed (same as "pure")
    }
)
_HASH_ML_DSA_MECHANISMS: dict[str, CKM] = {
    "SHA-224": CKM_HASH_ML_DSA_SHA224,
    "SHA-256": CKM_HASH_ML_DSA_SHA256,
    "SHA-384": CKM_HASH_ML_DSA_SHA384,
    "SHA-512": CKM_HASH_ML_DSA_SHA512,
    "SHA3-224": CKM_HASH_ML_DSA_SHA3_224,
    "SHA3-256": CKM_HASH_ML_DSA_SHA3_256,
    "SHA3-384": CKM_HASH_ML_DSA_SHA3_384,
    "SHA3-512": CKM_HASH_ML_DSA_SHA3_512,
    "SHAKE128": CKM_HASH_ML_DSA_SHAKE128,
    "SHAKE256": CKM_HASH_ML_DSA_SHAKE256,
}


def get_mldsa_mechanism(pre_hash: str = "pure") -> CKM:
    """Get the ML-DSA mechanism for a pre-hash mode.

    Per OASIS PKCS#11 v3.2 spec:
    - Pure ML-DSA uses CKM_ML_DSA mechanism with CKA_PARAMETER_SET attribute
    - Hash-ML-DSA uses hash-specific mechanisms (CKM_HASH_ML_DSA_SHA256, etc.)

    Args:
        pre_hash: Pre-hash mode ("pure", "none", or hash algorithm name)

    Returns:
        The CKM_ML_DSA or CKM_HASH_ML_DSA_* mechanism constant
    """
    if pre_hash in ("pure", "none"):
        return CKM_ML_DSA

    # Normalize ACVP hash names to PKCS#11 mechanism names
    # ACVP: "SHA2-256" -> PKCS#11: "SHA-256"
    # ACVP: "SHAKE-256" -> PKCS#11: "SHAKE256"
    normalized = pre_hash
    normalized = normalized.replace("SHA2-", "SHA-")
    normalized = normalized.replace("SHAKE-", "SHAKE")

    if normalized in _HASH_ML_DSA_MECHANISMS:
        return _HASH_ML_DSA_MECHANISMS[normalized]
    raise ValueError(f"Unknown pre-hash mode: {pre_hash} (normalized: {normalized})")


def _load_internal_vectors(algorithm: str) -> list[tuple[str, dict[str, Any]]]:
    """Load internalProjection.json for sigGen vectors."""
    vec_dir = ACVP_DIR / algorithm
    internal_file = vec_dir / "internalProjection.json"
    if not internal_file.exists():
        return []

    with open(internal_file) as f:
        data = json.load(f)

    result: list[tuple[str, dict[str, Any]]] = []
    for tg in data.get("testGroups", []):
        param_set = tg.get("parameterSet", "")
        if param_set not in _ML_DSA_PARAM_MAP:
            continue

        for test in tg.get("tests", []):
            tc_id = test.get("tcId", 0)
            msg_hex = test.get("message", "")
            sig_hex = test.get("signature", "")
            ctx_hex = test.get("context", "")
            sk_hex = test.get("sk", "")
            pk_hex = test.get("pk", "")

            if not msg_hex or not sig_hex or not sk_hex:
                continue

            # Skip unsupported hash algorithms (e.g. SHA2-512/224, SHA2-512/256)
            # not defined by PKCS#11 v3.2 or FIPS 204 for Hash-ML-DSA
            test_hash_alg = test.get("hashAlg", "")
            if test_hash_alg and test_hash_alg not in _SUPPORTED_MLDSA_HASH_ALGS:
                continue

            try:
                msg_bytes = bytes.fromhex(msg_hex)
                sig_bytes = bytes.fromhex(sig_hex)
                ctx_bytes = bytes.fromhex(ctx_hex) if ctx_hex else b""
            except ValueError:
                continue

            vec_data: dict[str, Any] = {
                "param_set": param_set,
                "parameter_set": _ML_DSA_PARAM_MAP[param_set],
                "tc_id": tc_id,
                "msg": msg_bytes,
                "expected_sig": sig_bytes,
                "context": ctx_bytes,
                "pre_hash": tg.get("preHash", "pure"),
                "hash_alg": test.get("hashAlg", ""),
            }

            # Add key material from test level
            try:
                vec_data["sk"] = bytes.fromhex(sk_hex)
            except ValueError:
                pass
            if pk_hex:
                try:
                    vec_data["pk"] = bytes.fromhex(pk_hex)
                except ValueError:
                    pass

            vec_id = f"ML-DSA-sigGen-{param_set}-tc{tc_id}"
            result.append((vec_id, vec_data))

    return result


def load_mldsa_keygen_vectors(limit: int | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Load ML-DSA KeyGen ACVP vectors.

    Uses internalProjection.json which contains the expected key pairs
    for deterministic key generation testing.
    """
    keygen_dir = ACVP_DIR / "ML-DSA-keyGen-FIPS204"
    internal_file = keygen_dir / "internalProjection.json"
    if not internal_file.exists():
        return []

    with open(internal_file) as f:
        data = json.load(f)

    result: list[tuple[str, dict[str, Any]]] = []

    for tg in data.get("testGroups", []):
        param_set = tg.get("parameterSet", "")
        if param_set not in _ML_DSA_PARAM_MAP:
            continue

        for test in tg.get("tests", []):
            tc_id = test.get("tcId", 0)
            pk_hex = test.get("pk", "")
            sk_hex = test.get("sk", "")
            seed_hex = test.get("seed", "")

            if not pk_hex or not sk_hex or not seed_hex:
                continue

            try:
                pk_bytes = bytes.fromhex(pk_hex)
                sk_bytes = bytes.fromhex(sk_hex)
                seed_bytes = bytes.fromhex(seed_hex)
            except ValueError:
                continue

            vec_data: dict[str, Any] = {
                "param_set": param_set,
                "parameter_set": _ML_DSA_PARAM_MAP[param_set],
                "tc_id": tc_id,
                "pk": pk_bytes,
                "sk": sk_bytes,
                "seed": seed_bytes,
            }
            vec_id = f"ML-DSA-keyGen-{param_set}-tc{tc_id}"
            result.append((vec_id, vec_data))

            if limit is not None and len(result) >= limit:
                return mark_duplicate_pkcs11_inputs(result, lambda item: item["parameter_set"])

    return mark_duplicate_pkcs11_inputs(result, lambda item: item["parameter_set"])


def load_mldsa_siggen_vectors(limit: int | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Load ML-DSA SigGen ACVP vectors.

    Uses internalProjection.json which contains the private key and
    expected signatures for deterministic signature generation testing.
    """
    all_vecs = _load_internal_vectors("ML-DSA-sigGen-FIPS204")
    if limit is None:
        return all_vecs
    return all_vecs[:limit]


def load_mldsa_sigver_vectors(limit: int | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Load ML-DSA SigVer ACVP vectors.

    Loads from prompt.json and expectedResults.json.
    Each test contains a public key, message, signature, and expected result.
    """
    all_vecs = load_acvp_vectors("ML-DSA-sigVer-FIPS204")
    result: list[tuple[str, dict[str, Any]]] = []

    for vec in all_vecs:
        group = vec["group"]
        inp = vec["input"]
        exp = vec["expected"]

        param_set = group.get("parameterSet", "")
        if param_set not in _ML_DSA_PARAM_MAP:
            continue

        # PKCS#11 v3.2 only exposes the *external* ML-DSA Verify (CKM_ML_DSA /
        # CKM_HASH_ML_DSA_*), which constructs M' from (M, ctx) internally per
        # FIPS 204 Algorithm 3. ACVP's signatureInterface="internal" groups
        # (Sign_internal/Verify_internal, FIPS 204 Algorithm 8) deliver a
        # pre-formatted message or a precomputed mu — neither is representable
        # through PKCS#11, so feeding them to CKM_ML_DSA would wrap them again
        # and (correctly) fail to verify a mathematically-valid signature.
        if group.get("signatureInterface") == "internal":
            continue

        # Skip unsupported hash algorithms (e.g. SHA2-512/224, SHA2-512/256)
        # not defined by PKCS#11 v3.2 or FIPS 204 for Hash-ML-DSA
        hash_alg = inp.get("hashAlg", "")
        if hash_alg and hash_alg not in _SUPPORTED_MLDSA_HASH_ALGS:
            continue

        tc_id = inp.get("tcId", 0)
        pk_hex = inp.get("pk", "")
        msg_hex = inp.get("message", "")
        sig_hex = inp.get("signature", "")
        ctx_hex = inp.get("context", "")
        expected_pass = exp.get("testPassed", True)

        if not (pk_hex and msg_hex and sig_hex):
            continue

        try:
            pk_bytes = bytes.fromhex(pk_hex)
            msg_bytes = bytes.fromhex(msg_hex)
            sig_bytes = bytes.fromhex(sig_hex)
            ctx_bytes = bytes.fromhex(ctx_hex) if ctx_hex else b""
        except ValueError:
            continue

        vec_data: dict[str, Any] = {
            "param_set": param_set,
            "parameter_set": _ML_DSA_PARAM_MAP[param_set],
            "tc_id": tc_id,
            "pk": pk_bytes,
            "msg": msg_bytes,
            "sig": sig_bytes,
            "context": ctx_bytes,
            "expected_pass": expected_pass,
            "pre_hash": group.get("preHash", "pure"),
            "hash_alg": inp.get("hashAlg", ""),
        }
        vec_id = f"ML-DSA-sigVer-{param_set}-tc{tc_id}"
        result.append((vec_id, vec_data))

        if limit is not None and len(result) >= limit:
            break

    return result
