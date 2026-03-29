"""ACVP RSA vector loading utilities.

Vector sources:
- RSA-SigGen-FIPS186-4: Signature generation (legacy)
- RSA-SigGen-FIPS186-5: Signature generation (current)
- RSA-SigVer-FIPS186-2: Signature verification (legacy)
- RSA-SigVer-FIPS186-4: Signature verification (FIPS 186-4)
- RSA-SigVer-FIPS186-5: Signature verification (FIPS 186-5)
"""

from __future__ import annotations

from typing import Any

from pkcs11_check.raw.types_std import (
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA3_224,
    CKG_MGF1_SHA3_256,
    CKG_MGF1_SHA3_384,
    CKG_MGF1_SHA3_512,
    CKG_MGF1_SHA224,
    CKG_MGF1_SHA256,
    CKG_MGF1_SHA384,
    CKG_MGF1_SHA512,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA3_224,
    CKM_SHA3_224_RSA_PKCS,
    CKM_SHA3_224_RSA_PKCS_PSS,
    CKM_SHA3_256,
    CKM_SHA3_256_RSA_PKCS,
    CKM_SHA3_256_RSA_PKCS_PSS,
    CKM_SHA3_384,
    CKM_SHA3_384_RSA_PKCS,
    CKM_SHA3_384_RSA_PKCS_PSS,
    CKM_SHA3_512,
    CKM_SHA3_512_RSA_PKCS,
    CKM_SHA3_512_RSA_PKCS_PSS,
    CKM_SHA224,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_SHA_1,
)
from pkcs11_check.testcases.data.acvp_loader import load_acvp_vectors

# ACVP hashAlg -> PKCS#1 v1.5 mechanism mapping
_HASH_TO_PKCS15_MECH: dict[str, tuple[Any, str]] = {
    "SHA-1": (CKM_SHA1_RSA_PKCS, "SHA1_RSA_PKCS"),
    "SHA2-224": (CKM_SHA224_RSA_PKCS, "SHA224_RSA_PKCS"),
    "SHA2-256": (CKM_SHA256_RSA_PKCS, "SHA256_RSA_PKCS"),
    "SHA2-384": (CKM_SHA384_RSA_PKCS, "SHA384_RSA_PKCS"),
    "SHA2-512": (CKM_SHA512_RSA_PKCS, "SHA512_RSA_PKCS"),
    "SHA3-224": (CKM_SHA3_224_RSA_PKCS, "SHA3_224_RSA_PKCS"),
    "SHA3-256": (CKM_SHA3_256_RSA_PKCS, "SHA3_256_RSA_PKCS"),
    "SHA3-384": (CKM_SHA3_384_RSA_PKCS, "SHA3_384_RSA_PKCS"),
    "SHA3-512": (CKM_SHA3_512_RSA_PKCS, "SHA3_512_RSA_PKCS"),
}

# ACVP hashAlg -> PSS mechanism mapping
_HASH_TO_PSS_MECH: dict[str, tuple[Any, str]] = {
    "SHA-1": (CKM_SHA1_RSA_PKCS_PSS, "SHA1_RSA_PKCS_PSS"),
    "SHA2-224": (CKM_SHA224_RSA_PKCS_PSS, "SHA224_RSA_PKCS_PSS"),
    "SHA2-256": (CKM_SHA256_RSA_PKCS_PSS, "SHA256_RSA_PKCS_PSS"),
    "SHA2-384": (CKM_SHA384_RSA_PKCS_PSS, "SHA384_RSA_PKCS_PSS"),
    "SHA2-512": (CKM_SHA512_RSA_PKCS_PSS, "SHA512_RSA_PKCS_PSS"),
    "SHA3-224": (CKM_SHA3_224_RSA_PKCS_PSS, "SHA3_224_RSA_PKCS_PSS"),
    "SHA3-256": (CKM_SHA3_256_RSA_PKCS_PSS, "SHA3_256_RSA_PKCS_PSS"),
    "SHA3-384": (CKM_SHA3_384_RSA_PKCS_PSS, "SHA3_384_RSA_PKCS_PSS"),
    "SHA3-512": (CKM_SHA3_512_RSA_PKCS_PSS, "SHA3_512_RSA_PKCS_PSS"),
}

# ACVP hashAlg -> hash mechanism for PSS params
_HASH_TO_HASH_MECH: dict[str, Any] = {
    "SHA-1": CKM_SHA_1,
    "SHA2-224": CKM_SHA224,
    "SHA2-256": CKM_SHA256,
    "SHA2-384": CKM_SHA384,
    "SHA2-512": CKM_SHA512,
    "SHA3-224": CKM_SHA3_224,
    "SHA3-256": CKM_SHA3_256,
    "SHA3-384": CKM_SHA3_384,
    "SHA3-512": CKM_SHA3_512,
}

# ACVP hashAlg -> MGF mapping
_HASH_TO_MGF: dict[str, int] = {
    "SHA-1": CKG_MGF1_SHA1,
    "SHA2-224": CKG_MGF1_SHA224,
    "SHA2-256": CKG_MGF1_SHA256,
    "SHA2-384": CKG_MGF1_SHA384,
    "SHA2-512": CKG_MGF1_SHA512,
    "SHA3-224": CKG_MGF1_SHA3_224,
    "SHA3-256": CKG_MGF1_SHA3_256,
    "SHA3-384": CKG_MGF1_SHA3_384,
    "SHA3-512": CKG_MGF1_SHA3_512,
}

# Maximum vectors per algorithm for speed
_MAX_VECTORS_PER_SET = 15


def load_siggen_pkcs15_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA-SigGen PKCS#1 v1.5 vectors from FIPS186-4 and FIPS186-5."""
    result: list[tuple[str, dict[str, Any]]] = []

    for algorithm in ["RSA-SigGen-FIPS186-4", "RSA-SigGen-FIPS186-5"]:
        raw = load_acvp_vectors(algorithm)

        for vec in raw:
            if len(result) >= _MAX_VECTORS_PER_SET:
                break

            group = vec["group"]
            inp = vec["input"]
            exp = vec["expected"]

            sig_type = group.get("sigType", "")
            if sig_type != "pkcs1v1.5":
                continue

            hash_alg = group.get("hashAlg", "")
            if hash_alg not in _HASH_TO_PKCS15_MECH:
                continue

            mech_int, mech_name = _HASH_TO_PKCS15_MECH[hash_alg]
            tc_id = inp.get("tcId", 0)
            message = bytes.fromhex(inp.get("message", ""))
            signature = bytes.fromhex(exp.get("signature", ""))
            n = bytes.fromhex(group.get("n", ""))
            e = bytes.fromhex(group.get("e", ""))
            modulo = group.get("modulo", 0)

            if not (message and signature and n and e):
                continue

            merged: dict[str, Any] = {
                "algorithm": algorithm,
                "tc_id": tc_id,
                "hash_alg": hash_alg,
                "mech_int": mech_int,
                "mech_name": mech_name,
                "message": message,
                "signature": signature,
                "n": n,
                "e": e,
                "modulo": modulo,
            }

            vec_id = f"{algorithm.split('-')[1]}-pkcs15-{hash_alg}-tc{tc_id}"
            result.append((vec_id, merged))

    return result


def load_siggen_pss_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA-SigGen PSS vectors from FIPS186-4 and FIPS186-5."""
    result: list[tuple[str, dict[str, Any]]] = []

    for algorithm in ["RSA-SigGen-FIPS186-4", "RSA-SigGen-FIPS186-5"]:
        raw = load_acvp_vectors(algorithm)

        for vec in raw:
            if len(result) >= _MAX_VECTORS_PER_SET:
                break

            group = vec["group"]
            inp = vec["input"]
            exp = vec["expected"]

            sig_type = group.get("sigType", "")
            if sig_type not in ("pss", "ansx9.31"):
                continue

            hash_alg = group.get("hashAlg", "")
            if hash_alg not in _HASH_TO_PSS_MECH:
                continue

            mech_int, mech_name = _HASH_TO_PSS_MECH[hash_alg]
            hash_mech = _HASH_TO_HASH_MECH.get(hash_alg)
            mgf = _HASH_TO_MGF.get(hash_alg)

            if hash_mech is None or mgf is None:
                continue

            tc_id = inp.get("tcId", 0)
            message = bytes.fromhex(inp.get("message", ""))
            signature = bytes.fromhex(exp.get("signature", ""))
            n = bytes.fromhex(group.get("n", ""))
            e = bytes.fromhex(group.get("e", ""))
            salt_len = group.get("saltLen", 0)
            modulo = group.get("modulo", 0)

            if not (message and signature and n and e):
                continue

            merged: dict[str, Any] = {
                "algorithm": algorithm,
                "tc_id": tc_id,
                "hash_alg": hash_alg,
                "mech_int": mech_int,
                "mech_name": mech_name,
                "hash_mech": hash_mech,
                "mgf": mgf,
                "salt_len": salt_len,
                "message": message,
                "signature": signature,
                "n": n,
                "e": e,
                "modulo": modulo,
            }

            vec_id = f"{algorithm.split('-')[1]}-pss-{hash_alg}-tc{tc_id}"
            result.append((vec_id, merged))

    return result


def load_sigver_pkcs15_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA-SigVer PKCS#1 v1.5 vectors from FIPS186-2, FIPS186-4, FIPS186-5."""
    result: list[tuple[str, dict[str, Any]]] = []

    for algorithm in ["RSA-SigVer-FIPS186-2", "RSA-SigVer-FIPS186-4", "RSA-SigVer-FIPS186-5"]:
        raw = load_acvp_vectors(algorithm)

        count = 0
        for vec in raw:
            if count >= _MAX_VECTORS_PER_SET:
                break

            group = vec["group"]
            inp = vec["input"]
            exp = vec["expected"]

            sig_type = group.get("sigType", "")
            if sig_type != "pkcs1v1.5":
                continue

            hash_alg = group.get("hashAlg", "")
            if hash_alg not in _HASH_TO_PKCS15_MECH:
                continue

            mech_int, mech_name = _HASH_TO_PKCS15_MECH[hash_alg]
            tc_id = inp.get("tcId", 0)
            message = bytes.fromhex(inp.get("message", ""))
            signature = bytes.fromhex(inp.get("signature", ""))
            n = bytes.fromhex(group.get("n", ""))
            e = bytes.fromhex(group.get("e", ""))
            expected_pass = exp.get("testPassed", True)
            modulo = group.get("modulo", 0)

            if not (message and signature and n and e):
                continue

            merged: dict[str, Any] = {
                "algorithm": algorithm,
                "tc_id": tc_id,
                "hash_alg": hash_alg,
                "mech_int": mech_int,
                "mech_name": mech_name,
                "message": message,
                "signature": signature,
                "n": n,
                "e": e,
                "expected_pass": expected_pass,
                "modulo": modulo,
            }

            vec_id = f"{algorithm.split('-')[1]}-pkcs15-ver-{hash_alg}-tc{tc_id}"
            result.append((vec_id, merged))
            count += 1

    return result


def load_sigver_pss_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA-SigVer PSS vectors from FIPS186-2, FIPS186-4, FIPS186-5."""
    result: list[tuple[str, dict[str, Any]]] = []

    for algorithm in ["RSA-SigVer-FIPS186-2", "RSA-SigVer-FIPS186-4", "RSA-SigVer-FIPS186-5"]:
        raw = load_acvp_vectors(algorithm)

        count = 0
        for vec in raw:
            if count >= _MAX_VECTORS_PER_SET:
                break

            group = vec["group"]
            inp = vec["input"]
            exp = vec["expected"]

            sig_type = group.get("sigType", "")
            if sig_type not in ("pss", "ansx9.31"):
                continue

            hash_alg = group.get("hashAlg", "")
            if hash_alg not in _HASH_TO_PSS_MECH:
                continue

            mech_int, mech_name = _HASH_TO_PSS_MECH[hash_alg]
            hash_mech = _HASH_TO_HASH_MECH.get(hash_alg)
            mgf = _HASH_TO_MGF.get(hash_alg)

            if hash_mech is None or mgf is None:
                continue

            tc_id = inp.get("tcId", 0)
            message = bytes.fromhex(inp.get("message", ""))
            signature = bytes.fromhex(inp.get("signature", ""))
            n = bytes.fromhex(group.get("n", ""))
            e = bytes.fromhex(group.get("e", ""))
            expected_pass = exp.get("testPassed", True)
            salt_len = group.get("saltLen", 0)
            modulo = group.get("modulo", 0)

            if not (message and signature and n and e):
                continue

            merged: dict[str, Any] = {
                "algorithm": algorithm,
                "tc_id": tc_id,
                "hash_alg": hash_alg,
                "mech_int": mech_int,
                "mech_name": mech_name,
                "hash_mech": hash_mech,
                "mgf": mgf,
                "salt_len": salt_len,
                "message": message,
                "signature": signature,
                "n": n,
                "e": e,
                "expected_pass": expected_pass,
                "modulo": modulo,
            }

            vec_id = f"{algorithm.split('-')[1]}-pss-ver-{hash_alg}-tc{tc_id}"
            result.append((vec_id, merged))
            count += 1

    return result
