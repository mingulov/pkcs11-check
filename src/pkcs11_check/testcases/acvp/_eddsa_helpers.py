"""EdDSA ACVP test helpers - shared utilities for EdDSA ACVP tests.

This module contains helper functions for loading and processing
NIST ACVP EdDSA test vectors.
"""

from __future__ import annotations

from typing import Any

from pkcs11_check.testcases.acvp._duplicates import mark_duplicate_pkcs11_inputs
from pkcs11_check.testcases.acvp.acvp_loader import load_acvp_vectors
from pkcs11_check.testcases.data import ACVP_DIR, load_json_cached

# OID for Ed25519 (1.3.101.112) and Ed448 (1.3.101.113)
_ED25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
_ED448_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x71])

# ACVP curve name -> (EC_PARAMS OID bytes, pk_len, sig_len)
CURVE_MAP: dict[str, tuple[bytes, int, int]] = {
    "ED-25519": (_ED25519_OID, 32, 64),
    "ED-448": (_ED448_OID, 57, 114),
}


def load_eddsa_keygen_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load EdDSA KeyGen ACVP vectors for Ed25519 and Ed448.

    Uses internalProjection.json which contains the expected private key (d)
    and public key (q) for deterministic key generation testing.
    Limits to 10 vectors for speed.
    """
    keygen_dir = ACVP_DIR / "EDDSA-KeyGen-1.0"
    internal_file = keygen_dir / "internalProjection.json"
    if not internal_file.exists():
        return []

    data = load_json_cached(internal_file)

    result: list[tuple[str, dict[str, Any]]] = []

    for tg in data.get("testGroups", []):
        curve_name = tg.get("curve", "")
        if curve_name not in CURVE_MAP:
            continue

        oid, pk_len, _ = CURVE_MAP[curve_name]

        for test in tg.get("tests", []):
            tc_id = test.get("tcId", 0)
            d_hex = test.get("d", "")
            q_hex = test.get("q", "")

            if not d_hex or not q_hex:
                continue

            try:
                d_bytes = bytes.fromhex(d_hex)
                q_bytes = bytes.fromhex(q_hex)
            except ValueError:
                continue

            if len(q_bytes) != pk_len:
                continue

            merged: dict[str, Any] = {
                "curve": curve_name,
                "ec_params": oid,
                "d": d_bytes,
                "q": q_bytes,
                "ec_point": q_bytes,
                "tc_id": tc_id,
            }
            vec_id = f"EDDSA-KeyGen-{curve_name}-tc{tc_id}"
            result.append((vec_id, merged))

            if len(result) >= 10:
                return mark_duplicate_pkcs11_inputs(result, lambda item: item["ec_params"])

    return mark_duplicate_pkcs11_inputs(result, lambda item: item["ec_params"])


def load_eddsa_keyver_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load EdDSA KeyVer ACVP vectors for Ed25519 and Ed448.

    Key verification tests check if a public key is valid on the curve.
    The expected results indicate whether the key should pass validation.
    Limits to 10 vectors for speed.
    """
    all_vecs = load_acvp_vectors("EDDSA-KeyVer-1.0")
    result: list[tuple[str, dict[str, Any]]] = []

    for vec in all_vecs:
        group = vec["group"]
        inp = vec["input"]
        exp = vec["expected"]

        curve_name = group.get("curve", "")
        if curve_name not in CURVE_MAP:
            continue

        tc_id = inp.get("tcId", 0)
        q_hex = inp.get("q", "")
        expected_pass = exp.get("testPassed", True)

        if not q_hex:
            continue

        oid, pk_len, _ = CURVE_MAP[curve_name]
        try:
            q_bytes = bytes.fromhex(q_hex)
        except ValueError:
            continue

        if len(q_bytes) != pk_len:
            continue

        merged: dict[str, Any] = {
            "curve": curve_name,
            "ec_params": oid,
            "q": q_bytes,
            "ec_point": q_bytes,
            "expected_pass": expected_pass,
            "tc_id": tc_id,
        }
        vec_id = f"EDDSA-KeyVer-{curve_name}-tc{tc_id}"
        result.append((vec_id, merged))

        if len(result) >= 10:
            break

    return result


def load_eddsa_sigver_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load EdDSA SigVer ACVP vectors for Ed25519 and Ed448.

    Limits to 15 total vectors (mix of valid and invalid) for speed.
    Only pure EdDSA (preHash=False) vectors are included, since
    CKM_EDDSA in PKCS#11 3.0+ maps to the non-prehash variant.
    """
    all_vecs = load_acvp_vectors("EDDSA-SigVer-1.0")
    result: list[tuple[str, dict[str, Any]]] = []

    for vec in all_vecs:
        group = vec["group"]
        inp = vec["input"]
        exp = vec["expected"]

        curve_name = group.get("curve", "")
        pre_hash = group.get("preHash", False)

        if curve_name not in CURVE_MAP:
            continue
        if pre_hash:
            # CKM_EDDSA is pure EdDSA (no pre-hashing); skip prehash variants
            continue

        q_hex = inp.get("q", "")
        sig_hex = inp.get("signature", "")
        msg_hex = inp.get("message", "")
        tc_id = inp.get("tcId", 0)
        expected_pass = exp.get("testPassed", True)

        if not (q_hex and sig_hex and msg_hex):
            continue

        oid, pk_len, _ = CURVE_MAP[curve_name]
        try:
            q_bytes = bytes.fromhex(q_hex)
            sig_bytes = bytes.fromhex(sig_hex)
            msg_bytes = bytes.fromhex(msg_hex)
        except ValueError:
            continue

        if len(q_bytes) != pk_len:
            continue

        merged: dict[str, Any] = {
            "curve": curve_name,
            "ec_params": oid,
            "q": q_bytes,
            "ec_point": q_bytes,
            "msg": msg_bytes,
            "sig": sig_bytes,
            "expected_pass": expected_pass,
            "tc_id": tc_id,
        }
        vec_id = f"EDDSA-SigVer-{curve_name}-tc{tc_id}"
        result.append((vec_id, merged))

        if len(result) >= 15:
            break

    return result


def load_eddsa_siggen_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load Ed25519 SigGen ACVP vectors from internalProjection.json.

    The standard ACVP prompt.json for SigGen does not expose the private key.
    The internalProjection.json file contains the private key seed (d) at the
    test-group level, along with the public key (q) and expected signatures.

    Only pure Ed25519 vectors (preHash=False, contextLength=0, no context)
    are included. Ed25519 is deterministic (RFC 8032), so exact signature
    comparison is valid. Limit to 5 vectors for speed.
    """
    siggen_dir = ACVP_DIR / "EDDSA-SigGen-1.0"
    internal_file = siggen_dir / "internalProjection.json"
    if not internal_file.exists():
        return []

    data = load_json_cached(internal_file)

    result: list[tuple[str, dict[str, Any]]] = []

    for tg in data.get("testGroups", []):
        curve = tg.get("curve", "")
        pre_hash = tg.get("preHash", False)
        context_length = tg.get("contextLength", 0)

        # Only plain Ed25519: no prehash, no context
        if curve != "ED-25519":
            continue
        if pre_hash:
            continue
        if context_length != 0:
            continue

        d_hex = tg.get("d", "")
        q_hex = tg.get("q", "")
        if not d_hex or not q_hex:
            continue

        try:
            d_bytes = bytes.fromhex(d_hex)
            q_bytes = bytes.fromhex(q_hex)
        except ValueError:
            continue

        if len(d_bytes) != 32 or len(q_bytes) != 32:
            continue

        for test in tg.get("tests", []):
            tc_id = test.get("tcId", 0)
            msg_hex = test.get("message", "")
            sig_hex = test.get("signature", "")
            ctx = test.get("context", "")

            # Only include tests with no context
            if ctx:
                continue
            if not msg_hex or not sig_hex:
                continue

            try:
                msg_bytes = bytes.fromhex(msg_hex)
                expected_sig = bytes.fromhex(sig_hex)
            except ValueError:
                continue

            merged: dict[str, Any] = {
                "d": d_bytes,
                "q": q_bytes,
                "ec_params": _ED25519_OID,
                "ec_point": q_bytes,
                "msg": msg_bytes,
                "expected_sig": expected_sig,
                "tc_id": tc_id,
            }
            vec_id = f"EDDSA-SigGen-ED-25519-tc{tc_id}"
            result.append((vec_id, merged))

            if len(result) >= 5:
                return result

    return result
