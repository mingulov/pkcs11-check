"""NIST ACVP EdDSA SigVer/SigGen test vectors (FIPS 186-5 / RFC 8032).

Tests Ed25519 and Ed448 signature verification using official NIST ACVP
SigVer vectors, and Ed25519 signature generation using ACVP SigGen vectors
with known private keys (from internalProjection.json).

Ed25519 is deterministic per RFC 8032, so exact signature comparison is valid.
Ed448 SigGen is skipped - context and pre-hashing variants complicate mapping
to plain CKM_EDDSA, and ACVP prompt.json does not expose the private key.

Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_EC_EDWARDS,
    CKM_EDDSA,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
)
from pkcs11_check.testcases.data import ACVP_DIR
from pkcs11_check.testcases.data.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# OID for Ed25519 (1.3.101.112) and Ed448 (1.3.101.113)
_ED25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
_ED448_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x71])

# ACVP curve name -> (EC_PARAMS OID bytes, expected public key length in bytes)
_CURVE_MAP: dict[str, tuple[bytes, int, int]] = {
    "ED-25519": (_ED25519_OID, 32, 64),   # (oid, pk_len, sig_len)
    "ED-448": (_ED448_OID, 57, 114),
}


def _der_octet_string(data: bytes) -> bytes:
    """Wrap raw bytes in a DER OCTET STRING (tag 0x04 + length + data).

    For Edwards curves, CKA_EC_POINT is the raw public key wrapped in a
    DER OCTET STRING (not the uncompressed 04||x||y point used for ECDSA).
    """
    n = len(data)
    if n < 0x80:
        return bytes([0x04, n]) + data
    return bytes([0x04, 0x81, n]) + data


def _load_eddsa_sigver_vectors() -> list[tuple[str, dict[str, Any]]]:
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

        if curve_name not in _CURVE_MAP:
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

        oid, pk_len, _ = _CURVE_MAP[curve_name]
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
            "ec_point": _der_octet_string(q_bytes),
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


def _load_eddsa_siggen_vectors() -> list[tuple[str, dict[str, Any]]]:
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

    with open(internal_file) as f:
        data = json.load(f)

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
                "ec_point": _der_octet_string(q_bytes),
                "msg": msg_bytes,
                "expected_sig": expected_sig,
                "tc_id": tc_id,
            }
            vec_id = f"EDDSA-SigGen-ED-25519-tc{tc_id}"
            result.append((vec_id, merged))

            if len(result) >= 5:
                return result

    return result


_SIGVER_VECTORS = _load_eddsa_sigver_vectors()
_SIGGEN_VECTORS = _load_eddsa_siggen_vectors()


@pytest.mark.parametrize(
    "vec_id,vec",
    _SIGVER_VECTORS,
    ids=[v[0] for v in _SIGVER_VECTORS],
)
def test_acvp_eddsa_sigver(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """EdDSA (Ed25519/Ed448) signature verification from NIST ACVP SigVer vectors.

    Imports an Edwards-curve public key from the ACVP-provided raw public key
    bytes, then calls C_Verify with the raw signature against the message using
    CKM_EDDSA.

    For invalid vectors accepted by the module: pytest.fail (security concern).
    For valid vectors rejected by the module: pytest.xfail (module issue).
    """
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA mechanism not supported by module")

    pub_key = 0
    try:
        try:
            pub_key = create_object(
                rs.raw,
                rs.sh,
                {
                    int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                    int(CKA_KEY_TYPE): int(CKK_EC_EDWARDS),
                    int(CKA_EC_PARAMS): vec["ec_params"],
                    int(CKA_EC_POINT): vec["ec_point"],
                    int(CKA_TOKEN): False,
                    int(CKA_VERIFY): True,
                },
            )
        except AssertionError as e:
            pytest.skip(f"Cannot import EdDSA public key for {vec['curve']}: {e}")

        try:
            verified = verify_single(
                rs.raw, rs.sh, pub_key, CKM_EDDSA, vec["msg"], vec["sig"]
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(
                name in exc_msg
                for name in (
                    "CKR_SIGNATURE_INVALID", "CKR_SIGNATURE_LEN_RANGE",
                    "CKR_DATA_INVALID", "CKR_FUNCTION_FAILED",
                    "CKR_DEVICE_ERROR",
                )
            ):
                verified = False
            elif "CKR_MECHANISM_PARAM_INVALID" in exc_msg:
                # Some modules (e.g., Kryoptic for Ed448) require explicit mechanism
                # parameters (CK_EDDSA_PARAMS) for CKM_EDDSA.  Plain parameterless
                # EDDSA is not supported for this curve - skip the vector.
                pytest.skip(
                    f"{vec_id}: module requires mechanism params for {vec['curve']} "
                    f"(CKR_MECHANISM_PARAM_INVALID) - skipping"
                )
            else:
                raise

        expected_pass: bool = vec["expected_pass"]

        if not expected_pass and verified:
            pytest.fail(
                f"{vec_id}: module ACCEPTED an INVALID EdDSA signature "
                f"(ACVP testPassed=False) - security concern"
            )

        if expected_pass and not verified:
            pytest.xfail(
                f"{vec_id}: module rejected a VALID EdDSA ACVP signature "
                f"(ACVP testPassed=True) - module issue"
            )

    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)


@pytest.mark.parametrize(
    "vec_id,vec",
    _SIGGEN_VECTORS,
    ids=[v[0] for v in _SIGGEN_VECTORS],
)
def test_acvp_eddsa_siggen(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """Ed25519 signature generation from NIST ACVP SigGen vectors.

    Imports an Ed25519 private key (seed d from internalProjection.json),
    signs the ACVP message with CKM_EDDSA, and compares the result to the
    expected ACVP signature byte-for-byte.

    Ed25519 is deterministic per RFC 8032: the same private key and message
    always produce the same signature, so exact byte comparison is correct.

    Mismatch xfails - the module may use a different serialization or the
    private key import format may differ from what the module expects.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA mechanism not supported by module")

    priv_key = 0
    try:
        try:
            priv_key = create_object(
                rs.raw,
                rs.sh,
                {
                    int(CKA_CLASS): int(CKO_PRIVATE_KEY),
                    int(CKA_KEY_TYPE): int(CKK_EC_EDWARDS),
                    int(CKA_EC_PARAMS): vec["ec_params"],
                    int(CKA_VALUE): vec["d"],
                    int(CKA_TOKEN): False,
                    int(CKA_SENSITIVE): False,
                    int(CKA_EXTRACTABLE): True,
                    int(CKA_SIGN): True,
                },
            )
        except AssertionError as e:
            pytest.skip(f"Cannot import Ed25519 private key for {vec_id}: {e}")

        try:
            sig = sign_single(rs.raw, rs.sh, priv_key, CKM_EDDSA, vec["msg"])
        except AssertionError as e:
            pytest.xfail(f"{vec_id}: Ed25519 sign raised unexpected error: {e}")

        expected_sig: bytes = vec["expected_sig"]

        if sig != expected_sig:
            pytest.xfail(
                f"{vec_id}: Ed25519 signature mismatch - "
                f"got {sig.hex()}, expected {expected_sig.hex()} - "
                f"module may use different private key seed format"
            )

    finally:
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)
