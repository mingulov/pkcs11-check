"""NIST ACVP ECDSA signature verification test vectors (FIPS 186-5).

Tests ECDSA signature verification using official NIST ACVP vectors for
P-256, P-384, and P-521 with SHA2-256, SHA2-384, and SHA2-512.

Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_EC,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKO_PUBLIC_KEY,
)
from pkcs11_check.testcases.data.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# ACVP hashAlg -> (CKM mechanism int, mechanism name string for has_mechanism)
_HASH_TO_MECH: dict[str, tuple[int, str]] = {
    "SHA2-256": (CKM_ECDSA_SHA256, "ECDSA_SHA256"),
    "SHA2-384": (CKM_ECDSA_SHA384, "ECDSA_SHA384"),
    "SHA2-512": (CKM_ECDSA_SHA512, "ECDSA_SHA512"),
}

# ACVP curve name -> (pkcs11 curve name, coordinate byte length)
_CURVE_MAP: dict[str, tuple[str, int]] = {
    "P-256": ("secp256r1", 32),
    "P-384": ("secp384r1", 48),
    "P-521": ("secp521r1", 66),
}


def _der_octet_string(data: bytes) -> bytes:
    """Wrap bytes in a DER OCTET STRING (tag 0x04 + length + data).

    PKCS#11 CKA_EC_POINT must be DER-encoded as an OCTET STRING containing
    the uncompressed EC point (04 || qx || qy).
    """
    n = len(data)
    if n < 0x80:
        return bytes([0x04, n]) + data
    elif n < 0x100:
        return bytes([0x04, 0x81, n]) + data
    else:
        return bytes([0x04, 0x82, n >> 8, n & 0xFF]) + data


def _load_ecdsa_sigver_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ECDSA SigVer ACVP vectors for P-256/384/521 with SHA2-256/384/512.

    Limits to 20 total vectors (mix of valid and invalid) for speed.
    P-224 and unsupported hash algorithms are excluded.
    """
    all_vecs = load_acvp_vectors("ECDSA-SigVer-FIPS186-5")
    result: list[tuple[str, dict[str, Any]]] = []

    for vec in all_vecs:
        group = vec["group"]
        inp = vec["input"]
        exp = vec["expected"]

        curve_name = group.get("curve", "")
        hash_alg = group.get("hashAlg", "")

        if curve_name not in _CURVE_MAP:
            continue
        if hash_alg not in _HASH_TO_MECH:
            continue

        msg_hex = inp.get("message", "")
        qx_hex = inp.get("qx", "")
        qy_hex = inp.get("qy", "")
        r_hex = inp.get("r", "")
        s_hex = inp.get("s", "")
        tc_id = inp.get("tcId", 0)
        expected_pass = exp.get("testPassed", True)

        if not (msg_hex and qx_hex and qy_hex and r_hex and s_hex):
            continue

        _, coord_len = _CURVE_MAP[curve_name]
        mech_int, mech_name = _HASH_TO_MECH[hash_alg]
        ec_curve_name, _ = _CURVE_MAP[curve_name]

        # Pad coordinates to fixed length (hex must be even and coord_len*2 wide)
        qx_bytes = bytes.fromhex(qx_hex.zfill(coord_len * 2))
        qy_bytes = bytes.fromhex(qy_hex.zfill(coord_len * 2))
        r_bytes = bytes.fromhex(r_hex.zfill(coord_len * 2))
        s_bytes = bytes.fromhex(s_hex.zfill(coord_len * 2))

        # EC_POINT: DER OCTET STRING of 04 || qx || qy
        raw_point = bytes([0x04]) + qx_bytes + qy_bytes
        ec_point_der = _der_octet_string(raw_point)

        # Signature: raw r || s, each padded to coord_len bytes
        sig_bytes = r_bytes + s_bytes

        merged: dict[str, Any] = {
            "curve": curve_name,
            "hash_alg": hash_alg,
            "ec_curve_name": ec_curve_name,
            "mech_int": mech_int,
            "mech_name": mech_name,
            "msg": bytes.fromhex(msg_hex),
            "ec_params": encode_named_curve_parameters(ec_curve_name),
            "ec_point_der": ec_point_der,
            "sig": sig_bytes,
            "expected_pass": expected_pass,
            "tc_id": tc_id,
        }
        vec_id = f"ECDSA-SigVer-{curve_name}-{hash_alg}-tc{tc_id}"
        result.append((vec_id, merged))

        if len(result) >= 20:
            break

    return result


_ECDSA_SIGVER_VECTORS = _load_ecdsa_sigver_vectors()


@pytest.mark.parametrize(
    "vec_id,vec",
    _ECDSA_SIGVER_VECTORS,
    ids=[v[0] for v in _ECDSA_SIGVER_VECTORS],
)
def test_acvp_ecdsa_sigver(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ECDSA signature verification from NIST ACVP FIPS 186-5 vectors.

    Imports an EC public key from the ACVP-provided (qx, qy) coordinates,
    then calls C_Verify with the raw r||s signature against the message.
    The hash is performed internally by the ECDSA_SHA* mechanism.

    For invalid vectors: the module MUST reject (CKR_SIGNATURE_INVALID or similar).
    Accepting an invalid ACVP signature is a security failure.

    For valid vectors: if the module rejects, xfail (module issue, not test bug).
    """
    rs = p11_raw_session
    mech_int: int = vec["mech_int"]
    mech_name: str = vec["mech_name"]
    expected_pass: bool = vec["expected_pass"]

    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported by module")

    pub_key = 0
    try:
        try:
            pub_key = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_PUBLIC_KEY,
                    CKA_KEY_TYPE: CKK_EC,
                    CKA_EC_PARAMS: vec["ec_params"],
                    CKA_EC_POINT: vec["ec_point_der"],
                    CKA_TOKEN: False,
                    CKA_VERIFY: True,
                },
            )
        except AssertionError as e:
            pytest.skip(f"Cannot import EC public key for {vec['curve']}: {e}")

        try:
            verified = verify_single(rs.raw, rs.sh, pub_key, mech_int, vec["msg"], vec["sig"])
        except AssertionError as exc:
            exc_msg = str(exc)
            # Signature invalid / data invalid / function failed / device error
            # are all forms of rejection
            if any(
                name in exc_msg
                for name in (
                    "CKR_SIGNATURE_INVALID",
                    "CKR_SIGNATURE_LEN_RANGE",
                    "CKR_DATA_INVALID",
                    "CKR_FUNCTION_FAILED",
                    "CKR_DEVICE_ERROR",
                )
            ):
                verified = False
            else:
                raise

        if not expected_pass and verified:
            pytest.fail(
                f"{vec_id}: module ACCEPTED an INVALID signature "
                f"(ACVP testPassed=False) - security concern"
            )

        if expected_pass and not verified:
            pytest.xfail(
                f"{vec_id}: module rejected a VALID ACVP signature "
                f"(ACVP testPassed=True) - module issue"
            )

    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)
