"""NIST ACVP HMAC test vectors - SHA-2, SHA-3 MACs.

Tests HMAC signature generation using official NIST ACVP vectors.
Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_secret_key,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKK_SHA3_224_HMAC,
    CKK_SHA3_256_HMAC,
    CKK_SHA3_384_HMAC,
    CKK_SHA3_512_HMAC,
    CKK_SHA224_HMAC,
    CKK_SHA256_HMAC,
    CKK_SHA384_HMAC,
    CKK_SHA512_224_HMAC,
    CKK_SHA512_256_HMAC,
    CKK_SHA512_HMAC,
    CKM_SHA3_224_HMAC,
    CKM_SHA3_256_HMAC,
    CKM_SHA3_384_HMAC,
    CKM_SHA3_512_HMAC,
    CKM_SHA224_HMAC,
    CKM_SHA256_HMAC,
    CKM_SHA384_HMAC,
    CKM_SHA512_224_HMAC,
    CKM_SHA512_256_HMAC,
    CKM_SHA512_HMAC,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# ACVP algorithm name -> (CKK key type, CKM mechanism, display name)
_ALG_MAP: dict[str, tuple[int, int, str]] = {
    # SHA-2 HMAC
    "HMAC-SHA2-224-2.0": (CKK_SHA224_HMAC, CKM_SHA224_HMAC, "SHA224_HMAC"),
    "HMAC-SHA2-256-2.0": (CKK_SHA256_HMAC, CKM_SHA256_HMAC, "SHA256_HMAC"),
    "HMAC-SHA2-384-2.0": (CKK_SHA384_HMAC, CKM_SHA384_HMAC, "SHA384_HMAC"),
    "HMAC-SHA2-512-2.0": (CKK_SHA512_HMAC, CKM_SHA512_HMAC, "SHA512_HMAC"),
    # Truncated SHA-2 HMAC (512 -> 224/256)
    "HMAC-SHA2-512-224-2.0": (
        CKK_SHA512_224_HMAC,
        CKM_SHA512_224_HMAC,
        "SHA512_224_HMAC",
    ),
    "HMAC-SHA2-512-256-2.0": (
        CKK_SHA512_256_HMAC,
        CKM_SHA512_256_HMAC,
        "SHA512_256_HMAC",
    ),
    # SHA-3 HMAC
    "HMAC-SHA3-224-2.0": (
        CKK_SHA3_224_HMAC,
        CKM_SHA3_224_HMAC,
        "SHA3_224_HMAC",
    ),
    "HMAC-SHA3-256-2.0": (
        CKK_SHA3_256_HMAC,
        CKM_SHA3_256_HMAC,
        "SHA3_256_HMAC",
    ),
    "HMAC-SHA3-384-2.0": (
        CKK_SHA3_384_HMAC,
        CKM_SHA3_384_HMAC,
        "SHA3_384_HMAC",
    ),
    "HMAC-SHA3-512-2.0": (
        CKK_SHA3_512_HMAC,
        CKM_SHA3_512_HMAC,
        "SHA3_512_HMAC",
    ),
}

# Maximum vectors per algorithm (None = no limit)
_MAX_PER_ALG: int | None = None


def _load_hmac_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load HMAC ACVP vectors from all supported algorithms.

    Returns list of (vec_id, merged_dict) tuples.
    """
    all_vecs = []
    for alg_name, (key_type, mechanism, mech_display) in _ALG_MAP.items():
        vecs = load_acvp_vectors(alg_name)
        # Apply limit if set
        if _MAX_PER_ALG is not None:
            vecs = vecs[:_MAX_PER_ALG]
        for vec in vecs:
            inp = vec["input"]
            exp = vec["expected"]
            key_hex = inp.get("key", "")
            key_len_bits = inp.get("keyLen", 0)
            msg_hex = inp.get("msg", "")
            mac_len_bits = inp.get("macLen", 256)
            mac_expected_hex = exp.get("mac", "")
            tc_id = inp.get("tcId", 0)

            if not key_hex or not msg_hex or not mac_expected_hex:
                continue

            merged = {
                "alg": alg_name,
                "key_type": key_type,
                "mechanism": mechanism,
                "mech_display": mech_display,
                "key": bytes.fromhex(key_hex),
                "key_len_bits": key_len_bits,
                "msg": bytes.fromhex(msg_hex),
                "mac_len_bits": mac_len_bits,
                "mac_expected": bytes.fromhex(mac_expected_hex),
                "tc_id": tc_id,
            }
            vec_id = f"{alg_name}-tc{tc_id}"
            all_vecs.append((vec_id, merged))

    return all_vecs


_ALL_HMAC_VECTORS = _load_hmac_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_HMAC_VECTORS, ids=[v[0] for v in _ALL_HMAC_VECTORS])
def test_acvp_hmac(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """HMAC generation from NIST ACVP vectors.

    Tests that the PKCS#11 module can correctly compute HMAC MACs using
    standard SHA-2 and SHA-3 algorithms with truncated output (macLen in bits).
    """
    rs = p11_raw_session
    if not rs.has_mechanism(vec["mech_display"]):
        pytest.skip(f"{vec['mech_display']} not supported by module")

    key = 0
    try:
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                vec["key_type"],
                vec["key"],
                attrs={
                    CKA_SIGN: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                },
            )
        except AssertionError as e:
            pytest.skip(f"Cannot import {len(vec['key'])}-byte HMAC key: {e}")

        # Compute HMAC
        try:
            mac = sign_single(rs.raw, rs.sh, key, vec["mechanism"], vec["msg"])
        except AssertionError as exc:
            exc_msg = str(exc)
            if "CKR_KEY_SIZE_RANGE" in exc_msg:
                # Module rejects this key size for HMAC with this mechanism
                pytest.skip(f"Key size out of range for {vec['mech_display']}")
            if "CKR_KEY_HANDLE_INVALID" in exc_msg:
                # Module rejects this key for HMAC (key type/mechanism mismatch)
                pytest.skip(f"Key not valid for HMAC mechanism {vec['mech_display']}")
            raise

        # Compare truncated to expected (macLen is in bits)
        mac_len_bytes = vec["mac_len_bits"] // 8
        truncated = mac[:mac_len_bytes]
        expected = vec["mac_expected"]

        assert truncated == expected, (
            f"HMAC mismatch for {vec_id}: got {truncated.hex()}, expected {expected.hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
