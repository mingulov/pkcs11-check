"""NIST ACVP HMAC test vectors — SHA-2, SHA-3 MACs.

Tests HMAC signature generation using official NIST ACVP vectors.
Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import KeySizeRange, PKCS11Error

from pkcs11_check.testcases.conftest import has_mechanism
from pkcs11_check.testcases.data.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# ACVP algorithm name -> (KeyType, Mechanism, display name)
_ALG_MAP = {
    "HMAC-SHA2-256-2.0": (KeyType.SHA256_HMAC, Mechanism.SHA256_HMAC, "SHA256_HMAC"),
    "HMAC-SHA2-384-2.0": (KeyType.SHA384_HMAC, Mechanism.SHA384_HMAC, "SHA384_HMAC"),
    "HMAC-SHA2-512-2.0": (KeyType.SHA512_HMAC, Mechanism.SHA512_HMAC, "SHA512_HMAC"),
    "HMAC-SHA3-256-2.0": (KeyType.SHA3_256_HMAC, Mechanism.SHA3_256_HMAC, "SHA3_256_HMAC"),
    "HMAC-SHA3-384-2.0": (KeyType.SHA3_384_HMAC, Mechanism.SHA3_384_HMAC, "SHA3_384_HMAC"),
    "HMAC-SHA3-512-2.0": (KeyType.SHA3_512_HMAC, Mechanism.SHA3_512_HMAC, "SHA3_512_HMAC"),
}


def _load_hmac_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load HMAC ACVP vectors from all supported algorithms.

    Returns list of (vec_id, merged_dict) tuples.
    """
    all_vecs = []
    for alg_name, (key_type, mechanism, mech_display) in _ALG_MAP.items():
        vecs = load_acvp_vectors(alg_name)
        for vec in vecs[:20]:  # cap per algorithm for speed
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
def test_acvp_hmac(
    p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """HMAC generation from NIST ACVP vectors.

    Tests that the PKCS#11 module can correctly compute HMAC MACs using
    standard SHA-2 and SHA-3 algorithms with truncated output (macLen in bits).
    """
    if not has_mechanism(p11_module, vec["mech_display"]):
        pytest.skip(f"{vec['mech_display']} not supported by module")

    key = None
    try:
        try:
            key = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: vec["key_type"],
                    Attribute.VALUE: vec["key"],
                    Attribute.SIGN: True,
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                }
            )
        except (PKCS11Error, KeySizeRange) as e:
            pytest.skip(f"Cannot import {len(vec['key'])}-byte HMAC key: {e}")

        # Compute HMAC
        try:
            mac = key.sign(vec["msg"], mechanism=vec["mechanism"])
        except KeySizeRange:
            # Module rejects this key size for HMAC with this mechanism
            pytest.skip(f"Key size out of range for {vec['mech_display']}")

        # Compare truncated to expected (macLen is in bits)
        mac_len_bytes = vec["mac_len_bits"] // 8
        truncated = mac[:mac_len_bytes]
        expected = vec["mac_expected"]

        assert truncated == expected, (
            f"HMAC mismatch for {vec_id}: "
            f"got {truncated.hex()}, expected {expected.hex()}"
        )
    finally:
        if key is not None:
            key.destroy()
