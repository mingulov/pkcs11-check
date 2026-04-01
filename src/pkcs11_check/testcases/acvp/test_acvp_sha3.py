"""NIST ACVP SHA-3 digest test vectors.

Tests SHA-3-224, SHA-3-256, SHA-3-384, and SHA-3-512 using official NIST ACVP
vectors.  Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import digest_single
from pkcs11_check.raw.types_std import (
    CKM_SHA3_224,
    CKM_SHA3_256,
    CKM_SHA3_384,
    CKM_SHA3_512,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# ACVP algorithm name -> (CKM mechanism int, mechanism name string)
_ALG_TO_MECH: dict[str, tuple[int, str]] = {
    "SHA3-224-2.0": (CKM_SHA3_224, "SHA3_224"),
    "SHA3-256-2.0": (CKM_SHA3_256, "SHA3_256"),
    "SHA3-384-2.0": (CKM_SHA3_384, "SHA3_384"),
    "SHA3-512-2.0": (CKM_SHA3_512, "SHA3_512"),
}


def _load_sha3_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SHA-3 ACVP vectors from all variants.

    PKCS#11 digest() takes full bytes only. ACVP vectors may have partial-bit
    messages (where len % 8 != 0). This loader skips partial-bit vectors since
    PKCS#11 cannot express them.

    Returns list of (vec_id, vec_dict) tuples where vec_id is
    '<algorithm>-tc<tcId>' for parametrize.
    """
    result = []
    for alg_name in _ALG_TO_MECH:
        vecs = load_acvp_vectors(alg_name)
        vec_count = 0
        for vec in vecs:
            inp = vec["input"]
            exp = vec["expected"]
            tc_id = inp.get("tcId", 0)
            msg_hex = inp.get("msg", "")
            msg_len = inp.get("len", 0)
            md_hex = exp.get("md", "")

            if not md_hex:
                continue

            # Skip partial-bit messages (PKCS#11 only supports full-byte inputs)
            if msg_len % 8 != 0:
                continue

            merged: dict[str, Any] = {
                "alg_name": alg_name,
                "msg": bytes.fromhex(msg_hex) if msg_hex else b"",
                "msg_len": msg_len,
                "expected_md": bytes.fromhex(md_hex),
                "tc_id": tc_id,
            }
            vec_id = f"{alg_name}-tc{tc_id}"
            result.append((vec_id, merged))

            vec_count += 1
            # Limit to 20 full-byte vectors per algorithm
            if vec_count >= 20:
                break

    return result


_SHA3_VECTORS = _load_sha3_vectors()


@pytest.mark.parametrize("vec_id,vec", _SHA3_VECTORS, ids=[v[0] for v in _SHA3_VECTORS])
def test_acvp_sha3(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SHA-3 digest from NIST ACVP vectors.

    Compares PKCS#11 digest output against official NIST ACVP expected results.
    """
    rs = p11_raw_session
    alg_name: str = vec["alg_name"]
    msg: bytes = vec["msg"]
    expected_md: bytes = vec["expected_md"]

    if alg_name not in _ALG_TO_MECH:
        pytest.skip(f"Unknown algorithm: {alg_name}")

    mech_int, mech_name_str = _ALG_TO_MECH[alg_name]

    # Check mechanism availability
    if not rs.has_mechanism(mech_name_str):
        pytest.skip(f"{mech_name_str} not supported")

    try:
        digest = digest_single(rs.raw, rs.sh, mech_int, msg)
    except AssertionError as e:
        # Unexpected error from the module
        pytest.fail(f"SHA-3 digest failed for {vec_id}: {e}")

    assert digest == expected_md, (
        f"{vec_id}: digest mismatch\n  expected: {expected_md.hex()}\n  got:      {digest.hex()}"
    )
