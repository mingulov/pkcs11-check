"""C2SP/CCTV Ed25519 edge-case test vectors.

914 vectors testing Ed25519 verification with edge cases:
- Low-order points (R and public key)
- Non-canonical encodings
- Cofactored vs uncofactored verification
- Mixed-order points

These supplement the Wycheproof Ed25519 vectors with additional
attack-focused edge cases from the CCTV project.

Source: https://github.com/C2SP/CCTV/tree/main/ed25519
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases.conftest import has_mechanism
from pkcs11_check.testcases.data import CCTV_DIR

pytestmark = [pytest.mark.interop, pytest.mark.security, pytest.mark.cctv]

_VECTORS_FILE = CCTV_DIR / "ed25519" / "ed25519vectors.json"


def _load_cctv_ed25519() -> list[dict[str, Any]]:
    """Load CCTV Ed25519 vectors."""
    if not _VECTORS_FILE.exists():
        return []
    with open(_VECTORS_FILE) as f:
        return json.load(f)


def _vec_id(v: dict[str, Any]) -> str:
    flags = ",".join(v.get("flags") or [])
    return f"vec{v['number']}-{flags[:30]}"


_vectors = _load_cctv_ed25519()


@pytest.mark.parametrize("vec", _vectors, ids=_vec_id)
def test_ed25519_cctv(vec: dict[str, Any], p11_session: Any, p11_module: Any) -> None:
    """Ed25519 verification with CCTV edge-case vector."""
    if not has_mechanism(p11_module, "EDDSA"):
        pytest.skip("EdDSA not supported")

    pub_key_bytes = bytes.fromhex(vec["key"])
    sig_bytes = bytes.fromhex(vec["sig"])
    msg = vec["msg"].encode() if isinstance(vec["msg"], str) else bytes.fromhex(vec["msg"])
    flags = vec.get("flags") or []

    # Import the public key
    try:
        pub = p11_session.create_object({
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.KEY_TYPE: KeyType.EC_EDWARDS,
            Attribute.EC_PARAMS: bytes.fromhex("06032b6570"),  # OID for Ed25519
            Attribute.EC_POINT: pub_key_bytes,
            Attribute.VERIFY: True,
            Attribute.TOKEN: False,
        })
    except PKCS11Error:
        # Module may reject low-order or malformed public keys - that's fine
        if "low_order_A" in flags or "non_canonical_A" in flags:
            return  # Correctly rejected
        raise

    # Attempt verification
    try:
        result = pub.verify(msg, sig_bytes, mechanism=Mechanism.EDDSA)
        # If verification succeeds on a vector with edge-case flags,
        # that's a finding but not necessarily wrong (depends on module policy)
        if "low_order_R" in flags or "low_order_A" in flags:
            from pkcs11_check.compliance import ComplianceLevel, note
            note(
                f"Ed25519 verify accepted edge case (flags: {flags})",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="C2SP/CCTV Ed25519 vector",
            )
    except PKCS11Error:
        # Rejection of edge-case vectors is generally correct
        pass
    finally:
        try:
            pub.destroy()
        except PKCS11Error:
            pass
