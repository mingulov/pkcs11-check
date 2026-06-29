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

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKK_EC_EDWARDS,
    CKM_EDDSA,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._provisioning import provision_public_key
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr
from pkcs11_check.testcases.data import CCTV_DIR, load_json_cached

pytestmark = [
    pytest.mark.interop,
    pytest.mark.security,
    pytest.mark.cctv,
    pytest.mark.module_session_fast,
]

REQUIRED_MECHANISMS = ["EDDSA"]

_VECTORS_FILE = CCTV_DIR / "ed25519" / "ed25519vectors.json"


def _load_cctv_ed25519() -> list[dict[str, Any]]:
    """Load CCTV Ed25519 vectors."""
    if not _VECTORS_FILE.exists():
        return []
    result: list[dict[str, Any]] = load_json_cached(_VECTORS_FILE)
    return result


def _vec_id(v: dict[str, Any]) -> str:
    flags = ",".join(v.get("flags") or [])
    return f"vec{v['number']}-{flags[:30]}"


_vectors = _load_cctv_ed25519()

_INVALID_PUBLIC_KEY_FLAGS = {"low_order_A", "non_canonical_A"}

_ED25519_PUBLIC_IMPORT_CLEAN_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_ED25519_PUBLIC_IMPORT_NON_CLEAN_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_PARAM_INVALID,
)


def _has_invalid_public_key_flags(flags: list[str]) -> bool:
    return bool(_INVALID_PUBLIC_KEY_FLAGS.intersection(flags))


def _invalid_public_key_rejected_cleanly(exc: AssertionError, flags: list[str]) -> bool:
    """Return true for expected CCTV invalid-key import rejects."""
    if not _has_invalid_public_key_flags(flags):
        # Valid vector: the import should succeed. A clean reject means the module
        # advertises Ed25519 but cannot import an external public key (e.g. a KMS
        # bridge) -> advertised-but-not-operational xfail, not a raw failure.
        xfail_if_known_ckr(
            exc,
            _ED25519_PUBLIC_IMPORT_CLEAN_REJECT_RVS + _ED25519_PUBLIC_IMPORT_NON_CLEAN_REJECT_RVS,
            "CCTV Ed25519 public-key import not operational",
        )
        raise exc
    if is_known_error(exc, _ED25519_PUBLIC_IMPORT_CLEAN_REJECT_RVS):
        return True
    xfail_if_known_ckr(
        exc,
        _ED25519_PUBLIC_IMPORT_NON_CLEAN_REJECT_RVS,
        "CCTV Ed25519 invalid public key rejected with non-clean CKR",
    )
    raise exc


@pytest.mark.parametrize("vec", _vectors, ids=_vec_id)
def test_ed25519_cctv(vec: dict[str, Any], p11_module_session: Any, p11_config: Any) -> None:
    """Ed25519 verification with CCTV edge-case vector."""
    rs = p11_module_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EdDSA not supported")

    pub_key_bytes = bytes.fromhex(vec["key"])
    sig_bytes = bytes.fromhex(vec["sig"])
    msg = vec["msg"].encode() if isinstance(vec["msg"], str) else bytes.fromhex(vec["msg"])
    flags = vec.get("flags") or []

    # Import the public key
    pub = 0
    try:
        try:
            pub = provision_public_key(
                rs,
                p11_config,
                ec_params=bytes.fromhex("06032b6570"),  # OID for Ed25519
                ec_point=pub_key_bytes,
                key_type=CKK_EC_EDWARDS,
                attrs={CKA_VERIFY: True},
                label="cctv ed25519 verify KAT",
            )
        except AssertionError as exc:
            if _invalid_public_key_rejected_cleanly(exc, flags):
                return

        # Attempt verification
        try:
            verified = verify_single(rs.raw, rs.sh, pub, CKM_EDDSA, msg, sig_bytes)
            if not verified:
                return
            # If verification succeeds on a vector with edge-case flags,
            # that's a finding but not necessarily wrong (depends on module policy)
            if "low_order_R" in flags or "low_order_A" in flags:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"Ed25519 verify accepted edge case (flags: {flags})",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="C2SP/CCTV Ed25519 vector",
                )
        except AssertionError as exc:
            # Rejection of edge-case vectors is generally correct
            signature_rejected_or_xfail(exc, f"CCTV Ed25519 vector {vec['number']}")
    finally:
        if pub:
            destroy_quietly(rs.raw, rs.sh, pub)
