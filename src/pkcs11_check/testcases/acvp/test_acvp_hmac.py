"""NIST ACVP HMAC test vectors - SHA-2, SHA-3 MACs.

Tests HMAC signature generation using official NIST ACVP vectors.
Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import xfail_as
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKK_GENERIC_SECRET,
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
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors
from pkcs11_check.testcases.conftest import (
    assert_correct,
    import_secret_key_negotiated,
    is_known_error,
    skip_unless_create_object_supported,
)

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

_HMAC_KEY_SETUP_ERROR_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_HMAC_KEY_USE_ERROR_CKRS = (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
)


def _hmac_key_type_candidates(key_type: int) -> tuple[int, ...]:
    if int(key_type) == int(CKK_GENERIC_SECRET):
        return (int(CKK_GENERIC_SECRET),)
    return (int(key_type), int(CKK_GENERIC_SECRET))


def _sign_hmac_with_key_fallback(rs: Any, vec: dict[str, Any]) -> bytes:
    """Import an HMAC key, trying the typed key first and GENERIC_SECRET second."""
    key_setup_errors: list[str] = []
    key_use_errors: list[str] = []
    for key_type in _hmac_key_type_candidates(vec["key_type"]):
        key = 0
        try:
            key = import_secret_key_negotiated(
                rs,
                key_type,
                vec["key"],
                attrs={
                    CKA_SIGN: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                },
                purpose="ACVP HMAC key import",
            )
            return sign_single(rs.raw, rs.sh, key, vec["mechanism"], vec["msg"])
        except AssertionError as exc:
            if is_known_error(exc, _HMAC_KEY_SETUP_ERROR_CKRS):
                key_setup_errors.append(f"key_type=0x{key_type:x}: {exc}")
                continue
            if is_known_error(exc, _HMAC_KEY_USE_ERROR_CKRS):
                key_use_errors.append(f"key_type=0x{key_type:x}: {exc}")
                continue
            raise
        finally:
            if key:
                destroy_quietly(rs.raw, rs.sh, key)

    if key_use_errors:
        xfail_as(
            "not_operational",
            kind="crypto",
            label=f"{vec['mech_display']}:sign",
            summary=(
                f"{vec['mech_display']} advertised but imported HMAC key was not accepted: "
                + "; ".join(key_use_errors)
            ),
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    xfail_as(
        "not_operational",
        kind="crypto",
        label=f"{vec['mech_display']}:sign",
        summary=(
            f"{vec['mech_display']} advertised but HMAC key setup failed for typed and "
            f"generic key types: {'; '.join(key_setup_errors)}"
        ),
        source=vec.get("_source"),
        vector_id=vec.get("_vector_id"),
    )


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
def test_acvp_hmac(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """HMAC generation from NIST ACVP vectors.

    Tests that the PKCS#11 module can correctly compute HMAC MACs using
    standard SHA-2 and SHA-3 algorithms with truncated output (macLen in bits).
    """
    rs = p11_module_session
    skip_unless_create_object_supported(rs)
    if not rs.has_mechanism(vec["mech_display"]):
        pytest.skip(f"{vec['mech_display']} not supported by module")

    mac = _sign_hmac_with_key_fallback(rs, vec)

    # Compare truncated to expected (macLen is in bits)
    mac_len_bytes = vec["mac_len_bits"] // 8
    truncated = mac[:mac_len_bytes]
    expected = vec["mac_expected"]

    assert_correct(
        actual=truncated,
        expected=expected,
        label=f"{vec['mech_display']}:C_Sign KAT {vec_id}",
        operation="C_Sign",
        mechanism=vec["mech_display"],
        source=vec.get("_source"),
        vector_id=vec.get("_vector_id"),
    )
