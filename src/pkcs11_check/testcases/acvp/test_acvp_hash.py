"""NIST ACVP hash (SHA) test vectors - SHA-1, SHA-2, SHA-3, SHAKE.

Tests digest operations using official NIST ACVP vectors.
Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import xfail_as
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import digest_single, to_ubyte_buf
from pkcs11_check.raw.rv import CkrAssertionError, expect_rv
from pkcs11_check.raw.types_std import (
    CK_BYTE,
    CKM,
    CKM_SHA3_224,
    CKM_SHA3_256,
    CKM_SHA3_384,
    CKM_SHA3_512,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY,
    CKR_DEVICE_REMOVED,
    CKR_FUNCTION_CANCELED,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_PENDING,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors
from pkcs11_check.testcases.conftest import xfail_if_known_ckr

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )


# ACVP algorithm name -> (CKM mechanism, mechanism name string, hash_len_bytes)
_ALG_MAP: dict[str, tuple[Any, str, int]] = {
    # SHA-2 family (if ACVP data available)
    "SHA-1-1.0": (CKM_SHA_1, "SHA_1", 20),
    "SHA2-224-1.0": (CKM_SHA224, "SHA224", 28),
    "SHA2-256-1.0": (CKM_SHA256, "SHA256", 32),
    "SHA2-384-1.0": (CKM_SHA384, "SHA384", 48),
    "SHA2-512-1.0": (CKM_SHA512, "SHA512", 64),
    # SHA-3 family
    "SHA3-224-2.0": (CKM_SHA3_224, "SHA3_224", 28),
    "SHA3-256-2.0": (CKM_SHA3_256, "SHA3_256", 32),
    "SHA3-384-2.0": (CKM_SHA3_384, "SHA3_384", 48),
    "SHA3-512-2.0": (CKM_SHA3_512, "SHA3_512", 64),
}


_CKM_SHAKE_128 = CKM(0x00000418, "CKM_SHAKE_128")
_CKM_SHAKE_256 = CKM(0x00000419, "CKM_SHAKE_256")

_SHAKE_ALG_MAP: dict[str, tuple[Any, str]] = {
    "SHAKE-128-1.0": (_CKM_SHAKE_128, "SHAKE_128"),
    "SHAKE-256-1.0": (_CKM_SHAKE_256, "SHAKE_256"),
}

_SHAKE_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_DEVICE_MEMORY,
    CKR_DEVICE_REMOVED,
    CKR_FUNCTION_CANCELED,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_HOST_MEMORY,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_PENDING,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
    CKR_USER_NOT_LOGGED_IN,
)


def _load_hash_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load hash ACVP vectors from all supported algorithms.

    PKCS#11 digest() takes full bytes only. ACVP vectors may have partial-bit
    messages (where len % 8 != 0). This loader skips partial-bit vectors since
    PKCS#11 cannot express them.

    Returns list of (vec_id, vec_dict) tuples where vec_id is
    '<algorithm>-tc<tcId>' for parametrize.
    """
    result = []
    for alg_name, (mech, mech_name, hash_len) in _ALG_MAP.items():
        vecs = load_acvp_vectors(alg_name)
        if not vecs:
            continue  # Algorithm data not available

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
                "mech": mech,
                "mech_name": mech_name,
                "hash_len": hash_len,
                "msg": bytes.fromhex(msg_hex) if msg_hex else b"",
                "msg_len": msg_len,
                "expected_md": bytes.fromhex(md_hex),
                "tc_id": tc_id,
            }
            vec_id = f"{alg_name}-tc{tc_id}"
            result.append((vec_id, merged))

            vec_count += 1
            # Limit to 20 full-byte vectors per algorithm for speed
            if vec_count >= 20:
                break

    return result


def _load_shake_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SHAKE ACVP vectors for variable-output XOF testing.

    SHAKE is tested via C_DeriveKey with the SHAKE key derivation mechanisms,
    deriving a key of the requested output length.

    Returns list of (vec_id, vec_dict) tuples.
    """
    result = []
    for alg_name, (mech_int, mech_name) in _SHAKE_ALG_MAP.items():
        vecs = load_acvp_vectors(alg_name)
        if not vecs:
            continue

        vec_count = 0
        for vec in vecs:
            inp = vec["input"]
            exp = vec["expected"]
            tc_id = inp.get("tcId", 0)
            msg_hex = inp.get("msg", "")
            msg_len = inp.get("len", 0)
            out_len_bits = inp.get("outLen", 0)
            md_hex = exp.get("md", "")

            if not md_hex:
                continue

            # Skip partial-bit messages
            if msg_len % 8 != 0:
                continue
            if out_len_bits % 8 != 0:
                continue

            out_len_bytes = out_len_bits // 8

            merged: dict[str, Any] = {
                "alg_name": alg_name,
                "mech_int": mech_int,
                "mech_name": mech_name,
                "msg": bytes.fromhex(msg_hex) if msg_hex else b"",
                "msg_len": msg_len,
                "out_len_bits": out_len_bits,
                "out_len_bytes": out_len_bytes,
                "expected_md": bytes.fromhex(md_hex),
                "tc_id": tc_id,
            }
            vec_id = f"{alg_name}-tc{tc_id}"
            result.append((vec_id, merged))

            vec_count += 1
            if vec_count >= 15:  # Fewer vectors for SHAKE due to derivation overhead
                break

    return result


_ALL_HASH_VECTORS = _load_hash_vectors()
_SHAKE_VECTORS = _load_shake_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_HASH_VECTORS, ids=[v[0] for v in _ALL_HASH_VECTORS])
def test_acvp_hash(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Hash digest from NIST ACVP vectors.

    Compares PKCS#11 digest output against official NIST ACVP expected results
    for SHA-1, SHA-2, and SHA-3 families.
    """
    rs = p11_module_session
    mech_name: str = vec["mech_name"]

    # Check mechanism availability
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported")

    mech: Any = vec["mech"]
    msg: bytes = vec["msg"]
    expected_md: bytes = vec["expected_md"]

    try:
        digest = digest_single(rs.raw, rs.sh, mech, msg)
    except AssertionError as e:
        if not isinstance(e, CkrAssertionError):
            # Non-CKR AssertionError -- a harness/ctypes bug must never be
            # classified as "not operational"; let it surface.
            raise
        xfail_as(
            "not_operational",
            kind="crypto",
            label=f"{mech_name}:digest",
            summary=f"Digest failed for {vec_id}: {e}",
        )

    assert digest == expected_md, (
        f"{vec_id}: digest mismatch\n  expected: {expected_md.hex()}\n  got:      {digest.hex()}"
    )


def _run_acvp_shake_vector(rs: Any, vec_id: str, vec: dict[str, Any]) -> None:
    for function_name in ("C_DigestXofInit", "C_DigestXof"):
        if not hasattr(rs.raw, function_name):
            pytest.skip(f"{function_name} not available in this raw binding")

    mech = mech_simple(vec["mech_int"])
    rv = rs.raw.C_DigestXofInit(rs.sh, mech.byref())
    try:
        expect_rv(rv, CKR_OK, context=f"{vec_id} C_DigestXofInit")
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _SHAKE_RUNTIME_REJECT_RVS, f"{vec_id} XOF init not operational")

    msg: bytes = vec["msg"]
    expected_md: bytes = vec["expected_md"]
    msg_buf = to_ubyte_buf(msg)
    out_len = len(expected_md)
    output = (CK_BYTE * out_len)()
    rv = rs.raw.C_DigestXof(rs.sh, msg_buf, len(msg), output, out_len)
    try:
        expect_rv(rv, CKR_OK, context=f"{vec_id} C_DigestXof")
    except AssertionError as exc:
        xfail_if_known_ckr(exc, _SHAKE_RUNTIME_REJECT_RVS, f"{vec_id} XOF not operational")

    digest = bytes(output)
    assert digest == expected_md, (
        f"{vec_id}: SHAKE XOF mismatch\n  expected: {expected_md.hex()}\n  got:      {digest.hex()}"
    )


@pytest.mark.parametrize("vec_id,vec", _SHAKE_VECTORS, ids=[v[0] for v in _SHAKE_VECTORS])
def test_acvp_shake(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SHAKE XOF (extendable-output function) from NIST ACVP vectors.

    SHAKE produces variable-length output based on the requested output length.
    The ACVP vectors specify outLen in bits, which we convert to bytes for
    the PKCS#11 digest operation.
    """
    rs = p11_module_session
    mech_name: str = vec["mech_name"]

    # Check mechanism availability
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"{mech_name} not supported")

    _run_acvp_shake_vector(rs, vec_id, vec)
