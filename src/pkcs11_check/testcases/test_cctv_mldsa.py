"""CCTV ML-DSA benchmark message sign/verify round-trip tests.

The CCTV ML-DSA benchmark directory contains lists of ASCII message strings
designed as benchmark signing inputs (not KAT vectors - no expected signatures).

Each test generates an ML-DSA key pair (per parameter set), signs a message
from the benchmark list, and verifies the resulting signature.  This confirms
the sign+verify path is internally consistent across all three ML-DSA sizes.

Requires: PKCS#11 v3.2 module with ML_DSA support (e.g., Kryoptic).
SoftHSM2 (v2.40) skips all tests - it has no ML-DSA support.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_PARAMETER_SET,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM_ML_DSA,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKP_ML_DSA_44,
    CKP_ML_DSA_65,
    CKP_ML_DSA_87,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_PARAMETER_SET_NOT_SUPPORTED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr
from pkcs11_check.testcases.data import CCTV_DIR

pytestmark = [
    pytest.mark.pqc,
    pytest.mark.kat,
    pytest.mark.cctv,
    pytest.mark.module_session_fast,
]

REQUIRED_MECHANISMS = ["ML_DSA", "ML_DSA_KEY_PAIR_GEN"]

_BENCHMARK_DIR = CCTV_DIR / "ML-DSA" / "benchmark"

# ML-DSA parameter set name -> (CKP parameter set int, benchmark file)
_PARAM_CONFIGS: list[tuple[str, int, Path]] = [
    ("ML-DSA-44", CKP_ML_DSA_44, _BENCHMARK_DIR / "ML-DSA-44.json"),
    ("ML-DSA-65", CKP_ML_DSA_65, _BENCHMARK_DIR / "ML-DSA-65.json"),
    ("ML-DSA-87", CKP_ML_DSA_87, _BENCHMARK_DIR / "ML-DSA-87.json"),
]

_MLDSA_KEYGEN_ERROR_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_PARAMETER_SET_NOT_SUPPORTED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


def _load_messages(path: Path) -> list[bytes]:
    """Load benchmark message strings, encoded to UTF-8 bytes."""
    if not path.exists():
        return []
    with open(path) as f:
        data: list[str] = json.load(f)
    return [msg.encode("utf-8") for msg in data]


def _build_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Build (vec_id, vec) pairs for parametrize."""
    vectors: list[tuple[str, dict[str, Any]]] = []
    for param_name, param_set, path in _PARAM_CONFIGS:
        messages = _load_messages(path)
        for i, msg in enumerate(messages):
            vec_id = f"{param_name}-msg{i}"
            vectors.append((vec_id, {"param_name": param_name, "param_set": param_set, "msg": msg}))
    return vectors


_ALL_VECTORS = _build_vectors()


def _gen_mldsa_keypair(rs: Any, param_set: int) -> tuple[int, int]:
    """Generate an ML-DSA key pair using the raw API."""
    from ctypes import byref

    from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
    from pkcs11_check.raw.rv import expect_rv
    from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CKR_OK

    pub_tmpl = template(
        attr_bool(CKA_VERIFY, True),
        attr_ulong(CKA_PARAMETER_SET, param_set),
        attr_bool(CKA_TOKEN, False),
    )
    priv_tmpl = template(
        attr_bool(CKA_SIGN, True),
        attr_bool(CKA_TOKEN, False),
    )
    mech = mech_simple(CKM_ML_DSA_KEY_PAIR_GEN)
    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = rs.raw.C_GenerateKeyPair(
        rs.sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_h),
        byref(priv_h),
    )
    expect_rv(rv, CKR_OK)
    return pub_h.value, priv_h.value


@pytest.mark.parametrize(
    "vec_id,vec",
    _ALL_VECTORS,
    ids=[v[0] for v in _ALL_VECTORS],
)
def test_cctv_mldsa_sign_verify(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ML-DSA sign + verify round-trip using CCTV benchmark messages.

    Generates a fresh ML-DSA key pair, signs the message, then verifies the
    signature using the same key pair.  No expected signature is compared --
    the benchmark files provide messages only.

    Security property: if sign succeeds and verify rejects the fresh
    signature, the module has a sign/verify inconsistency (test failure).
    """
    rs = p11_module_session
    if not _BENCHMARK_DIR.exists():
        pytest.skip("CCTV ML-DSA benchmark data not found")

    param_name: str = vec["param_name"]
    param_set: int = vec["param_set"]
    msg: bytes = vec["msg"]

    if not rs.has_mechanism("ML_DSA"):
        pytest.skip(f"{param_name}: ML_DSA not supported by module")
    if not rs.has_mechanism("ML_DSA_KEY_PAIR_GEN"):
        pytest.skip(f"{param_name}: ML_DSA_KEY_PAIR_GEN not supported by module")

    pub_key = 0
    priv_key = 0
    try:
        try:
            pub_key, priv_key = _gen_mldsa_keypair(rs, param_set)
        except AssertionError as e:
            xfail_if_known_ckr(
                e,
                _MLDSA_KEYGEN_ERROR_CKRS,
                f"{param_name}: CKM_ML_DSA_KEY_PAIR_GEN advertised but key generation failed",
            )

        sig = sign_single(rs.raw, rs.sh, priv_key, CKM_ML_DSA, msg)
        assert len(sig) > 0, f"{vec_id}: sign() returned empty signature"

        verified = verify_single(rs.raw, rs.sh, pub_key, CKM_ML_DSA, msg, sig)
        assert verified, f"{vec_id}: verify rejected a freshly-signed signature"

    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)
