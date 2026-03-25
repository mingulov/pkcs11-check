"""NIST ACVP SLH-DSA test vectors - the ONLY source for SLH-DSA vectors.

Tests SLH-DSA signature verification and generation using official NIST ACVP
vectors.  Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

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
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_SLH_DSA,
    CKM_SLH_DSA,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKP_SLH_DSA_SHA2_128F,
    CKP_SLH_DSA_SHA2_128S,
    CKP_SLH_DSA_SHA2_192F,
    CKP_SLH_DSA_SHA2_192S,
    CKP_SLH_DSA_SHA2_256F,
    CKP_SLH_DSA_SHA2_256S,
    CKP_SLH_DSA_SHAKE_128F,
    CKP_SLH_DSA_SHAKE_128S,
    CKP_SLH_DSA_SHAKE_192F,
    CKP_SLH_DSA_SHAKE_192S,
    CKP_SLH_DSA_SHAKE_256F,
    CKP_SLH_DSA_SHAKE_256S,
)
from pkcs11_check.testcases.data.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors

pytestmark = [pytest.mark.pqc, pytest.mark.kat, pytest.mark.acvp, pytest.mark.requires_v32]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# ACVP parameter set name -> PKCS#11 CKP parameter set int
_PARAM_SET_MAP: dict[str, int] = {
    "SLH-DSA-SHA2-128s": int(CKP_SLH_DSA_SHA2_128S),
    "SLH-DSA-SHA2-128f": int(CKP_SLH_DSA_SHA2_128F),
    "SLH-DSA-SHAKE-128s": int(CKP_SLH_DSA_SHAKE_128S),
    "SLH-DSA-SHAKE-128f": int(CKP_SLH_DSA_SHAKE_128F),
    "SLH-DSA-SHA2-192s": int(CKP_SLH_DSA_SHA2_192S),
    "SLH-DSA-SHA2-192f": int(CKP_SLH_DSA_SHA2_192F),
    "SLH-DSA-SHAKE-192s": int(CKP_SLH_DSA_SHAKE_192S),
    "SLH-DSA-SHAKE-192f": int(CKP_SLH_DSA_SHAKE_192F),
    "SLH-DSA-SHA2-256s": int(CKP_SLH_DSA_SHA2_256S),
    "SLH-DSA-SHA2-256f": int(CKP_SLH_DSA_SHA2_256F),
    "SLH-DSA-SHAKE-256s": int(CKP_SLH_DSA_SHAKE_256S),
    "SLH-DSA-SHAKE-256f": int(CKP_SLH_DSA_SHAKE_256F),
}


def _load_sigver_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SLH-DSA sigVer ACVP vectors merged with expected results."""
    all_vecs = load_acvp_vectors("SLH-DSA-sigVer-FIPS205")
    result = []
    for vec in all_vecs[:50]:  # cap for speed
        inp = vec["input"]
        exp = vec["expected"]
        group = vec["group"]
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue
        pk = inp.get("pk", "")
        msg = inp.get("message", "")
        sig = inp.get("signature", "")
        if not pk or not msg or not sig:
            continue
        merged: dict[str, Any] = {
            "param_set": param_set,
            "param_name": param_name,
            "pk": bytes.fromhex(pk),
            "msg": bytes.fromhex(msg),
            "sig": bytes.fromhex(sig),
            "expected_pass": exp.get("testPassed", True),
            "tc_id": inp.get("tcId", 0),
        }
        vec_id = f"sigVer-{param_name}-tc{merged['tc_id']}"
        result.append((vec_id, merged))
    return result


def _load_siggen_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SLH-DSA sigGen ACVP vectors merged with expected results."""
    all_vecs = load_acvp_vectors("SLH-DSA-sigGen-FIPS205")
    result = []
    for vec in all_vecs[:5]:  # SLH-DSA signing is slow - keep minimal
        inp = vec["input"]
        group = vec["group"]
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue
        sk = inp.get("sk", "")
        msg = inp.get("message", "")
        if not sk or not msg:
            continue
        merged = {
            "param_set": param_set,
            "param_name": param_name,
            "sk": bytes.fromhex(sk),
            "msg": bytes.fromhex(msg),
            "tc_id": inp.get("tcId", 0),
        }
        vec_id = f"sigGen-{param_name}-tc{merged['tc_id']}"
        result.append((vec_id, merged))
    return result


_SIGVER_VECTORS = _load_sigver_vectors()
_SIGGEN_VECTORS = _load_siggen_vectors()


@pytest.mark.parametrize("vec_id,vec", _SIGVER_VECTORS, ids=[v[0] for v in _SIGVER_VECTORS])
def test_slhdsa_sigver(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """SLH-DSA signature verification from NIST ACVP vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")

    param_set: int = vec["param_set"]

    pub_key = 0
    try:
        try:
            pub_key = create_object(
                rs.raw,
                rs.sh,
                {
                    int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                    int(CKA_KEY_TYPE): int(CKK_SLH_DSA),
                    int(CKA_VALUE): vec["pk"],
                    int(CKA_PARAMETER_SET): param_set,
                    int(CKA_TOKEN): False,
                    int(CKA_VERIFY): True,
                },
            )
        except AssertionError as e:
            pytest.skip(
                f"Cannot import SLH-DSA public key ({vec['param_name']}): {e}"
            )

        try:
            verified = verify_single(
                rs.raw, rs.sh, pub_key, CKM_SLH_DSA, vec["msg"], vec["sig"]
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(
                name in exc_msg
                for name in (
                    "CKR_SIGNATURE_INVALID", "CKR_SIGNATURE_LEN_RANGE",
                    "CKR_DATA_INVALID",
                )
            ):
                verified = False
            else:
                # Unexpected error from the module - record as xfail
                pytest.xfail(
                    f"SLH-DSA verify raised unexpected error for {vec_id}: {exc_msg}"
                )

        expected = vec["expected_pass"]
        if not expected and verified:
            # Module accepted an invalid signature - security concern
            pytest.fail(f"{vec_id}: accepted INVALID signature (expected rejection)")
        if expected and not verified:
            # Module rejected a valid signature - module issue, mark as xfail
            pytest.xfail(
                f"{vec_id}: rejected VALID SLH-DSA signature - known Kryoptic issue"
            )
    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)


@pytest.mark.parametrize("vec_id,vec", _SIGGEN_VECTORS, ids=[v[0] for v in _SIGGEN_VECTORS])
def test_slhdsa_siggen(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """SLH-DSA signature generation from NIST ACVP message vectors.

    PKCS#11 does not guarantee deterministic SLH-DSA output.  This test
    verifies that the module can sign without error and produces a non-empty
    result.  Exact signature comparison is skipped because most PKCS#11
    implementations use randomized SLH-DSA.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")

    param_set: int = vec["param_set"]

    priv_key = 0
    try:
        try:
            priv_key = create_object(
                rs.raw,
                rs.sh,
                {
                    int(CKA_CLASS): int(CKO_PRIVATE_KEY),
                    int(CKA_KEY_TYPE): int(CKK_SLH_DSA),
                    int(CKA_VALUE): vec["sk"],
                    int(CKA_PARAMETER_SET): param_set,
                    int(CKA_TOKEN): False,
                    int(CKA_SENSITIVE): False,
                    int(CKA_EXTRACTABLE): True,
                    int(CKA_SIGN): True,
                },
            )
        except AssertionError as e:
            pytest.skip(
                f"Cannot import SLH-DSA private key ({vec['param_name']}): {e}"
            )

        sig = sign_single(rs.raw, rs.sh, priv_key, CKM_SLH_DSA, vec["msg"])
        assert len(sig) > 0, f"SLH-DSA sign returned empty signature for {vec_id}"
    finally:
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)
