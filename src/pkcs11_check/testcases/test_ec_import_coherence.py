"""EC public key import coherence: a CKR_OK C_CreateObject must be honored.

A module may cleanly reject an unsupported curve at import (skip — capability
absent). What it must NOT do is claim success and not honor it: corePKCS11
(probed 2026-06-09, triage H6) accepts a secp256k1 public key with CKR_OK while
binding the stored key to P-256 — the resulting object is incoherent
(C_GetAttributeValue returns CKR_OBJECT_HANDLE_INVALID; C_VerifyInit returns
CKR_KEY_HANDLE_INVALID). Claimed success that is not honored is a lifecycle
self-contradiction (classification model): ``fail``, never xfail/skip.

KAT suites (e.g. Wycheproof ECDSA) skip vectors of such curves via the same
effect check (``ec_public_key_binding_defect``); this is the single dedicated
test that turns the underlying contradiction into a reported failure.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import CKA_VERIFY
from pkcs11_check.testcases.conftest import (
    ec_public_key_binding_defect,
    import_ec_public_key_negotiated,
    is_known_error,
)
from pkcs11_check.testcases.wycheproof.test_wycheproof_ecdsa import (
    _CURVE_UNSUPPORTED_CKRS,
    _EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS,
)

REQUIRED_MECHANISMS = ["ECDSA"]

# Fixed valid uncompressed public points (generated with `cryptography`).
_CURVE_POINTS = {
    "secp256r1": "0461b71a975c53edeb10c3e29e83a197a0f8d4ca600e2b6f396d40282deccd34"
    "6273965b65b3471bfbd932837f75e09d6f1b9bb92c68737625d0ba933e126ec828",
    "secp256k1": "04342d07856dd253aa0e516c9ed538b9c8c25bd590d1d1c8db365d6fe64f3d7d"
    "5544af5abb0a38a06abadadc1c9327e03ae51e5623bff07fd8db6baa67c1ce0581",
    "secp224r1": "04317190606c7c82ab8f59331a364228ce1cb931226f2f6c22d59ab0864ee5e0"
    "2e95e5a33cbeed1291ef0ed3973418b4c93d799defbc7ceac9",
    "brainpoolP256r1": "046b0faeaddd32f7f4096663033785cc6c5d4a40e43cd8a4287acf39f6"
    "9311d1ff0e0e902476c140921802eaed84b1d0739f33255d5fe4c35665b6d53da54611a1",
}


@pytest.mark.parametrize("curve", sorted(_CURVE_POINTS))
def test_ec_public_key_import_is_coherent(p11_module_session: Any, curve: str) -> None:
    """If C_CreateObject claims CKR_OK for an EC public key, the object must be
    coherent: attribute readback works and CKA_EC_PARAMS round-trips."""
    rs = p11_module_session
    if not rs.has_mechanism("ECDSA"):
        pytest.skip("ECDSA not supported by module")

    ec_params = encode_named_curve_parameters(curve)
    point = bytes.fromhex(_CURVE_POINTS[curve])
    ec_point_der = bytes([0x04, len(point)]) + point

    try:
        handle = import_ec_public_key_negotiated(
            rs,
            ec_params=ec_params,
            ec_point=ec_point_der,
            attrs={CKA_VERIFY: True},
            purpose=f"EC import coherence {curve}",
        )
    except AssertionError as exc:
        if is_known_error(exc, _CURVE_UNSUPPORTED_CKRS + _EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS):
            pytest.skip(f"Module cleanly rejects {curve} import: {exc}")
        raise

    try:
        defect = ec_public_key_binding_defect(rs, handle, ec_params)
        if defect:
            classify(
                "self_contradiction",
                kind="lifecycle",
                label=f"EC import coherence {curve}",
                operation="C_CreateObject",
                summary=(
                    f"{curve}: C_CreateObject returned CKR_OK but the object is not "
                    f"honored (lifecycle self-contradiction): {defect}"
                ),
            )
    finally:
        destroy_quietly(rs.raw, rs.sh, handle)
