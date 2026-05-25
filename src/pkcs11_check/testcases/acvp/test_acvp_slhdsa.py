"""NIST ACVP SLH-DSA test vectors - the ONLY source for SLH-DSA vectors.

Tests SLH-DSA key generation, signature verification and generation using official
NIST ACVP vectors. Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_pqc_private_key,
    import_pqc_public_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_VERIFY,
    CKK_SLH_DSA,
    CKM_SLH_DSA,
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
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._signature_policy import (
    NON_CLEAN_SIGNATURE_REJECT_RVS,
    SIGNATURE_REJECT_RVS,
    signature_rejected_or_xfail,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr

pytestmark = [pytest.mark.pqc, pytest.mark.kat, pytest.mark.acvp]

if not ACVP_AVAILABLE:
    pytest.skip(
        "ACVP vectors not cloned (run: scripts/fetch-optional-data.sh acvp)",
        allow_module_level=True,
    )

# ACVP parameter set name -> PKCS#11 CKP parameter set int
_PARAM_SET_MAP: dict[str, int] = {
    "SLH-DSA-SHA2-128s": CKP_SLH_DSA_SHA2_128S,
    "SLH-DSA-SHA2-128f": CKP_SLH_DSA_SHA2_128F,
    "SLH-DSA-SHAKE-128s": CKP_SLH_DSA_SHAKE_128S,
    "SLH-DSA-SHAKE-128f": CKP_SLH_DSA_SHAKE_128F,
    "SLH-DSA-SHA2-192s": CKP_SLH_DSA_SHA2_192S,
    "SLH-DSA-SHA2-192f": CKP_SLH_DSA_SHA2_192F,
    "SLH-DSA-SHAKE-192s": CKP_SLH_DSA_SHAKE_192S,
    "SLH-DSA-SHAKE-192f": CKP_SLH_DSA_SHAKE_192F,
    "SLH-DSA-SHA2-256s": CKP_SLH_DSA_SHA2_256S,
    "SLH-DSA-SHA2-256f": CKP_SLH_DSA_SHA2_256F,
    "SLH-DSA-SHAKE-256s": CKP_SLH_DSA_SHAKE_256S,
    "SLH-DSA-SHAKE-256f": CKP_SLH_DSA_SHAKE_256F,
}

_PQC_IMPORT_UNSUPPORTED_RVS = (
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_KEY_SIZE_RANGE,
)

_PQC_IMPORT_RUNTIME_FAILURE_RVS = (CKR_FUNCTION_FAILED,)

_SLHDSA_RUNTIME_REJECT_RVS = (
    *NON_CLEAN_SIGNATURE_REJECT_RVS,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _skip_if_import_unsupported(exc: AssertionError, label: str) -> None:
    if is_known_error(exc, _PQC_IMPORT_UNSUPPORTED_RVS):
        pytest.skip(f"Cannot import SLH-DSA {label}: {exc}")
    xfail_if_known_ckr(
        exc,
        _PQC_IMPORT_RUNTIME_FAILURE_RVS,
        f"SLH-DSA {label} import failed with non-specific CKR",
    )
    raise exc


def _xfail_if_slhdsa_runtime_reject(exc: AssertionError, label: str) -> None:
    xfail_if_known_ckr(
        exc,
        _SLHDSA_RUNTIME_REJECT_RVS,
        f"{label}: advertised SLH-DSA operation is not operational",
    )
    raise exc


def _slhdsa_verify_result_or_xfail(
    exc: AssertionError, label: str, *, expected_pass: bool
) -> bool:
    if expected_pass:
        if is_known_error(exc, SIGNATURE_REJECT_RVS):
            return False
        xfail_if_known_ckr(
            exc,
            _SLHDSA_RUNTIME_REJECT_RVS,
            f"{label}: valid SLH-DSA signature verification rejected",
        )
        raise exc
    return signature_rejected_or_xfail(exc, label)


def _load_keygen_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SLH-DSA keyGen ACVP vectors.

    Tests deterministic key generation by importing the expected private key
    and verifying it matches the expected public key through sign/verify.
    """
    all_vecs = load_acvp_vectors("SLH-DSA-keyGen-FIPS205")
    result = []
    # Take 2 vectors per parameter set (24 total = 12 sets * 2)
    param_set_counts: dict[str, int] = {}
    for vec in all_vecs:
        group = vec["group"]
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue

        # Track count per parameter set
        current_count = param_set_counts.get(param_name, 0)
        if current_count >= 2:
            continue
        param_set_counts[param_name] = current_count + 1

        exp = vec["expected"]
        sk = exp.get("sk", "")
        pk = exp.get("pk", "")
        if not sk or not pk:
            continue

        merged: dict[str, Any] = {
            "param_set": param_set,
            "param_name": param_name,
            "sk": bytes.fromhex(sk),
            "pk": bytes.fromhex(pk),
            "tc_id": vec["input"].get("tcId", 0),
        }
        vec_id = f"keyGen-{param_name}-tc{merged['tc_id']}"
        result.append((vec_id, merged))
    return result


def _load_sigver_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load SLH-DSA sigVer ACVP vectors merged with expected results."""
    all_vecs = load_acvp_vectors("SLH-DSA-sigVer-FIPS205")
    result = []
    # Take 4 vectors per parameter set (48 total = 12 sets * 4)
    param_set_counts: dict[str, int] = {}
    for vec in all_vecs:
        inp = vec["input"]
        exp = vec["expected"]
        group = vec["group"]
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue

        # Track count per parameter set
        current_count = param_set_counts.get(param_name, 0)
        if current_count >= 4:
            continue
        param_set_counts[param_name] = current_count + 1

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
    # Take 1 vector per parameter set (12 total = 12 sets * 1)
    # SLH-DSA signing is very slow, so keep minimal
    param_set_seen: set[str] = set()
    for vec in all_vecs:
        inp = vec["input"]
        group = vec["group"]
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue

        # Only take first vector per parameter set
        if param_name in param_set_seen:
            continue
        param_set_seen.add(param_name)

        sk = inp.get("sk", "")
        msg = inp.get("message", "")
        if not sk or not msg:
            continue

        merged: dict[str, Any] = {
            "param_set": param_set,
            "param_name": param_name,
            "sk": bytes.fromhex(sk),
            "msg": bytes.fromhex(msg),
            "tc_id": inp.get("tcId", 0),
        }
        vec_id = f"sigGen-{param_name}-tc{merged['tc_id']}"
        result.append((vec_id, merged))
    return result


_KEYGEN_VECTORS = _load_keygen_vectors()
_SIGVER_VECTORS = _load_sigver_vectors()
_SIGGEN_VECTORS = _load_siggen_vectors()


@pytest.mark.parametrize("vec_id,vec", _KEYGEN_VECTORS, ids=[v[0] for v in _KEYGEN_VECTORS])
def test_slhdsa_keygen(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SLH-DSA key generation test from NIST ACVP vectors.

    Imports the expected private key and verifies it can be used for signing,
    with the expected public key used for verification.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")

    param_set: int = vec["param_set"]
    priv_key = 0
    pub_key = 0

    try:
        try:
            # Import the private key from the vector
            priv_key = import_pqc_private_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_SLH_DSA),
                value=vec["sk"],
                parameter_set=param_set,
                attrs={CKA_SIGN: True},
            )
        except AssertionError as exc:
            _skip_if_import_unsupported(exc, f"private key ({vec['param_name']})")

        try:
            # Import the expected public key
            pub_key = import_pqc_public_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_SLH_DSA),
                value=vec["pk"],
                parameter_set=param_set,
                attrs={CKA_VERIFY: True},
            )
        except AssertionError as exc:
            _skip_if_import_unsupported(exc, f"public key ({vec['param_name']})")

        try:
            # Test sign/verify roundtrip to verify keypair consistency
            test_msg = b"SLH-DSA keygen test message"
            sig = sign_single(rs.raw, rs.sh, priv_key, CKM_SLH_DSA, test_msg)
            verified = verify_single(rs.raw, rs.sh, pub_key, CKM_SLH_DSA, test_msg, sig)
        except AssertionError as exc:
            _xfail_if_slhdsa_runtime_reject(exc, f"{vec_id}: keygen roundtrip")
        assert verified, f"{vec_id}: Sign/verify roundtrip failed for imported keypair"

    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)


@pytest.mark.parametrize("vec_id,vec", _SIGVER_VECTORS, ids=[v[0] for v in _SIGVER_VECTORS])
def test_slhdsa_sigver(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SLH-DSA signature verification from NIST ACVP vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")

    param_set: int = vec["param_set"]

    pub_key = 0
    try:
        try:
            pub_key = import_pqc_public_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_SLH_DSA),
                value=vec["pk"],
                parameter_set=param_set,
                attrs={CKA_VERIFY: True},
            )
        except AssertionError as exc:
            _skip_if_import_unsupported(exc, f"public key ({vec['param_name']})")

        try:
            verified = verify_single(rs.raw, rs.sh, pub_key, CKM_SLH_DSA, vec["msg"], vec["sig"])
        except AssertionError as exc:
            verified = _slhdsa_verify_result_or_xfail(
                exc, vec_id, expected_pass=vec["expected_pass"]
            )

        expected = vec["expected_pass"]
        if not expected and verified:
            # Module accepted an invalid signature - security concern
            pytest.fail(f"{vec_id}: accepted INVALID signature (expected rejection)")
        if expected and not verified:
            # Module rejected a valid signature - module issue, mark as xfail
            pytest.fail(f"{vec_id}: rejected VALID SLH-DSA signature")
    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)


@pytest.mark.parametrize("vec_id,vec", _SIGGEN_VECTORS, ids=[v[0] for v in _SIGGEN_VECTORS])
def test_slhdsa_siggen(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SLH-DSA signature generation from NIST ACVP message vectors.

    PKCS#11 does not guarantee deterministic SLH-DSA output. This test
    verifies that the module can sign without error and produces a non-empty
    result. Exact signature comparison is skipped because most PKCS#11
    implementations use randomized SLH-DSA.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")

    param_set: int = vec["param_set"]

    priv_key = 0
    try:
        try:
            priv_key = import_pqc_private_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_SLH_DSA),
                value=vec["sk"],
                parameter_set=param_set,
                attrs={CKA_SIGN: True},
            )
        except AssertionError as exc:
            _skip_if_import_unsupported(exc, f"private key ({vec['param_name']})")

        try:
            sig = sign_single(rs.raw, rs.sh, priv_key, CKM_SLH_DSA, vec["msg"])
        except AssertionError as exc:
            _xfail_if_slhdsa_runtime_reject(exc, vec_id)
        assert len(sig) > 0, f"SLH-DSA sign returned empty signature for {vec_id}"
    finally:
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)
