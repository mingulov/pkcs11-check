"""NIST ACVP SLH-DSA test vectors - the ONLY source for SLH-DSA vectors.

Tests SLH-DSA key generation, signature verification and generation using official
NIST ACVP vectors. Requires: scripts/fetch-optional-data.sh acvp

Skips gracefully if ACVP vectors not cloned or mechanism unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as, set_mechanism
from pkcs11_check.raw.pack_mechanisms import mech_sign_context
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_pqc_private_key,
    import_pqc_public_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_VERIFY,
    CKF_VERIFY,
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
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._signature_policy import (
    NON_CLEAN_SIGNATURE_REJECT_RVS,
    SIGNATURE_REJECT_RVS,
    signature_rejected_or_xfail,
)
from pkcs11_check.testcases.acvp.acvp_loader import ACVP_AVAILABLE, load_acvp_vectors
from pkcs11_check.testcases.conftest import (
    is_known_error,
    skip_unless_mechanism_flag,
    xfail_if_known_ckr,
)

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

# import-audit D3 boundary: SLH-DSA is advertised when these sites run (has_mechanism gate
# precedes every import). For PQC the genuine-absence signal IS mechanism
# advertisement -- there is no curve-absence CKR analogue. So once advertised,
# ANY clean import reject is "advertised but not operational" -> xfail (mirrors
# the ML-DSA precedent in test_wycheproof_mldsa* and the documented ML-KEM
# raw-private import convention). The previous skip/xfail
# split (CKR_FUNCTION_FAILED alone xfailed; the rest skipped) was an incoherent
# asymmetry -- both buckets are the same not-operational signal.
_PQC_IMPORT_NOT_OPERATIONAL_RVS = (
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_KEY_SIZE_RANGE,
    CKR_FUNCTION_FAILED,
)

_SLHDSA_RUNTIME_REJECT_RVS = (
    *NON_CLEAN_SIGNATURE_REJECT_RVS,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _xfail_if_import_not_operational(exc: AssertionError, label: str) -> None:
    """Advertised SLH-DSA whose canonical key import is refused -> xfail.

    A clean import reject (any code in ``_PQC_IMPORT_NOT_OPERATIONAL_RVS``) on an
    advertised mechanism is "advertised but not operational" per the
    classification model -- recorded as xfail, never hidden as skip. A non-CKR
    AssertionError (harness/ctypes bug) propagates.
    """
    if isinstance(exc, CkrAssertionError) and is_known_error(exc, _PQC_IMPORT_NOT_OPERATIONAL_RVS):
        classify(
            "not_operational",
            kind="crypto",
            label=f"SLH-DSA:import ({label})",
            summary=not_operational_reason(f"SLH-DSA:import ({label})", ckr_name(exc.rv)),
        )
    raise exc


def _xfail_if_slhdsa_runtime_reject(exc: AssertionError, label: str) -> None:
    xfail_if_known_ckr(
        exc,
        _SLHDSA_RUNTIME_REJECT_RVS,
        f"{label}: advertised SLH-DSA operation is not operational",
    )
    raise exc


def _slhdsa_verify_result_or_xfail(exc: AssertionError, label: str, *, expected_pass: bool) -> bool:
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
        ctx_hex = inp.get("context", "")
        if not pk or not msg or not sig:
            continue

        merged: dict[str, Any] = {
            "param_set": param_set,
            "param_name": param_name,
            "pk": bytes.fromhex(pk),
            "msg": bytes.fromhex(msg),
            "sig": bytes.fromhex(sig),
            "context": bytes.fromhex(ctx_hex) if ctx_hex else b"",
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
    # SLH-DSA signing is very slow, so keep minimal: the first vector per
    # parameter set, plus the first vector of the opposite context shape, so
    # both mechanism-parameter representations (NULL and explicit context)
    # stay covered no matter how the corpus orders its tests. PreHash groups
    # are skipped: their messages are digests for the hash-sign mechanisms,
    # not pure CKM_SLH_DSA inputs.
    taken_shapes: dict[str, set[bool]] = {}
    for vec in all_vecs:
        inp = vec["input"]
        group = vec["group"]
        if group.get("preHash") == "preHash":
            continue
        param_name = group.get("parameterSet", "")
        param_set = _PARAM_SET_MAP.get(param_name)
        if param_set is None:
            continue

        sk = inp.get("sk", "")
        msg = inp.get("message", "")
        if not sk or not msg:
            continue

        ctx_hex = inp.get("context", "")
        shapes = taken_shapes.setdefault(param_name, set())
        if bool(ctx_hex) in shapes:
            continue
        shapes.add(bool(ctx_hex))

        merged: dict[str, Any] = {
            "param_set": param_set,
            "param_name": param_name,
            "sk": bytes.fromhex(sk),
            "msg": bytes.fromhex(msg),
            "context": bytes.fromhex(ctx_hex) if ctx_hex else b"",
            "tc_id": inp.get("tcId", 0),
        }
        vec_id = f"sigGen-{param_name}-tc{merged['tc_id']}"
        result.append((vec_id, merged))
    return result


_KEYGEN_VECTORS = _load_keygen_vectors()
_SIGVER_VECTORS = _load_sigver_vectors()
_SIGGEN_VECTORS = _load_siggen_vectors()


@pytest.mark.parametrize("vec_id,vec", _KEYGEN_VECTORS, ids=[v[0] for v in _KEYGEN_VECTORS])
def test_slhdsa_keygen(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SLH-DSA key generation test from NIST ACVP vectors.

    Imports the expected private key and verifies it can be used for signing,
    with the expected public key used for verification.
    """
    rs = p11_module_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")
    # Roundtrip below signs then verifies with CKM_SLH_DSA: declare C_Sign
    # only, one call -- C_Verify is backstopped by test_slhdsa_sigver.
    set_mechanism("SLH_DSA", operation="C_Sign", expect_success=True)

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
            _xfail_if_import_not_operational(exc, f"private key ({vec['param_name']})")

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
            _xfail_if_import_not_operational(exc, f"public key ({vec['param_name']})")

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
def test_slhdsa_sigver(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SLH-DSA signature verification from NIST ACVP vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")
    skip_unless_mechanism_flag(rs, CKM_SLH_DSA, int(CKF_VERIFY))

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
            _xfail_if_import_not_operational(exc, f"public key ({vec['param_name']})")

        # Verify the signature, passing context when non-empty
        context = vec.get("context", b"")
        if isinstance(context, str):
            context = bytes.fromhex(context) if context else b""
        mech_param = mech_sign_context(CKM_SLH_DSA, context=context) if context else None
        try:
            verified = verify_single(
                rs.raw,
                rs.sh,
                pub_key,
                CKM_SLH_DSA,
                vec["msg"],
                vec["sig"],
                mech_param=mech_param,
            )
        except AssertionError as exc:
            verified = _slhdsa_verify_result_or_xfail(
                exc, vec_id, expected_pass=vec["expected_pass"]
            )

        expected = vec["expected_pass"]
        if not expected and verified:
            # Module accepted an invalid signature - security concern
            fail_as(
                "accepted_invalid",
                kind="crypto",
                label="SLH-DSA:verify",
                summary=f"{vec_id}: accepted INVALID signature (expected rejection)",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        if expected and not verified:
            # Module rejected a valid signature - crypto-correctness break
            fail_as(
                "wrong_result",
                kind="crypto",
                label="SLH-DSA:verify",
                summary=f"{vec_id}: rejected VALID SLH-DSA signature",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)


@pytest.mark.parametrize("vec_id,vec", _SIGGEN_VECTORS, ids=[v[0] for v in _SIGGEN_VECTORS])
def test_slhdsa_siggen(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """SLH-DSA signature generation from NIST ACVP message vectors.

    PKCS#11 does not guarantee deterministic SLH-DSA output. This test
    verifies that the module can sign without error and produces a non-empty
    result. Exact signature comparison is skipped because most PKCS#11
    implementations use randomized SLH-DSA.
    """
    rs = p11_module_session
    if not rs.has_mechanism("SLH_DSA"):
        pytest.skip("SLH_DSA not supported")
    set_mechanism("SLH_DSA", operation="C_Sign", expect_success=True)

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
            _xfail_if_import_not_operational(exc, f"private key ({vec['param_name']})")

        # Sign with the vector's context, mirroring sigVer: non-empty context
        # selects CK_SIGN_ADDITIONAL_CONTEXT, pure vectors keep NULL params.
        context = vec.get("context", b"")
        if isinstance(context, str):
            context = bytes.fromhex(context) if context else b""
        mech_param = mech_sign_context(CKM_SLH_DSA, context=context) if context else None
        try:
            sig = sign_single(
                rs.raw, rs.sh, priv_key, CKM_SLH_DSA, vec["msg"], mech_param=mech_param
            )
        except AssertionError as exc:
            _xfail_if_slhdsa_runtime_reject(exc, vec_id)
        assert len(sig) > 0, f"SLH-DSA sign returned empty signature for {vec_id}"
    finally:
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)
