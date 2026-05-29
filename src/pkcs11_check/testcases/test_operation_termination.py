"""Conformance: a single-shot C_Verify MUST terminate the operation.

PKCS#11 v3.0/v3.1, "Functions for verifying signatures and MACs", C_Verify:

    "The verification operation MUST have been initialized with C_VerifyInit. A
     call to C_Verify always terminates the active verification operation."
    "A successful call to C_Verify should return either the value CKR_OK
     (indicating that the supplied signature is valid) or CKR_SIGNATURE_INVALID
     (indicating that the supplied signature is invalid). If the signature can
     be seen to be invalid purely on the basis of its length, then
     CKR_SIGNATURE_LEN_RANGE should be returned. In any of these cases, the
     active verification operation is terminated."

So CKR_SIGNATURE_INVALID and CKR_SIGNATURE_LEN_RANGE are EXPLICITLY terminal
outcomes. A provider that leaves the verify operation active after one of them
violates the spec: the next C_VerifyInit then returns CKR_OPERATION_ACTIVE.

Observed offenders: kryoptic v1.5.0 and tpm2-pkcs11 (across RSA, ECDSA, PSS,
HMAC, and PQC verify mechanisms). Under the shared module-scoped session this
single dangling operation cascaded CKR_OPERATION_ACTIVE onto thousands of
unrelated tests; the harness now cancels dangling operations on each handout
(see tests/test_module_session_hygiene.py), and THIS test attributes the
genuine provider bug to its source as a Type-C lifecycle self-contradiction
(C_Verify returned a terminal verdict, then did not honor termination).

Runs on a fresh function-scoped session so the bug-trigger operation, if left
dangling by a non-compliant provider, dies with the session.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import destroy_quietly, sign_single, to_ubyte_buf
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CKF_VERIFY,
    CKM_ECDSA,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases.conftest import (
    classify_lifecycle_effect,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
)

_TERMINAL_REJECTIONS = (CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE)


def _cancel_verify(raw: Any, sh: int) -> None:
    """Best-effort cancel of any active verify op (no-op on pre-v3.0 modules)."""
    try:
        raw.C_SessionCancel(sh, int(CKF_VERIFY))
    except AttributeError:
        pass


def _assert_verify_terminates(
    rs: Any, key: int, verify_mech: int, msg: bytes, good_sig: bytes, label: str
) -> None:
    """Reject a signature, then assert the verify operation was terminated."""
    raw, sh = rs.raw, rs.sh
    bad_sig = good_sig[:-1]  # one byte short -> a length-based terminal rejection
    mech = mech_simple(verify_mech)

    expect_rv(raw.C_VerifyInit(sh, mech.byref(), key), CKR_OK)
    rv = int(raw.C_Verify(sh, to_ubyte_buf(msg), len(msg), to_ubyte_buf(bad_sig), len(bad_sig)))

    if rv == CKR_OK:
        _cancel_verify(raw, sh)
        pytest.skip(f"{label}: truncated signature was accepted; cannot probe rejection path")
    if rv not in _TERMINAL_REJECTIONS:
        # A clean-but-unexpected rejection code: a noted deviation, not this finding.
        _cancel_verify(raw, sh)
        pytest.xfail(
            f"{label}: C_Verify rejected with {ckr_name(rv)} "
            f"(expected CKR_SIGNATURE_INVALID/CKR_SIGNATURE_LEN_RANGE)"
        )

    # rv is a terminal verdict -> the spec REQUIRES the operation be terminated.
    rv2 = int(raw.C_VerifyInit(sh, mech.byref(), key))
    _cancel_verify(raw, sh)  # tidy whichever op is now active
    if rv2 not in (CKR_OK, CKR_OPERATION_ACTIVE):
        pytest.xfail(f"{label}: probing C_VerifyInit returned unexpected {ckr_name(rv2)}")

    classify_lifecycle_effect(
        claimed_success=True,  # C_Verify returned a terminal verdict (op complete per spec)
        effect_observed=(rv2 == CKR_OPERATION_ACTIVE),  # yet a verify op is still active
        label=(
            f"{label}: C_Verify returned a terminal verdict ({ckr_name(rv)}) but left the "
            f"verify operation active (next C_VerifyInit -> CKR_OPERATION_ACTIVE) -- the spec "
            f"requires C_Verify to always terminate the active verification operation"
        ),
    )


def test_c_verify_terminates_after_rejected_rsa_signature(p11_raw_session: Any) -> None:
    """RSA PKCS#1 v1.5: a rejected C_Verify must leave no active operation."""
    rs = p11_raw_session
    if not rs.has_mechanism("SHA256_RSA_PKCS"):
        pytest.skip("SHA256_RSA_PKCS not supported by module")
    pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
    try:
        msg = b"pkcs11-check operation-termination conformance probe"
        good_sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, msg)
        _assert_verify_terminates(rs, pub, CKM_SHA256_RSA_PKCS, msg, good_sig, "RSA")
    finally:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)


def test_c_verify_terminates_after_rejected_ecdsa_signature(p11_raw_session: Any) -> None:
    """ECDSA P-256: a rejected C_Verify must leave no active operation."""
    rs = p11_raw_session
    if not rs.has_mechanism("ECDSA"):
        pytest.skip("ECDSA not supported by module")
    pub, priv = gen_ec_keypair_or_xfail(rs, encode_named_curve_parameters("secp256r1"))
    try:
        # CKM_ECDSA (raw) signs the message hash directly; P-256 -> 32-byte input.
        digest = hashlib.sha256(b"pkcs11-check operation-termination conformance probe").digest()
        good_sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
        _assert_verify_terminates(rs, pub, CKM_ECDSA, digest, good_sig, "ECDSA")
    finally:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)
