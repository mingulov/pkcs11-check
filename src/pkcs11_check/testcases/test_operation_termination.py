"""Conformance: a single-shot C_Verify MUST terminate the operation.

PKCS#11 v3.0/v3.1, "Functions for verifying signatures and MACs", C_Verify:

    "The verification operation MUST have been initialized with C_VerifyInit. A
     call to C_Verify always terminates the active verification operation."

The termination guarantee is UNCONDITIONAL -- it holds whether C_Verify returns
CKR_OK, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_ARGUMENTS_BAD, or
any other code. A provider that leaves the verify operation active after
rejecting a signature violates the spec: the next C_VerifyInit then returns
CKR_OPERATION_ACTIVE.

Observed offenders fail on DIFFERENT malformations, so we probe several:
  - kryoptic v1.5.0  leaves the op active after a wrong-LENGTH sig
    (CKR_SIGNATURE_LEN_RANGE);
  - tpm2-pkcs11      leaves the op active after an empty / too-long sig
    (CKR_ARGUMENTS_BAD), but terminates correctly on CKR_SIGNATURE_INVALID.

Under the shared module-scoped session this single dangling operation cascaded
CKR_OPERATION_ACTIVE onto thousands of unrelated tests; the harness now recovers
the shared session (see tests/test_operation_active_recovery.py) and THIS test
attributes the genuine provider bug to its source as a Type-C lifecycle
self-contradiction (C_Verify returned a verdict, then did not honor termination).

Runs on a fresh function-scoped session so any operation a non-compliant provider
leaves dangling dies with the session.
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
)
from pkcs11_check.testcases.conftest import (
    classify_lifecycle_effect,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
)


def _cancel_verify(raw: Any, sh: int) -> None:
    """Best-effort cancel of any active verify op (no-op on pre-v3.0 modules)."""
    try:
        raw.C_SessionCancel(sh, int(CKF_VERIFY))
    except AttributeError:
        pass


def _bad_sig_variants(good_sig: bytes, wrong_value_sig: bytes) -> list[tuple[str, bytes]]:
    """Malformations that should each be REJECTED -- and, per spec, each terminate
    the operation. Different non-compliant providers fail on different ones."""
    return [
        ("too-short", good_sig[:-1]),
        ("too-long", good_sig + b"\x00\x00"),
        ("empty", b""),
        ("all-zero", bytes(len(good_sig))),
        ("wrong-value", wrong_value_sig),
    ]


def _assert_verify_terminates(
    rs: Any,
    key: int,
    verify_mech: int,
    msg: bytes,
    good_sig: bytes,
    wrong_value_sig: bytes,
    label: str,
) -> None:
    """For each rejected-signature variant, assert C_Verify terminated the op.

    Fails on the FIRST variant that leaves the operation active (one offending
    malformation is enough to surface the spec violation).
    """
    raw, sh = rs.raw, rs.sh
    mech = mech_simple(verify_mech)
    probed = 0
    for name, bad in _bad_sig_variants(good_sig, wrong_value_sig):
        expect_rv(raw.C_VerifyInit(sh, mech.byref(), key), CKR_OK)
        rv = int(raw.C_Verify(sh, to_ubyte_buf(msg), len(msg), to_ubyte_buf(bad), len(bad)))
        if rv == CKR_OK:
            continue  # variant unexpectedly verified; op terminated, try the next one
        probed += 1
        rv2 = int(raw.C_VerifyInit(sh, mech.byref(), key))
        if rv2 == CKR_OPERATION_ACTIVE:
            _cancel_verify(raw, sh)  # tidy (best-effort; session is closed after the test anyway)
            classify_lifecycle_effect(
                claimed_success=True,  # C_Verify returned a verdict (op complete per spec)
                effect_observed=True,  # yet a verify op is still active
                label=(
                    f"{label}: C_Verify({name}) returned {ckr_name(rv)} but left the verify "
                    f"operation active (next C_VerifyInit -> CKR_OPERATION_ACTIVE) -- the spec "
                    f"requires C_Verify to ALWAYS terminate the active verification operation"
                ),
            )
            return  # unreachable: classify_lifecycle_effect raised
        # Terminated correctly. rv2 started a fresh verify op -> complete it so the
        # next variant's C_VerifyInit starts clean.
        if rv2 == CKR_OK:
            raw.C_Verify(sh, to_ubyte_buf(msg), len(msg), to_ubyte_buf(bad), len(bad))
        else:
            _cancel_verify(raw, sh)
    if probed == 0:
        pytest.skip(f"{label}: no malformed signature produced a rejection to probe")
    # Every probed rejection terminated the operation -> spec-compliant.


def test_c_verify_terminates_after_rejected_rsa_signature(p11_raw_session: Any) -> None:
    """RSA PKCS#1 v1.5: a rejected C_Verify must leave no active operation."""
    rs = p11_raw_session
    if not rs.has_mechanism("SHA256_RSA_PKCS"):
        pytest.skip("SHA256_RSA_PKCS not supported by module")
    pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
    try:
        msg = b"pkcs11-check operation-termination conformance probe"
        good_sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, msg)
        # structurally valid, wrong hash -> typically CKR_SIGNATURE_INVALID
        wrong = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"a different message")
        _assert_verify_terminates(rs, pub, CKM_SHA256_RSA_PKCS, msg, good_sig, wrong, "RSA")
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
        wrong = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, hashlib.sha256(b"different").digest())
        _assert_verify_terminates(rs, pub, CKM_ECDSA, digest, good_sig, wrong, "ECDSA")
    finally:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)
