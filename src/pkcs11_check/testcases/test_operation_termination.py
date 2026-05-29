"""Conformance: a single-shot C_Verify / C_Digest MUST terminate the operation.

PKCS#11 v3.0/v3.1 makes the termination guarantee UNCONDITIONAL:
  - C_Verify: "A call to C_Verify always terminates the active verification
    operation" (whether it returns CKR_OK, CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE, CKR_ARGUMENTS_BAD, ...).
  - C_Digest: "A call to C_Digest always terminates the active digest operation
    unless it returns CKR_BUFFER_TOO_SMALL" (so with an adequate output buffer,
    any return code must terminate the op).

A provider that leaves the operation active after a rejection violates the spec:
the next C_*Init then returns CKR_OPERATION_ACTIVE.

Observed offenders fail on DIFFERENT operations / inputs, so we probe several:
  - kryoptic v1.5.0  verify: wrong-LENGTH sig -> CKR_SIGNATURE_LEN_RANGE, op left active;
  - tpm2-pkcs11      verify: empty sig -> CKR_ARGUMENTS_BAD, op left active
    (terminates fine on CKR_SIGNATURE_INVALID);
  - BouncyHSM        verify AND digest: empty input -> CKR_ARGUMENTS_BAD, op left
    active (its real-suite cascade was in digest, test_acvp_hash SHA2-224 tc148,
    a 0-length message).

Under the shared module-scoped session this single dangling operation cascaded
CKR_OPERATION_ACTIVE onto thousands of unrelated tests; the harness now recovers
the shared session (see tests/test_operation_active_recovery.py) and THIS test
attributes the genuine provider bug to its source as a Type-C lifecycle
self-contradiction (the op returned a verdict, then did not honor termination).

Runs on a fresh function-scoped session so any operation a non-compliant provider
leaves dangling dies with the session.
"""

from __future__ import annotations

import ctypes
import hashlib
from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    _cancel_operation,
    destroy_quietly,
    sign_single,
    to_ubyte_buf,
)
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CKF_DIGEST,
    CKF_VERIFY,
    CKM_ECDSA,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA_1,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
)
from pkcs11_check.testcases.conftest import (
    classify_lifecycle_effect,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
)


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
            _cancel_operation(
                raw, sh, int(CKF_VERIFY)
            )  # tidy (best-effort; session is closed after the test anyway)
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
            _cancel_operation(raw, sh, int(CKF_VERIFY))
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


# Digest mechanisms to try, in preference order (first advertised one is used).
_DIGEST_MECHS: tuple[tuple[str, int], ...] = (
    ("SHA256", CKM_SHA256),
    ("SHA224", CKM_SHA224),
    ("SHA_1", CKM_SHA_1),
)


def _assert_digest_terminates(rs: Any, digest_mech: int, label: str) -> None:
    """For several inputs, assert C_Digest terminated the digest operation.

    PKCS#11 ("Message digesting functions", C_Digest): "A call to C_Digest always
    terminates the active digest operation unless it returns CKR_BUFFER_TOO_SMALL"
    -- so with an adequate output buffer the operation MUST be terminated for ANY
    return code. The empty-message digest is itself well-defined (the hash of the
    empty string), so a compliant module returns CKR_OK for it; BouncyHSM instead
    returns CKR_ARGUMENTS_BAD AND leaves the digest operation active (the exact
    cascade trigger observed in test_acvp_hash, SHA2-224 tc148, a 0-length msg).
    """
    raw, sh = rs.raw, rs.sh
    mech = mech_simple(digest_mech)
    for name, data in (("empty", b""), ("one-byte", b"\x00"), ("block", b"\x00" * 64)):
        expect_rv(raw.C_DigestInit(sh, mech.byref()), CKR_OK)
        out = (ctypes.c_ubyte * 64)()  # >= any SHA-1/2 digest length, so never BUFFER_TOO_SMALL
        out_len = ctypes.c_ulong(64)
        rv = int(raw.C_Digest(sh, to_ubyte_buf(data), len(data), out, ctypes.byref(out_len)))
        rv2 = int(raw.C_DigestInit(sh, mech.byref()))
        if rv2 == CKR_OPERATION_ACTIVE:
            _cancel_operation(raw, sh, int(CKF_DIGEST))
            classify_lifecycle_effect(
                claimed_success=True,  # C_Digest returned a verdict (op complete per spec)
                effect_observed=True,  # yet a digest op is still active
                label=(
                    f"{label}: C_Digest({name}) returned {ckr_name(rv)} but left the digest "
                    f"operation active (next C_DigestInit -> CKR_OPERATION_ACTIVE) -- the spec "
                    f"requires C_Digest to always terminate the active digest operation"
                ),
            )
            return  # unreachable: classify_lifecycle_effect raised
        # Terminated correctly. rv2 started a fresh digest op -> complete it so the
        # next input's C_DigestInit starts clean.
        if rv2 == CKR_OK:
            out2 = (ctypes.c_ubyte * 64)()
            out2_len = ctypes.c_ulong(64)
            raw.C_Digest(sh, to_ubyte_buf(data), len(data), out2, ctypes.byref(out2_len))
        else:
            _cancel_operation(raw, sh, int(CKF_DIGEST))


def test_c_digest_terminates_after_each_call(p11_raw_session: Any) -> None:
    """A single-shot C_Digest must leave no active operation, including for the
    empty message (BouncyHSM's cascade trigger -- see test_acvp_hash)."""
    rs = p11_raw_session
    for name, mech in _DIGEST_MECHS:
        if rs.has_mechanism(name):
            _assert_digest_terminates(rs, mech, name)
            return
    pytest.skip("no SHA-1/SHA-224/SHA-256 digest mechanism supported by module")
