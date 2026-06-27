"""Conformance: C_Verify / C_VerifyFinal / C_Digest / C_EncryptFinal MUST
terminate the operation.

PKCS#11 v3.0/v3.1 makes the termination guarantee UNCONDITIONAL:
  - C_Verify / C_VerifyFinal: "A call to C_Verify[Final] always terminates the
    active verification operation" (whether it returns CKR_OK,
    CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE, CKR_ARGUMENTS_BAD, ...).
  - C_Digest: "A call to C_Digest always terminates the active digest operation
    unless it returns CKR_BUFFER_TOO_SMALL" (so with an adequate output buffer,
    any return code must terminate the op).

A provider that leaves the operation active after a rejection violates the spec:
the next C_*Init then returns CKR_OPERATION_ACTIVE.

Observed offenders fail on DIFFERENT operations / inputs, so we probe several:
  - verify: wrong-LENGTH sig -> CKR_SIGNATURE_LEN_RANGE, op left active (some modules);
  - verify: empty sig -> CKR_ARGUMENTS_BAD, op left active (some modules; terminates
    fine on CKR_SIGNATURE_INVALID);
  - verify AND digest: empty input -> CKR_ARGUMENTS_BAD, op left active (some modules;
    real-suite cascade observed in digest, test_acvp_hash SHA2-224 tc148,
    a 0-length message).

Under the shared module-scoped session this single dangling operation cascaded
CKR_OPERATION_ACTIVE onto thousands of unrelated tests; the harness now recovers
the shared session (see tests/test_operation_active_recovery.py) and THIS test
attributes the genuine provider bug to its source as a lifecycle
self-contradiction (the op returned a verdict, then did not honor termination).

Runs on a fresh function-scoped session so any operation a non-compliant provider
leaves dangling dies with the session.
"""

from __future__ import annotations

import ctypes
import hashlib
from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.recipes import (
    _cancel_operation,
    destroy_quietly,
    encrypt_multipart,
    sign_single,
    to_ubyte_buf,
)
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_DIGEST,
    CKF_ENCRYPT,
    CKF_VERIFY,
    CKM,
    CKM_AES_CBC,
    CKM_ECDSA,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_CANCEL_FAILED,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.testcases.conftest import (
    classify_lifecycle_effect,
    classify_negative_rv,
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import (
    generate_key_for_encrypt,
    get_test_plaintext_bytes,
    make_mech_param_or_skip,
)

# Crypto-operation rejection codes meaning "advertised but not operational" (an
# xfail, not a termination finding) when a multipart encrypt cannot run.
_ENCRYPT_RUNTIME_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
)

# AES-XTS does not support multipart on most implementations.
_CKK_AES_XTS_ID = 0
try:
    from pkcs11_check.raw.types_std import CKK_AES_XTS

    _CKK_AES_XTS_ID = int(CKK_AES_XTS)
except ImportError:
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


def _assert_verify_final_terminates(
    rs: Any,
    key: int,
    verify_mech: int,
    chunks: list[bytes],
    good_sig: bytes,
    wrong_value_sig: bytes,
    label: str,
) -> None:
    """Multipart analogue of `_assert_verify_terminates`.

    For each rejected-signature variant, C_VerifyInit + C_VerifyUpdate(chunks) +
    C_VerifyFinal(bad) must leave NO active operation. Fails on the first variant
    that leaves the verify operation active.
    """
    raw, sh = rs.raw, rs.sh
    mech = mech_simple(verify_mech)
    probed = 0
    for name, bad in _bad_sig_variants(good_sig, wrong_value_sig):
        expect_rv(raw.C_VerifyInit(sh, mech.byref(), key), CKR_OK)
        for chunk in chunks:
            expect_rv(raw.C_VerifyUpdate(sh, to_ubyte_buf(chunk), len(chunk)), CKR_OK)
        rv = int(raw.C_VerifyFinal(sh, to_ubyte_buf(bad), len(bad)))
        if rv == CKR_OK:
            continue  # variant unexpectedly verified; op terminated, try the next one
        probed += 1
        rv2 = int(raw.C_VerifyInit(sh, mech.byref(), key))
        if rv2 == CKR_OPERATION_ACTIVE:
            _cancel_operation(raw, sh, int(CKF_VERIFY))  # tidy; session closed after the test
            classify_lifecycle_effect(
                claimed_success=True,  # C_VerifyFinal returned a verdict (op complete per spec)
                effect_observed=True,  # yet a verify op is still active
                label=(
                    f"{label}: C_VerifyFinal({name}) returned {ckr_name(rv)} but left the verify "
                    f"operation active (next C_VerifyInit -> CKR_OPERATION_ACTIVE) -- the spec "
                    f"requires C_VerifyFinal to ALWAYS terminate the active verification operation"
                ),
            )
            return  # unreachable: classify_lifecycle_effect raised
        # Terminated correctly. rv2 started a fresh verify op -> complete it so the
        # next variant's C_VerifyInit starts clean.
        if rv2 == CKR_OK:
            for chunk in chunks:
                raw.C_VerifyUpdate(sh, to_ubyte_buf(chunk), len(chunk))
            raw.C_VerifyFinal(sh, to_ubyte_buf(bad), len(bad))
        else:
            _cancel_operation(raw, sh, int(CKF_VERIFY))
    if probed == 0:
        pytest.skip(f"{label}: no malformed signature produced a rejection to probe")


def test_c_verify_final_terminates_after_rejected_signature(p11_raw_session: Any) -> None:
    """Multipart RSA PKCS#1 v1.5: a rejected C_VerifyFinal must leave no active op.

    The multipart analogue of test_c_verify_terminates_after_rejected_rsa_signature.
    PKCS#11 ("Functions for verifying signatures and MACs", C_VerifyFinal): "A call
    to C_VerifyFinal always terminates the active verification operation" -- including
    a wrong-LENGTH signature (CKR_SIGNATURE_LEN_RANGE), which some modules' verify_final
    leave dangling exactly as their single-shot verify() does.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("SHA256_RSA_PKCS"):
        pytest.skip("SHA256_RSA_PKCS not supported by module")
    pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
    try:
        msg = b"pkcs11-check multipart verify-final termination conformance probe"
        chunks = [msg[: len(msg) // 2], msg[len(msg) // 2 :]]
        good_sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, msg)
        wrong = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"a different message")
        _assert_verify_final_terminates(
            rs, pub, CKM_SHA256_RSA_PKCS, chunks, good_sig, wrong, "RSA"
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)


# Digest mechanisms to try, in preference order (first advertised one is used).
_DIGEST_MECHS: tuple[tuple[str, int], ...] = (
    ("SHA256", CKM_SHA256),
    ("SHA224", CKM_SHA224),
    ("SHA_1", CKM_SHA_1),
)


def _finish_active_digest(raw: Any, sh: int) -> None:
    out = (ctypes.c_ubyte * 64)()
    out_len = ctypes.c_ulong(64)
    raw.C_DigestFinal(sh, out, ctypes.byref(out_len))


def test_digest_init_null_mechanism_cancels_active_digest(p11_raw_session: Any) -> None:
    """On v3+ interfaces, C_DigestInit(NULL) is an operation-cancel path."""
    rs = p11_raw_session
    for name, digest_mech in _DIGEST_MECHS:
        if not rs.has_mechanism(name):
            continue
        mech = mech_simple(digest_mech)
        expect_rv(rs.raw.C_DigestInit(rs.sh, mech.byref()), CKR_OK)
        rv = int(rs.raw.C_DigestInit(rs.sh, None))
        if rv != CKR_OK:
            _finish_active_digest(rs.raw, rs.sh)
            classify_negative_rv(
                rv,
                (CKR_OPERATION_CANCEL_FAILED,),
                label=f"{name}: C_DigestInit(NULL) cancel of active digest operation",
            )
            return

        restart_rv = int(rs.raw.C_DigestInit(rs.sh, mech.byref()))
        if restart_rv != CKR_OK:
            _finish_active_digest(rs.raw, rs.sh)
            classify_lifecycle_effect(
                claimed_success=True,
                effect_observed=True,
                label=(
                    f"{name}: C_DigestInit(NULL) returned CKR_OK but did not leave the "
                    f"session ready for a fresh digest init (next C_DigestInit -> "
                    f"{ckr_name(restart_rv)})"
                ),
            )
        _finish_active_digest(rs.raw, rs.sh)
        return
    pytest.skip("no SHA-1/SHA-224/SHA-256 digest mechanism supported by module")


def _assert_digest_terminates(rs: Any, digest_mech: int, label: str) -> None:
    """For several inputs, assert C_Digest terminated the digest operation.

    PKCS#11 ("Message digesting functions", C_Digest): "A call to C_Digest always
    terminates the active digest operation unless it returns CKR_BUFFER_TOO_SMALL"
    -- so with an adequate output buffer the operation MUST be terminated for ANY
    return code. The empty-message digest is itself well-defined (the hash of the
    empty string), so a compliant module returns CKR_OK for it; some modules instead
    return CKR_ARGUMENTS_BAD AND leave the digest operation active (the exact
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
    empty message (a known cascade trigger -- see test_acvp_hash)."""
    rs = p11_raw_session
    for name, mech in _DIGEST_MECHS:
        if rs.has_mechanism(name):
            _assert_digest_terminates(rs, mech, name)
            return
    pytest.skip("no SHA-1/SHA-224/SHA-256 digest mechanism supported by module")


def test_c_encrypt_terminates_after_multipart(
    p11_raw_session: Any, mech_multipart_encrypt_entry: MechEntry
) -> None:
    """A multipart C_Encrypt (Init+Update+Final) must leave no active operation.

    PKCS#11 ("Encryption functions", C_EncryptFinal): "A call to C_EncryptFinal
    always terminates the active encryption operation unless it returns
    CKR_BUFFER_TOO_SMALL ...". Parametrized over every multipart-encrypt mechanism
    the module advertises, on a FRESH function-scoped session so each mechanism's
    own termination is tested in isolation. Some modules leave the operation
    active after C_EncryptFinal for essentially every symmetric cipher - a
    widespread spec violation that the shared-session run can mask down to one
    collateral failure.
    """
    rs = p11_raw_session
    entry = mech_multipart_encrypt_entry
    config = entry.config
    if config is None:
        pytest.skip(f"{entry.mech_name}: no registry config")
    if config.key_type is not None and int(config.key_type) == _CKK_AES_XTS_ID:
        pytest.skip(f"{entry.mech_name}: AES-XTS multipart not widely supported")

    enc_key, _dec_key = generate_key_for_encrypt(rs, entry, config)
    try:
        packed = make_mech_param_or_skip(entry)  # PackedMechanism | None (may skip)
        mech_id = CKM(entry.mech_id)
        plaintext = get_test_plaintext_bytes()
        chunks = [plaintext[: len(plaintext) // 2], plaintext[len(plaintext) // 2 :]]
        try:
            encrypt_multipart(rs.raw, rs.sh, enc_key, mech_id, chunks, mech_param=packed)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _ENCRYPT_RUNTIME_REJECT_RVS,
                f"{entry.mech_name}: multipart encrypt not operational",
            )
            return
        probe = packed if packed is not None else mech_simple(mech_id)
        rv2 = int(rs.raw.C_EncryptInit(rs.sh, probe.byref(), enc_key))
        _cancel_operation(rs.raw, rs.sh, int(CKF_ENCRYPT))  # tidy (session closed after the test)
        classify_lifecycle_effect(
            claimed_success=True,  # C_EncryptFinal completed (op complete per spec)
            effect_observed=(rv2 == CKR_OPERATION_ACTIVE),  # yet an encrypt op is still active
            label=(
                f"{entry.mech_name}: C_EncryptFinal completed but left the encrypt operation "
                f"active (next C_EncryptInit -> {ckr_name(rv2)}) -- the spec requires "
                f"C_EncryptFinal to terminate the active encryption operation"
            ),
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, enc_key)


_NULL_ARG_ENC_DEC_CASES = (
    pytest.param("encrypt", "single", "input", id="encrypt-input"),
    pytest.param("encrypt", "single", "length", id="encrypt-length"),
    pytest.param("encrypt", "update", "input", id="encrypt-update-input"),
    pytest.param("encrypt", "update", "length", id="encrypt-update-length"),
    pytest.param("decrypt", "single", "input", id="decrypt-input"),
    pytest.param("decrypt", "single", "length", id="decrypt-length"),
    pytest.param("decrypt", "update", "input", id="decrypt-update-input"),
    pytest.param("decrypt", "update", "length", id="decrypt-update-length"),
)


def _start_aes_cbc_op(rs: Any, operation: str, key: int, mech: Any) -> int:
    if operation == "encrypt":
        return int(rs.raw.C_EncryptInit(rs.sh, mech.byref(), key))
    if operation == "decrypt":
        return int(rs.raw.C_DecryptInit(rs.sh, mech.byref(), key))
    raise ValueError(f"unknown operation: {operation}")


def _enc_dec_cancel_flag(operation: str) -> int:
    if operation == "encrypt":
        return int(CKF_ENCRYPT)
    if operation == "decrypt":
        return int(CKF_DECRYPT)
    raise ValueError(f"unknown operation: {operation}")


def _call_null_arg_enc_dec(rs: Any, operation: str, call_kind: str, null_arg: str) -> int:
    data = to_ubyte_buf(bytes(range(16)))
    out = (ctypes.c_ubyte * 64)()
    out_len = ctypes.c_ulong(64)
    data_arg = None if null_arg == "input" else data
    len_arg = None if null_arg == "length" else ctypes.byref(out_len)
    if operation == "encrypt":
        if call_kind == "single":
            return int(rs.raw.C_Encrypt(rs.sh, data_arg, 16, out, len_arg))
        if call_kind == "update":
            return int(rs.raw.C_EncryptUpdate(rs.sh, data_arg, 16, out, len_arg))
    if operation == "decrypt":
        if call_kind == "single":
            return int(rs.raw.C_Decrypt(rs.sh, data_arg, 16, out, len_arg))
        if call_kind == "update":
            return int(rs.raw.C_DecryptUpdate(rs.sh, data_arg, 16, out, len_arg))
    raise ValueError(f"unknown operation/call kind: {operation}/{call_kind}")


@pytest.mark.parametrize("operation,call_kind,null_arg", _NULL_ARG_ENC_DEC_CASES)
def test_null_argument_rejection_terminates_encrypt_decrypt_operation(
    p11_raw_session: Any,
    operation: str,
    call_kind: str,
    null_arg: str,
) -> None:
    """Clean invalid-argument rejections in encrypt/decrypt paths must terminate state."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_CBC"):
        pytest.skip("AES_CBC not supported by module")

    key = gen_aes_key_or_xfail(rs, 128, purpose="AES-CBC null-argument lifecycle")
    mech = mech_bytes(CKM_AES_CBC, bytes(16))
    label = f"C_{operation.capitalize()}{'Update' if call_kind == 'update' else ''}"
    try:
        expect_rv(_start_aes_cbc_op(rs, operation, key, mech), CKR_OK)
        rv = _call_null_arg_enc_dec(rs, operation, call_kind, null_arg)
        restart_rv = _start_aes_cbc_op(rs, operation, key, mech)
        if restart_rv == CKR_OPERATION_ACTIVE:
            _cancel_operation(rs.raw, rs.sh, _enc_dec_cancel_flag(operation))
            classify_lifecycle_effect(
                claimed_success=True,
                effect_observed=True,
                label=(
                    f"{label} with NULL {null_arg} pointer returned {ckr_name(rv)} but "
                    f"left the {operation} operation active (next init -> "
                    "CKR_OPERATION_ACTIVE)"
                ),
            )
        if restart_rv != CKR_OK:
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label=f"{label}:state-after-null-arg-reject",
                operation=label,
                actual=restart_rv,
                summary=(
                    f"{label} with NULL {null_arg} pointer returned {ckr_name(rv)}; "
                    f"fresh {operation} init after rejection returned {ckr_name(restart_rv)}"
                ),
            )
        _cancel_operation(rs.raw, rs.sh, _enc_dec_cancel_flag(operation))
        if rv == CKR_OK:
            fail_as(
                "accepted_invalid",
                kind="crypto",
                label=f"{label}:null-pointer-nonzero-length",
                operation=label,
                actual=rv,
                summary=f"{label} accepted NULL {null_arg} pointer with non-zero length",
            )
        classify_negative_rv(
            rv,
            (CKR_ARGUMENTS_BAD,),
            label=f"{label} with NULL {null_arg} pointer and non-zero length",
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, key)
