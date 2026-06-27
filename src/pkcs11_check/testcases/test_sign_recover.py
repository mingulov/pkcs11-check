"""Tests for C_SignRecoverInit / C_SignRecover and C_VerifyRecoverInit / C_VerifyRecover.

Happy-path functional tests exercising sign-recover and verify-recover operations.

Source: PKCS#11 v3.2 (C_SignRecoverInit, C_SignRecover,
        C_VerifyRecoverInit, C_VerifyRecover).

C_SignRecover produces a signature from which the original data can be recovered.
C_VerifyRecover takes a signature and recovers the original data (and verifies it).
The primary mechanism is CKM_RSA_X_509 (raw RSA, no padding).

For RSA X.509, the input data must be padded to exactly the modulus size (2048
bits -> 256 bytes).  The token performs raw modular exponentiation; the caller is
responsible for any padding.  CKM_RSA_X_509 is widely supported in hardware and
software tokens as the recovery-capable RSA mechanism.

These operations are only accessible via the raw C API - python-pkcs11 does not
expose high-level sign_recover() / verify_recover() methods on Key or Session
objects.  Tests use a ctypes subprocess in the same pattern as test_operation_state.py.

CK_FUNCTION_LIST indices (0-based, after the CK_VERSION field):
  C_SignRecoverInit = 45
  C_SignRecover     = 46
  C_VerifyRecoverInit = 51
  C_VerifyRecover     = 52
  C_GenerateKeyPair   = 59
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    sign_recover_single,
    verify_recover_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import CKM_RSA_X_509, CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases._raw_subprocess import parse_output as _parse_output
from pkcs11_check.testcases._raw_subprocess import run_raw_script
from pkcs11_check.testcases.conftest import KEYPAIR_RUNTIME_REJECT_RVS, assert_correct

pytestmark = pytest.mark.full

_SCRIPT_PREAMBLE = """\
import binascii
import ctypes
import sys
from ctypes import byref, c_ubyte, cast

from pkcs11_check.raw import CK_ATTRIBUTE_PTR, CK_OBJECT_HANDLE, RawPKCS11
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_SIGN_RECOVER,
    CKA_TOKEN,
    CKA_VERIFY_RECOVER,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_RSA,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_X_509,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.raw.bootstrap import close_session_quietly, get_slot_ids, login_user, open_session
from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, mech_simple, template


def _template_ptr(attrs):
    return cast(attrs.ptr, CK_ATTRIBUTE_PTR)


def _byte_array(data: bytes):
    return (c_ubyte * len(data)).from_buffer_copy(data)


raw = RawPKCS11.from_lib({module_path!r})
hSession = None
rv = raw.C_Initialize(None)
if rv not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
    print(f"FATAL:Initialize:0x{{rv:08x}}")
    sys.exit(1)

slot_ids = get_slot_ids(raw)
if len(slot_ids) <= {slot_index}:
    print(f"FATAL:GetSlotList:index={slot_index}:count={{len(slot_ids)}}")
    raw.C_Finalize(None)
    sys.exit(1)

hSession = open_session(raw, slot_ids[{slot_index}], CKF_SERIAL_SESSION | CKF_RW_SESSION)

import os as _os
_PIN = _os.environ.get("_P11CHECK_PIN")
if _PIN:
    login_user(raw, hSession, 1, _PIN.encode())
"""

_KEYGEN_SCRIPT = """\
    pub_template = template(
        attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_RSA),
        attr_ulong(CKA_MODULUS_BITS, 2048),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_VERIFY_RECOVER, True),
        attr_bytes(CKA_PUBLIC_EXPONENT, b"\\x01\\x00\\x01"),
    )
    prv_template = template(
        attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_RSA),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SIGN_RECOVER, True),
    )

    kg_mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
    hPub = CK_OBJECT_HANDLE(0)
    hPrv = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        hSession,
        kg_mech.byref(),
        _template_ptr(pub_template),
        pub_template.count,
        _template_ptr(prv_template),
        prv_template.count,
        byref(hPub),
        byref(hPrv),
    )
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:GenerateKeyPairUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:GenerateKeyPair:0x{rv:08x}")
        sys.exit(1)
    print(f"KEYGEN_OK:{hPub.value}:{hPrv.value}")
"""

_SCRIPT_CLEANUP = """\
close_session_quietly(raw, hSession)
raw.C_Finalize(None)
"""


def _run_script(
    module_path: str,
    slot_index: int,
    pin: str | None,
    script_body: str,
    timeout: int = 30,
) -> tuple[int, str, str]:
    # The PIN is forwarded to the child via the env (run_raw_script's ``pin``
    # arg), never interpolated into the script text -- so it cannot appear in
    # the child argv (``ps``/``/proc``) or any traceback.
    return run_raw_script(
        _SCRIPT_PREAMBLE.format(
            module_path=module_path,
            slot_index=slot_index,
        ),
        script_body,
        cleanup=_SCRIPT_CLEANUP,
        timeout=timeout,
        pin=pin,
    )


def _get_params(p11_config: Any) -> tuple[str, int, str | None]:
    """Extract (module_path, slot_index, pin) from config fixture.

    The PIN is returned as a plain ``str`` (or None) only to be forwarded into
    the child env by :func:`_run_script`; it is never embedded in script text.
    """
    module_path = str(p11_config.module)
    slot_index = p11_config.slot if p11_config.slot is not None else 0
    pin = p11_config.pin.get_secret_value() if p11_config.pin else None
    return module_path, slot_index, pin


def _handle_subprocess_failure(returncode: int, stdout: str, stderr: str) -> None:
    """Fail or xfail a raw subprocess result after checking setup-reject fatals."""
    if returncode == 0:
        return

    fatals = [ln for ln in stdout.splitlines() if ln.startswith("FATAL:")]
    if fatals:
        detail = fatals[0]
        _, _, payload = detail.partition(":")
        label, _, rv_text = payload.partition(":")
        if label == "GenerateKeyPair":
            try:
                rv = int(rv_text, 16)
            except ValueError:
                rv = None
            if rv is not None and rv in KEYPAIR_RUNTIME_REJECT_RVS:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="RSA_PKCS_KEY_PAIR_GEN:keypair setup",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    actual=rv,
                    summary=f"RSA_PKCS_KEY_PAIR_GEN keypair setup rejected: {ckr_name(rv)}",
                )
    else:
        detail = f"stdout={stdout!r} stderr={stderr!r}"

    classify(
        "crash",
        label="sign-recover subprocess",
        summary=f"Subprocess failed: {detail}",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("p11_module")
class TestSignRecover:
    """C_SignRecover / C_VerifyRecover functional tests using CKM_RSA_X_509.

    C_SignRecover (Sec.5.10.6): Signs data with a private key using a mechanism
    that allows the original data to be recovered from the signature.

    C_VerifyRecover (Sec.5.11.6): Verifies a signature and recovers the original
    data from the signature using the corresponding public key.

    CKM_RSA_X_509 (raw RSA) is the standard mechanism for these operations.
    The input must be padded to the modulus size (2048 bits -> 256 bytes).
    """

    def test_sign_recover_produces_output(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover with RSA X.509 produces a 256-byte signature block.

        Steps:
        1. Generate RSA-2048 key pair with CKA_SIGN_RECOVER / CKA_VERIFY_RECOVER.
        2. C_SignRecoverInit(CKM_RSA_X_509, privateKey).
        3. C_SignRecover(padded_data) -> signature.
        4. Verify signature length equals modulus size (256 bytes).

        Source: PKCS#11 v3.2.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")

        module_path, slot_index, pin = _get_params(p11_config)

        script = (
            _KEYGEN_SCRIPT
            + """\
    sr_mech = mech_simple(CKM_RSA_X_509)

    # Input must be exactly 256 bytes (RSA-2048 modulus size)
    # Use PKCS#1 v1.5-style padding: 0x00 0x01 0xFF...FF 0x00 <data>
    data = b"Hello sign-recover"
    pad_len = 256 - 3 - len(data)
    padded = b"\\x00\\x01" + b"\\xff" * pad_len + b"\\x00" + data
    padded_buf = _byte_array(padded)

    rv = raw.C_SignRecoverInit(hSession, sr_mech.byref(), hPrv)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:SignRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Length query
    sig_len = ctypes.c_ulong(0)
    rv = raw.C_SignRecover(hSession, padded_buf, len(padded), None, byref(sig_len))
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:SignRecoverUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverLen:0x{rv:08x}")
        sys.exit(1)

    sig_buf = (c_ubyte * sig_len.value)()
    rv = raw.C_SignRecover(hSession, padded_buf, len(padded), sig_buf, byref(sig_len))
    if rv != CKR_OK:
        print(f"FATAL:SignRecover:0x{rv:08x}")
        sys.exit(1)

    sig_hex = binascii.hexlify(bytes(sig_buf[:sig_len.value])).decode()
    print(f"SIG_LEN:{sig_len.value}")
    print(f"SIG:{sig_hex}")
"""
        )

        returncode, stdout, stderr = _run_script(module_path, slot_index, pin, script)
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign-recover: {lines_map['SKIP']}")

        _handle_subprocess_failure(returncode, stdout, stderr)

        assert "SIG_LEN" in lines_map, f"Missing SIG_LEN in output: {stdout!r}"
        assert "SIG" in lines_map, f"Missing SIG in output: {stdout!r}"

        sig_len = int(lines_map["SIG_LEN"])
        assert sig_len == 256, f"RSA-2048 sign-recover output must be 256 bytes, got {sig_len}"

    def test_verify_recover_round_trip(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover then C_VerifyRecover recovers the original padded data.

        Steps:
        1. Generate RSA-2048 key pair.
        2. C_SignRecoverInit -> C_SignRecover(padded_data) -> signature.
        3. C_VerifyRecoverInit -> C_VerifyRecover(signature) -> recovered_data.
        4. Assert recovered_data == padded_data.

        Source: PKCS#11 v3.2.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")

        module_path, slot_index, pin = _get_params(p11_config)

        script = (
            _KEYGEN_SCRIPT
            + """\
    sr_mech = mech_simple(CKM_RSA_X_509)

    # Input: exactly 256 bytes with PKCS#1 type-1 padding
    data = b"Round-trip test data"
    pad_len = 256 - 3 - len(data)
    padded = b"\\x00\\x01" + b"\\xff" * pad_len + b"\\x00" + data
    padded_buf = _byte_array(padded)
    padded_hex = binascii.hexlify(padded).decode()
    print(f"ORIGINAL:{padded_hex}")

    # --- Sign-recover ---
    rv = raw.C_SignRecoverInit(hSession, sr_mech.byref(), hPrv)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:SignRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Length query
    sig_len = ctypes.c_ulong(0)
    rv = raw.C_SignRecover(hSession, padded_buf, len(padded), None, byref(sig_len))
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:SignRecoverUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverLen:0x{rv:08x}")
        sys.exit(1)

    sig_buf = (c_ubyte * sig_len.value)()
    rv = raw.C_SignRecover(hSession, padded_buf, len(padded), sig_buf, byref(sig_len))
    if rv != CKR_OK:
        print(f"FATAL:SignRecover:0x{rv:08x}")
        sys.exit(1)
    sig_bytes = bytes(sig_buf[:sig_len.value])
    sig_in = _byte_array(sig_bytes)
    print(f"SIG_LEN:{sig_len.value}")

    # --- Verify-recover ---
    rv = raw.C_VerifyRecoverInit(hSession, sr_mech.byref(), hPub)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:VerifyRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:VerifyRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Length query
    rec_len = ctypes.c_ulong(0)
    rv = raw.C_VerifyRecover(hSession, sig_in, len(sig_bytes), None, byref(rec_len))
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID):
        print(f"SKIP:VerifyRecoverUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:VerifyRecoverLen:0x{rv:08x}")
        sys.exit(1)

    rec_buf = (c_ubyte * rec_len.value)()
    rv = raw.C_VerifyRecover(hSession, sig_in, len(sig_bytes), rec_buf, byref(rec_len))
    if rv != CKR_OK:
        print(f"FATAL:VerifyRecover:0x{rv:08x}")
        sys.exit(1)

    recovered_hex = binascii.hexlify(bytes(rec_buf[:rec_len.value])).decode()
    print(f"RECOVERED:{recovered_hex}")
"""
        )

        returncode, stdout, stderr = _run_script(module_path, slot_index, pin, script)
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign/verify-recover: {lines_map['SKIP']}")

        _handle_subprocess_failure(returncode, stdout, stderr)

        assert "ORIGINAL" in lines_map, f"Missing ORIGINAL in output: {stdout!r}"
        assert "RECOVERED" in lines_map, f"Missing RECOVERED in output: {stdout!r}"

        original = lines_map["ORIGINAL"]
        recovered = lines_map["RECOVERED"]
        assert_correct(
            actual=recovered,
            expected=original,
            label="CKM_RSA_X_509:Sign/VerifyRecover round-trip",
            operation="C_VerifyRecover",
            mechanism="CKM_RSA_X_509",
        )

    def test_sign_recover_wrong_data_length(self, p11_config: Any, p11_module: Any) -> None:
        """C_SignRecover with wrong-length data returns a PKCS#11 error (not crash).

        For CKM_RSA_X_509 with a 2048-bit key, input must be exactly 256 bytes.
        Passing shorter data must return CKR_DATA_LEN_RANGE or CKR_ARGUMENTS_BAD
        (or similar), not crash or silently succeed.

        Source: PKCS#11 v3.2 error table.
        """
        if not _has_rsa_x509(p11_module):
            pytest.skip("CKM_RSA_X_509 not supported by this module")

        module_path, slot_index, pin = _get_params(p11_config)

        script = (
            _KEYGEN_SCRIPT
            + """\
    sr_mech = mech_simple(CKM_RSA_X_509)

    rv = raw.C_SignRecoverInit(hSession, sr_mech.byref(), hPrv)
    if rv in (CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED):
        print(f"SKIP:SignRecoverInitUnsupported:0x{rv:08x}")
        sys.exit(0)
    if rv != CKR_OK:
        print(f"FATAL:SignRecoverInit:0x{rv:08x}")
        sys.exit(1)

    # Data shorter than modulus - must be rejected
    short_data = b"too short"
    short_data_buf = _byte_array(short_data)
    sig_len = ctypes.c_ulong(256)
    sig_buf = (c_ubyte * 256)()
    rv = raw.C_SignRecover(hSession, short_data_buf, len(short_data), sig_buf, byref(sig_len))

    if rv == CKR_OK:
        print("RESULT:ACCEPTED_SHORT_DATA")
    else:
        print(f"RESULT:REJECTED:0x{rv:08x}")
        # Any non-OK return is acceptable - the module correctly rejected it
        acceptable = {CKR_DATA_LEN_RANGE, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
                      CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID}
        if rv not in acceptable:
            # Non-standard CKR - still a valid rejection; note it
            print(f"NOTE:NonStandardRejection:0x{rv:08x}")
"""
        )

        returncode, stdout, stderr = _run_script(module_path, slot_index, pin, script)
        lines_map = _parse_output(stdout)

        if "SKIP" in lines_map:
            pytest.skip(f"Module skipped sign-recover error test: {lines_map['SKIP']}")

        _handle_subprocess_failure(returncode, stdout, stderr)

        assert "RESULT" in lines_map, f"Missing RESULT in output: {stdout!r}"

        # The module should not silently accept wrong-length data.
        # Some modules pad internally and accept any length - this is non-standard
        # for CKM_RSA_X_509 but we don't fail on it; we just note it.
        result = lines_map["RESULT"]
        if result == "ACCEPTED_SHORT_DATA":
            classify(
                "honest_deviation",
                kind="crypto",
                label="CKM_RSA_X_509:C_SignRecover short data",
                operation="C_SignRecover",
                mechanism="CKM_RSA_X_509",
                summary=(
                    "Module accepted short data for CKM_RSA_X_509 C_SignRecover - "
                    "non-standard behaviour (spec requires CKR_DATA_LEN_RANGE)"
                ),
            )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _has_rsa_x509(p11_module: Any) -> bool:
    """Return True if the module's first token supports CKM_RSA_X_509."""
    slots = list(p11_module.get_slots(token_present=True))
    if not slots:
        return False

    mechs = {getattr(m, "name", str(m)) for m in slots[0].get_mechanisms()}
    return "RSA_X_509" in mechs


class TestSignRecoverRecipes:
    """In-process tests exercising sign_recover_single / verify_recover_single recipes."""

    @staticmethod
    def _check_sign_recover(rs: Any) -> None:
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        try:
            mech = mech_simple(CKM_RSA_X_509)
            rv = rs.raw.C_SignRecoverInit(rs.sh, mech.byref(), 0)
        except (AttributeError, TypeError):
            pytest.skip("C_SignRecoverInit not available")
        if rv == CKR_FUNCTION_NOT_SUPPORTED:
            pytest.skip("C_SignRecover not supported by module")

    @staticmethod
    def _gen_recover_key(rs: Any) -> tuple[int, int]:
        TestSignRecoverRecipes._check_sign_recover(rs)
        return gen_rsa_keypair(rs.raw, rs.sh, 2048)

    def test_sign_recover_single_returns_signature(self, p11_raw_session: Any) -> None:
        rs = p11_raw_session
        pub, priv = self._gen_recover_key(rs)
        try:
            data = b"\x00" + b"\xff" * 254
            sig = sign_recover_single(rs.raw, rs.sh, priv, CKM_RSA_X_509, data)
            assert isinstance(sig, bytes)
            assert len(sig) == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_verify_recover_round_trip(self, p11_raw_session: Any) -> None:
        """C_VerifyRecover should recover the original data from a valid signature.

        Some modules recover wrong/unexpected data on CKM_RSA_X_509 --
        the recovered bytes do not match the original padded input.
        """
        rs = p11_raw_session
        pub, priv = self._gen_recover_key(rs)
        try:
            data = b"\x00" + b"\xff" * 254
            sig = sign_recover_single(rs.raw, rs.sh, priv, CKM_RSA_X_509, data)
            valid, recovered = verify_recover_single(rs.raw, rs.sh, pub, CKM_RSA_X_509, sig)
            assert valid is True
            # Raw RSA (CKM_RSA_X_509) VerifyRecover returns sig^e mod n, i.e. the signed
            # value AS AN INTEGER. Compare as integers so a benign leading-zero / length
            # representation difference is not mis-flagged. A genuine integer mismatch IS a
            # crypto-correctness break (the module recovered the wrong value) -> wrong_result
            # (crypto fail), not a tolerable deviation. (Any documented per-module bug is
            # cross-referenced as KNOWN_ISSUE at the report layer, not hidden here.)
            recovered_int = int.from_bytes(recovered, "big") if recovered else -1
            if recovered_int != int.from_bytes(data, "big"):
                classify(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_RSA_X_509:C_VerifyRecover recovered data",
                    operation="C_VerifyRecover",
                    mechanism="CKM_RSA_X_509",
                    summary=(
                        "C_VerifyRecover recovered the wrong value for CKM_RSA_X_509 "
                        "(recovered integer != signed integer) -- crypto-correctness break"
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_verify_recover_invalid_signature(self, p11_raw_session: Any) -> None:
        """C_VerifyRecover should reject an invalid signature.

        Some modules return valid=True and non-empty recovered data for an
        invalid (all-zero) signature block, failing to detect the invalid input.
        """
        rs = p11_raw_session
        pub, priv = self._gen_recover_key(rs)
        try:
            bad_sig = b"\x00" * 256
            valid, recovered = verify_recover_single(rs.raw, rs.sh, pub, CKM_RSA_X_509, bad_sig)
            if valid is True or recovered != b"":
                classify(
                    "honest_deviation",
                    kind="crypto",
                    label="CKM_RSA_X_509:C_VerifyRecover invalid signature",
                    operation="C_VerifyRecover",
                    mechanism="CKM_RSA_X_509",
                    summary=(
                        f"Module C_VerifyRecover accepted invalid all-zero signature: "
                        f"valid={valid}, recovered={recovered!r} -- "
                        f"the signature block is not validated in C_VerifyRecover"
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
