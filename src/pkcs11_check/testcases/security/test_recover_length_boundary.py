"""Crash-safe length-boundary probes for sign/verify-recover APIs."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import compliance
from pkcs11_check.classification import fail_as
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.types_std import (
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security._boundary_values import requires_64bit_ck_ulong
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [
    pytest.mark.security,
    pytest.mark.subprocess,
    requires_64bit_ck_ulong,
]

_ISIZE_MAX_64 = 0x7FFFFFFFFFFFFFFF
_ISIZE_MAX_PLUS_1_64 = 0x8000000000000000
# Oversized output-length: low 32 bits = 256 (matches a 256-byte output buffer),
# high 32 bits set.  A module that writes only the low 32 bits of *pulDataLen
# leaves the high half intact, producing a huge value that drives an OOB copy.
_R6_INFLATED_PULDATALEN = (1 << 32) + 256

_BOUNDARY_LENGTHS = [
    pytest.param(_ISIZE_MAX_64, id="isize_max"),
    pytest.param(_ISIZE_MAX_PLUS_1_64, id="isize_max_plus_1"),
]


def _preamble(p11_config: Any) -> str:
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=pin_from_config(p11_config),
    )


def _parse_output_value(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


_RECOVER_SETUP = """
import ctypes
from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT,
    CKA_SIGN_RECOVER,
    CKA_TOKEN,
    CKA_VERIFY_RECOVER,
    CKK_RSA,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_X_509,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CK_ULONG,
)
from pkcs11_check.testcases.conftest import KEYPAIR_RUNTIME_REJECT_RVS


def _template_ptr(attrs):
    return ctypes.cast(attrs.ptr, CK_ATTRIBUTE_PTR)


def _byte_array(data):
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


_RECOVER_SETUP_RVS = tuple(int(rv) for rv in KEYPAIR_RUNTIME_REJECT_RVS) + (
    int(CKR_FUNCTION_NOT_SUPPORTED),
    int(CKR_KEY_FUNCTION_NOT_PERMITTED),
    int(CKR_MECHANISM_INVALID),
    int(CKR_OPERATION_NOT_INITIALIZED),
    int(CKR_TEMPLATE_INCOMPLETE),
    int(CKR_TEMPLATE_INCONSISTENT),
)


def _setup_xfail_rv(rv, purpose):
    print(f"SETUP_XFAIL:{purpose}: {ckr_name(rv)}")
    cleanup()
    raise SystemExit(0)


def _setup_xfail_if_known(rv, purpose):
    if int(rv) in _RECOVER_SETUP_RVS:
        _setup_xfail_rv(rv, purpose)


def _gen_recover_keypair():
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
    pub = CK_OBJECT_HANDLE(0)
    priv = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        kg_mech.byref(),
        _template_ptr(pub_template),
        pub_template.count,
        _template_ptr(prv_template),
        prv_template.count,
        ctypes.byref(pub),
        ctypes.byref(priv),
    )
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "RSA recover keypair generation rejected")
        raise AssertionError(f"C_GenerateKeyPair returned {ckr_name(rv)}")
    return pub, priv


def _padded_recover_block(label):
    data = label
    pad_len = 256 - 3 - len(data)
    return b"\\x00\\x01" + b"\\xff" * pad_len + b"\\x00" + data


def _sign_recover(priv, payload):
    mech = mech_simple(CKM_RSA_X_509)
    rv = raw.C_SignRecoverInit(sh, mech.byref(), priv.value)
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_SignRecoverInit rejected")
        raise AssertionError(f"C_SignRecoverInit returned {ckr_name(rv)}")

    payload_buf = _byte_array(payload)
    sig_len = CK_ULONG(0)
    rv = raw.C_SignRecover(sh, payload_buf, len(payload), None, ctypes.byref(sig_len))
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_SignRecover size query rejected")
        raise AssertionError(f"C_SignRecover size query returned {ckr_name(rv)}")
    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    rv = raw.C_SignRecover(sh, payload_buf, len(payload), sig_buf, ctypes.byref(sig_len))
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_SignRecover setup signing rejected")
        raise AssertionError(f"C_SignRecover returned {ckr_name(rv)}")
    return bytes(sig_buf[: sig_len.value])
"""


class TestRecoverInputLengthBoundary:
    """Recover APIs must reject impossible claimed input lengths without crashing."""

    @pytest.mark.parametrize("data_len", _BOUNDARY_LENGTHS)
    def test_sign_recover_huge_data_len_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """``C_SignRecover`` with a tiny real buffer and huge ``ulDataLen``."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        body = (
            _RECOVER_SETUP
            + f"""
pub = CK_OBJECT_HANDLE(0)
priv = CK_OBJECT_HANDLE(0)
try:
    pub, priv = _gen_recover_keypair()
    mech = mech_simple(CKM_RSA_X_509)
    rv = raw.C_SignRecoverInit(sh, mech.byref(), priv.value)
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_SignRecoverInit rejected")
        raise AssertionError(f"C_SignRecoverInit returned {{ckr_name(rv)}}")

    data = (ctypes.c_ubyte * 16)(*range(16))
    sig_buf = (ctypes.c_ubyte * 256)()
    sig_len = CK_ULONG(256)
    print("TARGET:C_SignRecover")
    print("LEN:{data_len:#x}")
    rv = raw.C_SignRecover(sh, data, {data_len}, sig_buf, ctypes.byref(sig_len))
    print(f"CKR:0x{{rv:08x}}")
    print(f"OUT_LEN:{{sig_len.value}}")
finally:
    if priv.value:
        destroy_quietly(raw, sh, priv.value)
    if pub.value:
        destroy_quietly(raw, sh, pub.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_SignRecover(ulDataLen={data_len:#x})",
        )
        rv = _parse_output_value(stdout, "CKR:")
        classify_negative_rv(
            rv,
            (CKR_DATA_LEN_RANGE,),
            label=f"C_SignRecover with ulDataLen={data_len:#x}",
        )

    @pytest.mark.parametrize("sig_len", _BOUNDARY_LENGTHS)
    def test_verify_recover_huge_signature_len_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        sig_len: int,
    ) -> None:
        """``C_VerifyRecover`` with a tiny real signature and huge ``ulSignatureLen``."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        body = (
            _RECOVER_SETUP
            + f"""
pub = CK_OBJECT_HANDLE(0)
priv = CK_OBJECT_HANDLE(0)
try:
    pub, priv = _gen_recover_keypair()
    mech = mech_simple(CKM_RSA_X_509)
    rv = raw.C_VerifyRecoverInit(sh, mech.byref(), pub.value)
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_VerifyRecoverInit rejected")
        raise AssertionError(f"C_VerifyRecoverInit returned {{ckr_name(rv)}}")

    signature = (ctypes.c_ubyte * 16)(*range(16))
    recovered = (ctypes.c_ubyte * 256)()
    recovered_len = CK_ULONG(256)
    print("TARGET:C_VerifyRecover")
    print("LEN:{sig_len:#x}")
    rv = raw.C_VerifyRecover(
        sh,
        signature,
        {sig_len},
        recovered,
        ctypes.byref(recovered_len),
    )
    print(f"CKR:0x{{rv:08x}}")
    print(f"OUT_LEN:{{recovered_len.value}}")
finally:
    if priv.value:
        destroy_quietly(raw, sh, priv.value)
    if pub.value:
        destroy_quietly(raw, sh, pub.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_VerifyRecover(ulSignatureLen={sig_len:#x})",
        )
        rv = _parse_output_value(stdout, "CKR:")
        classify_negative_rv(
            rv,
            (CKR_SIGNATURE_LEN_RANGE,),
            label=f"C_VerifyRecover with ulSignatureLen={sig_len:#x}",
        )


class TestRecoverOutputLengthBoundary:
    """Recover output buffers must not be overrun on valid operations."""

    def test_verify_recover_inflated_pul_data_len_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_VerifyRecover`` with ``*pulDataLen`` high 32 bits set must not crash.

        The output-length pointer value exceeds 32 bits: low 32 bits = 256
        (the actual output buffer size), high 32 bits set.  A module that writes
        only the low 32 bits of ``*pulDataLen`` leaves the high half intact;
        the surviving large value then drives an oversized output copy (OOB).
        A conformant module treats ``*pulDataLen`` as a capacity and writes only
        the actual recovered length (≤256); the high bits are irrelevant to a
        correct implementation.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        body = (
            _RECOVER_SETUP
            + f"""
pub = CK_OBJECT_HANDLE(0)
priv = CK_OBJECT_HANDLE(0)
try:
    pub, priv = _gen_recover_keypair()
    payload = _padded_recover_block(b"output-len-pun-probe")
    signature = _sign_recover(priv, payload)
    signature_buf = _byte_array(signature)

    mech = mech_simple(CKM_RSA_X_509)
    rv = raw.C_VerifyRecoverInit(sh, mech.byref(), pub.value)
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_VerifyRecoverInit rejected")
        raise AssertionError(f"C_VerifyRecoverInit returned {{ckr_name(rv)}}")

    out_buf = (ctypes.c_ubyte * 256)()
    out_len = CK_ULONG({_R6_INFLATED_PULDATALEN})
    print("TARGET:C_VerifyRecover")
    print(f"INFLATED_LEN:{{out_len.value:#x}}")
    rv = raw.C_VerifyRecover(
        sh,
        signature_buf,
        len(signature),
        out_buf,
        ctypes.byref(out_len),
    )
    print(f"CKR:0x{{rv:08x}}")
    print(f"OUT_LEN:{{out_len.value}}")
finally:
    if priv.value:
        destroy_quietly(raw, sh, priv.value)
    if pub.value:
        destroy_quietly(raw, sh, pub.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=20,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_VerifyRecover(*pulDataLen={_R6_INFLATED_PULDATALEN:#x})",
        )
        rv = _parse_output_value(stdout, "CKR:")
        classify_negative_rv(
            rv,
            (CKR_BUFFER_TOO_SMALL,),
            label=(
                f"C_VerifyRecover with *pulDataLen={_R6_INFLATED_PULDATALEN:#x} (high 32 bits set)"
            ),
            allow_ok=True,
        )

    def test_verify_recover_one_byte_output_preserves_guard(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_VerifyRecover`` with one declared output byte preserves guard bytes."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        body = (
            _RECOVER_SETUP
            + """
pub = CK_OBJECT_HANDLE(0)
priv = CK_OBJECT_HANDLE(0)
try:
    pub, priv = _gen_recover_keypair()
    payload = _padded_recover_block(b"verify-recover guard")
    signature = _sign_recover(priv, payload)
    signature_buf = _byte_array(signature)

    mech = mech_simple(CKM_RSA_X_509)
    rv = raw.C_VerifyRecoverInit(sh, mech.byref(), pub.value)
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_VerifyRecoverInit rejected")
        raise AssertionError(f"C_VerifyRecoverInit returned {ckr_name(rv)}")

    needed = CK_ULONG(0)
    rv = raw.C_VerifyRecover(
        sh,
        signature_buf,
        len(signature),
        None,
        ctypes.byref(needed),
    )
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_VerifyRecover size query rejected")
        raise AssertionError(f"C_VerifyRecover size query returned {ckr_name(rv)}")
    if needed.value <= 1:
        _setup_xfail_rv(CKR_OK, f"C_VerifyRecover reported only {needed.value} output byte(s)")

    GUARD = 0xB6
    GUARD_SIZE = 32

    class RecoverProbe(ctypes.Structure):
        _fields_ = [
            ("data", ctypes.c_ubyte * 1),
            ("guard", ctypes.c_ubyte * GUARD_SIZE),
        ]

    probe = RecoverProbe()
    for idx in range(GUARD_SIZE):
        probe.guard[idx] = GUARD

    # No re-Init here: per PKCS#11, the NULL-output size query above did NOT
    # terminate the operation. Calling C_VerifyRecover again with a real output
    # buffer is the correct continuation. (Re-Init would return
    # CKR_OPERATION_ACTIVE on a conformant module -- the previous test bug.)
    out_len = CK_ULONG(1)
    print(f"NEEDED:{needed.value}")
    rv = raw.C_VerifyRecover(
        sh,
        signature_buf,
        len(signature),
        ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.byref(out_len),
    )
    print(f"CKR:0x{rv:08x}")
    print(f"LEN:{out_len.value}")
    overwritten = sum(1 for byte in probe.guard if byte != GUARD)
    print(f"OVERWRITTEN:{overwritten}")
    assert overwritten == 0, (
        "C_VerifyRecover wrote past the declared one-byte output buffer: "
        f"{overwritten} guard byte(s) changed"
    )
finally:
    if priv.value:
        destroy_quietly(raw, sh, priv.value)
    if pub.value:
        destroy_quietly(raw, sh, pub.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=20,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_VerifyRecover one-byte output buffer guard",
        )
        rv = _parse_output_value(stdout, "CKR:")
        if rv == CKR_BUFFER_TOO_SMALL:
            needed = _parse_output_value(stdout, "NEEDED:")
            out_len = _parse_output_value(stdout, "LEN:")
            # PKCS#11 v3.2 §5.2: both the NULL-size-query length and the
            # CKR_BUFFER_TOO_SMALL *pulBufLen may over-estimate, so they need not be
            # equal. Only a length that does not exceed the 1-byte probe buffer is a
            # self-contradiction (module said "too small" yet needs <= 1 byte).
            if out_len <= 1:
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label="C_VerifyRecover one-byte output buffer length",
                    actual=out_len,
                    summary=f"CKR_BUFFER_TOO_SMALL but reported needed length {out_len} <= 1",
                )
            elif out_len != needed:
                compliance.note(
                    "C_VerifyRecover size-query length "
                    f"{needed} != BUFFER_TOO_SMALL length {out_len} "
                    "(both spec-legal over-estimates)",
                    ComplianceLevel.EXTENDED,
                )
        else:
            classify_negative_rv(
                rv,
                (CKR_BUFFER_TOO_SMALL,),
                label="C_VerifyRecover with a one-byte output buffer",
            )

    def test_sign_recover_one_byte_output_preserves_guard(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_SignRecover`` with one declared output byte preserves guard bytes.

        Mirrors the verify-recover guard probe on the sign side: ``C_SignRecoverInit``
        -> NULL-output size query -> real call with a 1-byte guard-backed output
        buffer (NO re-Init -- the size query does not terminate the operation).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X_509"):
            pytest.skip("CKM_RSA_X_509 not supported")
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        body = (
            _RECOVER_SETUP
            + """
pub = CK_OBJECT_HANDLE(0)
priv = CK_OBJECT_HANDLE(0)
try:
    pub, priv = _gen_recover_keypair()
    payload = _padded_recover_block(b"sign-recover guard")
    payload_buf = _byte_array(payload)

    mech = mech_simple(CKM_RSA_X_509)
    rv = raw.C_SignRecoverInit(sh, mech.byref(), priv.value)
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_SignRecoverInit rejected")
        raise AssertionError(f"C_SignRecoverInit returned {ckr_name(rv)}")

    needed = CK_ULONG(0)
    rv = raw.C_SignRecover(sh, payload_buf, len(payload), None, ctypes.byref(needed))
    if rv != CKR_OK:
        _setup_xfail_if_known(rv, "C_SignRecover size query rejected")
        raise AssertionError(f"C_SignRecover size query returned {ckr_name(rv)}")
    if needed.value <= 1:
        _setup_xfail_rv(CKR_OK, f"C_SignRecover reported only {needed.value} output byte(s)")

    GUARD = 0xB7
    GUARD_SIZE = 32

    class RecoverProbe(ctypes.Structure):
        _fields_ = [
            ("data", ctypes.c_ubyte * 1),
            ("guard", ctypes.c_ubyte * GUARD_SIZE),
        ]

    probe = RecoverProbe()
    for idx in range(GUARD_SIZE):
        probe.guard[idx] = GUARD

    # Continuation real call (NO re-Init): the NULL-output size query above did
    # not terminate the operation, so we call C_SignRecover again with a real
    # 1-byte output buffer + guard bytes to detect overflow.
    out_len = CK_ULONG(1)
    print(f"NEEDED:{needed.value}")
    rv = raw.C_SignRecover(
        sh,
        payload_buf,
        len(payload),
        ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.byref(out_len),
    )
    print(f"CKR:0x{rv:08x}")
    print(f"LEN:{out_len.value}")
    overwritten = sum(1 for byte in probe.guard if byte != GUARD)
    print(f"OVERWRITTEN:{overwritten}")
    assert overwritten == 0, (
        "C_SignRecover wrote past the declared one-byte output buffer: "
        f"{overwritten} guard byte(s) changed"
    )
finally:
    if priv.value:
        destroy_quietly(raw, sh, priv.value)
    if pub.value:
        destroy_quietly(raw, sh, pub.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=20,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_SignRecover one-byte output buffer guard",
        )
        rv = _parse_output_value(stdout, "CKR:")
        if rv == CKR_BUFFER_TOO_SMALL:
            needed = _parse_output_value(stdout, "NEEDED:")
            out_len = _parse_output_value(stdout, "LEN:")
            # PKCS#11 v3.2 §5.2: both the NULL-size-query length and the
            # CKR_BUFFER_TOO_SMALL *pulBufLen may over-estimate, so they need not be
            # equal. Only a length that does not exceed the 1-byte probe buffer is a
            # self-contradiction (module said "too small" yet needs <= 1 byte).
            if out_len <= 1:
                fail_as(
                    "self_contradiction",
                    kind="metadata",
                    label="C_SignRecover one-byte output buffer length",
                    actual=out_len,
                    summary=f"CKR_BUFFER_TOO_SMALL but reported needed length {out_len} <= 1",
                )
            elif out_len != needed:
                compliance.note(
                    "C_SignRecover size-query length "
                    f"{needed} != BUFFER_TOO_SMALL length {out_len} "
                    "(both spec-legal over-estimates)",
                    ComplianceLevel.EXTENDED,
                )
        else:
            classify_negative_rv(
                rv,
                (CKR_BUFFER_TOO_SMALL,),
                label="C_SignRecover with a one-byte output buffer",
            )
