"""FFI length boundary and mechanism parameter probes.

All tests run in subprocess for crash safety. Tests exercise:
- isize::MAX boundary for data length parameters (Rust-specific UB at 2^63)
- OOM allocation guards (large but valid CKA_VALUE_LEN)
- v3.0 message API input length boundaries
- NULL inner pointers in mechanism parameter structures

Inspired by Kryoptic fix/ffi-integer-overflow-hardening which added
check_slice_len(), ffi_slice(), ffi_slice_mut(), and bytes_to_vec() guards.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.types_std import (
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKF_MESSAGE_DECRYPT,
    CKF_MESSAGE_ENCRYPT,
    CKF_MESSAGE_SIGN,
    CKF_MESSAGE_VERIFY,
    CKM_AES_GCM,
    CKM_SHA256_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_SIGNATURE_LEN_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    destroy_returned_handles,
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_edwards_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# ---------------------------------------------------------------------------
# Constants for isize::MAX boundary probing (64-bit)
# ---------------------------------------------------------------------------

# Rust's isize::MAX -- the maximum byte count for slice::from_raw_parts.
_ISIZE_MAX_64 = 0x7FFFFFFFFFFFFFFF

# isize::MAX + 1 -- causes UB in slice::from_raw_parts because total byte
# size exceeds isize::MAX.  This is the exact boundary Kryoptic's
# check_slice_len<u8>() validates.
_ISIZE_MAX_PLUS_1_64 = 0x8000000000000000

# Large but sub-OOM value for allocation guard testing (2 GB).
_ALLOC_GUARD_VALUE_LEN = 0x7FFFFFFF

_KDF_LENGTH_REJECT_RVS = (
    CKR_MECHANISM_PARAM_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_MESSAGE_LENGTH_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
)

_MESSAGE_DECRYPT_LENGTH_REJECT_RVS = _MESSAGE_LENGTH_REJECT_RVS + (CKR_ENCRYPTED_DATA_LEN_RANGE,)

_MESSAGE_VERIFY_LENGTH_REJECT_RVS = _MESSAGE_LENGTH_REJECT_RVS + (CKR_SIGNATURE_LEN_RANGE,)


def _preamble(p11_config: Any) -> str:
    """Build subprocess session preamble from p11_config."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
    )


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


_CHILD_SETUP_REJECT_HELPERS = """
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    is_known_error,
)


def setup_xfail_if_known_ckr(exc, known_ckrs, purpose):
    if is_known_error(exc, known_ckrs):
        rv = getattr(exc, "rv", None)
        detail = ckr_name(rv) if rv is not None else str(exc)
        print(f"SETUP_XFAIL:{purpose}: {detail}")
        cleanup()
        raise SystemExit(0)
    raise exc

"""

_HMAC_KEY_IMPORT_HELPER = """
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_GENERIC_SECRET,
    CKO_SECRET_KEY,
    CKR_OK,
    CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.recipes import destroy_quietly


def import_hmac_key(*, sign=False, verify=False):
    key_bytes = (ctypes.c_ubyte * 32)(*range(32))
    cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
    kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
    sign_val = ctypes.c_ubyte(1 if sign else 0)
    verify_val = ctypes.c_ubyte(1 if verify else 0)
    token_false = ctypes.c_ubyte(0)

    attrs = (CK_ATTRIBUTE * 6)()
    attrs[0].type = CKA_CLASS
    attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    attrs[0].ulValueLen = ctypes.sizeof(cls_val)
    attrs[1].type = CKA_KEY_TYPE
    attrs[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
    attrs[1].ulValueLen = ctypes.sizeof(kt_val)
    attrs[2].type = CKA_VALUE
    attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
    attrs[2].ulValueLen = 32
    attrs[3].type = CKA_SIGN
    attrs[3].pValue = ctypes.cast(ctypes.pointer(sign_val), ctypes.c_void_p)
    attrs[3].ulValueLen = 1
    attrs[4].type = CKA_VERIFY
    attrs[4].pValue = ctypes.cast(ctypes.pointer(verify_val), ctypes.c_void_p)
    attrs[4].ulValueLen = 1
    attrs[5].type = CKA_TOKEN
    attrs[5].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    attrs[5].ulValueLen = 1

    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_CreateObject(
        sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        6, ctypes.byref(key),
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:HMAC key import rejected: {ckr_name(rv)}")
        cleanup()
        raise SystemExit(0)
    return key

"""


# ---------------------------------------------------------------------------
# TestIsizeMaxDataLength
# ---------------------------------------------------------------------------

_ISIZE_BOUNDARY_LENGTHS = [
    pytest.param(_ISIZE_MAX_64, id="isize_max"),
    pytest.param(_ISIZE_MAX_PLUS_1_64, id="isize_max_plus_1"),
]


class TestIsizeMaxDataLength:
    """Probe data functions with isize::MAX boundary lengths.

    On 64-bit systems, isize::MAX = 0x7FFFFFFFFFFFFFFF.  Passing this
    (or isize::MAX + 1) as the data length to C_Encrypt / C_Decrypt /
    C_Sign / C_Digest with a small real buffer triggers the exact
    boundary that Kryoptic's check_slice_len<u8>() validates.  A module
    that calls Rust's slice::from_raw_parts with byte count > isize::MAX
    hits undefined behavior.
    """

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_encrypt_isize_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Encrypt isize-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_ECB
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.C_Encrypt(
            sh, buf, {data_len}, out_buf, ctypes.byref(out_len),
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Encrypt(ulDataLen={data_len:#x})",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_decrypt_isize_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_Decrypt isize-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_ECB
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.C_Decrypt(
            sh, buf, {data_len}, out_buf, ctypes.byref(out_len),
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Decrypt(ulDataLen={data_len:#x})",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_sign_isize_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CK_ULONG, CKR_OK,
    CKA_SIGN, CKA_TOKEN, CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET,
    CK_ATTRIBUTE, CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a 32-byte HMAC key via C_CreateObject
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
sign_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

attrs = (CK_ATTRIBUTE * 5)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = CKA_VALUE
attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
attrs[2].ulValueLen = 32
attrs[3].type = CKA_SIGN
attrs[3].pValue = ctypes.cast(
    ctypes.pointer(sign_true), ctypes.c_void_p,
)
attrs[3].ulValueLen = 1
attrs[4].type = CKA_TOKEN
attrs[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
attrs[4].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(key),
)
if rv != CKR_OK:
    print(f"rv={{rv}}")
    cleanup()
    raise SystemExit(0)

try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_HMAC
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        sig_len = CK_ULONG(64)
        sig_buf = (ctypes.c_ubyte * 64)()
        rv2 = raw.C_Sign(
            sh, buf, {data_len}, sig_buf, ctypes.byref(sig_len),
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Sign(HMAC_SHA256, ulDataLen={data_len:#x})",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_verify_isize_data_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """C_Verify must validate a huge claimed data length without crashing."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import CK_MECHANISM, CKM_SHA256_HMAC, CKR_OK
{_HMAC_KEY_IMPORT_HELPER}

key = import_hmac_key(verify=True)
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_HMAC
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key.value)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        sig_buf = (ctypes.c_ubyte * 32)()
        rv2 = raw.C_Verify(sh, buf, {data_len}, sig_buf, 32)
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Verify(HMAC_SHA256, ulDataLen={data_len:#x})",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_digest_isize_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256, CK_ULONG, CKR_OK,
)

mech = CK_MECHANISM()
mech.mechanism = CKM_SHA256
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DigestInit(sh, ctypes.byref(mech))
if rv == CKR_OK:
    buf = (ctypes.c_ubyte * 16)(*range(16))
    digest_len = CK_ULONG(64)
    digest_buf = (ctypes.c_ubyte * 64)()
    rv2 = raw.C_Digest(
        sh, buf, {data_len}, digest_buf, ctypes.byref(digest_len),
    )
    print(f"rv={{rv2}}")
else:
    print(f"rv={{rv}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Digest(SHA256, ulDataLen={data_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestMessageApiLengthBoundary
# ---------------------------------------------------------------------------

_MESSAGE_ENCRYPT_LENGTH_FIELDS = [
    pytest.param("associated_data", id="associated_data_len"),
    pytest.param("plaintext", id="plaintext_len"),
]

_MESSAGE_DECRYPT_LENGTH_FIELDS = [
    pytest.param("associated_data", id="associated_data_len"),
    pytest.param("ciphertext", id="ciphertext_len"),
]

_MESSAGE_VERIFY_LENGTH_FIELDS = [
    pytest.param("data", id="data_len"),
    pytest.param("signature", id="signature_len"),
]

_MESSAGE_ENCRYPT_MULTIPART_OPS = [
    pytest.param("C_EncryptMessageBegin", id="begin_plaintext_len"),
    pytest.param("C_EncryptMessageNext", id="next_plaintext_len"),
]

_MESSAGE_DECRYPT_MULTIPART_OPS = [
    pytest.param("C_DecryptMessageBegin", id="begin_ciphertext_len"),
    pytest.param("C_DecryptMessageNext", id="next_ciphertext_len"),
]

_MESSAGE_SIGN_MULTIPART_OPS = [
    pytest.param("C_SignMessageBegin", id="begin_data_len"),
    pytest.param("C_SignMessageNext", id="next_data_len"),
]

_MESSAGE_VERIFY_MULTIPART_FIELDS = [
    pytest.param("begin_parameter", id="begin_parameter_len"),
    pytest.param("next_data", id="next_data_len"),
    pytest.param("next_signature", id="next_signature_len"),
]


class TestMessageApiLengthBoundary:
    """v3.0 message APIs must reject huge claimed input lengths safely."""

    @pytest.mark.requires_v30
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("field", _MESSAGE_ENCRYPT_LENGTH_FIELDS)
    def test_encrypt_message_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        field: str,
    ) -> None:
        """C_EncryptMessage must not turn tiny input buffers into huge reads."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_ENCRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_ENCRYPT")

        available = rs.raw.available_function_names()
        for fname in ("C_MessageEncryptInit", "C_EncryptMessage", "C_MessageEncryptFinal"):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_EncryptMessage length-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        aad_len = data_len if field == "associated_data" else 16
        plaintext_len = data_len if field == "plaintext" else 16
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_GCM_MESSAGE_PARAMS,
    CK_MECHANISM,
    CKM_AES_GCM,
    CKR_OK,
    CK_ULONG,
)

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )

try:
    init_iv = (ctypes.c_ubyte * 12)(*range(12))
    init_tag = (ctypes.c_ubyte * 16)()
    init_params = CK_GCM_MESSAGE_PARAMS()
    init_params.pIv = ctypes.cast(init_iv, ctypes.c_void_p)
    init_params.ulIvLen = 12
    init_params.ulIvFixedBits = 0
    init_params.ivGenerator = 0
    init_params.pTag = ctypes.cast(init_tag, ctypes.c_void_p)
    init_params.ulTagBits = 128

    init_mech = CK_MECHANISM()
    init_mech.mechanism = CKM_AES_GCM
    init_mech.pParameter = ctypes.cast(ctypes.pointer(init_params), ctypes.c_void_p)
    init_mech.ulParameterLen = ctypes.sizeof(init_params)

    rv = raw.C_MessageEncryptInit(sh, ctypes.byref(init_mech), key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_MessageEncryptInit rejected: {{ckr_name(rv)}}")
        cleanup()
        raise SystemExit(0)

    msg_iv = (ctypes.c_ubyte * 12)(*range(12, 24))
    msg_tag = (ctypes.c_ubyte * 16)()
    msg_params = CK_GCM_MESSAGE_PARAMS()
    msg_params.pIv = ctypes.cast(msg_iv, ctypes.c_void_p)
    msg_params.ulIvLen = 12
    msg_params.ulIvFixedBits = 0
    msg_params.ivGenerator = 0
    msg_params.pTag = ctypes.cast(msg_tag, ctypes.c_void_p)
    msg_params.ulTagBits = 128

    aad = (ctypes.c_ubyte * 16)(*range(16))
    plaintext = (ctypes.c_ubyte * 16)(*range(16, 32))
    out_len = CK_ULONG(256)
    out_buf = (ctypes.c_ubyte * 256)()

    rv = raw.C_EncryptMessage(
        sh,
        ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
        ctypes.sizeof(msg_params),
        aad,
        {aad_len},
        plaintext,
        {plaintext_len},
        out_buf,
        ctypes.byref(out_len),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    final_rv = raw.C_MessageEncryptFinal(sh)
    print(f"FINAL_RV:0x{{final_rv:08x}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_EncryptMessage({field}={data_len:#x})",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])

        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_LENGTH_REJECT_RVS,
            label=f"C_EncryptMessage({field}={data_len:#x})",
        )

    @pytest.mark.requires_v30
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("field", _MESSAGE_DECRYPT_LENGTH_FIELDS)
    def test_decrypt_message_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        field: str,
    ) -> None:
        """C_DecryptMessage must not turn tiny input buffers into huge reads."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_DECRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_DECRYPT")

        available = rs.raw.available_function_names()
        for fname in ("C_MessageDecryptInit", "C_DecryptMessage", "C_MessageDecryptFinal"):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="C_DecryptMessage length-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        aad_len = data_len if field == "associated_data" else 16
        ciphertext_len = data_len if field == "ciphertext" else 16
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_GCM_MESSAGE_PARAMS,
    CK_MECHANISM,
    CKM_AES_GCM,
    CKR_OK,
    CK_ULONG,
)

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )

try:
    init_iv = (ctypes.c_ubyte * 12)(*range(12))
    init_tag = (ctypes.c_ubyte * 16)()
    init_params = CK_GCM_MESSAGE_PARAMS()
    init_params.pIv = ctypes.cast(init_iv, ctypes.c_void_p)
    init_params.ulIvLen = 12
    init_params.ulIvFixedBits = 0
    init_params.ivGenerator = 0
    init_params.pTag = ctypes.cast(init_tag, ctypes.c_void_p)
    init_params.ulTagBits = 128

    init_mech = CK_MECHANISM()
    init_mech.mechanism = CKM_AES_GCM
    init_mech.pParameter = ctypes.cast(ctypes.pointer(init_params), ctypes.c_void_p)
    init_mech.ulParameterLen = ctypes.sizeof(init_params)

    rv = raw.C_MessageDecryptInit(sh, ctypes.byref(init_mech), key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_MessageDecryptInit rejected: {{ckr_name(rv)}}")
        cleanup()
        raise SystemExit(0)

    msg_iv = (ctypes.c_ubyte * 12)(*range(12, 24))
    msg_tag = (ctypes.c_ubyte * 16)(*range(24, 40))
    msg_params = CK_GCM_MESSAGE_PARAMS()
    msg_params.pIv = ctypes.cast(msg_iv, ctypes.c_void_p)
    msg_params.ulIvLen = 12
    msg_params.ulIvFixedBits = 0
    msg_params.ivGenerator = 0
    msg_params.pTag = ctypes.cast(msg_tag, ctypes.c_void_p)
    msg_params.ulTagBits = 128

    aad = (ctypes.c_ubyte * 16)(*range(16))
    ciphertext = (ctypes.c_ubyte * 16)(*range(40, 56))
    out_len = CK_ULONG(256)
    out_buf = (ctypes.c_ubyte * 256)()

    rv = raw.C_DecryptMessage(
        sh,
        ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
        ctypes.sizeof(msg_params),
        aad,
        {aad_len},
        ciphertext,
        {ciphertext_len},
        out_buf,
        ctypes.byref(out_len),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    final_rv = raw.C_MessageDecryptFinal(sh)
    print(f"FINAL_RV:0x{{final_rv:08x}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_DecryptMessage({field}={data_len:#x})",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])

        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_DECRYPT_LENGTH_REJECT_RVS,
            label=f"C_DecryptMessage({field}={data_len:#x})",
        )

    @pytest.mark.requires_v30
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("op", _MESSAGE_DECRYPT_MULTIPART_OPS)
    def test_decrypt_message_multipart_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        op: str,
    ) -> None:
        """C_DecryptMessageBegin/Next must reject huge input lengths safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_DECRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_DECRYPT")

        available = rs.raw.available_function_names()
        for fname in (
            "C_MessageDecryptInit",
            "C_DecryptMessageBegin",
            "C_DecryptMessageNext",
            "C_MessageDecryptFinal",
        ):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose=f"{op} length-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKF_END_OF_MESSAGE,
    CK_GCM_MESSAGE_PARAMS,
    CK_MECHANISM,
    CKM_AES_GCM,
    CKR_OK,
    CK_ULONG,
)

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )

try:
    init_iv = (ctypes.c_ubyte * 12)(*range(12))
    init_tag = (ctypes.c_ubyte * 16)(*range(12, 28))
    init_params = CK_GCM_MESSAGE_PARAMS()
    init_params.pIv = ctypes.cast(init_iv, ctypes.c_void_p)
    init_params.ulIvLen = 12
    init_params.ulIvFixedBits = 0
    init_params.ivGenerator = 0
    init_params.pTag = ctypes.cast(init_tag, ctypes.c_void_p)
    init_params.ulTagBits = 128

    init_mech = CK_MECHANISM()
    init_mech.mechanism = CKM_AES_GCM
    init_mech.pParameter = ctypes.cast(ctypes.pointer(init_params), ctypes.c_void_p)
    init_mech.ulParameterLen = ctypes.sizeof(init_params)

    rv = raw.C_MessageDecryptInit(sh, ctypes.byref(init_mech), key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_MessageDecryptInit rejected: {{ckr_name(rv)}}")
        cleanup()
        raise SystemExit(0)

    msg_iv = (ctypes.c_ubyte * 12)(*range(28, 40))
    msg_tag = (ctypes.c_ubyte * 16)(*range(40, 56))
    msg_params = CK_GCM_MESSAGE_PARAMS()
    msg_params.pIv = ctypes.cast(msg_iv, ctypes.c_void_p)
    msg_params.ulIvLen = 12
    msg_params.ulIvFixedBits = 0
    msg_params.ivGenerator = 0
    msg_params.pTag = ctypes.cast(msg_tag, ctypes.c_void_p)
    msg_params.ulTagBits = 128

    ciphertext = (ctypes.c_ubyte * 16)(*range(56, 72))
    out_len = CK_ULONG(256)
    out_buf = (ctypes.c_ubyte * 256)()

    if "{op}" == "C_DecryptMessageBegin":
        rv = raw.C_DecryptMessageBegin(
            sh,
            ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
            ctypes.sizeof(msg_params),
            ciphertext,
            {data_len},
        )
    else:
        rv = raw.C_DecryptMessageBegin(
            sh,
            ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
            ctypes.sizeof(msg_params),
            ciphertext,
            16,
        )
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_DecryptMessageBegin rejected: {{ckr_name(rv)}}")
            cleanup()
            raise SystemExit(0)
        part = (ctypes.c_ubyte * 16)(*range(72, 88))
        rv = raw.C_DecryptMessageNext(
            sh,
            None,
            0,
            part,
            {data_len},
            out_buf,
            ctypes.byref(out_len),
            CKF_END_OF_MESSAGE,
        )

    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    final_rv = raw.C_MessageDecryptFinal(sh)
    print(f"FINAL_RV:0x{{final_rv:08x}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{op}(ciphertext_len={data_len:#x})",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])

        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_DECRYPT_LENGTH_REJECT_RVS,
            label=f"{op}(ciphertext_len={data_len:#x})",
        )

    @pytest.mark.requires_v30
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_sign_message_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """C_SignMessage must not turn a tiny data buffer into a huge read."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_SHA256_RSA_PKCS)
        if not (info["flags"] & int(CKF_MESSAGE_SIGN)):
            pytest.skip("CKM_SHA256_RSA_PKCS does not advertise CKF_MESSAGE_SIGN")

        available = rs.raw.available_function_names()
        for fname in ("C_MessageSignInit", "C_SignMessage", "C_MessageSignFinal"):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CK_MECHANISM,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
    CK_ULONG,
)

try:
    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        public_attrs={{CKA_TOKEN: False}},
        private_attrs={{CKA_SIGN: True, CKA_TOKEN: False}},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected",
    )

try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_RSA_PKCS
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_MessageSignInit(sh, ctypes.byref(mech), priv)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_MessageSignInit rejected: {{ckr_name(rv)}}")
        cleanup()
        raise SystemExit(0)

    data = (ctypes.c_ubyte * 16)(*range(16))
    sig_len = CK_ULONG(512)
    sig_buf = (ctypes.c_ubyte * 512)()
    rv = raw.C_SignMessage(sh, None, 0, data, {data_len}, sig_buf, ctypes.byref(sig_len))
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    final_rv = raw.C_MessageSignFinal(sh)
    print(f"FINAL_RV:0x{{final_rv:08x}}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_SignMessage(data_len={data_len:#x})",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])

        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_LENGTH_REJECT_RVS,
            label=f"C_SignMessage(data_len={data_len:#x})",
        )

    @pytest.mark.requires_v30
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("field", _MESSAGE_VERIFY_LENGTH_FIELDS)
    def test_verify_message_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        field: str,
    ) -> None:
        """C_VerifyMessage must reject huge data/signature lengths safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_SHA256_RSA_PKCS)
        if not (info["flags"] & int(CKF_MESSAGE_VERIFY)):
            pytest.skip("CKM_SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY")

        available = rs.raw.available_function_names()
        for fname in ("C_MessageVerifyInit", "C_VerifyMessage", "C_MessageVerifyFinal"):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)

        normal_data_len = 16
        verify_data_len = data_len if field == "data" else normal_data_len
        signature_len = data_len if field == "signature" else 256
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair, sign_single
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CK_MECHANISM,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
)

try:
    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        public_attrs={{CKA_VERIFY: True, CKA_TOKEN: False}},
        private_attrs={{CKA_SIGN: True, CKA_TOKEN: False}},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected",
    )

try:
    data_bytes = bytes(range({normal_data_len}))
    try:
        signature = sign_single(raw, sh, priv, CKM_SHA256_RSA_PKCS, data_bytes)
    except AssertionError as exc:
        rv = getattr(exc, "rv", None)
        detail = ckr_name(rv) if rv is not None else str(exc)
        print(f"SETUP_XFAIL:standard signature generation rejected: {{detail}}")
        cleanup()
        raise SystemExit(0)

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_RSA_PKCS
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_MessageVerifyInit(sh, ctypes.byref(mech), pub)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_MessageVerifyInit rejected: {{ckr_name(rv)}}")
        cleanup()
        raise SystemExit(0)

    data = (ctypes.c_ubyte * {normal_data_len})(*range({normal_data_len}))
    sig_buf = (ctypes.c_ubyte * len(signature))(*signature)
    rv = raw.C_VerifyMessage(
        sh,
        None,
        0,
        data,
        {verify_data_len},
        sig_buf,
        {signature_len},
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    final_rv = raw.C_MessageVerifyFinal(sh)
    print(f"FINAL_RV:0x{{final_rv:08x}}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_VerifyMessage({field}_len={data_len:#x})",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])

        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_VERIFY_LENGTH_REJECT_RVS,
            label=f"C_VerifyMessage({field}_len={data_len:#x})",
        )

    @pytest.mark.requires_v30
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("op", _MESSAGE_SIGN_MULTIPART_OPS)
    def test_sign_message_multipart_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        op: str,
    ) -> None:
        """C_SignMessageBegin/Next must reject huge input lengths safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_SHA256_RSA_PKCS)
        if not (info["flags"] & int(CKF_MESSAGE_SIGN)):
            pytest.skip("CKM_SHA256_RSA_PKCS does not advertise CKF_MESSAGE_SIGN")

        available = rs.raw.available_function_names()
        for fname in (
            "C_MessageSignInit",
            "C_SignMessageBegin",
            "C_SignMessageNext",
            "C_MessageSignFinal",
        ):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKF_END_OF_MESSAGE,
    CK_MECHANISM,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
    CK_ULONG,
)

try:
    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        public_attrs={{CKA_TOKEN: False}},
        private_attrs={{CKA_SIGN: True, CKA_TOKEN: False}},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected",
    )

try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_RSA_PKCS
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_MessageSignInit(sh, ctypes.byref(mech), priv)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_MessageSignInit rejected: {{ckr_name(rv)}}")
        cleanup()
        raise SystemExit(0)

    data = (ctypes.c_ubyte * 16)(*range(16))
    sig_len = CK_ULONG(512)
    sig_buf = (ctypes.c_ubyte * 512)()

    if "{op}" == "C_SignMessageBegin":
        rv = raw.C_SignMessageBegin(sh, None, 0, data, {data_len})
    else:
        rv = raw.C_SignMessageBegin(sh, None, 0, data, 16)
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_SignMessageBegin rejected: {{ckr_name(rv)}}")
            cleanup()
            raise SystemExit(0)
        part = (ctypes.c_ubyte * 16)(*range(16, 32))
        rv = raw.C_SignMessageNext(
            sh,
            None,
            0,
            part,
            {data_len},
            sig_buf,
            ctypes.byref(sig_len),
            CKF_END_OF_MESSAGE,
        )

    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    final_rv = raw.C_MessageSignFinal(sh)
    print(f"FINAL_RV:0x{{final_rv:08x}}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{op}(data_len={data_len:#x})",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])

        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_LENGTH_REJECT_RVS,
            label=f"{op}(data_len={data_len:#x})",
        )

    @pytest.mark.requires_v30
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("field", _MESSAGE_VERIFY_MULTIPART_FIELDS)
    def test_verify_message_multipart_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        field: str,
    ) -> None:
        """C_VerifyMessageBegin/Next must reject huge input lengths safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_SHA256_RSA_PKCS)
        if not (info["flags"] & int(CKF_MESSAGE_VERIFY)):
            pytest.skip("CKM_SHA256_RSA_PKCS does not advertise CKF_MESSAGE_VERIFY")

        available = rs.raw.available_function_names()
        for fname in (
            "C_MessageVerifyInit",
            "C_VerifyMessageBegin",
            "C_VerifyMessageNext",
            "C_MessageVerifyFinal",
        ):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)

        normal_data_len = 16
        begin_param_len = data_len if field == "begin_parameter" else 0
        next_data_len = data_len if field == "next_data" else normal_data_len
        next_signature_len = data_len if field == "next_signature" else 256
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair, sign_single
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKF_END_OF_MESSAGE,
    CK_MECHANISM,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
)

try:
    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        public_attrs={{CKA_VERIFY: True, CKA_TOKEN: False}},
        private_attrs={{CKA_SIGN: True, CKA_TOKEN: False}},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected",
    )

try:
    data_bytes = bytes(range({normal_data_len}))
    try:
        signature = sign_single(raw, sh, priv, CKM_SHA256_RSA_PKCS, data_bytes)
    except AssertionError as exc:
        rv = getattr(exc, "rv", None)
        detail = ckr_name(rv) if rv is not None else str(exc)
        print(f"SETUP_XFAIL:standard signature generation rejected: {{detail}}")
        cleanup()
        raise SystemExit(0)

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_RSA_PKCS
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_MessageVerifyInit(sh, ctypes.byref(mech), pub)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_MessageVerifyInit rejected: {{ckr_name(rv)}}")
        cleanup()
        raise SystemExit(0)

    begin_params = (ctypes.c_ubyte * 1)(0)
    begin_param_ptr = ctypes.cast(begin_params, ctypes.c_void_p)
    if "{field}" == "begin_parameter":
        rv = raw.C_VerifyMessageBegin(sh, begin_param_ptr, {begin_param_len})
    else:
        rv = raw.C_VerifyMessageBegin(sh, None, 0)
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_VerifyMessageBegin rejected: {{ckr_name(rv)}}")
            cleanup()
            raise SystemExit(0)
        data = (ctypes.c_ubyte * {normal_data_len})(*range({normal_data_len}))
        sig_buf = (ctypes.c_ubyte * len(signature))(*signature)
        rv = raw.C_VerifyMessageNext(
            sh,
            None,
            0,
            data,
            {next_data_len},
            sig_buf,
            {next_signature_len},
            CKF_END_OF_MESSAGE,
        )

    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    final_rv = raw.C_MessageVerifyFinal(sh)
    print(f"FINAL_RV:0x{{final_rv:08x}}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_VerifyMessage multipart {field}={data_len:#x}",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])

        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_VERIFY_LENGTH_REJECT_RVS,
            label=f"C_VerifyMessage multipart {field}={data_len:#x}",
        )

    @pytest.mark.requires_v30
    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("op", _MESSAGE_ENCRYPT_MULTIPART_OPS)
    def test_encrypt_message_multipart_isize_input_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        op: str,
    ) -> None:
        """C_EncryptMessageBegin/Next must reject huge input lengths safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_ENCRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_ENCRYPT")

        available = rs.raw.available_function_names()
        for fname in (
            "C_MessageEncryptInit",
            "C_EncryptMessageBegin",
            "C_EncryptMessageNext",
            "C_MessageEncryptFinal",
        ):
            if fname not in available:
                pytest.skip(f"{fname} not available")

        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose=f"{op} length-boundary crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)

        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKF_END_OF_MESSAGE,
    CK_GCM_MESSAGE_PARAMS,
    CK_MECHANISM,
    CKM_AES_GCM,
    CKR_OK,
    CK_ULONG,
)

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )

try:
    init_iv = (ctypes.c_ubyte * 12)(*range(12))
    init_tag = (ctypes.c_ubyte * 16)()
    init_params = CK_GCM_MESSAGE_PARAMS()
    init_params.pIv = ctypes.cast(init_iv, ctypes.c_void_p)
    init_params.ulIvLen = 12
    init_params.ulIvFixedBits = 0
    init_params.ivGenerator = 0
    init_params.pTag = ctypes.cast(init_tag, ctypes.c_void_p)
    init_params.ulTagBits = 128

    init_mech = CK_MECHANISM()
    init_mech.mechanism = CKM_AES_GCM
    init_mech.pParameter = ctypes.cast(ctypes.pointer(init_params), ctypes.c_void_p)
    init_mech.ulParameterLen = ctypes.sizeof(init_params)

    rv = raw.C_MessageEncryptInit(sh, ctypes.byref(init_mech), key)
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_MessageEncryptInit rejected: {{ckr_name(rv)}}")
        cleanup()
        raise SystemExit(0)

    msg_iv = (ctypes.c_ubyte * 12)(*range(12, 24))
    msg_tag = (ctypes.c_ubyte * 16)()
    msg_params = CK_GCM_MESSAGE_PARAMS()
    msg_params.pIv = ctypes.cast(msg_iv, ctypes.c_void_p)
    msg_params.ulIvLen = 12
    msg_params.ulIvFixedBits = 0
    msg_params.ivGenerator = 0
    msg_params.pTag = ctypes.cast(msg_tag, ctypes.c_void_p)
    msg_params.ulTagBits = 128

    plaintext = (ctypes.c_ubyte * 16)(*range(16))
    out_len = CK_ULONG(256)
    out_buf = (ctypes.c_ubyte * 256)()

    if "{op}" == "C_EncryptMessageBegin":
        rv = raw.C_EncryptMessageBegin(
            sh,
            ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
            ctypes.sizeof(msg_params),
            plaintext,
            {data_len},
        )
    else:
        rv = raw.C_EncryptMessageBegin(
            sh,
            ctypes.cast(ctypes.pointer(msg_params), ctypes.c_void_p),
            ctypes.sizeof(msg_params),
            plaintext,
            16,
        )
        if rv != CKR_OK:
            print(f"SETUP_XFAIL:C_EncryptMessageBegin rejected: {{ckr_name(rv)}}")
            cleanup()
            raise SystemExit(0)
        part = (ctypes.c_ubyte * 16)(*range(16, 32))
        rv = raw.C_EncryptMessageNext(
            sh,
            None,
            0,
            part,
            {data_len},
            out_buf,
            ctypes.byref(out_len),
            CKF_END_OF_MESSAGE,
        )

    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    final_rv = raw.C_MessageEncryptFinal(sh)
    print(f"FINAL_RV:0x{{final_rv:08x}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{op}(plaintext_len={data_len:#x})",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])

        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_LENGTH_REJECT_RVS,
            label=f"{op}(plaintext_len={data_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestIsizeMaxUpdateLength
# ---------------------------------------------------------------------------

_UPDATE_LENGTH_OPS = [
    pytest.param("C_EncryptUpdate", id="encrypt_update"),
    pytest.param("C_DecryptUpdate", id="decrypt_update"),
    pytest.param("C_SignUpdate", id="sign_update"),
    pytest.param("C_VerifyUpdate", id="verify_update"),
    pytest.param("C_DigestUpdate", id="digest_update"),
]


class TestIsizeMaxUpdateLength:
    """Initialized update APIs must reject huge claimed input lengths safely."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("op", _UPDATE_LENGTH_OPS)
    def test_update_isize_data_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
        op: str,
    ) -> None:
        rs = p11_raw_session
        if op in {"C_EncryptUpdate", "C_DecryptUpdate"}:
            if not rs.has_mechanism("AES_ECB"):
                pytest.skip("CKM_AES_ECB not supported")
            setup_key = gen_aes_key_or_xfail(
                rs,
                256,
                purpose=f"{op} isize-boundary crash probe setup",
            )
            destroy_returned_handles(rs, setup_key)
        elif op in {"C_SignUpdate", "C_VerifyUpdate"}:
            if not rs.has_mechanism("SHA256_HMAC"):
                pytest.skip("CKM_SHA256_HMAC not supported")
        elif op == "C_DigestUpdate":
            if not rs.has_mechanism("SHA256"):
                pytest.skip("CKM_SHA256 not supported")
        else:
            raise ValueError(f"Unhandled op: {op}")

        preamble = _preamble(p11_config)
        if op in {"C_EncryptUpdate", "C_DecryptUpdate"}:
            init_op = "C_EncryptInit" if op == "C_EncryptUpdate" else "C_DecryptInit"
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
{_CHILD_SETUP_REJECT_HELPERS}

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_ECB
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.{init_op}(sh, ctypes.byref(mech), key)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        print("TARGET:{op}", flush=True)
        print("LEN:{data_len}", flush=True)
        rv2 = raw.{op}(sh, buf, {data_len}, out_buf, ctypes.byref(out_len))
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif op == "C_SignUpdate":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_MECHANISM, CKM_SHA256_HMAC, CKR_OK
{_HMAC_KEY_IMPORT_HELPER}

key = import_hmac_key(sign=True)
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_HMAC
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        print("TARGET:C_SignUpdate", flush=True)
        print("LEN:{data_len}", flush=True)
        rv2 = raw.C_SignUpdate(sh, buf, {data_len})
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        elif op == "C_VerifyUpdate":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_MECHANISM, CKM_SHA256_HMAC, CKR_OK
{_HMAC_KEY_IMPORT_HELPER}

key = import_hmac_key(verify=True)
try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_HMAC
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key.value)
    if rv == CKR_OK:
        buf = (ctypes.c_ubyte * 16)(*range(16))
        print("TARGET:C_VerifyUpdate", flush=True)
        print("LEN:{data_len}", flush=True)
        rv2 = raw.C_VerifyUpdate(sh, buf, {data_len})
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        elif op == "C_DigestUpdate":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_MECHANISM, CKM_SHA256, CKR_OK

mech = CK_MECHANISM()
mech.mechanism = CKM_SHA256
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DigestInit(sh, ctypes.byref(mech))
if rv == CKR_OK:
    buf = (ctypes.c_ubyte * 16)(*range(16))
    print("TARGET:C_DigestUpdate", flush=True)
    print("LEN:{data_len}", flush=True)
    rv2 = raw.C_DigestUpdate(sh, buf, {data_len})
    print(f"rv={{rv2}}")
else:
    print(f"rv={{rv}}")
cleanup()
"""
        else:
            raise ValueError(f"Unhandled op: {op}")

        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{op}(ulDataLen={data_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestRandomIsizeLength
# ---------------------------------------------------------------------------


class TestRandomIsizeLength:
    """Random APIs must handle impossible claimed buffer lengths safely."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_generate_random_isize_length_preserves_guard(
        self,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """``C_GenerateRandom`` must not accept or overwrite a tiny real buffer."""
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import CKR_OK

GUARD = 0xA7
GUARD_SIZE = 64

class RandomProbe(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_ubyte * 1),
        ("guard", ctypes.c_ubyte * GUARD_SIZE),
    ]

probe = RandomProbe()
for idx in range(GUARD_SIZE):
    probe.guard[idx] = GUARD

print("TARGET:C_GenerateRandom", flush=True)
print("LEN:{data_len}", flush=True)
rv = raw.C_GenerateRandom(
    sh,
    ctypes.cast(probe.data, ctypes.POINTER(ctypes.c_ubyte)),
    {data_len},
)
print(f"rv={{rv}}")
print(f"rv_name={{ckr_name(rv)}}")
overwritten = sum(1 for byte in probe.guard if byte != GUARD)
print(f"OVERWRITTEN:{{overwritten}}")
assert overwritten == 0, (
    "C_GenerateRandom wrote past the tiny real output allocation: "
    f"{{overwritten}} guard byte(s) changed"
)
assert rv != CKR_OK, (
    "C_GenerateRandom accepted an impossible claimed output length "
    f"({data_len:#x}) for a tiny real allocation"
)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateRandom(ulRandomLen={data_len:#x})",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_seed_random_isize_length_rejects_cleanly(
        self,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """``C_SeedRandom`` must reject an impossible claimed seed length cleanly."""
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import CKR_OK

seed = (ctypes.c_ubyte * 16)(*range(16))
print("TARGET:C_SeedRandom", flush=True)
print("LEN:{data_len}", flush=True)
rv = raw.C_SeedRandom(sh, seed, {data_len})
print(f"rv={{rv}}")
print(f"rv_name={{ckr_name(rv)}}")
assert rv != CKR_OK, (
    "C_SeedRandom accepted an impossible claimed seed length "
    f"({data_len:#x}) for a tiny real allocation"
)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_SeedRandom(ulSeedLen={data_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestAllocationGuard
# ---------------------------------------------------------------------------


class TestAllocationGuard:
    """Probe key generation with large but valid CKA_VALUE_LEN.

    Kryoptic changed ``vec![0; value_len]`` (panics on OOM) to
    ``try_reserve_exact`` (returns CKR_HOST_MEMORY).  A 2 GB
    CKA_VALUE_LEN is large enough to likely OOM on most systems but
    is NOT in integer-overflow territory (unlike the ULONG_MAX tests
    in test_arithmetic_overflow.py).
    """

    @pytest.mark.slow
    def test_generate_key_oom_value_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_KEY_GEN, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE, CKA_VALUE_LEN, CKA_TOKEN, CKA_ENCRYPT, CK_ULONG,
)

mech = CK_MECHANISM()
mech.mechanism = CKM_AES_KEY_GEN
mech.pParameter = None
mech.ulParameterLen = 0

val_len = CK_ULONG({_ALLOC_GUARD_VALUE_LEN})
token_false = ctypes.c_ubyte(0)
enc_true = ctypes.c_ubyte(1)

attrs = (CK_ATTRIBUTE * 3)()
attrs[0].type = CKA_VALUE_LEN
attrs[0].pValue = ctypes.cast(
    ctypes.pointer(val_len), ctypes.c_void_p,
)
attrs[0].ulValueLen = ctypes.sizeof(val_len)
attrs[1].type = CKA_TOKEN
attrs[1].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
attrs[1].ulValueLen = 1
attrs[2].type = CKA_ENCRYPT
attrs[2].pValue = ctypes.cast(
    ctypes.pointer(enc_true), ctypes.c_void_p,
)
attrs[2].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(
    sh, ctypes.byref(mech),
    ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)), 3,
    ctypes.byref(key),
)
print(f"rv={{rv}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=5, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(f"C_GenerateKey(AES, CKA_VALUE_LEN={_ALLOC_GUARD_VALUE_LEN:#x})"),
        )


# ---------------------------------------------------------------------------
# TestMechanismNullInnerParams
# ---------------------------------------------------------------------------


class TestMechanismNullInnerParams:
    """Probe *Init / DeriveKey with valid mechanism structs whose inner
    parameter structures contain NULL data pointers.

    Distinct from TestMechanismParamNullWithLength in test_api_boundary.py
    which tests NULL pParameter on the outer CK_MECHANISM.  These tests
    put a valid CK_MECHANISM struct with a valid pParameter pointer, but
    the inner struct has NULL data pointers where non-NULL is expected.
    """

    def test_gcm_null_iv(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """AES-GCM with pIv=NULL but ulIvLen=12, ulIvBits=96."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-GCM NULL-IV crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_AES_GCM_PARAMS, CK_MECHANISM, CKM_AES_GCM,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    params = CK_AES_GCM_PARAMS()
    params.pIv = None            # NULL -- should be rejected
    params.ulIvLen = 12
    params.ulIvBits = 96
    params.pAAD = None
    params.ulAADLen = 0
    params.ulTagBits = 128
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_GCM
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptInit(AES_GCM, pIv=NULL, ulIvLen=12)",
        )

    def test_ecdh_null_public_data(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """ECDH1 derive with pPublicData=NULL but ulPublicDataLen=65."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(
            rs,
            curve_oid,
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_ECDH1_DERIVE_PARAMS, CK_MECHANISM, CKM_ECDH1_DERIVE,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKD_NULL, CK_ULONG,
)
from pkcs11_check.raw.recipes import gen_ec_keypair, destroy_quietly
from pkcs11_check.raw.ec import encode_named_curve_parameters

curve_oid = encode_named_curve_parameters("secp256r1")
try:
    pub, priv = gen_ec_keypair(raw, sh, curve_oid,
        private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "EC keypair generation rejected",
    )
try:
    params = CK_ECDH1_DERIVE_PARAMS()
    params.kdf = CKD_NULL
    params.ulSharedDataLen = 0
    params.pSharedData = None
    params.ulPublicDataLen = 65  # Claim 65 bytes (uncompressed P-256)
    params.pPublicData = None    # NULL -- should be rejected
    mech = CK_MECHANISM()
    mech.mechanism = CKM_ECDH1_DERIVE
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Template for the derived key
    cls_val = CK_ULONG(CKO_SECRET_KEY)
    kt_val = CK_ULONG(CKK_GENERIC_SECRET)
    vl_val = CK_ULONG(32)
    token_false = ctypes.c_ubyte(0)
    tmpl = (CK_ATTRIBUTE * 4)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(cls_val), ctypes.c_void_p,
    )
    tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    tmpl[1].type = CKA_KEY_TYPE
    tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(kt_val), ctypes.c_void_p,
    )
    tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
    tmpl[2].type = CKA_VALUE_LEN
    tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(vl_val), ctypes.c_void_p,
    )
    tmpl[2].ulValueLen = ctypes.sizeof(vl_val)
    tmpl[3].type = CKA_TOKEN
    tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(token_false), ctypes.c_void_p,
    )
    tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), priv,
        ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(ECDH1, pPublicData=NULL, ulPublicDataLen=65)"),
        )

    def test_oaep_null_source_data(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """RSA-OAEP with pSourceData=NULL but ulSourceDataLen=16."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_RSA_PKCS_OAEP_PARAMS, CK_MECHANISM, CKM_RSA_PKCS_OAEP,
    CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED,
    CKA_ENCRYPT, CKA_TOKEN, CKA_VERIFY,
)
from pkcs11_check.raw.recipes import gen_rsa_keypair, destroy_quietly

try:
    pub, priv = gen_rsa_keypair(raw, sh, 2048,
        public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
        private_attrs={CKA_TOKEN: False},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected",
    )
try:
    params = CK_RSA_PKCS_OAEP_PARAMS()
    params.hashAlg = CKM_SHA256
    params.mgf = CKG_MGF1_SHA256
    params.source = CKZ_DATA_SPECIFIED
    params.pSourceData = None     # NULL -- should be rejected
    params.ulSourceDataLen = 16   # Claim 16 bytes
    mech = CK_MECHANISM()
    mech.mechanism = CKM_RSA_PKCS_OAEP
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), pub)
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_EncryptInit(RSA_OAEP, pSourceData=NULL, ulSourceDataLen=16)"),
        )

    def test_hkdf_null_salt(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """HKDF derive with pSalt=NULL but ulSaltLen=16,
        ulSaltType=CKF_HKDF_SALT_DATA.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_HKDF_PARAMS, CK_MECHANISM, CKM_HKDF_DERIVE, CKM_SHA256,
    CKF_HKDF_SALT_DATA,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_VALUE, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import an HMAC key for HKDF input
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(
    ctypes.pointer(derive_true), ctypes.c_void_p,
)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"rv={rv}")
    cleanup()
    raise SystemExit(0)

try:
    info_data = (ctypes.c_ubyte * 4)(*b"test")
    params = CK_HKDF_PARAMS()
    params.bExtract = 1
    params.bExpand = 1
    params.prfHashMechanism = CKM_SHA256
    params.ulSaltType = CKF_HKDF_SALT_DATA
    params.pSalt = None          # NULL -- should be rejected
    params.ulSaltLen = 16        # Claim 16 bytes
    params.hSaltKey = 0
    params.pInfo = ctypes.cast(info_data, ctypes.c_void_p)
    params.ulInfoLen = 4
    mech = CK_MECHANISM()
    mech.mechanism = CKM_HKDF_DERIVE
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Derived key template
    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_GENERIC_SECRET)
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(d_cls), ctypes.c_void_p,
    )
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(d_kt), ctypes.c_void_p,
    )
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(d_vl), ctypes.c_void_p,
    )
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(d_tok), ctypes.c_void_p,
    )
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(HKDF, pSalt=NULL, ulSaltLen=16, ulSaltType=CKF_HKDF_SALT_DATA)"),
        )


# ---------------------------------------------------------------------------
# TestIsizeMaxOutputLength
# ---------------------------------------------------------------------------


class TestIsizeMaxOutputLength:
    """Probe OUTPUT buffer length parameters with isize::MAX boundary.

    Complementary to TestIsizeMaxDataLength which tests INPUT data length.
    Kryoptic's check_slice_len<u8>() also guards output/signature buffer
    sizes in sign(), verify(), digest(), sign_final(), verify_final(),
    digest_final().  A claimed output buffer size of isize::MAX (or +1)
    with a small real buffer should be rejected, not cause UB.
    """

    @pytest.mark.parametrize("out_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_sign_isize_output(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        out_len: int,
    ) -> None:
        """C_Sign with isize::MAX claimed output buffer length."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CK_ULONG, CKR_OK,
    CKA_SIGN, CKA_TOKEN, CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET,
    CK_ATTRIBUTE, CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a 32-byte HMAC key via C_CreateObject
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
sign_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

attrs = (CK_ATTRIBUTE * 5)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = CKA_VALUE
attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
attrs[2].ulValueLen = 32
attrs[3].type = CKA_SIGN
attrs[3].pValue = ctypes.cast(
    ctypes.pointer(sign_true), ctypes.c_void_p,
)
attrs[3].ulValueLen = 1
attrs[4].type = CKA_TOKEN
attrs[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
attrs[4].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(key),
)
if rv != CKR_OK:
    print(f"rv={{rv}}")
    cleanup()
    raise SystemExit(0)

try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_HMAC
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        sig_buf = (ctypes.c_ubyte * 64)()
        sig_len = CK_ULONG({out_len})
        rv2 = raw.C_Sign(
            sh, data, 16, sig_buf, ctypes.byref(sig_len),
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Sign(HMAC_SHA256, sig_len={out_len:#x})",
        )

    @pytest.mark.parametrize("out_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_digest_isize_output(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        out_len: int,
    ) -> None:
        """C_Digest with isize::MAX claimed output buffer length."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256, CK_ULONG, CKR_OK,
)

mech = CK_MECHANISM()
mech.mechanism = CKM_SHA256
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DigestInit(sh, ctypes.byref(mech))
if rv == CKR_OK:
    data = (ctypes.c_ubyte * 16)(*range(16))
    digest_buf = (ctypes.c_ubyte * 64)()
    digest_len = CK_ULONG({out_len})
    rv2 = raw.C_Digest(
        sh, data, 16, digest_buf, ctypes.byref(digest_len),
    )
    print(f"rv={{rv2}}")
else:
    print(f"rv={{rv}}")
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Digest(SHA256, digest_len={out_len:#x})",
        )

    @pytest.mark.parametrize("sig_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_verify_isize_sig_len(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        sig_len: int,
    ) -> None:
        """C_Verify with isize::MAX claimed signature length."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CK_ULONG, CKR_OK,
    CKA_VERIFY, CKA_TOKEN, CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET,
    CK_ATTRIBUTE, CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a 32-byte HMAC key via C_CreateObject
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
verify_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

attrs = (CK_ATTRIBUTE * 5)()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
attrs[1].ulValueLen = ctypes.sizeof(kt_val)
attrs[2].type = CKA_VALUE
attrs[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
attrs[2].ulValueLen = 32
attrs[3].type = CKA_VERIFY
attrs[3].pValue = ctypes.cast(
    ctypes.pointer(verify_true), ctypes.c_void_p,
)
attrs[3].ulValueLen = 1
attrs[4].type = CKA_TOKEN
attrs[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
attrs[4].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh, ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(key),
)
if rv != CKR_OK:
    print(f"rv={{rv}}")
    cleanup()
    raise SystemExit(0)

try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_HMAC
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key.value)
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        sig_buf = (ctypes.c_ubyte * 64)()
        rv2 = raw.C_Verify(
            sh, data, 16, sig_buf, {sig_len},
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Verify(HMAC_SHA256, sig_len={sig_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestHkdfNullInfo
# ---------------------------------------------------------------------------


class TestHkdfNullInfo:
    """HKDF derive with pInfo=NULL but ulInfoLen>0.

    Complementary to test_hkdf_null_salt in TestMechanismNullInnerParams
    which tests the NULL salt field.  This tests the other NULL-able
    parameter: the info/context data pointer.
    """

    def test_hkdf_null_info(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """HKDF derive with pInfo=NULL but ulInfoLen=16."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_HKDF_PARAMS, CK_MECHANISM, CKM_HKDF_DERIVE, CKM_SHA256,
    CKF_HKDF_SALT_NULL,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_VALUE, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a generic secret key with CKA_DERIVE=True
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(
    ctypes.pointer(derive_true), ctypes.c_void_p,
)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"rv={rv}")
    cleanup()
    raise SystemExit(0)

try:
    params = CK_HKDF_PARAMS()
    params.bExtract = 1
    params.bExpand = 1
    params.prfHashMechanism = CKM_SHA256
    params.ulSaltType = CKF_HKDF_SALT_NULL
    params.pSalt = None
    params.ulSaltLen = 0
    params.hSaltKey = 0
    params.pInfo = None          # NULL -- crash vector
    params.ulInfoLen = 16        # Non-zero length with NULL pointer
    mech = CK_MECHANISM()
    mech.mechanism = CKM_HKDF_DERIVE
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Derived key template
    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_GENERIC_SECRET)
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(d_cls), ctypes.c_void_p,
    )
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(d_kt), ctypes.c_void_p,
    )
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(d_vl), ctypes.c_void_p,
    )
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(d_tok), ctypes.c_void_p,
    )
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_DeriveKey(HKDF, pInfo=NULL, ulInfoLen=16)",
        )


# ---------------------------------------------------------------------------
# TestEddsaNullContext
# ---------------------------------------------------------------------------


class TestEddsaNullContext:
    """EdDSA with CK_EDDSA_PARAMS having pContextData=NULL but
    ulContextDataLen>0.

    Tests that the module does not dereference the NULL context data
    pointer when building the EdDSA signature context.
    """

    def test_eddsa_null_context_data(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """EdDSA SignInit with pContextData=NULL, ulContextDataLen=16."""
        rs = p11_raw_session
        if not rs.has_mechanism("EDDSA"):
            pytest.skip("CKM_EDDSA not supported")
        curve_oid = encode_named_curve_parameters("ed25519")
        pub, priv = gen_edwards_keypair_or_xfail(
            rs,
            curve_oid,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )
        destroy_returned_handles(rs, pub, priv)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_EDDSA_PARAMS, CK_MECHANISM, CKM_EDDSA, CKM_EC_EDWARDS_KEY_PAIR_GEN,
    CKA_EC_PARAMS, CKA_SIGN, CKA_TOKEN, CKA_VERIFY,
)
from pkcs11_check.raw.pack import attr_bytes
from pkcs11_check.raw.recipes import gen_keypair, destroy_quietly
from pkcs11_check.raw.ec import encode_named_curve_parameters

# Ed25519 OID
curve_oid = encode_named_curve_parameters("ed25519")
try:
    pub, priv = gen_keypair(
        raw, sh, CKM_EC_EDWARDS_KEY_PAIR_GEN,
        pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
        priv_base=[],
        public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        pub_skip={CKA_EC_PARAMS},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS,
        "EC_EDWARDS keypair generation rejected",
    )
try:
    params = CK_EDDSA_PARAMS()
    params.phFlag = 0
    params.ulContextDataLen = 16  # Non-zero
    params.pContextData = None     # NULL -- crash vector
    mech = CK_MECHANISM()
    mech.mechanism = CKM_EDDSA
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_SignInit(EDDSA, pContextData=NULL, ulContextDataLen=16)"),
        )


# ---------------------------------------------------------------------------
# TestMlDsaExplicitEmptyContext
# ---------------------------------------------------------------------------


class TestMlDsaExplicitEmptyContext:
    """ML-DSA with CK_SIGN_ADDITIONAL_CONTEXT carrying a non-NULL empty context."""

    def test_mldsa_verify_empty_context_nonnull_pointer(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """ML-DSA Verify with pContext non-NULL and ulContextLen=0."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA"):
            pytest.skip("CKM_ML_DSA not supported")
        if not rs.has_mechanism("ML_DSA_KEY_PAIR_GEN"):
            pytest.skip("CKM_ML_DSA_KEY_PAIR_GEN not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.pack import attr_ulong
from pkcs11_check.raw.types_std import (
    CKA_PARAMETER_SET, CKA_SIGN, CKA_TOKEN, CKA_VERIFY,
    CK_MECHANISM, CK_SIGN_ADDITIONAL_CONTEXT,
    CKH_HEDGE_PREFERRED, CKM_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN,
    CKP_ML_DSA_65, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly, gen_keypair, sign_single

message = b"ML-DSA empty context pointer crash probe"
try:
    pub, priv = gen_keypair(
        raw,
        sh,
        CKM_ML_DSA_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_PARAMETER_SET, CKP_ML_DSA_65)],
        priv_base=[],
        public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        pub_skip={CKA_PARAMETER_SET},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "ML-DSA keypair generation rejected",
    )
try:
    sig = sign_single(raw, sh, priv, CKM_ML_DSA, message)

    context = (ctypes.c_ubyte * 0)()
    params = CK_SIGN_ADDITIONAL_CONTEXT()
    params.hedgeVariant = CKH_HEDGE_PREFERRED
    params.pContext = ctypes.cast(context, ctypes.c_void_p)
    params.ulContextLen = 0

    mech = CK_MECHANISM()
    mech.mechanism = CKM_ML_DSA
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), pub)
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        data_buf = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
        sig_buf = (ctypes.c_ubyte * len(sig)).from_buffer_copy(sig)
        rv = raw.C_Verify(sh, data_buf, len(message), sig_buf, len(sig))
        print(f"verify_rv={rv}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_Verify(ML-DSA, pContext non-NULL, ulContextLen=0)"),
        )


# ---------------------------------------------------------------------------
# TestAesCcmNullNonce
# ---------------------------------------------------------------------------


class TestAesCcmNullNonce:
    """AES-CCM with CK_AES_CCM_PARAMS having pNonce=NULL but ulNonceLen>0.

    Separate mechanism from GCM.  Tests that the module does not
    dereference the NULL nonce pointer during C_EncryptInit.
    """

    def test_ccm_null_nonce(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """AES-CCM EncryptInit with pNonce=NULL, ulNonceLen=7."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CCM"):
            pytest.skip("CKM_AES_CCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-CCM NULL-nonce crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_AES_CCM_PARAMS, CK_MECHANISM, CKM_AES_CCM,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    params = CK_AES_CCM_PARAMS()
    params.ulDataLen = 32
    params.pNonce = None         # NULL -- crash vector
    params.ulNonceLen = 7        # Non-zero
    params.pAAD = None
    params.ulAADLen = 0
    params.ulMACLen = 16
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_CCM
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptInit(AES_CCM, pNonce=NULL, ulNonceLen=7)",
        )


# ---------------------------------------------------------------------------
# TestSimpleKdfNullData
# ---------------------------------------------------------------------------


class TestSimpleKdfNullData:
    """CKM_CONCATENATE_BASE_AND_DATA with CK_KEY_DERIVATION_STRING_DATA
    having pData=NULL but ulLen>0.

    Tests that the module validates the data pointer before
    dereferencing it during key derivation.
    """

    def test_concat_base_data_null(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_DeriveKey(CONCATENATE_BASE_AND_DATA) with pData=NULL."""
        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_KEY_DERIVATION_STRING_DATA, CK_MECHANISM,
    CKM_CONCATENATE_BASE_AND_DATA,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_VALUE, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a secret key with CKA_DERIVE=True
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(
    ctypes.pointer(derive_true), ctypes.c_void_p,
)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"rv={rv}")
    cleanup()
    raise SystemExit(0)

try:
    params = CK_KEY_DERIVATION_STRING_DATA()
    params.pData = None          # NULL -- crash vector
    params.ulLen = 16            # Non-zero length
    mech = CK_MECHANISM()
    mech.mechanism = CKM_CONCATENATE_BASE_AND_DATA
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Derived key template
    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_GENERIC_SECRET)
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(d_cls), ctypes.c_void_p,
    )
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(d_kt), ctypes.c_void_p,
    )
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(d_vl), ctypes.c_void_p,
    )
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(d_tok), ctypes.c_void_p,
    )
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(CONCATENATE_BASE_AND_DATA, pData=NULL, ulLen=16)"),
        )


# ---------------------------------------------------------------------------
# TestAesCbcEncryptDataMalformedParams
# ---------------------------------------------------------------------------

_AES_CBC_ENCRYPT_DATA_PARAM_CASES = (
    pytest.param("pData=NULL,length=16", "None", 16, id="null_data_nonzero_length"),
    pytest.param(
        "pData=tiny,length=isize_max_plus_1",
        "ctypes.cast(data_buf, ctypes.c_void_p)",
        _ISIZE_MAX_PLUS_1_64,
        id="tiny_data_huge_length",
    ),
)


class TestAesCbcEncryptDataMalformedParams:
    """CKM_AES_CBC_ENCRYPT_DATA must reject malformed nested data safely."""

    @pytest.mark.parametrize(
        ("case_label", "p_data_expr", "data_len"),
        _AES_CBC_ENCRYPT_DATA_PARAM_CASES,
    )
    def test_aes_cbc_encrypt_data_malformed_params(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        case_label: str,
        p_data_expr: str,
        data_len: int,
    ) -> None:
        """C_DeriveKey(AES_CBC_ENCRYPT_DATA) validates inner pData/length pairs."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_ENCRYPT_DATA"):
            pytest.skip("CKM_AES_CBC_ENCRYPT_DATA not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.pack import attr_bool, attr_ulong, template
from pkcs11_check.raw.recipes import destroy_quietly, import_secret_key
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_CBC_ENCRYPT_DATA_PARAMS,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_AES,
    CKM_AES_CBC_ENCRYPT_DATA,
    CKO_SECRET_KEY,
    CKR_OK,
)

data_len = {data_len}
data_buf = (ctypes.c_ubyte * 16)(*range(16))
base_key = 0
try:
    base_key = import_secret_key(
        raw,
        sh,
        CKK_AES,
        bytes(range(32)),
        attrs={{
            CKA_DERIVE: True,
            CKA_TOKEN: False,
        }},
    )
except AssertionError as exc:
    print(f"SETUP_XFAIL:AES derive base-key import rejected: {{exc}}")
    cleanup()
    raise SystemExit(0)

try:
    params = CK_AES_CBC_ENCRYPT_DATA_PARAMS()
    for idx in range(16):
        params.iv[idx] = idx
    params.pData = {p_data_expr}
    params.length = data_len

    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_CBC_ENCRYPT_DATA
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    derived_template = template(
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_AES),
        attr_ulong(CKA_VALUE_LEN, 16),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
        attr_bool(CKA_TOKEN, False),
    )
    derived = CK_OBJECT_HANDLE(0)
    print("TARGET_CALL:C_DeriveKey(AES_CBC_ENCRYPT_DATA,{case_label})", flush=True)
    rv = raw.C_DeriveKey(
        sh,
        ctypes.byref(mech),
        base_key,
        derived_template.ptr,
        derived_template.count,
        ctypes.byref(derived),
    )
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
    if rv == CKR_OK:
        destroy_quietly(raw, sh, derived.value)
finally:
    destroy_quietly(raw, sh, base_key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_DeriveKey(AES_CBC_ENCRYPT_DATA, {case_label})",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KDF_LENGTH_REJECT_RVS,
            label=f"C_DeriveKey(AES_CBC_ENCRYPT_DATA, {case_label})",
        )


# ---------------------------------------------------------------------------
# TestRsaPssSaltLengthBoundary
# ---------------------------------------------------------------------------


class TestRsaPssSaltLengthBoundary:
    """RSA-PSS sLen (salt length) must reject impossible values safely.

    CK_RSA_PKCS_PSS_PARAMS.sLen is a caller-controlled CK_ULONG. A module that
    uses it without bounds-checking against the modulus and hash sizes can
    over-read or over-allocate. For RSA-2048/SHA-256 the maximum salt length is
    ~222 bytes, so isize::MAX / isize::MAX+1 is impossible and must be cleanly
    rejected; a crash/hang is a finding and CKR_OK accepts a nonsensical param.
    """

    @pytest.mark.parametrize("salt_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_rsa_pss_salt_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        salt_len: int,
    ) -> None:
        """C_Sign(SHA256_RSA_PKCS_PSS) must reject an impossible sLen safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS_PSS"):
            pytest.skip("CKM_SHA256_RSA_PKCS_PSS not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_RSA_PKCS_PSS_PARAMS,
    CK_ULONG,
    CKA_SIGN,
    CKA_TOKEN,
    CKG_MGF1_SHA256,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS_PSS,
    CKR_OK,
)

pub = priv = 0
try:
    pub, priv = gen_rsa_keypair(
        raw,
        sh,
        2048,
        public_attrs={{CKA_TOKEN: False}},
        private_attrs={{CKA_SIGN: True, CKA_TOKEN: False}},
    )
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, KEYPAIR_RUNTIME_REJECT_RVS, "RSA keypair generation rejected",
    )

try:
    params = CK_RSA_PKCS_PSS_PARAMS()
    params.hashAlg = CKM_SHA256
    params.mgf = CKG_MGF1_SHA256
    params.sLen = {salt_len}

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_RSA_PKCS_PSS
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        sig_len = CK_ULONG(512)
        sig_buf = (ctypes.c_ubyte * 512)()
        print("TARGET_CALL:C_Sign(SHA256_RSA_PKCS_PSS,sLen={salt_len:#x})", flush=True)
        rv = raw.C_Sign(sh, data, 16, sig_buf, ctypes.byref(sig_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Sign(SHA256_RSA_PKCS_PSS, sLen={salt_len:#x})",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KDF_LENGTH_REJECT_RVS,
            label=f"C_Sign(SHA256_RSA_PKCS_PSS, sLen={salt_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestGcmAadLengthBoundary
# ---------------------------------------------------------------------------


class TestGcmAadLengthBoundary:
    """AES-GCM ulAADLen must not turn a tiny AAD buffer into a huge read.

    CK_AES_GCM_PARAMS.pAAD/ulAADLen are caller-controlled. A module that reads
    ulAADLen bytes from pAAD without bounds-checking over-reads when the claimed
    length is impossible. Drive C_EncryptInit + C_Encrypt with a tiny real AAD
    buffer and isize::MAX / isize::MAX+1 claimed lengths; crash/hang is a finding
    and CKR_OK accepts a nonsensical length.
    """

    @pytest.mark.parametrize("aad_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_gcm_aad_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        aad_len: int,
    ) -> None:
        """C_EncryptInit/C_Encrypt(AES_GCM) with tiny pAAD + huge ulAADLen."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        setup_key = gen_aes_key_or_xfail(
            rs,
            256,
            purpose="AES-GCM AAD-length crash probe setup",
        )
        destroy_returned_handles(rs, setup_key)
        preamble = _preamble(p11_config)
        script = (
            preamble
            + _CHILD_SETUP_REJECT_HELPERS
            + f"""
import ctypes
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_AES_GCM_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_GCM,
    CKR_OK,
)

try:
    key = gen_aes_key(raw, sh, 256)
except AssertionError as exc:
    setup_xfail_if_known_ckr(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected",
    )
try:
    iv = (ctypes.c_ubyte * 12)(*range(12))
    aad = (ctypes.c_ubyte * 16)(*range(16))
    params = CK_AES_GCM_PARAMS()
    params.pIv = ctypes.cast(iv, ctypes.c_void_p)
    params.ulIvLen = 12
    params.ulIvBits = 96
    params.pAAD = ctypes.cast(aad, ctypes.c_void_p)
    params.ulAADLen = {aad_len}
    params.ulTagBits = 128
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_GCM
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"INIT_RV:0x{{rv:08x}}", flush=True)
    if rv == CKR_OK:
        pt = (ctypes.c_ubyte * 16)(*range(16))
        out_len = CK_ULONG(64)
        out = (ctypes.c_ubyte * 64)()
        print("TARGET_CALL:C_Encrypt(AES_GCM,ulAADLen={aad_len:#x})", flush=True)
        rv = raw.C_Encrypt(sh, pt, 16, out, ctypes.byref(out_len))
    print(f"TARGET_RV:0x{{rv:08x}}", flush=True)
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}", flush=True)
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_Encrypt(AES_GCM, ulAADLen={aad_len:#x})",
        )
        if "SETUP_XFAIL:" in stdout:
            pytest.xfail(stdout.split("SETUP_XFAIL:", maxsplit=1)[1].splitlines()[0])
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _MESSAGE_LENGTH_REJECT_RVS,
            label=f"C_Encrypt(AES_GCM, ulAADLen={aad_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestPbkdf2NestedLengthBoundary
# ---------------------------------------------------------------------------


class TestPbkdf2NestedLengthBoundary:
    """PBKDF2 nested byte fields must reject impossible claimed lengths safely."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize(
        "field",
        (
            pytest.param("password", id="password"),
            pytest.param("salt", id="salt"),
            pytest.param("prf_data", id="prf_data"),
        ),
    )
    def test_pbkdf2_nested_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        field: str,
        data_len: int,
    ) -> None:
        """C_GenerateKey(PBKDF2) must not read past tiny nested input buffers."""
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PKCS5_PBKD2_PARAMS2,
    CK_ULONG,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_PKCS5_PBKD2,
    CKO_SECRET_KEY,
    CKP_PKCS5_PBKD2_HMAC_SHA256,
    CKR_OK,
    CKZ_SALT_SPECIFIED,
)

field = {field!r}
data_len = {data_len}

password = (ctypes.c_ubyte * 8)(*b"password")
salt = (ctypes.c_ubyte * 8)(*b"salt1234")
prf_data = (ctypes.c_ubyte * 4)(*b"prf!")

params = CK_PKCS5_PBKD2_PARAMS2()
params.saltSource = CKZ_SALT_SPECIFIED
params.pSaltSourceData = ctypes.cast(salt, ctypes.c_void_p)
params.ulSaltSourceDataLen = data_len if field == "salt" else len(salt)
params.iterations = 1024
params.prf = CKP_PKCS5_PBKD2_HMAC_SHA256
if field == "prf_data":
    params.pPrfData = ctypes.cast(prf_data, ctypes.c_void_p)
    params.ulPrfDataLen = data_len
else:
    params.pPrfData = None
    params.ulPrfDataLen = 0
params.pPassword = ctypes.cast(password, ctypes.c_void_p)
params.ulPasswordLen = data_len if field == "password" else len(password)

mech = CK_MECHANISM()
mech.mechanism = CKM_PKCS5_PBKD2
mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
mech.ulParameterLen = ctypes.sizeof(params)

cls_val = CK_ULONG(CKO_SECRET_KEY)
kt_val = CK_ULONG(CKK_GENERIC_SECRET)
value_len = CK_ULONG(32)
token_false = ctypes.c_ubyte(0)
sensitive_false = ctypes.c_ubyte(0)
extractable_true = ctypes.c_ubyte(1)

tmpl = (CK_ATTRIBUTE * 6)()
tmpl[0].type = CKA_CLASS
tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
tmpl[1].type = CKA_KEY_TYPE
tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
tmpl[2].type = CKA_VALUE_LEN
tmpl[2].pValue = ctypes.cast(ctypes.pointer(value_len), ctypes.c_void_p)
tmpl[2].ulValueLen = ctypes.sizeof(value_len)
tmpl[3].type = CKA_TOKEN
tmpl[3].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
tmpl[3].ulValueLen = 1
tmpl[4].type = CKA_SENSITIVE
tmpl[4].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
tmpl[4].ulValueLen = 1
tmpl[5].type = CKA_EXTRACTABLE
tmpl[5].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
tmpl[5].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(
    sh,
    ctypes.byref(mech),
    ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    6,
    ctypes.byref(key),
)
print(f"TARGET_RV:0x{{rv:08x}}")
print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
if rv == CKR_OK:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateKey(PBKDF2, {field} length={data_len:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KDF_LENGTH_REJECT_RVS,
            label=f"C_GenerateKey(PBKDF2, {field} length={data_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestPbeNestedLengthBoundary
# ---------------------------------------------------------------------------

_PBE_LENGTH_MECHANISMS = (
    pytest.param(
        (
            "PBE_SHA1_DES3_EDE_CBC",
            "CKM_PBE_SHA1_DES3_EDE_CBC",
            "CKK_DES3",
            8,
            False,
        ),
        id="pbe_sha1_des3",
    ),
    pytest.param(
        (
            "PBE_SHA1_DES2_EDE_CBC",
            "CKM_PBE_SHA1_DES2_EDE_CBC",
            "CKK_DES2",
            8,
            False,
        ),
        id="pbe_sha1_des2",
    ),
    pytest.param(
        (
            "PBA_SHA1_WITH_SHA1_HMAC",
            "CKM_PBA_SHA1_WITH_SHA1_HMAC",
            "CKK_SHA_1_HMAC",
            20,
            True,
        ),
        id="pba_sha1_hmac",
    ),
)


class TestPbeNestedLengthBoundary:
    """PBE parameter byte fields must reject impossible claimed lengths safely."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize("field", ("password", "salt"))
    @pytest.mark.parametrize("pbe_case", _PBE_LENGTH_MECHANISMS)
    def test_pbe_nested_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        pbe_case: tuple[str, str, str, int, bool],
        field: str,
        data_len: int,
    ) -> None:
        """C_GenerateKey(PBE) must not read past tiny password/salt buffers."""
        rs = p11_raw_session
        mech_name, mech_const, key_type_const, iv_len, sign_verify = pbe_case
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_const} not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PBE_PARAMS,
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_DES2,
    CKK_DES3,
    CKK_SHA_1_HMAC,
    CKM_PBA_SHA1_WITH_SHA1_HMAC,
    CKM_PBE_SHA1_DES2_EDE_CBC,
    CKM_PBE_SHA1_DES3_EDE_CBC,
    CKR_OK,
)

field = {field!r}
data_len = {data_len}
sign_verify = {sign_verify!r}

init_vector = (ctypes.c_ubyte * {iv_len})()
password = (ctypes.c_ubyte * 8)(*b"password")
salt = (ctypes.c_ubyte * 8)(*b"salt1234")

params = CK_PBE_PARAMS()
params.pInitVector = ctypes.cast(init_vector, ctypes.c_void_p)
params.pPassword = ctypes.cast(password, ctypes.c_void_p)
params.ulPasswordLen = data_len if field == "password" else len(password)
params.pSalt = ctypes.cast(salt, ctypes.c_void_p)
params.ulSaltLen = data_len if field == "salt" else len(salt)
params.ulIteration = 1024

mech = CK_MECHANISM()
mech.mechanism = {mech_const}
mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
mech.ulParameterLen = ctypes.sizeof(params)

key_type = CK_ULONG({key_type_const})
token_false = ctypes.c_ubyte(0)
sensitive_false = ctypes.c_ubyte(0)
extractable_true = ctypes.c_ubyte(1)
purpose_true = ctypes.c_ubyte(1)

tmpl = (CK_ATTRIBUTE * 6)()
tmpl[0].type = CKA_KEY_TYPE
tmpl[0].pValue = ctypes.cast(ctypes.pointer(key_type), ctypes.c_void_p)
tmpl[0].ulValueLen = ctypes.sizeof(key_type)
tmpl[1].type = CKA_TOKEN
tmpl[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
tmpl[1].ulValueLen = 1
tmpl[2].type = CKA_SENSITIVE
tmpl[2].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
tmpl[2].ulValueLen = 1
tmpl[3].type = CKA_EXTRACTABLE
tmpl[3].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
tmpl[3].ulValueLen = 1
tmpl[4].type = CKA_SIGN if sign_verify else CKA_ENCRYPT
tmpl[4].pValue = ctypes.cast(ctypes.pointer(purpose_true), ctypes.c_void_p)
tmpl[4].ulValueLen = 1
tmpl[5].type = CKA_VERIFY if sign_verify else CKA_DECRYPT
tmpl[5].pValue = ctypes.cast(ctypes.pointer(purpose_true), ctypes.c_void_p)
tmpl[5].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(
    sh,
    ctypes.byref(mech),
    ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    6,
    ctypes.byref(key),
)
print(f"TARGET_RV:0x{{rv:08x}}")
print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
if rv == CKR_OK:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateKey({mech_const}, {field} length={data_len:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KDF_LENGTH_REJECT_RVS,
            label=f"C_GenerateKey({mech_const}, {field} length={data_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestTlsKdfNullParams
# ---------------------------------------------------------------------------


class TestTlsKdfNullParams:
    """TLS KDF with null inner pointers in CK_TLS_KDF_PARAMS.

    Tests that the module validates the label pointer before
    dereferencing it during TLS key derivation.
    """

    def test_tls_kdf_null_label(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_DeriveKey(TLS_KDF) with pLabel=NULL, ulLabelLength=16."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_KDF"):
            pytest.skip("CKM_TLS_KDF not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_TLS_KDF_PARAMS, CK_SSL3_RANDOM_DATA, CK_MECHANISM,
    CKM_TLS_KDF, CKM_SHA256,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_VALUE, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a 48-byte generic secret key (TLS pre-master secret size)
key_bytes = (ctypes.c_ubyte * 48)(*range(48))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 48
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(
    ctypes.pointer(derive_true), ctypes.c_void_p,
)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"rv={rv}")
    cleanup()
    raise SystemExit(0)

try:
    # Build valid random data (32 bytes each)
    client_random = (ctypes.c_ubyte * 32)(*range(32))
    server_random = (ctypes.c_ubyte * 32)(*range(32))
    random_info = CK_SSL3_RANDOM_DATA()
    random_info.pClientRandom = ctypes.cast(
        client_random, ctypes.c_void_p,
    )
    random_info.ulClientRandomLen = 32
    random_info.pServerRandom = ctypes.cast(
        server_random, ctypes.c_void_p,
    )
    random_info.ulServerRandomLen = 32

    params = CK_TLS_KDF_PARAMS()
    params.prfMechanism = CKM_SHA256
    params.pLabel = None             # NULL -- crash vector
    params.ulLabelLength = 16        # Non-zero length
    params.RandomInfo = random_info
    params.pContextData = None
    params.ulContextDataLength = 0
    mech = CK_MECHANISM()
    mech.mechanism = CKM_TLS_KDF
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Derived key template
    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_GENERIC_SECRET)
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(d_cls), ctypes.c_void_p,
    )
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(d_kt), ctypes.c_void_p,
    )
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(d_vl), ctypes.c_void_p,
    )
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(d_tok), ctypes.c_void_p,
    )
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_DeriveKey(TLS_KDF, pLabel=NULL, ulLabelLength=16)"),
        )


# ---------------------------------------------------------------------------
# TestTlsKdfRandomLengthBoundary
# ---------------------------------------------------------------------------


class TestTlsKdfRandomLengthBoundary:
    """TLS KDF nested random buffers must reject impossible claimed lengths."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    @pytest.mark.parametrize(
        "field",
        (
            pytest.param("client", id="client_random"),
            pytest.param("server", id="server_random"),
        ),
    )
    def test_tls_kdf_random_length_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        field: str,
        data_len: int,
    ) -> None:
        """C_DeriveKey(TLS_KDF) must not read past tiny random buffers."""
        rs = p11_raw_session
        if not rs.has_mechanism("TLS_KDF"):
            pytest.skip("CKM_TLS_KDF not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_SSL3_RANDOM_DATA,
    CK_TLS_KDF_PARAMS,
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_SHA256,
    CKM_TLS_KDF,
    CKO_SECRET_KEY,
    CKR_OK,
)

field = {field!r}
data_len = {data_len}

key_bytes = (ctypes.c_ubyte * 48)(*range(48))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 48
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:TLS KDF base-key import rejected: {{ckr_name(rv)}}")
    cleanup()
    raise SystemExit(0)

try:
    label = (ctypes.c_ubyte * 12)(*b"test label!!")
    client_random = (ctypes.c_ubyte * 32)(*range(32))
    server_random = (ctypes.c_ubyte * 32)(*range(32))

    random_info = CK_SSL3_RANDOM_DATA()
    random_info.pClientRandom = ctypes.cast(client_random, ctypes.c_void_p)
    random_info.ulClientRandomLen = data_len if field == "client" else 32
    random_info.pServerRandom = ctypes.cast(server_random, ctypes.c_void_p)
    random_info.ulServerRandomLen = data_len if field == "server" else 32

    params = CK_TLS_KDF_PARAMS()
    params.prfMechanism = CKM_SHA256
    params.pLabel = ctypes.cast(label, ctypes.c_void_p)
    params.ulLabelLength = len(label)
    params.RandomInfo = random_info
    params.pContextData = None
    params.ulContextDataLength = 0

    mech = CK_MECHANISM()
    mech.mechanism = CKM_TLS_KDF
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_GENERIC_SECRET)
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(ctypes.pointer(d_cls), ctypes.c_void_p)
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(ctypes.pointer(d_kt), ctypes.c_void_p)
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(ctypes.pointer(d_vl), ctypes.c_void_p)
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(ctypes.pointer(d_tok), ctypes.c_void_p)
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh,
        ctypes.byref(mech),
        base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.byref(derived),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    if rv == CKR_OK:
        destroy_quietly(raw, sh, derived.value)
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_DeriveKey(TLS_KDF, {field} random length={data_len:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KDF_LENGTH_REJECT_RVS,
            label=f"C_DeriveKey(TLS_KDF, {field} random length={data_len:#x})",
        )


# ---------------------------------------------------------------------------
# TestSp800108NullDataParams
# ---------------------------------------------------------------------------


class TestSp800108NullDataParams:
    """SP800-108 Counter KDF with null data params pointer.

    Tests that the module validates pDataParams before dereferencing
    when ulNumberOfDataParams > 0.
    """

    def test_sp800_108_null_data_params(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_DeriveKey(SP800_108_COUNTER_KDF) with pDataParams=NULL."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_SP800_108_KDF_PARAMS, CK_MECHANISM,
    CKM_SP800_108_COUNTER_KDF, CKM_SHA256_HMAC,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE,
    CKA_VALUE_LEN, CKA_TOKEN, CKA_VALUE, CKA_DERIVE,
    CKO_SECRET_KEY, CKK_GENERIC_SECRET, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import destroy_quietly

# Import a generic secret key with CKA_DERIVE=True
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(
    ctypes.pointer(cls_val), ctypes.c_void_p,
)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(
    ctypes.pointer(kt_val), ctypes.c_void_p,
)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(
    ctypes.pointer(derive_true), ctypes.c_void_p,
)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(
    ctypes.pointer(token_false), ctypes.c_void_p,
)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5, ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"rv={rv}")
    cleanup()
    raise SystemExit(0)

try:
    params = CK_SP800_108_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = 1   # Non-zero count
    params.pDataParams = None         # NULL -- crash vector
    params.ulAdditionalDerivedKeys = 0
    params.pAdditionalDerivedKeys = None
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SP800_108_COUNTER_KDF
    mech.pParameter = ctypes.cast(
        ctypes.pointer(params), ctypes.c_void_p,
    )
    mech.ulParameterLen = ctypes.sizeof(params)

    # Derived key template
    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_GENERIC_SECRET)
    d_vl = CK_ULONG(32)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(
        ctypes.pointer(d_cls), ctypes.c_void_p,
    )
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(
        ctypes.pointer(d_kt), ctypes.c_void_p,
    )
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(
        ctypes.pointer(d_vl), ctypes.c_void_p,
    )
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(
        ctypes.pointer(d_tok), ctypes.c_void_p,
    )
    d_tmpl[3].ulValueLen = 1

    derived = CK_OBJECT_HANDLE(0)
    rv = raw.C_DeriveKey(
        sh, ctypes.byref(mech), base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)), 4,
        ctypes.byref(derived),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(
                "C_DeriveKey(SP800_108_COUNTER_KDF, pDataParams=NULL, ulNumberOfDataParams=1)"
            ),
        )


# ---------------------------------------------------------------------------
# TestSp800108NestedCountBoundary
# ---------------------------------------------------------------------------


class TestSp800108NestedCountBoundary:
    """SP800-108 nested arrays must reject impossible counts safely."""

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_sp800_108_data_param_count_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """A real pDataParams array with a huge count must not be overread."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PRF_DATA_PARAM,
    CK_SP800_108_BYTE_ARRAY,
    CK_SP800_108_DKM_LENGTH,
    CK_SP800_108_DKM_LENGTH_FORMAT,
    CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
    CK_SP800_108_ITERATION_VARIABLE,
    CK_SP800_108_COUNTER_FORMAT,
    CK_SP800_108_KDF_PARAMS,
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKM_SP800_108_COUNTER_KDF,
    CKO_SECRET_KEY,
    CKR_OK,
)

key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:SP800-108 base-key import rejected: {{ckr_name(rv)}}")
    cleanup()
    raise SystemExit(0)

derived = CK_OBJECT_HANDLE(0)
try:
    counter = CK_SP800_108_COUNTER_FORMAT()
    counter.bLittleEndian = 0
    counter.ulWidthInBits = 32
    label = (ctypes.c_ubyte * 12)(*b"hardening-1")
    context = (ctypes.c_ubyte * 12)(*b"hardening-2")
    dkm = CK_SP800_108_DKM_LENGTH_FORMAT()
    dkm.dkmLengthMethod = CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS
    dkm.bLittleEndian = 0
    dkm.ulWidthInBits = 32

    data_params = (CK_PRF_DATA_PARAM * 4)()
    data_params[0].type = CK_SP800_108_ITERATION_VARIABLE
    data_params[0].pValue = ctypes.cast(ctypes.pointer(counter), ctypes.c_void_p)
    data_params[0].ulValueLen = ctypes.sizeof(counter)
    data_params[1].type = CK_SP800_108_BYTE_ARRAY
    data_params[1].pValue = ctypes.cast(label, ctypes.c_void_p)
    data_params[1].ulValueLen = len(label)
    data_params[2].type = CK_SP800_108_BYTE_ARRAY
    data_params[2].pValue = ctypes.cast(context, ctypes.c_void_p)
    data_params[2].ulValueLen = len(context)
    data_params[3].type = CK_SP800_108_DKM_LENGTH
    data_params[3].pValue = ctypes.cast(ctypes.pointer(dkm), ctypes.c_void_p)
    data_params[3].ulValueLen = ctypes.sizeof(dkm)

    params = CK_SP800_108_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = {data_len}
    params.pDataParams = ctypes.cast(data_params, ctypes.c_void_p)
    params.ulAdditionalDerivedKeys = 0
    params.pAdditionalDerivedKeys = None

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SP800_108_COUNTER_KDF
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_AES)
    d_vl = CK_ULONG(16)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(ctypes.pointer(d_cls), ctypes.c_void_p)
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(ctypes.pointer(d_kt), ctypes.c_void_p)
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(ctypes.pointer(d_vl), ctypes.c_void_p)
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(ctypes.pointer(d_tok), ctypes.c_void_p)
    d_tmpl[3].ulValueLen = 1

    rv = raw.C_DeriveKey(
        sh,
        ctypes.byref(mech),
        base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.byref(derived),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    if rv == CKR_OK:
        destroy_quietly(raw, sh, derived.value)
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_DeriveKey(SP800_108_COUNTER_KDF, data-param count={data_len:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KDF_LENGTH_REJECT_RVS,
            label=f"C_DeriveKey(SP800_108_COUNTER_KDF, data-param count={data_len:#x})",
        )

    @pytest.mark.parametrize("data_len", _ISIZE_BOUNDARY_LENGTHS)
    def test_sp800_108_additional_derived_key_count_boundary(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        data_len: int,
    ) -> None:
        """A real additional-key array with a huge count must not be overread."""
        rs = p11_raw_session
        if not rs.has_mechanism("SP800_108_COUNTER_KDF"):
            pytest.skip("CKM_SP800_108_COUNTER_KDF not supported")
        preamble = _preamble(p11_config)
        script = (
            preamble
            + f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_DERIVED_KEY,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_PRF_DATA_PARAM,
    CK_SP800_108_BYTE_ARRAY,
    CK_SP800_108_COUNTER_FORMAT,
    CK_SP800_108_DKM_LENGTH,
    CK_SP800_108_DKM_LENGTH_FORMAT,
    CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
    CK_SP800_108_ITERATION_VARIABLE,
    CK_SP800_108_KDF_PARAMS,
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKM_SP800_108_COUNTER_KDF,
    CKO_SECRET_KEY,
    CKR_OK,
)

key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = ctypes.c_ulong(CKO_SECRET_KEY)
kt_val = ctypes.c_ulong(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(kt_val), ctypes.c_void_p)
key_tmpl[1].ulValueLen = ctypes.sizeof(kt_val)
key_tmpl[2].type = CKA_VALUE
key_tmpl[2].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[2].ulValueLen = 32
key_tmpl[3].type = CKA_DERIVE
key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(derive_true), ctypes.c_void_p)
key_tmpl[3].ulValueLen = 1
key_tmpl[4].type = CKA_TOKEN
key_tmpl[4].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
key_tmpl[4].ulValueLen = 1

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:SP800-108 base-key import rejected: {{ckr_name(rv)}}")
    cleanup()
    raise SystemExit(0)

primary = CK_OBJECT_HANDLE(0)
additional_handle = CK_OBJECT_HANDLE(0)
try:
    counter = CK_SP800_108_COUNTER_FORMAT()
    counter.bLittleEndian = 0
    counter.ulWidthInBits = 32
    label = (ctypes.c_ubyte * 12)(*b"hardening-1")
    context = (ctypes.c_ubyte * 12)(*b"hardening-2")
    dkm = CK_SP800_108_DKM_LENGTH_FORMAT()
    dkm.dkmLengthMethod = CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS
    dkm.bLittleEndian = 0
    dkm.ulWidthInBits = 32

    data_params = (CK_PRF_DATA_PARAM * 4)()
    data_params[0].type = CK_SP800_108_ITERATION_VARIABLE
    data_params[0].pValue = ctypes.cast(ctypes.pointer(counter), ctypes.c_void_p)
    data_params[0].ulValueLen = ctypes.sizeof(counter)
    data_params[1].type = CK_SP800_108_BYTE_ARRAY
    data_params[1].pValue = ctypes.cast(label, ctypes.c_void_p)
    data_params[1].ulValueLen = len(label)
    data_params[2].type = CK_SP800_108_BYTE_ARRAY
    data_params[2].pValue = ctypes.cast(context, ctypes.c_void_p)
    data_params[2].ulValueLen = len(context)
    data_params[3].type = CK_SP800_108_DKM_LENGTH
    data_params[3].pValue = ctypes.cast(ctypes.pointer(dkm), ctypes.c_void_p)
    data_params[3].ulValueLen = ctypes.sizeof(dkm)

    add_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    add_kt = ctypes.c_ulong(CKK_AES)
    add_vl = CK_ULONG(16)
    add_sensitive = ctypes.c_ubyte(0)
    add_extractable = ctypes.c_ubyte(1)
    add_token = ctypes.c_ubyte(0)
    add_tmpl = (CK_ATTRIBUTE * 6)()
    add_tmpl[0].type = CKA_CLASS
    add_tmpl[0].pValue = ctypes.cast(ctypes.pointer(add_cls), ctypes.c_void_p)
    add_tmpl[0].ulValueLen = ctypes.sizeof(add_cls)
    add_tmpl[1].type = CKA_KEY_TYPE
    add_tmpl[1].pValue = ctypes.cast(ctypes.pointer(add_kt), ctypes.c_void_p)
    add_tmpl[1].ulValueLen = ctypes.sizeof(add_kt)
    add_tmpl[2].type = CKA_VALUE_LEN
    add_tmpl[2].pValue = ctypes.cast(ctypes.pointer(add_vl), ctypes.c_void_p)
    add_tmpl[2].ulValueLen = ctypes.sizeof(add_vl)
    add_tmpl[3].type = CKA_SENSITIVE
    add_tmpl[3].pValue = ctypes.cast(ctypes.pointer(add_sensitive), ctypes.c_void_p)
    add_tmpl[3].ulValueLen = 1
    add_tmpl[4].type = CKA_EXTRACTABLE
    add_tmpl[4].pValue = ctypes.cast(ctypes.pointer(add_extractable), ctypes.c_void_p)
    add_tmpl[4].ulValueLen = 1
    add_tmpl[5].type = CKA_TOKEN
    add_tmpl[5].pValue = ctypes.cast(ctypes.pointer(add_token), ctypes.c_void_p)
    add_tmpl[5].ulValueLen = 1

    additional = (CK_DERIVED_KEY * 1)()
    additional[0].pTemplate = ctypes.cast(add_tmpl, ctypes.c_void_p)
    additional[0].ulAttributeCount = 6
    additional[0].phKey = ctypes.cast(ctypes.pointer(additional_handle), ctypes.c_void_p)

    params = CK_SP800_108_KDF_PARAMS()
    params.prfType = CKM_SHA256_HMAC
    params.ulNumberOfDataParams = 4
    params.pDataParams = ctypes.cast(data_params, ctypes.c_void_p)
    params.ulAdditionalDerivedKeys = {data_len}
    params.pAdditionalDerivedKeys = ctypes.cast(additional, ctypes.c_void_p)

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SP800_108_COUNTER_KDF
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    d_cls = ctypes.c_ulong(CKO_SECRET_KEY)
    d_kt = ctypes.c_ulong(CKK_AES)
    d_vl = CK_ULONG(16)
    d_tok = ctypes.c_ubyte(0)
    d_tmpl = (CK_ATTRIBUTE * 4)()
    d_tmpl[0].type = CKA_CLASS
    d_tmpl[0].pValue = ctypes.cast(ctypes.pointer(d_cls), ctypes.c_void_p)
    d_tmpl[0].ulValueLen = ctypes.sizeof(d_cls)
    d_tmpl[1].type = CKA_KEY_TYPE
    d_tmpl[1].pValue = ctypes.cast(ctypes.pointer(d_kt), ctypes.c_void_p)
    d_tmpl[1].ulValueLen = ctypes.sizeof(d_kt)
    d_tmpl[2].type = CKA_VALUE_LEN
    d_tmpl[2].pValue = ctypes.cast(ctypes.pointer(d_vl), ctypes.c_void_p)
    d_tmpl[2].ulValueLen = ctypes.sizeof(d_vl)
    d_tmpl[3].type = CKA_TOKEN
    d_tmpl[3].pValue = ctypes.cast(ctypes.pointer(d_tok), ctypes.c_void_p)
    d_tmpl[3].ulValueLen = 1

    rv = raw.C_DeriveKey(
        sh,
        ctypes.byref(mech),
        base_key.value,
        ctypes.cast(d_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.byref(primary),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
    if rv == CKR_OK:
        destroy_quietly(raw, sh, primary.value)
        if additional_handle.value:
            destroy_quietly(raw, sh, additional_handle.value)
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(
                f"C_DeriveKey(SP800_108_COUNTER_KDF, additional-derived-key count={data_len:#x})"
            ),
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _KDF_LENGTH_REJECT_RVS,
            label=(
                f"C_DeriveKey(SP800_108_COUNTER_KDF, additional-derived-key count={data_len:#x})"
            ),
        )
