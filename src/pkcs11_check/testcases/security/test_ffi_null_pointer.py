"""NULL pointer + non-zero length probes for PKCS#11 data operations.

All tests run in subprocess for crash safety. Each test passes a NULL pointer
where a data buffer is expected with a non-zero length claim, verifying the
module rejects the mismatch cleanly (CKR error) rather than crashing (SIGSEGV).

Inspired by Kryoptic fix/ffi-integer-overflow-hardening which added ffi_slice(),
ffi_slice_mut(), and bytes_to_slice() null-pointer guards.

Covers:
- NULL data pointer in multi-part Update operations
- NULL output buffer in Final operations (standard length-query path)
- NULL buffer in C_SeedRandom / C_GenerateRandom
- NULL PIN in C_InitPIN / C_SetPIN
- NULL state buffer in C_SetOperationState
- NULL wrapped key in C_UnwrapKey
- HMAC-General with NULL mechanism parameter
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases._subprocess_preamble import (
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]


def _preamble(p11_config: Any) -> str:
    """Build subprocess session preamble from p11_config."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
    )


def _preamble_no_login(p11_config: Any) -> str:
    """Build subprocess session preamble without login."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=None,
    )


# ---------------------------------------------------------------------------
# NULL data pointer in multi-part Update operations
# ---------------------------------------------------------------------------

# (operation, init_func, update_func, mechanism_check)
_UPDATE_CASES = [
    pytest.param(
        "encrypt",
        "C_EncryptInit",
        "C_EncryptUpdate",
        "AES_CBC",
        id="C_EncryptUpdate",
    ),
    pytest.param(
        "decrypt",
        "C_DecryptInit",
        "C_DecryptUpdate",
        "AES_CBC",
        id="C_DecryptUpdate",
    ),
    pytest.param(
        "sign",
        "C_SignInit",
        "C_SignUpdate",
        "SHA256_HMAC",
        id="C_SignUpdate",
    ),
    pytest.param(
        "verify",
        "C_VerifyInit",
        "C_VerifyUpdate",
        "SHA256_HMAC",
        id="C_VerifyUpdate",
    ),
    pytest.param(
        "digest",
        "C_DigestInit",
        "C_DigestUpdate",
        "SHA256",
        id="C_DigestUpdate",
    ),
]


class TestNullDataUpdate:
    """NULL data pointer with non-zero length in multi-part Update ops.

    PKCS#11 Update functions accept (session, data_ptr, data_len).
    Passing NULL data_ptr with non-zero data_len is a mismatch that can
    crash modules without proper NULL-pointer validation.
    """

    @pytest.mark.parametrize(
        "operation,init_func,update_func,mech_check",
        _UPDATE_CASES,
    )
    def test_null_data_update(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        operation: str,
        init_func: str,
        update_func: str,
        mech_check: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")
        preamble = _preamble(p11_config)

        if operation in ("encrypt", "decrypt"):
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_CBC, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

key = gen_aes_key(raw, sh, 256)
try:
    iv = (ctypes.c_ubyte * 16)(*range(16))
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_CBC)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(iv), ctypes.c_void_p
    )
    mech.ulParameterLen = 16
    rv = raw.{init_func}(sh, ctypes.byref(mech), key)
    print(f"init_rv={{rv}}")
    if rv == CKR_OK:
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.{update_func}(
            sh, None, 32, out_buf, ctypes.byref(out_len),
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif operation == "sign":
            body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CKR_OK,
    CKA_SIGN, CKA_VERIFY, CKA_TOKEN,
)
from pkcs11_check.raw.types_std import CKK_GENERIC_SECRET
from pkcs11_check.raw.recipes import import_secret_key, destroy_quietly

key = import_secret_key(raw, sh, CKK_GENERIC_SECRET, b'\\x00' * 32,
    attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False})
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SHA256_HMAC)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        rv2 = raw.C_SignUpdate(sh, None, 32)
        print(f"rv={rv2}")
    else:
        print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif operation == "verify":
            body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CKR_OK,
    CKA_SIGN, CKA_VERIFY, CKA_TOKEN,
)
from pkcs11_check.raw.types_std import CKK_GENERIC_SECRET
from pkcs11_check.raw.recipes import import_secret_key, destroy_quietly

key = import_secret_key(raw, sh, CKK_GENERIC_SECRET, b'\\x00' * 32,
    attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False})
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SHA256_HMAC)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key)
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        rv2 = raw.C_VerifyUpdate(sh, None, 32)
        print(f"rv={rv2}")
    else:
        print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif operation == "digest":
            body = """
import ctypes
from pkcs11_check.raw.types_std import CK_MECHANISM, CKM_SHA256, CKR_OK

mech = CK_MECHANISM()
mech.mechanism = int(CKM_SHA256)
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DigestInit(sh, ctypes.byref(mech))
print(f"init_rv={rv}")
if rv == CKR_OK:
    rv2 = raw.C_DigestUpdate(sh, None, 32)
    print(f"rv={rv2}")
else:
    print(f"rv={rv}")
cleanup()
"""
        else:
            raise ValueError(f"Unhandled operation: {operation}")

        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{update_func}(data=NULL, data_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL output buffer in Final operations (standard length-query path)
# ---------------------------------------------------------------------------

_FINAL_CASES = [
    pytest.param(
        "encrypt",
        "C_EncryptFinal",
        "AES_CBC",
        id="C_EncryptFinal",
    ),
    pytest.param(
        "decrypt",
        "C_DecryptFinal",
        "AES_CBC",
        id="C_DecryptFinal",
    ),
    pytest.param(
        "sign",
        "C_SignFinal",
        "SHA256_HMAC",
        id="C_SignFinal",
    ),
    pytest.param(
        "digest",
        "C_DigestFinal",
        "SHA256",
        id="C_DigestFinal",
    ),
]


class TestNullOutputFinal:
    """NULL output buffer in Final operations.

    In PKCS#11, passing NULL as the output buffer is the standard
    length-query mechanism. A correct module returns CKR_OK with the
    required buffer length. These tests verify the module handles this
    correctly and does not crash.
    """

    @pytest.mark.parametrize(
        "operation,final_func,mech_check",
        _FINAL_CASES,
    )
    def test_null_output_final(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        operation: str,
        final_func: str,
        mech_check: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")
        preamble = _preamble(p11_config)

        if operation == "encrypt":
            body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_CBC, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

key = gen_aes_key(raw, sh, 256)
try:
    iv = (ctypes.c_ubyte * 16)(*range(16))
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_CBC)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(iv), ctypes.c_void_p
    )
    mech.ulParameterLen = 16
    rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key)
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        upd_len = CK_ULONG(256)
        upd_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.C_EncryptUpdate(
            sh, data, 16, upd_buf, ctypes.byref(upd_len),
        )
        print(f"update_rv={rv2}")
        if rv2 == CKR_OK:
            fin_len = CK_ULONG(32)
            rv3 = raw.C_EncryptFinal(
                sh, None, ctypes.byref(fin_len),
            )
            print(f"rv={rv3}")
        else:
            print(f"rv={rv2}")
    else:
        print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif operation == "decrypt":
            body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_CBC, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

key = gen_aes_key(raw, sh, 256)
try:
    iv = (ctypes.c_ubyte * 16)(*range(16))
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_CBC)
    mech.pParameter = ctypes.cast(
        ctypes.pointer(iv), ctypes.c_void_p
    )
    mech.ulParameterLen = 16
    rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key)
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        upd_len = CK_ULONG(256)
        upd_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.C_DecryptUpdate(
            sh, data, 16, upd_buf, ctypes.byref(upd_len),
        )
        print(f"update_rv={rv2}")
        if rv2 == CKR_OK:
            fin_len = CK_ULONG(32)
            rv3 = raw.C_DecryptFinal(
                sh, None, ctypes.byref(fin_len),
            )
            print(f"rv={rv3}")
        else:
            print(f"rv={rv2}")
    else:
        print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif operation == "sign":
            body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CK_ULONG, CKR_OK,
    CKA_SIGN, CKA_VERIFY, CKA_TOKEN,
)
from pkcs11_check.raw.types_std import CKK_GENERIC_SECRET
from pkcs11_check.raw.recipes import import_secret_key, destroy_quietly

key = import_secret_key(raw, sh, CKK_GENERIC_SECRET, b'\\x00' * 32,
    attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False})
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SHA256_HMAC)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        data = (ctypes.c_ubyte * 16)(*range(16))
        rv2 = raw.C_SignUpdate(sh, data, 16)
        print(f"update_rv={rv2}")
        if rv2 == CKR_OK:
            sig_len = CK_ULONG(512)
            rv3 = raw.C_SignFinal(
                sh, None, ctypes.byref(sig_len),
            )
            print(f"rv={rv3}")
        else:
            print(f"rv={rv2}")
    else:
        print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif operation == "digest":
            body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256, CK_ULONG, CKR_OK,
)

mech = CK_MECHANISM()
mech.mechanism = int(CKM_SHA256)
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DigestInit(sh, ctypes.byref(mech))
print(f"init_rv={rv}")
if rv == CKR_OK:
    data = (ctypes.c_ubyte * 16)(*range(16))
    rv2 = raw.C_DigestUpdate(sh, data, 16)
    print(f"update_rv={rv2}")
    if rv2 == CKR_OK:
        dig_len = CK_ULONG(64)
        rv3 = raw.C_DigestFinal(
            sh, None, ctypes.byref(dig_len),
        )
        print(f"rv={rv3}")
    else:
        print(f"rv={rv2}")
else:
    print(f"rv={rv}")
cleanup()
"""
        else:
            raise ValueError(f"Unhandled operation: {operation}")

        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{final_func}(output=NULL, length_query)",
        )


# ---------------------------------------------------------------------------
# NULL buffer in C_SeedRandom / C_GenerateRandom
# ---------------------------------------------------------------------------


class TestNullRandomBuffer:
    """NULL buffer with non-zero length in random operations.

    C_SeedRandom and C_GenerateRandom have no length-query mode, so
    NULL pointer with non-zero length is always a crash vector.
    """

    def test_seed_random_null_buffer(self, p11_config: Any) -> None:
        preamble = _preamble(p11_config)
        body = """
rv = raw.C_SeedRandom(sh, None, 32)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_SeedRandom(data=NULL, data_len=32)",
        )

    def test_generate_random_null_buffer(
        self,
        p11_config: Any,
    ) -> None:
        preamble = _preamble(p11_config)
        body = """
rv = raw.C_GenerateRandom(sh, None, 32)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_GenerateRandom(buf=NULL, buf_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL PIN in C_InitPIN / C_SetPIN
# ---------------------------------------------------------------------------


class TestNullPinBuffer:
    """NULL PIN pointer with non-zero length in PIN management ops.

    These tests don't auto-login so we can test the raw PIN functions
    without interference from the session login state.
    """

    def test_init_pin_null_with_length(
        self,
        p11_config: Any,
    ) -> None:
        preamble = _preamble_no_login(p11_config)
        body = """
from pkcs11_check.raw.types_std import CKU_SO
# Attempt SO login -- may fail (that's fine, we just want no crash)
rv_login = raw.C_Login(sh, int(CKU_SO), None, 0)
print(f"so_login_rv={rv_login}")
rv = raw.C_InitPIN(sh, None, 8)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_InitPIN(pin=NULL, pin_len=8)",
        )

    def test_set_pin_null_old_pin(self, p11_config: Any) -> None:
        preamble = _preamble_no_login(p11_config)
        body = """
import ctypes
pin_buf = (ctypes.c_ubyte * 4)(0x31, 0x32, 0x33, 0x34)
rv = raw.C_SetPIN(
    sh, None, 8,
    ctypes.cast(ctypes.pointer(pin_buf), ctypes.c_void_p), 4,
)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_SetPIN(old_pin=NULL, old_pin_len=8)",
        )

    def test_set_pin_null_new_pin(self, p11_config: Any) -> None:
        preamble = _preamble_no_login(p11_config)
        body = """
import ctypes
pin_buf = (ctypes.c_ubyte * 4)(0x31, 0x32, 0x33, 0x34)
rv = raw.C_SetPIN(
    sh,
    ctypes.cast(ctypes.pointer(pin_buf), ctypes.c_void_p), 4,
    None, 8,
)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_SetPIN(new_pin=NULL, new_pin_len=8)",
        )


# ---------------------------------------------------------------------------
# NULL state buffer in C_SetOperationState
# ---------------------------------------------------------------------------


class TestNullOperationState:
    """NULL state buffer with non-zero length in C_SetOperationState.

    C_SetOperationState has no length-query mode for the input state
    buffer, so NULL pointer + non-zero length is a crash vector.
    """

    def test_set_operation_state_null_buffer(
        self,
        p11_config: Any,
    ) -> None:
        preamble = _preamble(p11_config)
        body = """
rv = raw.C_SetOperationState(sh, None, 32, 0, 0)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_SetOperationState(state=NULL, state_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL wrapped key data in C_UnwrapKey
# ---------------------------------------------------------------------------


class TestNullWrapUnwrap:
    """NULL wrapped-key data with non-zero length in C_UnwrapKey.

    Passing NULL as the wrapped key buffer with a non-zero length can
    crash modules that dereference the pointer without validation.
    """

    def test_unwrap_key_null_wrapped_data(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")
        preamble = _preamble(p11_config)
        body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE, CKA_CLASS, CKA_KEY_TYPE, CKA_TOKEN,
    CKA_ENCRYPT, CKA_DECRYPT, CKA_UNWRAP,
    CKO_SECRET_KEY, CKK_AES, CKA_VALUE_LEN, CK_ULONG,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

wrap_key = gen_aes_key(raw, sh, 256, attrs={CKA_UNWRAP: True})
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_ECB)
    mech.pParameter = None
    mech.ulParameterLen = 0

    # Minimal template for the unwrapped key
    token_false = ctypes.c_ubyte(0)
    attr = CK_ATTRIBUTE()
    attr.type = int(CKA_TOKEN)
    attr.pValue = ctypes.cast(
        ctypes.pointer(token_false), ctypes.c_void_p,
    )
    attr.ulValueLen = 1

    out_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_UnwrapKey(
        sh, ctypes.byref(mech), wrap_key,
        None, 32,
        ctypes.pointer(attr), 1,
        ctypes.byref(out_key),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, wrap_key)
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_UnwrapKey(wrapped=NULL, wrapped_len=32)",
        )


# ---------------------------------------------------------------------------
# HMAC-General with NULL mechanism parameter
# ---------------------------------------------------------------------------


class TestHmacGeneralNullParam:
    """CKM_SHA256_HMAC_GENERAL with NULL pParameter but non-zero length.

    CKM_SHA256_HMAC_GENERAL requires a CK_MAC_GENERAL_PARAMS (CK_ULONG)
    specifying the output MAC length. Passing NULL pParameter with
    ulParameterLen = sizeof(CK_ULONG) can crash modules that dereference
    the parameter pointer without checking for NULL.
    """

    def test_hmac_general_null_parameter(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC_GENERAL"):
            pytest.skip("CKM_SHA256_HMAC_GENERAL not supported")
        preamble = _preamble(p11_config)
        body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC_GENERAL,
    CKA_SIGN, CKA_VERIFY, CKA_TOKEN,
)
from pkcs11_check.raw.types_std import CKK_GENERIC_SECRET
from pkcs11_check.raw.recipes import import_secret_key, destroy_quietly

key = import_secret_key(raw, sh, CKK_GENERIC_SECRET, b'\\x00' * 32,
    attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False})
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SHA256_HMAC_GENERAL)
    mech.pParameter = None
    mech.ulParameterLen = 8  # sizeof(CK_ULONG) on 64-bit
    rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=("C_SignInit(CKM_SHA256_HMAC_GENERAL, pParameter=NULL, ulParameterLen=8)"),
        )


# ---------------------------------------------------------------------------
# NULL data pointer in one-shot operations
# ---------------------------------------------------------------------------

_ONESHOT_CASES = [
    pytest.param(
        "encrypt",
        "C_Encrypt",
        "AES_ECB",
        id="C_Encrypt",
    ),
    pytest.param(
        "decrypt",
        "C_Decrypt",
        "AES_ECB",
        id="C_Decrypt",
    ),
    pytest.param(
        "sign",
        "C_Sign",
        "SHA256_HMAC",
        id="C_Sign",
    ),
    pytest.param(
        "verify",
        "C_Verify",
        "SHA256_HMAC",
        id="C_Verify",
    ),
    pytest.param(
        "digest",
        "C_Digest",
        "SHA256",
        id="C_Digest",
    ),
]


class TestNullDataOneShot:
    """NULL data pointer with non-zero length in one-shot operations.

    One-shot C_Encrypt, C_Decrypt, C_Sign, C_Verify, and C_Digest hit
    different code paths from the multi-part Update functions. Passing
    NULL data with non-zero length can crash modules without proper
    NULL-pointer validation.
    """

    @pytest.mark.parametrize(
        "operation,func_name,mech_check",
        _ONESHOT_CASES,
    )
    def test_null_data_oneshot(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        operation: str,
        func_name: str,
        mech_check: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")
        preamble = _preamble(p11_config)

        if operation in ("encrypt", "decrypt"):
            init_func = "C_EncryptInit" if operation == "encrypt" else "C_DecryptInit"
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

key = gen_aes_key(raw, sh, 256)
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_ECB)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.{init_func}(sh, ctypes.byref(mech), key)
    print(f"init_rv={{rv}}")
    if rv == CKR_OK:
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.{func_name}(
            sh, None, 32, out_buf, ctypes.byref(out_len),
        )
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif operation == "sign":
            body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CK_ULONG, CKR_OK,
    CKA_SIGN, CKA_VERIFY, CKA_TOKEN,
)
from pkcs11_check.raw.types_std import CKK_GENERIC_SECRET
from pkcs11_check.raw.recipes import import_secret_key, destroy_quietly

key = import_secret_key(raw, sh, CKK_GENERIC_SECRET, b'\\x00' * 32,
    attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False})
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SHA256_HMAC)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), key)
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        sig_len = CK_ULONG(512)
        sig_buf = (ctypes.c_ubyte * 512)()
        rv2 = raw.C_Sign(
            sh, None, 32, sig_buf, ctypes.byref(sig_len),
        )
        print(f"rv={rv2}")
    else:
        print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif operation == "verify":
            body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256_HMAC, CKR_OK,
    CKA_SIGN, CKA_VERIFY, CKA_TOKEN,
)
from pkcs11_check.raw.types_std import CKK_GENERIC_SECRET
from pkcs11_check.raw.recipes import import_secret_key, destroy_quietly

key = import_secret_key(raw, sh, CKK_GENERIC_SECRET, b'\\x00' * 32,
    attrs={CKA_SIGN: True, CKA_VERIFY: True, CKA_TOKEN: False})
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_SHA256_HMAC)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key)
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        fake_sig = (ctypes.c_ubyte * 32)(*([0xAA] * 32))
        rv2 = raw.C_Verify(sh, None, 32, fake_sig, 32)
        print(f"rv={rv2}")
    else:
        print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif operation == "digest":
            body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_SHA256, CK_ULONG, CKR_OK,
)

mech = CK_MECHANISM()
mech.mechanism = int(CKM_SHA256)
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DigestInit(sh, ctypes.byref(mech))
print(f"init_rv={rv}")
if rv == CKR_OK:
    dig_len = CK_ULONG(64)
    digest_buf = (ctypes.c_ubyte * 64)()
    rv2 = raw.C_Digest(
        sh, None, 32, digest_buf, ctypes.byref(dig_len),
    )
    print(f"rv={rv2}")
else:
    print(f"rv={rv}")
cleanup()
"""
        else:
            raise ValueError(f"Unhandled operation: {operation}")

        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{func_name}(data=NULL, data_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL data pointers in v3.0 Message-based encryption/decryption
# ---------------------------------------------------------------------------


class TestNullMessageApi:
    """NULL data pointers in v3.0 Message-based encrypt/decrypt.

    The v3.0 Message API (C_EncryptMessage, C_DecryptMessage) has
    separate pointers for associated data and plaintext/ciphertext.
    Passing NULL for these with non-zero length can crash modules
    without proper NULL-pointer validation.

    Tests gracefully skip when the module does not support the v3.0
    Message API.
    """

    def test_encrypt_message_null_plaintext(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        preamble = _preamble(p11_config)
        body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_GCM, CK_ULONG, CKR_OK,
    CK_GCM_MESSAGE_PARAMS, CKG_GENERATE,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

if "C_MessageEncryptInit" not in raw.available_function_names():
    print("not_supported")
    cleanup()
    raise SystemExit(0)

key = gen_aes_key(raw, sh, 256)
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_GCM)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_MessageEncryptInit(sh, ctypes.byref(mech), key)
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        iv_buf = (ctypes.c_ubyte * 12)()
        tag_buf = (ctypes.c_ubyte * 16)()
        params = CK_GCM_MESSAGE_PARAMS()
        params.pIv = ctypes.cast(
            ctypes.pointer(iv_buf), ctypes.c_void_p,
        )
        params.ulIvLen = 12
        params.ulIvFixedBits = 0
        params.ivGenerator = int(CKG_GENERATE)
        params.pTag = ctypes.cast(
            ctypes.pointer(tag_buf), ctypes.c_void_p,
        )
        params.ulTagBits = 128
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.C_EncryptMessage(
            sh,
            ctypes.cast(ctypes.pointer(params), ctypes.c_void_p),
            ctypes.sizeof(params),
            None, 0,
            None, 32,
            out_buf, ctypes.byref(out_len),
        )
        print(f"rv={rv2}")
    else:
        print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        if "not_supported" in stdout:
            pytest.skip("C_MessageEncryptInit not available")
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptMessage(plaintext=NULL, plaintext_len=32)",
        )

    def test_decrypt_message_null_ciphertext(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        preamble = _preamble(p11_config)
        body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_GCM, CK_ULONG, CKR_OK,
    CK_GCM_MESSAGE_PARAMS, CKG_GENERATE,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

if "C_MessageDecryptInit" not in raw.available_function_names():
    print("not_supported")
    cleanup()
    raise SystemExit(0)

key = gen_aes_key(raw, sh, 256)
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_GCM)
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_MessageDecryptInit(sh, ctypes.byref(mech), key)
    print(f"init_rv={rv}")
    if rv == CKR_OK:
        iv_buf = (ctypes.c_ubyte * 12)(*range(12))
        tag_buf = (ctypes.c_ubyte * 16)()
        params = CK_GCM_MESSAGE_PARAMS()
        params.pIv = ctypes.cast(
            ctypes.pointer(iv_buf), ctypes.c_void_p,
        )
        params.ulIvLen = 12
        params.ulIvFixedBits = 0
        params.ivGenerator = int(CKG_GENERATE)
        params.pTag = ctypes.cast(
            ctypes.pointer(tag_buf), ctypes.c_void_p,
        )
        params.ulTagBits = 128
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.C_DecryptMessage(
            sh,
            ctypes.cast(ctypes.pointer(params), ctypes.c_void_p),
            ctypes.sizeof(params),
            None, 0,
            None, 32,
            out_buf, ctypes.byref(out_len),
        )
        print(f"rv={rv2}")
    else:
        print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        if "not_supported" in stdout:
            pytest.skip("C_MessageDecryptInit not available")
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_DecryptMessage(ciphertext=NULL, ciphertext_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL ciphertext in v3.2 C_DecapsulateKey
# ---------------------------------------------------------------------------


class TestNullKemApi:
    """NULL ciphertext pointer in v3.2 C_DecapsulateKey.

    C_DecapsulateKey accepts a ciphertext buffer pointer and length.
    Passing NULL ciphertext with non-zero length can crash modules
    that dereference the pointer without validation.

    Gracefully skips when the module does not support v3.2 KEM functions.
    """

    def test_decapsulate_key_null_ciphertext(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported (needed for key gen)")
        preamble = _preamble(p11_config)
        body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_ECB, CK_ULONG, CKR_OK,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE,
    CKA_CLASS, CKA_KEY_TYPE, CKA_TOKEN,
    CKO_SECRET_KEY, CKK_AES, CKA_VALUE_LEN,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

if "C_DecapsulateKey" not in raw.available_function_names():
    print("not_supported")
    cleanup()
    raise SystemExit(0)

key = gen_aes_key(raw, sh, 256)
try:
    mech = CK_MECHANISM()
    mech.mechanism = int(CKM_AES_ECB)
    mech.pParameter = None
    mech.ulParameterLen = 0

    # Minimal template for the derived key
    token_false = ctypes.c_ubyte(0)
    cls_val = CK_ULONG(int(CKO_SECRET_KEY))
    kt_val = CK_ULONG(int(CKK_AES))
    vl_val = CK_ULONG(16)

    attrs = (CK_ATTRIBUTE * 4)()
    attrs[0].type = int(CKA_CLASS)
    attrs[0].pValue = ctypes.cast(
        ctypes.pointer(cls_val), ctypes.c_void_p,
    )
    attrs[0].ulValueLen = ctypes.sizeof(CK_ULONG)
    attrs[1].type = int(CKA_KEY_TYPE)
    attrs[1].pValue = ctypes.cast(
        ctypes.pointer(kt_val), ctypes.c_void_p,
    )
    attrs[1].ulValueLen = ctypes.sizeof(CK_ULONG)
    attrs[2].type = int(CKA_TOKEN)
    attrs[2].pValue = ctypes.cast(
        ctypes.pointer(token_false), ctypes.c_void_p,
    )
    attrs[2].ulValueLen = 1
    attrs[3].type = int(CKA_VALUE_LEN)
    attrs[3].pValue = ctypes.cast(
        ctypes.pointer(vl_val), ctypes.c_void_p,
    )
    attrs[3].ulValueLen = ctypes.sizeof(CK_ULONG)

    out_key = CK_OBJECT_HANDLE(0)
    rv = raw.C_DecapsulateKey(
        sh, ctypes.byref(mech), key,
        ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        None, 32,
        ctypes.byref(out_key),
    )
    print(f"rv={rv}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        if "not_supported" in stdout:
            pytest.skip("C_DecapsulateKey not available")
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_DecapsulateKey(ciphertext=NULL, ciphertext_len=32)",
        )


# ---------------------------------------------------------------------------
# NULL PIN / NULL label in C_InitToken
# ---------------------------------------------------------------------------


class TestNullInitToken:
    """NULL PIN or NULL label in C_InitToken.

    C_InitToken(slot_id, pPin, ulPinLen, pLabel) is a sensitive
    operation. Passing NULL pPin with non-zero length or NULL pLabel
    can crash modules that dereference without validation.

    Since our preamble opens a session, C_InitToken will likely fail
    with CKR_SESSION_EXISTS or similar -- but the module must check
    that BEFORE dereferencing NULL pointers.
    """

    def test_init_token_null_pin(self, p11_config: Any) -> None:
        preamble = _preamble_no_login(p11_config)
        body = """
import ctypes

label_bytes = b"test_label" + b" " * 22  # 32-byte padded label
label_buf = (ctypes.c_ubyte * 32)(*label_bytes)
rv = raw.C_InitToken(
    slot_id, None, 8,
    ctypes.cast(ctypes.pointer(label_buf), ctypes.c_void_p),
)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_InitToken(pin=NULL, pin_len=8, label=valid)",
        )

    def test_init_token_null_label(self, p11_config: Any) -> None:
        preamble = _preamble_no_login(p11_config)
        body = """
import ctypes

pin_buf = (ctypes.c_ubyte * 4)(0x31, 0x32, 0x33, 0x34)
rv = raw.C_InitToken(
    slot_id,
    ctypes.cast(ctypes.pointer(pin_buf), ctypes.c_void_p),
    4,
    None,
)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10)
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_InitToken(pin=valid, pin_len=4, label=NULL)",
        )
