"""API boundary tests -- crash-safe probes for invalid handles, NULL pointers, and edge-case inputs.

All tests run in subprocess for crash safety. Each test builds a script string,
executes it via run_with_coverage(), and checks that the module did not crash
(negative returncode = killed by signal).

Covers:
- Session handle boundary values (0, ULONG_MAX)
- Object handle boundary values (0, ULONG_MAX)
- NULL mechanism pointer to *Init functions
- Mechanism with pParameter=NULL but ulParameterLen>0
- NULL template pointer with non-zero count
- Zero-length data to encrypt/decrypt/sign
- NULL PIN with non-zero length to C_Login
- Extreme and zero RSA/AES key sizes
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
)
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import (
    destroy_returned_handles,
    gen_aes_key_or_xfail,
    gen_ec_keypair_or_xfail,
    gen_rsa_keypair_or_xfail,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# 64-bit CK_ULONG max -- used as literal in subprocess script strings
_CK_ULONG_MAX_64 = 0xFFFFFFFFFFFFFFFF


def _preamble(p11_config: Any) -> str:
    """Build subprocess session preamble from p11_config."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
    )


# ---------------------------------------------------------------------------
# Session handle boundary values
# ---------------------------------------------------------------------------


class TestSessionHandleBoundary:
    """Probe C_* session functions with boundary session handles (0, MAX).

    PKCS#11 v3.2: functions taking CK_SESSION_HANDLE must return
    CKR_SESSION_HANDLE_INVALID for unknown handles -- never crash.
    """

    _SESSION_FUNCTIONS = ["C_GetSessionInfo", "C_CloseSession", "C_GetOperationState"]
    _BOUNDARY_HANDLES = [
        pytest.param(0, id="zero"),
        pytest.param(_CK_ULONG_MAX_64, id="max"),
    ]

    @pytest.mark.parametrize("func_name", _SESSION_FUNCTIONS)
    @pytest.mark.parametrize("handle", _BOUNDARY_HANDLES)
    def test_session_handle_boundary(
        self,
        p11_config: Any,
        func_name: str,
        handle: int,
    ) -> None:
        preamble = _preamble(p11_config)
        if func_name == "C_GetSessionInfo":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_SESSION_INFO
info = CK_SESSION_INFO()
rv = raw.C_GetSessionInfo({handle}, ctypes.byref(info))
print(f"rv={{rv}}")
cleanup()
"""
        elif func_name == "C_CloseSession":
            body = f"""
rv = raw.C_CloseSession({handle})
print(f"rv={{rv}}")
cleanup()
"""
        elif func_name == "C_GetOperationState":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_ULONG
out_len = CK_ULONG(0)
rv = raw.C_GetOperationState({handle}, None, ctypes.byref(out_len))
print(f"rv={{rv}}")
cleanup()
"""
        else:
            raise ValueError(f"Unhandled function: {func_name}")
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{func_name}(handle={handle:#x})",
        )


# ---------------------------------------------------------------------------
# Object handle boundary values
# ---------------------------------------------------------------------------


class TestObjectHandleBoundary:
    """Probe C_* object functions with boundary object handles (0, MAX).

    PKCS#11 v3.2: functions taking CK_OBJECT_HANDLE must return
    CKR_OBJECT_HANDLE_INVALID for unknown handles -- never crash.
    """

    _OBJECT_FUNCTIONS = [
        "C_GetAttributeValue",
        "C_SetAttributeValue",
        "C_DestroyObject",
        "C_CopyObject",
    ]
    _BOUNDARY_HANDLES = [
        pytest.param(0, id="zero"),
        pytest.param(_CK_ULONG_MAX_64, id="max"),
    ]

    @pytest.mark.parametrize("func_name", _OBJECT_FUNCTIONS)
    @pytest.mark.parametrize("handle", _BOUNDARY_HANDLES)
    def test_object_handle_boundary(
        self,
        p11_config: Any,
        func_name: str,
        handle: int,
    ) -> None:
        preamble = _preamble(p11_config)
        if func_name == "C_GetAttributeValue":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CKA_CLASS
attr = CK_ATTRIBUTE()
attr.type = CKA_CLASS
attr.pValue = None
attr.ulValueLen = 0
rv = raw.C_GetAttributeValue(sh, {handle}, ctypes.pointer(attr), 1)
print(f"rv={{rv}}")
cleanup()
"""
        elif func_name == "C_SetAttributeValue":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CKA_TOKEN
val = ctypes.c_ubyte(0)
attr = CK_ATTRIBUTE()
attr.type = CKA_TOKEN
attr.pValue = ctypes.cast(ctypes.pointer(val), ctypes.c_void_p)
attr.ulValueLen = 1
rv = raw.C_SetAttributeValue(sh, {handle}, ctypes.pointer(attr), 1)
print(f"rv={{rv}}")
cleanup()
"""
        elif func_name == "C_DestroyObject":
            body = f"""
rv = raw.C_DestroyObject(sh, {handle})
print(f"rv={{rv}}")
cleanup()
"""
        elif func_name == "C_CopyObject":
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE
new_handle = CK_OBJECT_HANDLE(0)
rv = raw.C_CopyObject(sh, {handle}, None, 0, ctypes.byref(new_handle))
print(f"rv={{rv}}")
cleanup()
"""
        else:
            raise ValueError(f"Unhandled function: {func_name}")
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{func_name}(object_handle={handle:#x})",
        )


# ---------------------------------------------------------------------------
# NULL mechanism pointer to *Init functions
# ---------------------------------------------------------------------------


class TestNullMechanismInit:
    """Probe C_*Init functions with NULL mechanism pointer.

    PKCS#11 v3.2: CK_MECHANISM_PTR must not be NULL. The module should
    return CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID -- never crash.
    """

    _INIT_FUNCTIONS = [
        "C_EncryptInit",
        "C_DecryptInit",
        "C_SignInit",
        "C_VerifyInit",
        "C_DigestInit",
    ]

    @pytest.mark.parametrize("func_name", _INIT_FUNCTIONS)
    def test_null_mechanism_init(
        self,
        p11_config: Any,
        func_name: str,
    ) -> None:
        preamble = _preamble(p11_config)
        if func_name == "C_DigestInit":
            # C_DigestInit(session, mechanism_ptr) -- no key argument
            body = """
rv = raw.C_DigestInit(sh, None)
print(f"rv={rv}")
cleanup()
"""
        else:
            # C_EncryptInit/DecryptInit/SignInit/VerifyInit(session, mech_ptr, key)
            # Use key handle 0 -- the NULL mechanism should be rejected first
            body = f"""
rv = raw.{func_name}(sh, None, 0)
print(f"rv={{rv}}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{func_name}(mechanism=NULL)",
        )


# ---------------------------------------------------------------------------
# Mechanism with pParameter=NULL but ulParameterLen>0
# ---------------------------------------------------------------------------


class TestMechanismParamNullWithLength:
    """Probe *Init with a mechanism whose pParameter is NULL but ulParameterLen > 0.

    This NULL-pointer + non-zero-length mismatch can cause crashes in modules
    that dereference pParameter without checking ulParameterLen first.
    """

    _INIT_FUNCTIONS = [
        "C_EncryptInit",
        "C_DecryptInit",
        "C_SignInit",
        "C_VerifyInit",
    ]

    @pytest.mark.parametrize("func_name", _INIT_FUNCTIONS)
    def test_mechanism_param_null_with_length(
        self,
        p11_config: Any,
        func_name: str,
    ) -> None:
        preamble = _preamble(p11_config)
        body = f"""
import ctypes
from pkcs11_check.raw.types_std import CK_MECHANISM, CKM_AES_CBC
mech = CK_MECHANISM()
mech.mechanism = CKM_AES_CBC
mech.pParameter = None              # NULL pointer
mech.ulParameterLen = 16             # Non-zero length -- mismatch!
rv = raw.{func_name}(sh, ctypes.byref(mech), 0)
print(f"rv={{rv}}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{func_name}(pParameter=NULL, ulParameterLen=16)",
        )


# ---------------------------------------------------------------------------
# NULL template pointer with non-zero count
# ---------------------------------------------------------------------------


class TestNullTemplateNonzeroCount:
    """Probe functions with NULL template pointer but count > 0.

    The NULL-pointer + non-zero-count mismatch can cause crashes in modules
    that iterate the template array without checking the pointer first.
    """

    _TEMPLATE_FUNCTIONS = [
        "C_CreateObject",
        "C_FindObjectsInit",
        "C_GenerateKey",
        "C_SetAttributeValue",
    ]

    @pytest.mark.parametrize("func_name", _TEMPLATE_FUNCTIONS)
    def test_null_template_nonzero_count(
        self,
        p11_config: Any,
        func_name: str,
    ) -> None:
        preamble = _preamble(p11_config)
        if func_name == "C_CreateObject":
            body = """
import ctypes
from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE
obj = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(sh, None, 5, ctypes.byref(obj))
print(f"rv={rv}")
cleanup()
"""
        elif func_name == "C_FindObjectsInit":
            body = """
rv = raw.C_FindObjectsInit(sh, None, 5)
print(f"rv={rv}")
cleanup()
"""
        elif func_name == "C_GenerateKey":
            body = """
import ctypes
from pkcs11_check.raw.types_std import CK_MECHANISM, CKM_AES_KEY_GEN, CK_OBJECT_HANDLE
mech = CK_MECHANISM()
mech.mechanism = CKM_AES_KEY_GEN
mech.pParameter = None
mech.ulParameterLen = 0
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, ctypes.byref(mech), None, 5, ctypes.byref(key))
print(f"rv={rv}")
cleanup()
"""
        elif func_name == "C_SetAttributeValue":
            body = """
rv = raw.C_SetAttributeValue(sh, 0, None, 5)
print(f"rv={rv}")
cleanup()
"""
        else:
            raise ValueError(f"Unhandled function: {func_name}")
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{func_name}(template=NULL, count=5)",
        )


# ---------------------------------------------------------------------------
# Zero-length data to encrypt/decrypt/sign
# ---------------------------------------------------------------------------

_ZERO_LENGTH_CASES = [
    pytest.param("encrypt", "AES_ECB", "CKM_AES_ECB", id="encrypt-AES_ECB"),
    pytest.param("encrypt", "AES_CBC", "CKM_AES_CBC", id="encrypt-AES_CBC"),
    pytest.param("decrypt", "AES_ECB", "CKM_AES_ECB", id="decrypt-AES_ECB"),
    pytest.param("decrypt", "AES_CBC", "CKM_AES_CBC", id="decrypt-AES_CBC"),
    pytest.param("sign", "RSA_PKCS", "CKM_SHA256_RSA_PKCS", id="sign-RSA_PKCS"),
    pytest.param("sign", "ECDSA", "CKM_ECDSA_SHA256", id="sign-ECDSA"),
]


class TestZeroLengthData:
    """Probe encrypt/decrypt/sign with zero-length data.

    Passing a zero-length buffer can cause edge-case failures in modules
    that don't validate data length before processing. The module should
    return an appropriate error code -- never crash.
    """

    @pytest.mark.parametrize("operation,mech_check,mech_name", _ZERO_LENGTH_CASES)
    def test_zero_length_data(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        operation: str,
        mech_check: str,
        mech_name: str,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism(mech_check):
            pytest.skip(f"CKM_{mech_check} not supported")
        preamble = _preamble(p11_config)
        if operation in ("encrypt", "decrypt") and "AES" in mech_name:
            setup_key = gen_aes_key_or_xfail(
                rs,
                256,
                purpose=f"{operation} zero-length {mech_name} crash probe setup",
            )
            destroy_returned_handles(rs, setup_key)
            c_func = "C_Encrypt" if operation == "encrypt" else "C_Decrypt"
            init_func = f"{c_func}Init"
            iv_setup = ""
            if "CBC" in mech_name:
                iv_setup = """\
    iv = (ctypes.c_ubyte * 16)(*range(16))
    mech.pParameter = ctypes.cast(ctypes.pointer(iv), ctypes.c_void_p)
    mech.ulParameterLen = 16
"""
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, {mech_name}, CK_ULONG, CKR_OK,
    CKA_ENCRYPT, CKA_DECRYPT, CKA_TOKEN, CKA_VALUE_LEN, CKM_AES_KEY_GEN,
)
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly

key = gen_aes_key(raw, sh, 256)
try:
    mech = CK_MECHANISM()
    mech.mechanism = {mech_name}
    mech.pParameter = None
    mech.ulParameterLen = 0
{iv_setup}
    rv = raw.{init_func}(sh, ctypes.byref(mech), key)
    print(f"init_rv={{rv}}")
    if rv == CKR_OK:
        out_len = CK_ULONG(256)
        out_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.{c_func}(sh, None, 0, out_buf, ctypes.byref(out_len))
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, key)
cleanup()
"""
        elif operation == "sign" and "RSA" in mech_name:
            pub, priv = gen_rsa_keypair_or_xfail(
                rs,
                2048,
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
                public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            )
            destroy_returned_handles(rs, pub, priv)
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, {mech_name}, CK_ULONG, CKR_OK,
)
from pkcs11_check.raw.recipes import gen_rsa_keypair, destroy_quietly
from pkcs11_check.raw.types_std import CKA_SIGN, CKA_TOKEN, CKA_VERIFY

pub, priv = gen_rsa_keypair(raw, sh, 2048,
    private_attrs={{CKA_SIGN: True, CKA_TOKEN: False}},
    public_attrs={{CKA_VERIFY: True, CKA_TOKEN: False}},
)
try:
    mech = CK_MECHANISM()
    mech.mechanism = {mech_name}
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
    print(f"init_rv={{rv}}")
    if rv == CKR_OK:
        sig_len = CK_ULONG(512)
        sig_buf = (ctypes.c_ubyte * 512)()
        rv2 = raw.C_Sign(sh, None, 0, sig_buf, ctypes.byref(sig_len))
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        elif operation == "sign" and "ECDSA" in mech_name:
            curve_oid = encode_named_curve_parameters("secp256r1")
            pub, priv = gen_ec_keypair_or_xfail(
                rs,
                curve_oid,
                private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            )
            destroy_returned_handles(rs, pub, priv)
            body = f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, {mech_name}, CK_ULONG, CKR_OK,
    CKA_SIGN, CKA_TOKEN, CKA_VERIFY,
)
from pkcs11_check.raw.recipes import gen_ec_keypair, destroy_quietly
from pkcs11_check.raw.ec import encode_named_curve_parameters

curve_oid = encode_named_curve_parameters("secp256r1")
pub, priv = gen_ec_keypair(raw, sh, curve_oid,
    private_attrs={{CKA_SIGN: True, CKA_TOKEN: False}},
)
try:
    mech = CK_MECHANISM()
    mech.mechanism = {mech_name}
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_SignInit(sh, ctypes.byref(mech), priv)
    print(f"init_rv={{rv}}")
    if rv == CKR_OK:
        sig_len = CK_ULONG(256)
        sig_buf = (ctypes.c_ubyte * 256)()
        rv2 = raw.C_Sign(sh, None, 0, sig_buf, ctypes.byref(sig_len))
        print(f"rv={{rv2}}")
    else:
        print(f"rv={{rv}}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        else:
            raise ValueError(f"Unhandled: operation={operation}, mech_name={mech_name}")
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"{operation}(mechanism={mech_name}, data_len=0)",
        )


# ---------------------------------------------------------------------------
# Standalone boundary tests
# ---------------------------------------------------------------------------


class TestLoginNullPin:
    """Probe C_Login with NULL PIN pointer but non-zero length.

    This mismatch (NULL pointer + non-zero length) can cause crashes in
    modules that memcpy the PIN without checking the pointer first.
    """

    def test_login_null_pin_nonzero_length(self, p11_config: Any) -> None:
        preamble = subprocess_session_preamble(
            str(p11_config.module),
            pin=None,  # Don't auto-login -- we're testing C_Login directly
        )
        body = """
from pkcs11_check.raw.types_std import CKU_USER
rv = raw.C_Login(sh, int(CKU_USER), None, 8)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_Login(pin=NULL, pin_len=8)",
        )


class TestGenerateRsaExtremeKeySize:
    """Probe RSA keygen with extreme modulus size (0xFFFFFFFF bits).

    A module that doesn't validate CKA_MODULUS_BITS before allocating
    memory could hang or exhaust resources. Enforced with a 5-second timeout.
    """

    def test_generate_rsa_extreme_key_size(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        preamble = _preamble(p11_config)
        body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_RSA_PKCS_KEY_PAIR_GEN, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE, CKA_MODULUS_BITS, CKA_TOKEN, CKA_ENCRYPT,
    CKA_DECRYPT, CKA_PUBLIC_EXPONENT,
)

mech = CK_MECHANISM()
mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN
mech.pParameter = None
mech.ulParameterLen = 0

# CKA_MODULUS_BITS = 0xFFFFFFFF (extreme)
bits_val = ctypes.c_ulong(0xFFFFFFFF)
exp_bytes = (ctypes.c_ubyte * 3)(0x01, 0x00, 0x01)  # 65537
token_false = ctypes.c_ubyte(0)

pub_attrs = (CK_ATTRIBUTE * 4)()
pub_attrs[0].type = CKA_MODULUS_BITS
pub_attrs[0].pValue = ctypes.cast(ctypes.pointer(bits_val), ctypes.c_void_p)
pub_attrs[0].ulValueLen = ctypes.sizeof(bits_val)
pub_attrs[1].type = CKA_PUBLIC_EXPONENT
pub_attrs[1].pValue = ctypes.cast(ctypes.pointer(exp_bytes), ctypes.c_void_p)
pub_attrs[1].ulValueLen = 3
pub_attrs[2].type = CKA_TOKEN
pub_attrs[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
pub_attrs[2].ulValueLen = 1
pub_attrs[3].type = CKA_ENCRYPT
enc_true = ctypes.c_ubyte(1)
pub_attrs[3].pValue = ctypes.cast(ctypes.pointer(enc_true), ctypes.c_void_p)
pub_attrs[3].ulValueLen = 1

priv_attrs = (CK_ATTRIBUTE * 2)()
priv_token = ctypes.c_ubyte(0)
priv_attrs[0].type = CKA_TOKEN
priv_attrs[0].pValue = ctypes.cast(ctypes.pointer(priv_token), ctypes.c_void_p)
priv_attrs[0].ulValueLen = 1
dec_true = ctypes.c_ubyte(1)
priv_attrs[1].type = CKA_DECRYPT
priv_attrs[1].pValue = ctypes.cast(ctypes.pointer(dec_true), ctypes.c_void_p)
priv_attrs[1].ulValueLen = 1

pub_h = CK_OBJECT_HANDLE(0)
priv_h = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKeyPair(
    sh, ctypes.byref(mech),
    ctypes.cast(pub_attrs, ctypes.POINTER(CK_ATTRIBUTE)), 4,
    ctypes.cast(priv_attrs, ctypes.POINTER(CK_ATTRIBUTE)), 2,
    ctypes.byref(pub_h), ctypes.byref(priv_h),
)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=5, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_GenerateKeyPair(CKA_MODULUS_BITS=0xFFFFFFFF)",
        )


class TestGenerateRsaZeroKeySize:
    """Probe RSA keygen with CKA_MODULUS_BITS = 0.

    A zero modulus size is invalid; the module should reject it cleanly.
    """

    def test_generate_rsa_zero_key_size(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")
        preamble = _preamble(p11_config)
        body = """
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_RSA_PKCS_KEY_PAIR_GEN, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE, CKA_MODULUS_BITS, CKA_TOKEN,
    CKA_ENCRYPT, CKA_DECRYPT, CKA_PUBLIC_EXPONENT,
)

mech = CK_MECHANISM()
mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN
mech.pParameter = None
mech.ulParameterLen = 0

# CKA_MODULUS_BITS = 0
bits_val = ctypes.c_ulong(0)
exp_bytes = (ctypes.c_ubyte * 3)(0x01, 0x00, 0x01)  # 65537
token_false = ctypes.c_ubyte(0)

pub_attrs = (CK_ATTRIBUTE * 4)()
pub_attrs[0].type = CKA_MODULUS_BITS
pub_attrs[0].pValue = ctypes.cast(ctypes.pointer(bits_val), ctypes.c_void_p)
pub_attrs[0].ulValueLen = ctypes.sizeof(bits_val)
pub_attrs[1].type = CKA_PUBLIC_EXPONENT
pub_attrs[1].pValue = ctypes.cast(ctypes.pointer(exp_bytes), ctypes.c_void_p)
pub_attrs[1].ulValueLen = 3
pub_attrs[2].type = CKA_TOKEN
pub_attrs[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
pub_attrs[2].ulValueLen = 1
pub_attrs[3].type = CKA_ENCRYPT
enc_true = ctypes.c_ubyte(1)
pub_attrs[3].pValue = ctypes.cast(ctypes.pointer(enc_true), ctypes.c_void_p)
pub_attrs[3].ulValueLen = 1

priv_attrs = (CK_ATTRIBUTE * 2)()
priv_token = ctypes.c_ubyte(0)
priv_attrs[0].type = CKA_TOKEN
priv_attrs[0].pValue = ctypes.cast(ctypes.pointer(priv_token), ctypes.c_void_p)
priv_attrs[0].ulValueLen = 1
dec_true = ctypes.c_ubyte(1)
priv_attrs[1].type = CKA_DECRYPT
priv_attrs[1].pValue = ctypes.cast(ctypes.pointer(dec_true), ctypes.c_void_p)
priv_attrs[1].ulValueLen = 1

pub_h = CK_OBJECT_HANDLE(0)
priv_h = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKeyPair(
    sh, ctypes.byref(mech),
    ctypes.cast(pub_attrs, ctypes.POINTER(CK_ATTRIBUTE)), 4,
    ctypes.cast(priv_attrs, ctypes.POINTER(CK_ATTRIBUTE)), 2,
    ctypes.byref(pub_h), ctypes.byref(priv_h),
)
print(f"rv={rv}")
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_GenerateKeyPair(CKA_MODULUS_BITS=0)",
        )


class TestGenerateAesExtremeKeySize:
    """Probe AES keygen with CKA_VALUE_LEN = ULONG_MAX.

    A module that doesn't validate CKA_VALUE_LEN before allocating memory
    could crash or exhaust resources.
    """

    def test_generate_aes_extreme_key_size(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES keygen not supported")
        preamble = _preamble(p11_config)
        body = f"""
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CKM_AES_KEY_GEN, CK_OBJECT_HANDLE,
    CK_ATTRIBUTE, CKA_VALUE_LEN, CKA_TOKEN, CKA_ENCRYPT,
)

mech = CK_MECHANISM()
mech.mechanism = CKM_AES_KEY_GEN
mech.pParameter = None
mech.ulParameterLen = 0

# CKA_VALUE_LEN = ULONG_MAX
val_len = ctypes.c_ulong({_CK_ULONG_MAX_64})
token_false = ctypes.c_ubyte(0)
enc_true = ctypes.c_ubyte(1)

attrs = (CK_ATTRIBUTE * 3)()
attrs[0].type = CKA_VALUE_LEN
attrs[0].pValue = ctypes.cast(ctypes.pointer(val_len), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(val_len)
attrs[1].type = CKA_TOKEN
attrs[1].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
attrs[1].ulValueLen = 1
attrs[2].type = CKA_ENCRYPT
attrs[2].pValue = ctypes.cast(ctypes.pointer(enc_true), ctypes.c_void_p)
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
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=5, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateKey(CKA_VALUE_LEN={_CK_ULONG_MAX_64:#x})",
        )
