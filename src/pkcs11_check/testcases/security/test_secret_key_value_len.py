"""Crash-safe probes for oversized secret-key ``CKA_VALUE_LEN`` templates.

These tests cover entry points not exercised by the existing key-generation
overflow probes. The target bug class is storing a caller-supplied secret-key
length before validating it, then reusing that stored length during cleanup,
digest, derive, unwrap, copy, or zeroization.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    _CK_ULONG_MAX,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

_ULONG_MAX = int(_CK_ULONG_MAX)
_HKDF_SHA256_MAX_OUTPUT = 255 * 32
_VALUE_LEN_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
)


def _preamble(p11_config: Any) -> str:
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=pin_from_config(p11_config),
    )


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


_CREATE_OBJECT_IMPORTS = """
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKO_SECRET_KEY,
    CKR_OK,
    CK_OBJECT_HANDLE,
    CK_ULONG,
)
"""

_BASE_SECRET_KEY_IMPORTS = """
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKO_SECRET_KEY,
    CKR_OK,
    CK_OBJECT_HANDLE,
    CK_ULONG,
)
"""

_BASE_SECRET_KEY_SETUP = """
key_bytes = (ctypes.c_ubyte * 16)(*range(16))
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
token_false = ctypes.c_ubyte(0)
normal_value_len = CK_ULONG(16)

base_tmpl = (CK_ATTRIBUTE * 5)()
base_tmpl[0].type = CKA_CLASS
base_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
base_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
base_tmpl[1].type = CKA_KEY_TYPE
base_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
base_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
base_tmpl[2].type = CKA_TOKEN
base_tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
base_tmpl[2].ulValueLen = 1
base_tmpl[3].type = CKA_VALUE
base_tmpl[3].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
base_tmpl[3].ulValueLen = 16
base_tmpl[4].type = CKA_VALUE_LEN
base_tmpl[4].pValue = ctypes.cast(ctypes.pointer(normal_value_len), ctypes.c_void_p)
base_tmpl[4].ulValueLen = ctypes.sizeof(normal_value_len)

base_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(base_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(base_key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:secret-key import rejected: {ckr_name(rv)}")
    cleanup()
    raise SystemExit(0)
"""

_VALUE_LEN_EFFECT_CHECK = f"""
def assert_value_len_not_toxic(obj, context):
    actual_len = CK_ULONG(0)
    attr = CK_ATTRIBUTE()
    attr.type = CKA_VALUE_LEN
    attr.pValue = ctypes.cast(ctypes.pointer(actual_len), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(actual_len)
    rv = raw.C_GetAttributeValue(sh, obj, ctypes.byref(attr), 1)
    print("VALUE_LEN_RV:0x%08x" % rv)
    if rv == CKR_OK:
        print("VALUE_LEN_VALUE:%d" % int(actual_len.value))
        if int(actual_len.value) == {_ULONG_MAX}:
            raise AssertionError(context + " stored oversized CKA_VALUE_LEN")
"""


class TestCreateObjectSecretKeyValueLen:
    """``C_CreateObject`` secret-key templates with oversized ``CKA_VALUE_LEN``."""

    @pytest.mark.parametrize(
        ("key_type_name", "include_value"),
        (
            pytest.param("CKK_GENERIC_SECRET", True, id="generic_secret_with_value"),
            pytest.param("CKK_GENERIC_SECRET", False, id="generic_secret_without_value"),
            pytest.param("CKK_AES", True, id="aes_with_value"),
        ),
    )
    def test_create_secret_key_with_oversized_value_len_does_not_crash(
        self,
        p11_config: Any,
        key_type_name: str,
        include_value: bool,
    ) -> None:
        """A bad secret-key import template must reject cleanly or tear down cleanly."""
        body = (
            _CREATE_OBJECT_IMPORTS
            + f"""
key_type = {key_type_name}
key_bytes = (ctypes.c_ubyte * 16)(*range(16))
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(key_type)
token_false = ctypes.c_ubyte(0)
value_len = CK_ULONG({_ULONG_MAX})

attrs = (CK_ATTRIBUTE * {5 if include_value else 4})()
attrs[0].type = CKA_CLASS
attrs[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
attrs[0].ulValueLen = ctypes.sizeof(cls_val)
attrs[1].type = CKA_KEY_TYPE
attrs[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
attrs[1].ulValueLen = ctypes.sizeof(key_type_val)
attrs[2].type = CKA_TOKEN
attrs[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
attrs[2].ulValueLen = 1
attrs[3].type = CKA_VALUE_LEN
attrs[3].pValue = ctypes.cast(ctypes.pointer(value_len), ctypes.c_void_p)
attrs[3].ulValueLen = ctypes.sizeof(value_len)
"""
        )
        if include_value:
            body += """
attrs[4].type = CKA_VALUE
attrs[4].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
attrs[4].ulValueLen = 16
"""
        body += f"""
{_VALUE_LEN_EFFECT_CHECK}

handle = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(attrs, ctypes.POINTER(CK_ATTRIBUTE)),
    {5 if include_value else 4},
    ctypes.byref(handle),
)
print(f"TARGET_RV:0x{{rv:08x}}")
if rv == CKR_OK:
    assert_value_len_not_toxic(handle.value, "C_CreateObject")
    destroy_quietly(raw, sh, handle.value)
cleanup()
"""
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(
                f"C_CreateObject({key_type_name}, "
                f"CKA_VALUE_LEN={_ULONG_MAX:#x}, include_value={include_value})"
            ),
        )


class TestExistingSecretKeyValueLen:
    """Existing secret-key paths with oversized ``CKA_VALUE_LEN`` templates."""

    def test_copy_secret_key_with_oversized_value_len_does_not_crash(
        self,
        p11_config: Any,
    ) -> None:
        """``C_CopyObject`` must reject a bad output template or tear down cleanly."""
        body = (
            _BASE_SECRET_KEY_IMPORTS
            + f"""
{_BASE_SECRET_KEY_SETUP}
{_VALUE_LEN_EFFECT_CHECK}

bad_value_len = CK_ULONG({_ULONG_MAX})
bad_attr = CK_ATTRIBUTE()
bad_attr.type = CKA_VALUE_LEN
bad_attr.pValue = ctypes.cast(ctypes.pointer(bad_value_len), ctypes.c_void_p)
bad_attr.ulValueLen = ctypes.sizeof(bad_value_len)
copy_key = CK_OBJECT_HANDLE(0)
try:
    rv = raw.C_CopyObject(
        sh,
        base_key.value,
        ctypes.byref(bad_attr),
        1,
        ctypes.byref(copy_key),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    if rv == CKR_OK:
        assert_value_len_not_toxic(copy_key.value, "C_CopyObject")
finally:
    if copy_key.value:
        destroy_quietly(raw, sh, copy_key.value)
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_CopyObject(secret key, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )

    def test_set_secret_key_oversized_value_len_does_not_crash(
        self,
        p11_config: Any,
    ) -> None:
        """``C_SetAttributeValue`` must not persist a toxic secret length."""
        body = (
            _BASE_SECRET_KEY_IMPORTS
            + f"""
{_BASE_SECRET_KEY_SETUP}
{_VALUE_LEN_EFFECT_CHECK}

bad_value_len = CK_ULONG({_ULONG_MAX})
bad_attr = CK_ATTRIBUTE()
bad_attr.type = CKA_VALUE_LEN
bad_attr.pValue = ctypes.cast(ctypes.pointer(bad_value_len), ctypes.c_void_p)
bad_attr.ulValueLen = ctypes.sizeof(bad_value_len)
try:
    rv = raw.C_SetAttributeValue(sh, base_key.value, ctypes.byref(bad_attr), 1)
    print(f"TARGET_RV:0x{{rv:08x}}")
    if rv == CKR_OK:
        assert_value_len_not_toxic(base_key.value, "C_SetAttributeValue")
finally:
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        )
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_SetAttributeValue(secret key, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )


class TestDigestKeySecretKeyValueLen:
    """``C_DigestKey`` must not consume a toxic stored secret length."""

    def test_digest_key_after_oversized_value_len_import_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Digesting an accepted bad-length secret key must be clean and correct."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        body = f"""
import ctypes
import hashlib
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CK_OBJECT_HANDLE,
    CK_ULONG,
)

{_VALUE_LEN_EFFECT_CHECK}

if "C_DigestKey" not in raw.available_function_names():
    print("SETUP_XFAIL:C_DigestKey is not exposed by this interface")
    cleanup()
    raise SystemExit(0)

key_material = bytes(range(16))
key_bytes = (ctypes.c_ubyte * len(key_material)).from_buffer_copy(key_material)
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
token_false = ctypes.c_ubyte(0)
sensitive_false = ctypes.c_ubyte(0)
extractable_true = ctypes.c_ubyte(1)
bad_value_len = CK_ULONG({_ULONG_MAX})

key_tmpl = (CK_ATTRIBUTE * 7)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
key_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
key_tmpl[2].type = CKA_TOKEN
key_tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
key_tmpl[2].ulValueLen = 1
key_tmpl[3].type = CKA_VALUE_LEN
key_tmpl[3].pValue = ctypes.cast(ctypes.pointer(bad_value_len), ctypes.c_void_p)
key_tmpl[3].ulValueLen = ctypes.sizeof(bad_value_len)
key_tmpl[4].type = CKA_VALUE
key_tmpl[4].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
key_tmpl[4].ulValueLen = len(key_material)
key_tmpl[5].type = CKA_SENSITIVE
key_tmpl[5].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
key_tmpl[5].ulValueLen = 1
key_tmpl[6].type = CKA_EXTRACTABLE
key_tmpl[6].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
key_tmpl[6].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(key_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    7,
    ctypes.byref(key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:secret-key import rejected: {{ckr_name(rv)}}")
    cleanup()
    raise SystemExit(0)

try:
    assert_value_len_not_toxic(key.value, "C_CreateObject for C_DigestKey")

    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_DigestInit(sh, ctypes.byref(mech))
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_DigestInit(CKM_SHA256) failed: {{ckr_name(rv)}}")
    else:
        rv = raw.C_DigestKey(sh, key.value)
        print(f"TARGET_RV:0x{{rv:08x}}")
        if rv == CKR_FUNCTION_NOT_SUPPORTED:
            print("SETUP_XFAIL:C_DigestKey returned CKR_FUNCTION_NOT_SUPPORTED")
        elif rv == CKR_OK:
            digest_len = CK_ULONG(0)
            rv = raw.C_DigestFinal(sh, None, ctypes.byref(digest_len))
            if rv != CKR_OK:
                raise AssertionError(
                    "C_DigestKey returned CKR_OK but C_DigestFinal size query "
                    f"returned {{ckr_name(rv)}}"
                )
            digest_buf = (ctypes.c_ubyte * digest_len.value)()
            rv = raw.C_DigestFinal(sh, digest_buf, ctypes.byref(digest_len))
            if rv != CKR_OK:
                raise AssertionError(
                    "C_DigestKey returned CKR_OK but C_DigestFinal returned "
                    f"{{ckr_name(rv)}}"
                )
            actual = bytes(digest_buf[: digest_len.value])
            expected = hashlib.sha256(key_material).digest()
            if actual != expected:
                raise AssertionError(
                    "C_DigestKey returned CKR_OK but digested bytes do not match "
                    "the imported key value"
                )
finally:
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(f"C_DigestKey(secret key imported with CKA_VALUE_LEN={_ULONG_MAX:#x})"),
        )


class TestUnwrapSecretKeyValueLen:
    """``C_UnwrapKey`` output templates with oversized ``CKA_VALUE_LEN``."""

    def test_aes_ecb_unwrap_oversized_value_len_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """A valid wrapped key with a toxic output template must not corrupt state."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        body = f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.recipes import wrap_key as wrap_key_recipe
from pkcs11_check.testcases.conftest import AES_KEYGEN_RUNTIME_REJECT_RVS
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKK_AES,
    CKM_AES_ECB,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
    CK_OBJECT_HANDLE,
    CK_ULONG,
)

{_VALUE_LEN_EFFECT_CHECK}

_WRAP_SETUP_REJECT_RVS = (
    int(CKR_ARGUMENTS_BAD),
    int(CKR_ATTRIBUTE_VALUE_INVALID),
    int(CKR_FUNCTION_FAILED),
    int(CKR_FUNCTION_NOT_SUPPORTED),
    int(CKR_GENERAL_ERROR),
    int(CKR_KEY_FUNCTION_NOT_PERMITTED),
    int(CKR_KEY_SIZE_RANGE),
    int(CKR_KEY_TYPE_INCONSISTENT),
    int(CKR_MECHANISM_INVALID),
    int(CKR_MECHANISM_PARAM_INVALID),
    int(CKR_TEMPLATE_INCOMPLETE),
    int(CKR_TEMPLATE_INCONSISTENT),
    int(CKR_WRAPPING_KEY_SIZE_RANGE),
    int(CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
)

wrap_key_handle = 0
target_key = 0
new_key = CK_OBJECT_HANDLE(0)
try:
    try:
        wrap_key_handle = gen_aes_key(
            raw,
            sh,
            256,
            attrs={{
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
            }},
        )
        target_key = gen_aes_key(
            raw,
            sh,
            128,
            attrs={{
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_TOKEN: False,
            }},
        )
    except AssertionError as exc:
        if child_setup_reject_known(
            exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
        ):
            raise SystemExit(0)
        raise

    try:
        wrapped_blob = wrap_key_recipe(raw, sh, wrap_key_handle, target_key, CKM_AES_ECB)
    except AssertionError as exc:
        if child_setup_reject_known(
            exc, _WRAP_SETUP_REJECT_RVS, "AES-ECB key wrap setup rejected"
        ):
            raise SystemExit(0)
        raise

    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_AES)
    token_false = ctypes.c_ubyte(0)
    encrypt_true = ctypes.c_ubyte(1)
    decrypt_true = ctypes.c_ubyte(1)
    bad_value_len = CK_ULONG({_ULONG_MAX})

    out_tmpl = (CK_ATTRIBUTE * 6)()
    out_tmpl[0].type = CKA_CLASS
    out_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    out_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    out_tmpl[1].type = CKA_KEY_TYPE
    out_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    out_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    out_tmpl[2].type = CKA_TOKEN
    out_tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
    out_tmpl[2].ulValueLen = 1
    out_tmpl[3].type = CKA_VALUE_LEN
    out_tmpl[3].pValue = ctypes.cast(ctypes.pointer(bad_value_len), ctypes.c_void_p)
    out_tmpl[3].ulValueLen = ctypes.sizeof(bad_value_len)
    out_tmpl[4].type = CKA_ENCRYPT
    out_tmpl[4].pValue = ctypes.cast(ctypes.pointer(encrypt_true), ctypes.c_void_p)
    out_tmpl[4].ulValueLen = 1
    out_tmpl[5].type = CKA_DECRYPT
    out_tmpl[5].pValue = ctypes.cast(ctypes.pointer(decrypt_true), ctypes.c_void_p)
    out_tmpl[5].ulValueLen = 1

    data_buf = (ctypes.c_ubyte * len(wrapped_blob)).from_buffer_copy(wrapped_blob)
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_ECB
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_UnwrapKey(
        sh,
        ctypes.byref(mech),
        wrap_key_handle,
        data_buf,
        len(wrapped_blob),
        ctypes.cast(out_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        6,
        ctypes.byref(new_key),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    if rv == CKR_OK:
        assert_value_len_not_toxic(new_key.value, "C_UnwrapKey")
finally:
    if new_key.value:
        destroy_quietly(raw, sh, new_key.value)
    if target_key:
        destroy_quietly(raw, sh, target_key)
    if wrap_key_handle:
        destroy_quietly(raw, sh, wrap_key_handle)
cleanup()
"""
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_UnwrapKey(AES_ECB, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )


class TestGenerateKeySecretKeyValueLen:
    """``C_GenerateKey`` output templates with oversized ``CKA_VALUE_LEN``."""

    def test_generic_secret_generate_key_oversized_value_len_rejects_cleanly(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Variable-length generic-secret generation must reject impossible sizes."""
        rs = p11_raw_session
        if not rs.has_mechanism("GENERIC_SECRET_KEY_GEN"):
            pytest.skip("CKM_GENERIC_SECRET_KEY_GEN not supported")

        body = f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKO_SECRET_KEY,
    CKR_OK,
)

{_VALUE_LEN_EFFECT_CHECK}

def generate_generic_secret(value_len, context):
    mech = CK_MECHANISM()
    mech.mechanism = CKM_GENERIC_SECRET_KEY_GEN
    mech.pParameter = None
    mech.ulParameterLen = 0

    cls_val = CK_ULONG(CKO_SECRET_KEY)
    key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
    requested_len = CK_ULONG(value_len)
    token_false = ctypes.c_ubyte(0)
    sensitive_false = ctypes.c_ubyte(0)
    extractable_true = ctypes.c_ubyte(1)

    tmpl = (CK_ATTRIBUTE * 6)()
    tmpl[0].type = CKA_CLASS
    tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
    tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
    tmpl[1].type = CKA_KEY_TYPE
    tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
    tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
    tmpl[2].type = CKA_VALUE_LEN
    tmpl[2].pValue = ctypes.cast(ctypes.pointer(requested_len), ctypes.c_void_p)
    tmpl[2].ulValueLen = ctypes.sizeof(requested_len)
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
    print(f"{{context}}_BEGIN:{{value_len}}", flush=True)
    rv = raw.C_GenerateKey(
        sh,
        ctypes.byref(mech),
        ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        6,
        ctypes.byref(key),
    )
    print(f"{{context}}_RV:0x{{rv:08x}}", flush=True)
    print(f"{{context}}_RV_NAME:{{ckr_name(rv)}}", flush=True)
    return rv, key

def get_value_len(obj, context):
    actual_len = CK_ULONG(0)
    attr = CK_ATTRIBUTE()
    attr.type = CKA_VALUE_LEN
    attr.pValue = ctypes.cast(ctypes.pointer(actual_len), ctypes.c_void_p)
    attr.ulValueLen = ctypes.sizeof(actual_len)
    rv = raw.C_GetAttributeValue(sh, obj, ctypes.byref(attr), 1)
    print(f"{{context}}_VALUE_LEN_RV:0x{{rv:08x}}", flush=True)
    if rv != CKR_OK:
        raise AssertionError(
            f"{{context}} generated key but CKA_VALUE_LEN read returned {{ckr_name(rv)}}"
        )
    print(f"{{context}}_VALUE_LEN:{{actual_len.value}}", flush=True)
    return int(actual_len.value)

normal_key = CK_OBJECT_HANDLE(0)
bad_key = CK_OBJECT_HANDLE(0)
try:
    rv, normal_key = generate_generic_secret(32, "CONTROL")
    if rv != CKR_OK:
        print(
            f"SETUP_XFAIL:CKM_GENERIC_SECRET_KEY_GEN control rejected: {{ckr_name(rv)}}",
            flush=True,
        )
        cleanup()
        raise SystemExit(0)
    actual_len = get_value_len(normal_key.value, "CONTROL")
    if actual_len != 32:
        raise AssertionError(
            f"CKM_GENERIC_SECRET_KEY_GEN generated {{actual_len}} bytes, expected 32"
        )

    rv, bad_key = generate_generic_secret({_ULONG_MAX}, "TARGET")
    if rv == CKR_OK:
        assert_value_len_not_toxic(bad_key.value, "C_GenerateKey(GENERIC_SECRET)")
finally:
    if bad_key.value:
        destroy_quietly(raw, sh, bad_key.value)
    if normal_key.value:
        destroy_quietly(raw, sh, normal_key.value)
cleanup()
"""
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateKey(GENERIC_SECRET, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _VALUE_LEN_REJECT_RVS,
            label=f"C_GenerateKey(GENERIC_SECRET, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )

    def test_pbkdf2_generate_key_oversized_value_len_rejects_cleanly(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """PBKDF2 output length must reject ``CK_ULONG_MAX`` without crashing."""
        rs = p11_raw_session
        if not rs.has_mechanism("PKCS5_PBKD2"):
            pytest.skip("CKM_PKCS5_PBKD2 not supported")

        body = f"""
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

{_VALUE_LEN_EFFECT_CHECK}

password = (ctypes.c_ubyte * 8)(*b"password")
salt = (ctypes.c_ubyte * 8)(*b"salt1234")

params = CK_PKCS5_PBKD2_PARAMS2()
params.saltSource = CKZ_SALT_SPECIFIED
params.pSaltSourceData = ctypes.cast(salt, ctypes.c_void_p)
params.ulSaltSourceDataLen = len(salt)
params.iterations = 1024
params.prf = CKP_PKCS5_PBKD2_HMAC_SHA256
params.pPrfData = None
params.ulPrfDataLen = 0
params.pPassword = ctypes.cast(password, ctypes.c_void_p)
params.ulPasswordLen = len(password)

mech = CK_MECHANISM()
mech.mechanism = CKM_PKCS5_PBKD2
mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
mech.ulParameterLen = ctypes.sizeof(params)

cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
bad_value_len = CK_ULONG({_ULONG_MAX})
token_false = ctypes.c_ubyte(0)
sensitive_false = ctypes.c_ubyte(0)
extractable_true = ctypes.c_ubyte(1)

out_tmpl = (CK_ATTRIBUTE * 6)()
out_tmpl[0].type = CKA_CLASS
out_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
out_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
out_tmpl[1].type = CKA_KEY_TYPE
out_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
out_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
out_tmpl[2].type = CKA_VALUE_LEN
out_tmpl[2].pValue = ctypes.cast(ctypes.pointer(bad_value_len), ctypes.c_void_p)
out_tmpl[2].ulValueLen = ctypes.sizeof(bad_value_len)
out_tmpl[3].type = CKA_TOKEN
out_tmpl[3].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
out_tmpl[3].ulValueLen = 1
out_tmpl[4].type = CKA_SENSITIVE
out_tmpl[4].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
out_tmpl[4].ulValueLen = 1
out_tmpl[5].type = CKA_EXTRACTABLE
out_tmpl[5].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
out_tmpl[5].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(
    sh,
    ctypes.byref(mech),
    ctypes.cast(out_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    6,
    ctypes.byref(key),
)
print(f"TARGET_RV:0x{{rv:08x}}")
print(f"TARGET_RV_NAME:{{ckr_name(rv)}}")
if rv == CKR_OK:
    assert_value_len_not_toxic(key.value, "C_GenerateKey(PBKDF2)")
    destroy_quietly(raw, sh, key.value)
cleanup()
"""
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=f"C_GenerateKey(PBKDF2, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )
        rv = _parse_prefixed_int(stdout, "TARGET_RV:")
        classify_negative_rv(
            rv,
            _VALUE_LEN_REJECT_RVS,
            label=f"C_GenerateKey(PBKDF2, CKA_VALUE_LEN={_ULONG_MAX:#x})",
        )


class TestDeriveKeySecretKeyValueLen:
    """``C_DeriveKey`` output templates with oversized ``CKA_VALUE_LEN``."""

    @pytest.mark.parametrize(
        "output_value_len",
        (
            pytest.param(_HKDF_SHA256_MAX_OUTPUT, id="hkdf_sha256_max_output"),
            pytest.param(_ULONG_MAX, id="ulong_max"),
        ),
    )
    def test_hkdf_derive_max_output_value_len_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
        output_value_len: int,
    ) -> None:
        """HKDF output lengths must not corrupt object creation or teardown."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")

        body = f"""
import ctypes
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CKF_HKDF_SALT_NULL,
    CK_ATTRIBUTE,
    CK_HKDF_PARAMS,
    CK_MECHANISM,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_HKDF_DERIVE,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_OK,
    CK_OBJECT_HANDLE,
    CK_ULONG,
)

{_VALUE_LEN_EFFECT_CHECK}

key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
derive_true = ctypes.c_ubyte(1)
token_false = ctypes.c_ubyte(0)

key_tmpl = (CK_ATTRIBUTE * 5)()
key_tmpl[0].type = CKA_CLASS
key_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
key_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
key_tmpl[1].type = CKA_KEY_TYPE
key_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
key_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
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
    print(f"SETUP_XFAIL:HKDF base-key import rejected: 0x{{rv:08x}}")
    cleanup()
    raise SystemExit(0)

derived = CK_OBJECT_HANDLE(0)
try:
    params = CK_HKDF_PARAMS()
    params.bExtract = 1
    params.bExpand = 1
    params.prfHashMechanism = CKM_SHA256
    params.ulSaltType = CKF_HKDF_SALT_NULL
    params.pSalt = None
    params.ulSaltLen = 0
    params.hSaltKey = 0
    params.pInfo = None
    params.ulInfoLen = 0

    mech = CK_MECHANISM()
    mech.mechanism = CKM_HKDF_DERIVE
    mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
    mech.ulParameterLen = ctypes.sizeof(params)

    out_cls = CK_ULONG(CKO_SECRET_KEY)
    out_key_type = CK_ULONG(CKK_GENERIC_SECRET)
    out_len = CK_ULONG({output_value_len})
    out_token = ctypes.c_ubyte(0)

    out_tmpl = (CK_ATTRIBUTE * 4)()
    out_tmpl[0].type = CKA_CLASS
    out_tmpl[0].pValue = ctypes.cast(ctypes.pointer(out_cls), ctypes.c_void_p)
    out_tmpl[0].ulValueLen = ctypes.sizeof(out_cls)
    out_tmpl[1].type = CKA_KEY_TYPE
    out_tmpl[1].pValue = ctypes.cast(ctypes.pointer(out_key_type), ctypes.c_void_p)
    out_tmpl[1].ulValueLen = ctypes.sizeof(out_key_type)
    out_tmpl[2].type = CKA_VALUE_LEN
    out_tmpl[2].pValue = ctypes.cast(ctypes.pointer(out_len), ctypes.c_void_p)
    out_tmpl[2].ulValueLen = ctypes.sizeof(out_len)
    out_tmpl[3].type = CKA_TOKEN
    out_tmpl[3].pValue = ctypes.cast(ctypes.pointer(out_token), ctypes.c_void_p)
    out_tmpl[3].ulValueLen = 1

    rv = raw.C_DeriveKey(
        sh,
        ctypes.byref(mech),
        base_key.value,
        ctypes.cast(out_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
        4,
        ctypes.byref(derived),
    )
    print(f"TARGET_RV:0x{{rv:08x}}")
    if rv == CKR_OK:
        assert_value_len_not_toxic(derived.value, "C_DeriveKey")
finally:
    if derived.value:
        destroy_quietly(raw, sh, derived.value)
    destroy_quietly(raw, sh, base_key.value)
cleanup()
"""
        script = _preamble(p11_config) + body
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(f"C_DeriveKey(HKDF_SHA256, CKA_VALUE_LEN={output_value_len:#x})"),
        )
