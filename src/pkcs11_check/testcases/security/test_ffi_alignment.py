"""FFI pointer-alignment hardening probes.

These tests exercise caller buffers whose bytes encode valid PKCS#11 structs or
scalar values but whose pointers are intentionally unaligned. This is a
crash-safety boundary for modules reached through foreign-function bindings:
providers may accept the call or reject it cleanly, but they must not crash.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]


def _preamble(p11_config: Any) -> str:
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
    )


_MISALIGNED_HELPERS = r"""
import ctypes

from pkcs11_check.raw.types_std import CK_ATTRIBUTE, CK_BBOOL, CK_MECHANISM, CK_ULONG


def misaligned_ptr_to_struct(value):
    storage = (ctypes.c_ubyte * (ctypes.sizeof(value) + 1))()
    ctypes.memmove(ctypes.addressof(storage) + 1, ctypes.byref(value), ctypes.sizeof(value))
    ptr_type = ctypes.POINTER(type(value))
    return storage, ctypes.cast(ctypes.byref(storage, 1), ptr_type)


def misaligned_scalar(ctype, value):
    storage = (ctypes.c_ubyte * (ctypes.sizeof(ctype) + 1))()
    scalar = ctype(value)
    ctypes.memmove(ctypes.addressof(storage) + 1, ctypes.byref(scalar), ctypes.sizeof(scalar))
    return storage, ctypes.cast(ctypes.byref(storage, 1), ctypes.c_void_p)
"""


class TestMisalignedAttributeValues:
    """CK_ATTRIBUTE.pValue points to unaligned scalar storage."""

    def test_generate_key_with_misaligned_scalar_attribute_values(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_GenerateKey must not crash on unaligned scalar pValue pointers."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        script = (
            _preamble(p11_config)
            + _MISALIGNED_HELPERS
            + r"""
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKM_AES_KEY_GEN,
    CKR_OK,
)

mech = CK_MECHANISM()
mech.mechanism = CKM_AES_KEY_GEN
mech.pParameter = None
mech.ulParameterLen = 0

attrs = (CK_ATTRIBUTE * 4)()
storages = []
for idx, (attr_type, ctype, attr_value) in enumerate((
    (CKA_VALUE_LEN, CK_ULONG, 16),
    (CKA_ENCRYPT, CK_BBOOL, 1),
    (CKA_DECRYPT, CK_BBOOL, 1),
    (CKA_TOKEN, CK_BBOOL, 0),
)):
    storage, ptr = misaligned_scalar(ctype, attr_value)
    storages.append(storage)
    attrs[idx].type = attr_type
    attrs[idx].pValue = ptr
    attrs[idx].ulValueLen = ctypes.sizeof(ctype)

key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, ctypes.byref(mech), attrs, len(attrs), ctypes.byref(key))
print(f"TARGET_RV:C_GenerateKey:{rv}", flush=True)
if rv == CKR_OK:
    raw.C_DestroyObject(sh, key)
cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_GenerateKey with misaligned CK_ATTRIBUTE.pValue scalars",
        )


class TestMisalignedMechanismPointer:
    """CK_MECHANISM_PTR itself points to unaligned struct storage."""

    def test_encrypt_init_with_misaligned_mechanism_pointer(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_EncryptInit must not crash on an unaligned CK_MECHANISM_PTR."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        script = (
            _preamble(p11_config)
            + _MISALIGNED_HELPERS
            + r"""
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKR_OK,
)

key_template = template(
    attr_ulong(CKA_VALUE_LEN, 16),
    attr_bool(CKA_ENCRYPT, True),
    attr_bool(CKA_DECRYPT, True),
    attr_bool(CKA_TOKEN, False),
)
key = CK_OBJECT_HANDLE(0)
keygen_mech = mech_simple(CKM_AES_KEY_GEN)
rv = raw.C_GenerateKey(
    sh,
    keygen_mech.byref(),
    key_template.ptr,
    key_template.count,
    ctypes.byref(key),
)
print(f"SETUP_RV:C_GenerateKey:{rv}", flush=True)
if rv != CKR_OK:
    cleanup()
    raise SystemExit(0)

try:
    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_ECB
    mech.pParameter = None
    mech.ulParameterLen = 0
    mech_storage, mech_ptr = misaligned_ptr_to_struct(mech)
    rv = raw.C_EncryptInit(sh, mech_ptr, key)
    print(f"TARGET_RV:C_EncryptInit:{rv}", flush=True)
finally:
    raw.C_DestroyObject(sh, key)
    cleanup()
"""
        )
        rc, stdout, stderr = run_with_coverage(script, timeout=10, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="C_EncryptInit with misaligned CK_MECHANISM_PTR",
        )
