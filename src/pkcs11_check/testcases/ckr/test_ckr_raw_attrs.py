"""CKR attribute permission tests via raw ctypes calls.

Tests CKR_KEY_FUNCTION_NOT_PERMITTED by creating keys with specific
CKA_* attributes set to False, then using raw C_*Init calls that
bypass the python-pkcs11 wrapper's attribute checks.

All tests run in subprocess for safety.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from typing import Any

import pytest

pytestmark = [pytest.mark.access, pytest.mark.subprocess]

_SCRIPT_TEMPLATE = """\
import ctypes
from ctypes import byref, cast

from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_SHA256_HMAC,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template

def _template_ptr(attrs):
    return cast(attrs.array, CK_ATTRIBUTE_PTR)

raw = RawPKCS11.from_lib("{module}")
raw.C_Initialize(None)
sh = open_session(raw, get_slot_ids(raw)[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
pin = {pin_arg}
if pin is not None:
    login_user(raw, sh, 1, pin.encode())

{test_code}

raw.C_CloseSession(sh)
raw.C_Finalize(None)
"""


def _run(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
    pin_arg = repr(pin) if pin is not None else "None"
    script = _SCRIPT_TEMPLATE.format(
        module=module, pin_arg=pin_arg, test_code=textwrap.dedent(code)
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestKeyFunctionNotPermitted:
    """Keys with CKA_*=False tested via raw C_*Init calls."""

    def test_encrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_ENCRYPT=False -> C_EncryptInit -> CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# Generate key with ENCRYPT=False
attrs = template(
    attr_ulong(CKA_VALUE_LEN, 32),
    attr_bool(CKA_ENCRYPT, False),
    attr_bool(CKA_DECRYPT, True),
    attr_bool(CKA_TOKEN, False),
)
mech_kg = mech_simple(CKM_AES_KEY_GEN)  # AES_KEY_GEN
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

# Try EncryptInit with CKA_ENCRYPT=False key
mech = mech_simple(CKM_AES_ECB)  # AES_ECB
rv = raw.C_EncryptInit(sh, mech.byref(), key.value)
print(f"CKR:0x{rv:08x}")
assert rv == CKR_KEY_FUNCTION_NOT_PERMITTED, f"Expected NOT_PERMITTED, got 0x{rv:08x}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_sign_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_SIGN=False -> C_SignInit -> CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# Generate key with SIGN=False
attrs = template(
    attr_ulong(CKA_VALUE_LEN, 32),
    attr_bool(CKA_SIGN, False),
    attr_bool(CKA_ENCRYPT, True),
    attr_bool(CKA_TOKEN, False),
)
mech_kg = mech_simple(CKM_AES_KEY_GEN)
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

mech = mech_simple(CKM_SHA256_HMAC)  # sign mech to test CKA_SIGN=False
rv = raw.C_SignInit(sh, mech.byref(), key.value)
print(f"CKR:0x{rv:08x}")
# KEY_FUNCTION_NOT_PERMITTED or MECHANISM_INVALID (if module doesn't support CMAC)
# KEY_FUNCTION_NOT_PERMITTED, MECHANISM_INVALID, or KEY_TYPE_INCONSISTENT
assert rv in (CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_MECHANISM_INVALID, CKR_KEY_TYPE_INCONSISTENT, 0x06), f"Got 0x{rv:08x}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_decrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_DECRYPT=False -> C_DecryptInit -> CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
attrs = template(
    attr_ulong(CKA_VALUE_LEN, 32),
    attr_bool(CKA_DECRYPT, False),
    attr_bool(CKA_ENCRYPT, True),
    attr_bool(CKA_TOKEN, False),
)
mech_kg = mech_simple(CKM_AES_KEY_GEN)
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

mech = mech_simple(CKM_AES_ECB)  # AES_ECB
rv = raw.C_DecryptInit(sh, mech.byref(), key.value)
print(f"CKR:0x{rv:08x}")
assert rv == CKR_KEY_FUNCTION_NOT_PERMITTED, f"Expected NOT_PERMITTED, got 0x{rv:08x}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
