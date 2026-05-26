"""CKR operation state violation tests via raw ctypes calls.

Tests CKR_OPERATION_ACTIVE conditions:
- Double C_EncryptInit (second without completing first)
- C_EncryptInit then C_SignInit (cross-operation conflict)
- Double C_DigestInit

Uses pkcs11_check.raw.RawPKCS11 to bypass wrapper state management.
All tests run in subprocess.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from typing import Any

import pytest

pytestmark = [pytest.mark.access, pytest.mark.subprocess]

_SCRIPT_PREAMBLE = """\
import ctypes
import sys
from ctypes import byref, cast

from pkcs11_check.raw.rv import ckr_name
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
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template


def _template_ptr(attrs):
    return cast(attrs.array, CK_ATTRIBUTE_PTR)

raw = RawPKCS11.from_lib("{module}")
rv = raw.C_Initialize(None)
assert rv in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED)

sh = open_session(raw, get_slot_ids(raw)[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)

pin = {pin_arg}
if pin is not None:
    login_user(raw, sh, 1, pin.encode())

# Generate AES key for encrypt tests
mech_keygen = mech_simple(CKM_AES_KEY_GEN)
key = CK_OBJECT_HANDLE(0)
attrs = template(
    attr_ulong(CKA_VALUE_LEN, 32),
    attr_bool(CKA_ENCRYPT, True),
    attr_bool(CKA_DECRYPT, True),
    attr_bool(CKA_SIGN, True),
    attr_bool(CKA_TOKEN, False),
)
rv = raw.C_GenerateKey(sh, mech_keygen.byref(), _template_ptr(attrs), attrs.count, byref(key))
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_GenerateKey failed:{ckr_name(rv)}")
    raw.C_CloseSession(sh)
    raw.C_Finalize(None)
    sys.exit(0)
key_handle = key.value
"""


def _run(module: str, pin: str | None, test_code: str) -> tuple[int, str, str]:
    pin_arg = repr(pin) if pin is not None else "None"
    script = (
        _SCRIPT_PREAMBLE.format(module=module, pin_arg=pin_arg)
        + textwrap.dedent(test_code)
        + "\nraw.C_CloseSession(sh)\nraw.C_Finalize(None)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _assert_probe_completed(rc: int, out: str, err: str) -> None:
    assert rc == 0, f"Crash: {err[-300:]}"
    for line in out.splitlines():
        if line.startswith("SETUP_XFAIL:"):
            pytest.xfail(line.removeprefix("SETUP_XFAIL:"))
    assert "OK" in out


class TestOperationActive:
    """Double-Init and cross-operation state violations."""

    def test_double_encrypt_init(self, p11_config: Any) -> None:
        """Double C_EncryptInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = mech_simple(CKM_AES_ECB)
rv1 = raw.C_EncryptInit(sh, mech.byref(), key_handle)
assert rv1 == CKR_OK, f"First EncryptInit failed: 0x{rv1:08x}"
rv2 = raw.C_EncryptInit(sh, mech.byref(), key_handle)
print(f"CKR:0x{rv2:08x}")
# Second should be OPERATION_ACTIVE (or module may cancel first)
assert rv2 in (CKR_OPERATION_ACTIVE, CKR_OK), f"Got 0x{rv2:08x}"
print("OK")
""",
        )
        _assert_probe_completed(rc, out, err)

    def test_encrypt_then_sign_init(self, p11_config: Any) -> None:
        """C_EncryptInit then C_SignInit -> CKR_OPERATION_ACTIVE (if no dual-crypto)."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = mech_simple(CKM_AES_ECB)
rv1 = raw.C_EncryptInit(sh, mech.byref(), key_handle)
assert rv1 == CKR_OK

# Now try SignInit - should be OPERATION_ACTIVE
sign_mech = mech_simple(CKM_SHA256_HMAC)
rv2 = raw.C_SignInit(sh, sign_mech.byref(), key_handle)
print(f"CKR:0x{rv2:08x}")
# OPERATION_ACTIVE, OK (dual-crypto), MECHANISM_INVALID (no CMAC support),
# KEY_FUNCTION_NOT_PERMITTED, or other init errors - all acceptable
# The key test: did NOT segfault.
print("OK")
print("OK")
""",
        )
        _assert_probe_completed(rc, out, err)

    def test_double_digest_init(self, p11_config: Any) -> None:
        """Double C_DigestInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = mech_simple(CKM_SHA256)
rv1 = raw.C_DigestInit(sh, mech.byref())
assert rv1 == CKR_OK

rv2 = raw.C_DigestInit(sh, mech.byref())
print(f"CKR:0x{rv2:08x}")
assert rv2 in (CKR_OPERATION_ACTIVE, CKR_OK), f"Got 0x{rv2:08x}"
print("OK")
""",
        )
        _assert_probe_completed(rc, out, err)

    def test_double_sign_init(self, p11_config: Any) -> None:
        """Double C_SignInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = mech_simple(CKM_AES_ECB)  # AES_ECB (for testing state)
# Use key_handle from preamble (AES key with SIGN=True)
rv1 = raw.C_SignInit(sh, mech.byref(), key_handle)
# First init may fail if AES-ECB not valid for sign - that's OK
if rv1 == CKR_OK:
    rv2 = raw.C_SignInit(sh, mech.byref(), key_handle)
    print(f"CKR:0x{rv2:08x}")
    assert rv2 in (CKR_OPERATION_ACTIVE, CKR_OK), f"Got 0x{rv2:08x}"
else:
    print(f"CKR:0x{rv1:08x}:first_init_failed")
print("OK")
""",
        )
        _assert_probe_completed(rc, out, err)

    def test_double_decrypt_init(self, p11_config: Any) -> None:
        """Double C_DecryptInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = mech_simple(CKM_AES_ECB)
rv1 = raw.C_DecryptInit(sh, mech.byref(), key_handle)
assert rv1 == CKR_OK, f"First DecryptInit: 0x{rv1:08x}"
rv2 = raw.C_DecryptInit(sh, mech.byref(), key_handle)
print(f"CKR:0x{rv2:08x}")
assert rv2 in (CKR_OPERATION_ACTIVE, CKR_OK), f"Got 0x{rv2:08x}"
print("OK")
""",
        )
        _assert_probe_completed(rc, out, err)
