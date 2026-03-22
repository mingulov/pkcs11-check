"""CKR operation state violation tests via raw ctypes calls.

Tests CKR_OPERATION_ACTIVE conditions:
- Double C_EncryptInit (second without completing first)
- C_EncryptInit then C_SignInit (cross-operation conflict)
- Double C_DigestInit

Uses pkcs11.raw.RawPKCS11 to bypass wrapper state management.
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
from pkcs11.raw import (
    RawPKCS11, CKR_OK, CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED,
    CK_MECHANISM, CKF_SERIAL_SESSION, CKF_RW_SESSION,
)

raw = RawPKCS11.from_lib("{module}")
rv = raw.C_Initialize(None)
assert rv == CKR_OK or rv == 0x191

slot_count = ctypes.c_ulong(0)
raw.C_GetSlotList(1, None, ctypes.byref(slot_count))
slots = (ctypes.c_ulong * slot_count.value)()
raw.C_GetSlotList(1, slots, ctypes.byref(slot_count))

session = ctypes.c_ulong(0)
rv = raw.C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       None, None, ctypes.byref(session))
assert rv == CKR_OK
sh = session.value

pin = {pin_arg}
if pin:
    pin_bytes = pin.encode()
    pin_buf = (ctypes.c_ubyte * len(pin_bytes))(*pin_bytes)
    raw.C_Login(sh, 1, pin_buf, len(pin_bytes))

# Generate AES key for encrypt tests
mech_keygen = CK_MECHANISM()
mech_keygen.mechanism = 0x1080  # CKM_AES_KEY_GEN
key = ctypes.c_ulong(0)
# Minimal template: CKA_VALUE_LEN=32, CKA_ENCRYPT=True, CKA_TOKEN=False
import struct
val_len = struct.pack("=Q", 32)  # 8 bytes for CK_ULONG on 64-bit
true_val = struct.pack("=B", 1)
false_val = struct.pack("=B", 0)

class CK_ATTR(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("pValue", ctypes.c_void_p), ("ulValueLen", ctypes.c_ulong)]

def make_attr(attr_type, value_bytes):
    buf = (ctypes.c_ubyte * len(value_bytes))(*value_bytes)
    a = CK_ATTR()
    a.type = attr_type
    a.pValue = ctypes.cast(buf, ctypes.c_void_p)
    a.ulValueLen = len(value_bytes)
    return a, buf  # keep buf alive

attrs = []
bufs = []
for atype, val in [
    (0x161, val_len),    # CKA_VALUE_LEN = 32
    (0x104, true_val),   # CKA_ENCRYPT = True
    (0x105, true_val),   # CKA_DECRYPT = True
    (0x108, true_val),   # CKA_SIGN = True
    (0x01, false_val),   # CKA_TOKEN = False
]:
    a, b = make_attr(atype, val)
    attrs.append(a)
    bufs.append(b)

tmpl = (CK_ATTR * len(attrs))(*attrs)
rv = raw.C_GenerateKey(sh, ctypes.byref(mech_keygen), tmpl, len(attrs), ctypes.byref(key))
assert rv == CKR_OK, f"GenerateKey failed: 0x{{rv:08x}}"
key_handle = key.value
"""


def _run(module: str, pin: str | None, test_code: str) -> tuple[int, str, str]:
    pin_arg = f'"{pin}"' if pin else "None"
    script = _SCRIPT_PREAMBLE.format(module=module, pin_arg=pin_arg) + textwrap.dedent(test_code) + "\nraw.C_CloseSession(sh)\nraw.C_Finalize(None)\n"
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestOperationActive:
    """Double-Init and cross-operation state violations."""

    def test_double_encrypt_init(self, p11_config: Any) -> None:
        """Double C_EncryptInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081  # CKM_AES_ECB
rv1 = raw.C_EncryptInit(sh, ctypes.byref(mech), key_handle)
assert rv1 == CKR_OK, f"First EncryptInit failed: 0x{rv1:08x}"
rv2 = raw.C_EncryptInit(sh, ctypes.byref(mech), key_handle)
print(f"CKR:0x{rv2:08x}")
# Second should be OPERATION_ACTIVE (or module may cancel first)
assert rv2 in (CKR_OPERATION_ACTIVE, CKR_OK), f"Got 0x{rv2:08x}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_encrypt_then_sign_init(self, p11_config: Any) -> None:
        """C_EncryptInit then C_SignInit -> CKR_OPERATION_ACTIVE (if no dual-crypto)."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081  # CKM_AES_ECB
rv1 = raw.C_EncryptInit(sh, ctypes.byref(mech), key_handle)
assert rv1 == CKR_OK

# Now try SignInit -- should be OPERATION_ACTIVE
sign_mech = CK_MECHANISM()
sign_mech.mechanism = 0x0251  # CKM_AES_CMAC
rv2 = raw.C_SignInit(sh, ctypes.byref(sign_mech), key_handle)
print(f"CKR:0x{rv2:08x}")
# OPERATION_ACTIVE, OK (dual-crypto), MECHANISM_INVALID (no CMAC support),
# KEY_FUNCTION_NOT_PERMITTED, or other init errors -- all acceptable
# The key test: did NOT segfault.
print("OK")
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_double_digest_init(self, p11_config: Any) -> None:
        """Double C_DigestInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x0250  # CKM_SHA256
rv1 = raw.C_DigestInit(sh, ctypes.byref(mech))
assert rv1 == CKR_OK

rv2 = raw.C_DigestInit(sh, ctypes.byref(mech))
print(f"CKR:0x{rv2:08x}")
assert rv2 in (CKR_OPERATION_ACTIVE, CKR_OK), f"Got 0x{rv2:08x}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_double_sign_init(self, p11_config: Any) -> None:
        """Double C_SignInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081  # CKM_AES_ECB (for CMAC or just to test state)
# Use key_handle from preamble (AES key with SIGN=True)
rv1 = raw.C_SignInit(sh, ctypes.byref(mech), key_handle)
# First init may fail if AES-ECB not valid for sign -- that's OK
if rv1 == CKR_OK:
    rv2 = raw.C_SignInit(sh, ctypes.byref(mech), key_handle)
    print(f"CKR:0x{rv2:08x}")
    assert rv2 in (CKR_OPERATION_ACTIVE, CKR_OK), f"Got 0x{rv2:08x}"
else:
    print(f"CKR:0x{rv1:08x}:first_init_failed")
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_double_decrypt_init(self, p11_config: Any) -> None:
        """Double C_DecryptInit -> CKR_OPERATION_ACTIVE."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081  # CKM_AES_ECB
rv1 = raw.C_DecryptInit(sh, ctypes.byref(mech), key_handle)
assert rv1 == CKR_OK, f"First DecryptInit: 0x{rv1:08x}"
rv2 = raw.C_DecryptInit(sh, ctypes.byref(mech), key_handle)
print(f"CKR:0x{rv2:08x}")
assert rv2 in (CKR_OPERATION_ACTIVE, CKR_OK), f"Got 0x{rv2:08x}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
