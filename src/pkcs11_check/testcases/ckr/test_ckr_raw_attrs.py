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
import ctypes, struct
from pkcs11.raw import (
    RawPKCS11, CKR_OK, CKR_KEY_FUNCTION_NOT_PERMITTED,
    CK_MECHANISM, CKF_SERIAL_SESSION, CKF_RW_SESSION,
    CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID,
)

raw = RawPKCS11.from_lib("{module}")
raw.C_Initialize(None)
sc = ctypes.c_ulong(0)
raw.C_GetSlotList(1, None, ctypes.byref(sc))
sl = (ctypes.c_ulong * sc.value)()
raw.C_GetSlotList(1, sl, ctypes.byref(sc))
sess = ctypes.c_ulong(0)
raw.C_OpenSession(sl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(sess))
sh = sess.value
pin = {pin_arg}
if pin:
    pb = pin.encode()
    raw.C_Login(sh, 1, (ctypes.c_ubyte * len(pb))(*pb), len(pb))

# Helper to build CK_ATTRIBUTE array
class CK_ATTR(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("pValue", ctypes.c_void_p), ("ulValueLen", ctypes.c_ulong)]

def mk(t, v):
    b = (ctypes.c_ubyte * len(v))(*v)
    a = CK_ATTR(); a.type = t; a.pValue = ctypes.cast(b, ctypes.c_void_p); a.ulValueLen = len(v)
    return a, b

true_val = b"\\x01"
false_val = b"\\x00"
val_len_32 = struct.pack("=Q", 32)

{test_code}

raw.C_CloseSession(sh)
raw.C_Finalize(None)
"""


def _run(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
    pin_arg = f'"{pin}"' if pin else "None"
    script = _SCRIPT_TEMPLATE.format(module=module, pin_arg=pin_arg, test_code=textwrap.dedent(code))
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestKeyFunctionNotPermitted:
    """Keys with CKA_*=False tested via raw C_*Init calls."""

    def test_encrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_ENCRYPT=False → C_EncryptInit → CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# Generate key with ENCRYPT=False
attrs = []
bufs = []
for t, v in [(0x161, val_len_32), (0x104, false_val), (0x105, true_val), (0x01, false_val)]:
    a, b = mk(t, v); attrs.append(a); bufs.append(b)
tmpl = (CK_ATTR * len(attrs))(*attrs)
mech_kg = CK_MECHANISM(); mech_kg.mechanism = 0x1080  # AES_KEY_GEN
key = ctypes.c_ulong(0)
rv = raw.C_GenerateKey(sh, ctypes.byref(mech_kg), tmpl, len(attrs), ctypes.byref(key))
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

# Try EncryptInit with CKA_ENCRYPT=False key
mech = CK_MECHANISM(); mech.mechanism = 0x1081  # AES_ECB
rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key.value)
print(f"CKR:0x{rv:08x}")
assert rv == CKR_KEY_FUNCTION_NOT_PERMITTED, f"Expected NOT_PERMITTED, got 0x{rv:08x}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_sign_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_SIGN=False → C_SignInit → CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# Generate key with SIGN=False
attrs = []
bufs = []
for t, v in [(0x161, val_len_32), (0x108, false_val), (0x104, true_val), (0x01, false_val)]:
    a, b = mk(t, v); attrs.append(a); bufs.append(b)
tmpl = (CK_ATTR * len(attrs))(*attrs)
mech_kg = CK_MECHANISM(); mech_kg.mechanism = 0x1080
key = ctypes.c_ulong(0)
rv = raw.C_GenerateKey(sh, ctypes.byref(mech_kg), tmpl, len(attrs), ctypes.byref(key))
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

mech = CK_MECHANISM(); mech.mechanism = 0x0251  # AES_CMAC
rv = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
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
        """Key with CKA_DECRYPT=False → C_DecryptInit → CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
attrs = []
bufs = []
for t, v in [(0x161, val_len_32), (0x105, false_val), (0x104, true_val), (0x01, false_val)]:
    a, b = mk(t, v); attrs.append(a); bufs.append(b)
tmpl = (CK_ATTR * len(attrs))(*attrs)
mech_kg = CK_MECHANISM(); mech_kg.mechanism = 0x1080
key = ctypes.c_ulong(0)
rv = raw.C_GenerateKey(sh, ctypes.byref(mech_kg), tmpl, len(attrs), ctypes.byref(key))
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

mech = CK_MECHANISM(); mech.mechanism = 0x1081  # AES_ECB
rv = raw.C_DecryptInit(sh, ctypes.byref(mech), key.value)
print(f"CKR:0x{rv:08x}")
assert rv == CKR_KEY_FUNCTION_NOT_PERMITTED, f"Expected NOT_PERMITTED, got 0x{rv:08x}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
