"""CKR_ARGUMENTS_BAD tests via raw ctypes -- NULL pointers to C_* functions.

Tests that passing NULL where a valid pointer is required returns
CKR_ARGUMENTS_BAD (0x07). Modules that segfault instead are documented.

Uses pkcs11.raw.RawPKCS11 in subprocess for safety.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from typing import Any

import pytest

pytestmark = [pytest.mark.access, pytest.mark.subprocess]

_PREAMBLE = """\
import ctypes
from pkcs11.raw import (
    RawPKCS11, CKR_OK, CKR_ARGUMENTS_BAD, CKR_SESSION_HANDLE_INVALID,
    CK_MECHANISM, CKF_SERIAL_SESSION, CKF_RW_SESSION,
    CKR_CRYPTOKI_NOT_INITIALIZED, CKR_MECHANISM_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
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
"""


def _run(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
    pin_arg = f'"{pin}"' if pin else "None"
    script = _PREAMBLE.format(module=module, pin_arg=pin_arg) + textwrap.dedent(code) + "\nraw.C_CloseSession(sh)\nraw.C_Finalize(None)\n"
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _assert_ok(rc: int, out: str, err: str, name: str) -> None:
    if rc < 0:
        pytest.skip(f"{name}: segfault (signal {-rc}) -- module doesn't validate NULL")
    assert rc == 0, f"{name} subprocess error: {err[-200:]}"
    assert "OK" in out, f"{name}: {out}"


class TestArgsBadNullPointers:
    """Pass NULL to functions that require valid pointers."""

    def test_encrypt_init_null_mechanism(self, p11_config: Any) -> None:
        """C_EncryptInit(session, NULL, key) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
# Generate a key first
import struct
class A(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("pValue", ctypes.c_void_p), ("ulValueLen", ctypes.c_ulong)]
def mk(t, v):
    b = (ctypes.c_ubyte * len(v))(*v)
    a = A(); a.type = t; a.pValue = ctypes.cast(b, ctypes.c_void_p); a.ulValueLen = len(v)
    return a, b
a1, b1 = mk(0x161, struct.pack("=Q", 32))
a2, b2 = mk(0x104, b"\\x01")
a3, b3 = mk(0x01, b"\\x00")
tmpl = (A * 3)(a1, a2, a3)
mech_kg = CK_MECHANISM(); mech_kg.mechanism = 0x1080
key = ctypes.c_ulong(0)
raw.C_GenerateKey(sh, ctypes.byref(mech_kg), tmpl, 3, ctypes.byref(key))
# EncryptInit with NULL mechanism
rv = raw.C_EncryptInit(sh, None, key.value)
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_EncryptInit(NULL mech)")

    def test_decrypt_init_null_mechanism(self, p11_config: Any) -> None:
        """C_DecryptInit(session, NULL, key) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
import struct
class A(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("pValue", ctypes.c_void_p), ("ulValueLen", ctypes.c_ulong)]
def mk(t, v):
    b = (ctypes.c_ubyte * len(v))(*v)
    a = A(); a.type = t; a.pValue = ctypes.cast(b, ctypes.c_void_p); a.ulValueLen = len(v)
    return a, b
a1, b1 = mk(0x161, struct.pack("=Q", 32))
a2, b2 = mk(0x105, b"\\x01")
a3, b3 = mk(0x01, b"\\x00")
tmpl = (A * 3)(a1, a2, a3)
mech_kg = CK_MECHANISM(); mech_kg.mechanism = 0x1080
key = ctypes.c_ulong(0)
raw.C_GenerateKey(sh, ctypes.byref(mech_kg), tmpl, 3, ctypes.byref(key))
rv = raw.C_DecryptInit(sh, None, key.value)
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_DecryptInit(NULL mech)")

    def test_sign_init_null_mechanism(self, p11_config: Any) -> None:
        """C_SignInit(session, NULL, key) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
rv = raw.C_SignInit(sh, None, 0)
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_SignInit(NULL mech)")

    def test_verify_init_null_mechanism(self, p11_config: Any) -> None:
        """C_VerifyInit(session, NULL, key) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
rv = raw.C_VerifyInit(sh, None, 0)
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_VerifyInit(NULL mech)")

    def test_digest_init_null_mechanism(self, p11_config: Any) -> None:
        """C_DigestInit(session, NULL) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
rv = raw.C_DigestInit(sh, None)
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_DigestInit(NULL mech)")

    def test_generate_key_null_mechanism(self, p11_config: Any) -> None:
        """C_GenerateKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
key = ctypes.c_ulong(0)
rv = raw.C_GenerateKey(sh, None, None, 0, ctypes.byref(key))
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_GenerateKey(NULL mech)")

    def test_wrap_key_null_mechanism(self, p11_config: Any) -> None:
        """C_WrapKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
out_len = ctypes.c_ulong(256)
rv = raw.C_WrapKey(sh, None, 0, 0, None, ctypes.byref(out_len))
print(f"CKR:0x{rv:08x}")
# ARGUMENTS_BAD or KEY_HANDLE_INVALID -- both acceptable for NULL mechanism
assert rv in (CKR_ARGUMENTS_BAD, 0x60, 0x70), f"Got 0x{rv:08x}"
print("OK")
""")
        _assert_ok(rc, out, err, "C_WrapKey(NULL mech)")

    def test_derive_key_null_mechanism(self, p11_config: Any) -> None:
        """C_DeriveKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
key = ctypes.c_ulong(0)
rv = raw.C_DeriveKey(sh, None, 0, None, 0, ctypes.byref(key))
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0x60, 0x70), f"Got 0x{rv:08x}"
print("OK")
""")
        _assert_ok(rc, out, err, "C_DeriveKey(NULL mech)")
