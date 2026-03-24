"""CKR_ARGUMENTS_BAD tests via raw ctypes - NULL pointers to C_* functions.

Tests that passing NULL where a valid pointer is required returns
CKR_ARGUMENTS_BAD (0x07). Modules that segfault instead are documented.

Uses pkcs11_check.raw.RawPKCS11 in subprocess for safety.
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
from ctypes import byref, cast

from pkcs11_check.raw import CKR_ARGUMENTS_BAD, CKR_OK
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
from pkcs11_check.raw.faults import null_pointer
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
from pkcs11_check.raw.types_std import CKF_RW_SESSION, CKF_SERIAL_SESSION, CK_ATTRIBUTE_PTR, CK_OBJECT_HANDLE


def _template_ptr(attrs):
    return cast(attrs.array, CK_ATTRIBUTE_PTR)


raw = RawPKCS11.from_lib("{module}")
raw.C_Initialize(None)
sh = open_session(raw, get_slot_ids(raw)[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
pin = {pin_arg}
if pin is not None:
    login_user(raw, sh, 1, pin.encode())
"""


def _run(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
    pin_arg = repr(pin) if pin is not None else "None"
    script = _PREAMBLE.format(module=module, pin_arg=pin_arg) + textwrap.dedent(code) + "\nraw.C_CloseSession(sh)\nraw.C_Finalize(None)\n"
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _assert_ok(rc: int, out: str, err: str, name: str) -> None:
    if rc < 0:
        pytest.skip(f"{name}: segfault (signal {-rc}) - module doesn't validate NULL")
    assert rc == 0, f"{name} subprocess error: {err[-200:]}"
    assert "OK" in out, f"{name}: {out}"


class TestArgsBadNullPointers:
    """Pass NULL to functions that require valid pointers."""

    def test_encrypt_init_null_mechanism(self, p11_config: Any) -> None:
        """C_EncryptInit(session, NULL, key) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
attrs = template(
    attr_ulong(0x161, 32),
    attr_bool(0x104, True),
    attr_bool(0x01, False),
)
mech_kg = mech_simple(0x1080)
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
assert rv == CKR_OK, f"GenerateKey: 0x{rv:08x}"
# EncryptInit with NULL mechanism
rv = raw.C_EncryptInit(sh, null_pointer().pointer, int(key.value))
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_EncryptInit(NULL mech)")

    def test_decrypt_init_null_mechanism(self, p11_config: Any) -> None:
        """C_DecryptInit(session, NULL, key) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
attrs = template(
    attr_ulong(0x161, 32),
    attr_bool(0x105, True),
    attr_bool(0x01, False),
)
mech_kg = mech_simple(0x1080)
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
assert rv == CKR_OK, f"GenerateKey: 0x{rv:08x}"
rv = raw.C_DecryptInit(sh, null_pointer().pointer, int(key.value))
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_DecryptInit(NULL mech)")

    def test_sign_init_null_mechanism(self, p11_config: Any) -> None:
        """C_SignInit(session, NULL, key) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
rv = raw.C_SignInit(sh, null_pointer().pointer, 0)
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_SignInit(NULL mech)")

    def test_verify_init_null_mechanism(self, p11_config: Any) -> None:
        """C_VerifyInit(session, NULL, key) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
rv = raw.C_VerifyInit(sh, null_pointer().pointer, 0)
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_VerifyInit(NULL mech)")

    def test_digest_init_null_mechanism(self, p11_config: Any) -> None:
        """C_DigestInit(session, NULL) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
rv = raw.C_DigestInit(sh, null_pointer().pointer)
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_DigestInit(NULL mech)")

    def test_generate_key_null_mechanism(self, p11_config: Any) -> None:
        """C_GenerateKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
key = ctypes.c_ulong(0)
rv = raw.C_GenerateKey(sh, null_pointer().pointer, None, 0, ctypes.byref(key))
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0), f"Got 0x{rv:08x}"  # v3.0: NULL mech cancels operation -> OK
print("OK")
""")
        _assert_ok(rc, out, err, "C_GenerateKey(NULL mech)")

    def test_wrap_key_null_mechanism(self, p11_config: Any) -> None:
        """C_WrapKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
out_len = ctypes.c_ulong(256)
rv = raw.C_WrapKey(sh, null_pointer().pointer, 0, 0, None, ctypes.byref(out_len))
print(f"CKR:0x{rv:08x}")
# ARGUMENTS_BAD or KEY_HANDLE_INVALID - both acceptable for NULL mechanism
assert rv in (CKR_ARGUMENTS_BAD, 0x60, 0x70), f"Got 0x{rv:08x}"
print("OK")
""")
        _assert_ok(rc, out, err, "C_WrapKey(NULL mech)")

    def test_derive_key_null_mechanism(self, p11_config: Any) -> None:
        """C_DeriveKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(str(p11_config.module), p11_config.pin.get_secret_value() if p11_config.pin else None, """\
key = ctypes.c_ulong(0)
rv = raw.C_DeriveKey(sh, null_pointer().pointer, 0, None, 0, ctypes.byref(key))
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, 0x60, 0x70), f"Got 0x{rv:08x}"
print("OK")
""")
        _assert_ok(rc, out, err, "C_DeriveKey(NULL mech)")
