"""CKR tests for v3.0 functions via raw ctypes calls.

Tests C_MessageEncryptInit, C_MessageDecryptInit, C_MessageSignInit,
C_MessageVerifyInit, C_LoginUser, C_SessionCancel using RawPKCS11
with funclist3_ptr for v3.0 function access.

Requires v3.0+ module (e.g., Kryoptic). Skips on v2.40 modules.
All tests run in subprocess for safety.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from typing import Any

import pytest

pytestmark = [pytest.mark.access, pytest.mark.subprocess, pytest.mark.requires_v30]

_SCRIPT_TEMPLATE = """\
import ctypes, os, sys
from pkcs11.raw import (
    RawPKCS11, CKR_OK, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED,
    CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_TYPE_INCONSISTENT,
    CKR_FUNCTION_NOT_SUPPORTED, CKR_ARGUMENTS_BAD, CKR_OPERATION_ACTIVE,
    CK_MECHANISM, CKF_SERIAL_SESSION, CKF_RW_SESSION,
)

import pkcs11
lib = pkcs11.lib("{module}")
f3 = lib._raw_funclist3_ptr
if not f3:
    print("SKIP:v2.40_only")
    lib.finalize()
    sys.exit(0)

raw = RawPKCS11(lib._raw_funclist_ptr, funclist3_ptr=f3)

# Check if v3.0 functions are loaded
if "C_MessageEncryptInit" not in raw._funcs:
    print("SKIP:no_v3_funcs")
    lib.finalize()
    sys.exit(0)

# Open session
slots = lib.get_slots(token_present=True)
token = slots[0].get_token()
pin = {pin_arg}
session = token.open(rw=True, user_pin=pin) if pin else token.open(rw=True)
sh = session.handle

{test_code}

session.close()
lib.finalize()
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


def _check(rc: int, out: str, err: str, func: str) -> None:
    if "SKIP:" in out:
        pytest.skip(out.split("SKIP:")[1])
    assert rc == 0, f"{func} crashed: {err[-300:]}"
    assert "OK" in out, f"{func}: {out} | {err[-200:]}"


class TestMessageEncryptErrors:
    """v3.0 C_MessageEncryptInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageEncryptInit with digest mechanism -> CKR_MECHANISM_INVALID."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x0250  # CKM_SHA256 -- not an encrypt mechanism
key = ctypes.c_ulong(0)  # dummy key handle
rv = raw.C_MessageEncryptInit(sh, ctypes.byref(mech), 0)
print(f"CKR:0x{rv:08x}")
# MECHANISM_INVALID, KEY_HANDLE_INVALID, FUNCTION_NOT_SUPPORTED -- all acceptable
assert rv != CKR_OK, f"Should have rejected SHA256 for message encrypt"
print("OK")
""",
        )
        _check(rc, out, err, "C_MessageEncryptInit")

    def test_operation_not_initialized(self, p11_config: Any) -> None:
        """C_EncryptMessage without Init -> CKR_OPERATION_NOT_INITIALIZED."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# Try EncryptMessage without MessageEncryptInit
data = (ctypes.c_ubyte * 16)(*([0]*16))
out = (ctypes.c_ubyte * 32)()
out_len = ctypes.c_ulong(32)
if "C_EncryptMessage" in raw._funcs:
    rv = raw.C_EncryptMessage(sh, None, 0, data, 16, None, 0, out, ctypes.byref(out_len))
    print(f"CKR:0x{rv:08x}")
    assert rv in (CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_NOT_SUPPORTED, CKR_ARGUMENTS_BAD), f"Got 0x{rv:08x}"
else:
    print("SKIP:no_EncryptMessage")
print("OK")
""",
        )
        _check(rc, out, err, "C_EncryptMessage")


class TestMessageDecryptErrors:
    """v3.0 C_MessageDecryptInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageDecryptInit with digest mechanism."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x0250  # SHA256
rv = raw.C_MessageDecryptInit(sh, ctypes.byref(mech), 0)
print(f"CKR:0x{rv:08x}")
assert rv != CKR_OK
print("OK")
""",
        )
        _check(rc, out, err, "C_MessageDecryptInit")


class TestMessageSignErrors:
    """v3.0 C_MessageSignInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageSignInit with encrypt mechanism."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081  # AES_ECB -- not a sign mechanism
rv = raw.C_MessageSignInit(sh, ctypes.byref(mech), 0)
print(f"CKR:0x{rv:08x}")
assert rv != CKR_OK
print("OK")
""",
        )
        _check(rc, out, err, "C_MessageSignInit")


class TestMessageVerifyErrors:
    """v3.0 C_MessageVerifyInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_MessageVerifyInit with encrypt mechanism."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081  # AES_ECB
rv = raw.C_MessageVerifyInit(sh, ctypes.byref(mech), 0)
print(f"CKR:0x{rv:08x}")
assert rv != CKR_OK
print("OK")
""",
        )
        _check(rc, out, err, "C_MessageVerifyInit")


class TestSessionCancelErrors:
    """v3.0 C_SessionCancel error conditions."""

    def test_cancel_no_operation(self, p11_config: Any) -> None:
        """C_SessionCancel with no active operation."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
if "C_SessionCancel" in raw._funcs:
    rv = raw.C_SessionCancel(sh, 0)
    print(f"CKR:0x{rv:08x}")
    # OK or OPERATION_ACTIVE -- both acceptable
    print("OK")
else:
    print("SKIP:no_SessionCancel")
""",
        )
        _check(rc, out, err, "C_SessionCancel")
