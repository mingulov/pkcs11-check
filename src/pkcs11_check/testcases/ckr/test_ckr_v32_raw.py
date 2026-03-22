"""CKR tests for v3.2 functions via raw ctypes calls.

Tests C_VerifySignatureInit, C_EncapsulateKey, C_DecapsulateKey,
C_WrapKeyAuthenticated, C_UnwrapKeyAuthenticated, C_AsyncGetID
using RawPKCS11 with funclist32_ptr.

Requires v3.2 module (Kryoptic). Skips on v2.40/v3.0 modules.
All tests run in subprocess for safety.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from typing import Any

import pytest

pytestmark = [pytest.mark.access, pytest.mark.subprocess, pytest.mark.requires_v32]

_SCRIPT_TEMPLATE = """\
import ctypes, os, sys
from pkcs11.raw import (
    RawPKCS11, CKR_OK, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED,
    CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_TYPE_INCONSISTENT,
    CKR_FUNCTION_NOT_SUPPORTED, CKR_ARGUMENTS_BAD, CKR_KEY_HANDLE_INVALID,
    CK_MECHANISM, CKF_SERIAL_SESSION, CKF_RW_SESSION,
)

import pkcs11
lib = pkcs11.lib("{module}")
f3 = lib._raw_funclist3_ptr
f32 = lib._raw_funclist32_ptr
if not f32:
    print("SKIP:no_v32")
    lib.finalize()
    sys.exit(0)

raw = RawPKCS11(lib._raw_funclist_ptr, funclist3_ptr=f3, funclist32_ptr=f32)

if "C_VerifySignatureInit" not in raw._funcs:
    print("SKIP:no_v32_funcs")
    lib.finalize()
    sys.exit(0)

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
        capture_output=True, text=True, timeout=30,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _check(rc: int, out: str, err: str, func: str) -> None:
    if "SKIP:" in out:
        pytest.skip(out.split("SKIP:")[1])
    assert rc == 0, f"{func} crashed: {err[-300:]}"
    assert "OK" in out, f"{func}: {out} | {err[-200:]}"


class TestVerifySignatureErrors:
    """v3.2 C_VerifySignatureInit error conditions."""

    def test_mechanism_invalid(self, p11_config: Any) -> None:
        """C_VerifySignatureInit with encrypt mechanism -> error."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081  # AES_ECB - not a verify mechanism
sig = (ctypes.c_ubyte * 32)(*([0]*32))
rv = raw.C_VerifySignatureInit(sh, ctypes.byref(mech), 0, sig, 32)
print(f"CKR:0x{rv:08x}")
assert rv != CKR_OK, f"Should have rejected AES_ECB for VerifySignature"
print("OK")
""",
        )
        _check(rc, out, err, "C_VerifySignatureInit")

    def test_operation_not_initialized(self, p11_config: Any) -> None:
        """C_VerifySignature without Init -> CKR_OPERATION_NOT_INITIALIZED."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
data = (ctypes.c_ubyte * 16)(*([0]*16))
rv = raw.C_VerifySignature(sh, data, 16)
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_NOT_SUPPORTED), f"Got 0x{rv:08x}"
print("OK")
""",
        )
        _check(rc, out, err, "C_VerifySignature")


class TestEncapsulateKeyErrors:
    """v3.2 C_EncapsulateKey via raw calls."""

    def test_encapsulate_wrong_mechanism(self, p11_config: Any) -> None:
        """C_EncapsulateKey with AES mechanism -> error."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081  # AES_ECB - not a KEM mechanism
key = ctypes.c_ulong(0)
ct = (ctypes.c_ubyte * 2048)()
ct_len = ctypes.c_ulong(2048)
rv = raw.C_EncapsulateKey(sh, ctypes.byref(mech), 0, None, 0, ctypes.byref(key), ct, ctypes.byref(ct_len))
print(f"CKR:0x{rv:08x}")
assert rv != CKR_OK, f"Should have rejected AES_ECB for Encapsulate"
print("OK")
""",
        )
        _check(rc, out, err, "C_EncapsulateKey")


class TestDecapsulateKeyErrors:
    """v3.2 C_DecapsulateKey via raw calls."""

    def test_decapsulate_wrong_mechanism(self, p11_config: Any) -> None:
        """C_DecapsulateKey with AES mechanism -> error."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081  # AES_ECB
ct = (ctypes.c_ubyte * 1088)(*([0xFF]*1088))
key = ctypes.c_ulong(0)
rv = raw.C_DecapsulateKey(sh, ctypes.byref(mech), 0, None, 0, ct, 1088, ctypes.byref(key))
print(f"CKR:0x{rv:08x}")
assert rv != CKR_OK, f"Should have rejected AES_ECB for Decapsulate"
print("OK")
""",
        )
        _check(rc, out, err, "C_DecapsulateKey")


class TestAsyncErrors:
    """v3.2 async function error conditions."""

    def test_async_get_id_no_operation(self, p11_config: Any) -> None:
        """C_AsyncGetID with no pending async operation."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
id_buf = (ctypes.c_ubyte * 256)()
id_len = ctypes.c_ulong(256)
rv = raw.C_AsyncGetID(sh, id_buf, ctypes.byref(id_len))
print(f"CKR:0x{rv:08x}")
# OPERATION_NOT_INITIALIZED or FUNCTION_NOT_SUPPORTED - both acceptable
assert rv != CKR_OK, f"Should have failed with no async operation"
print("OK")
""",
        )
        _check(rc, out, err, "C_AsyncGetID")


class TestWrapKeyAuthenticatedErrors:
    """v3.2 C_WrapKeyAuthenticated error conditions."""

    def test_wrap_auth_wrong_mechanism(self, p11_config: Any) -> None:
        """C_WrapKeyAuthenticated with SHA mechanism -> error."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x0250  # SHA256 - not a wrap mechanism
out = (ctypes.c_ubyte * 256)()
out_len = ctypes.c_ulong(256)
rv = raw.C_WrapKeyAuthenticated(sh, ctypes.byref(mech), 0, 0, 0, out, ctypes.byref(out_len))
print(f"CKR:0x{rv:08x}")
assert rv != CKR_OK, f"Should have rejected SHA256 for WrapAuth"
print("OK")
""",
        )
        _check(rc, out, err, "C_WrapKeyAuthenticated")
