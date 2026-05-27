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
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import get_slot_ids, open_session, login_user
from pkcs11_check.raw.types_std import (
    CKR_OK, CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED,
    CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_TYPE_INCONSISTENT,
    CKR_FUNCTION_NOT_SUPPORTED, CKR_ARGUMENTS_BAD, CKR_KEY_HANDLE_INVALID,
    CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
    CK_MECHANISM, CKF_SERIAL_SESSION, CKF_RW_SESSION, CKU_USER,
)

raw = RawPKCS11.from_lib("{module}")
raw.C_Initialize(None)

# Check if v3.2 functions are available
if raw.interface_version != "3.2":
    print("SKIP:no_v32")
    raw.C_Finalize(None)
    sys.exit(0)

if "C_VerifySignatureInit" not in raw._funcs:
    print("SKIP:no_v32_funcs")
    raw.C_Finalize(None)
    sys.exit(0)

# Open session
slots = get_slot_ids(raw, token_present=True)
sh = open_session(raw, slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
pin = {pin_arg}
if pin:
    login_user(raw, sh, CKU_USER, pin.encode())

{test_code}

raw.C_CloseSession(sh)
raw.C_Finalize(None)
"""


def _run(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
    pin_arg = f'"{pin}"' if pin else "None"
    script = _SCRIPT_TEMPLATE.format(
        module=module, pin_arg=pin_arg, test_code=textwrap.dedent(code)
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _check(rc: int, out: str, err: str, func: str) -> None:
    if "SKIP:" in out:
        pytest.skip(out.split("SKIP:")[1])
    if rc < 0:
        pytest.fail(f"{func}: subprocess crashed with signal {-rc}; stderr: {err[-300:]}")
    if rc != 0:
        pytest.fail(
            f"{func}: subprocess failed with exit code {rc}; "
            f"stdout: {out[-300:]}; stderr: {err[-300:]}"
        )
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
enc_key = ctypes.c_ulong(0)
rv = raw.C_EncapsulateKey(
    sh, ctypes.byref(mech), 0, None, 0, ct, ctypes.byref(ct_len), ctypes.byref(enc_key)
)
print(f"CKR:0x{rv:08x}")
assert rv != CKR_OK, f"Should have rejected AES_ECB for Encapsulate"
print("OK")
""",
        )
        _check(rc, out, err, "C_EncapsulateKey")

    def test_encapsulate_null_pointers(self, p11_config: Any) -> None:
        """C_EncapsulateKey with NULL pointers must return CKR_ARGUMENTS_BAD without crashing."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081
ct = (ctypes.c_ubyte * 2048)()
ct_len = ctypes.c_ulong(2048)
enc_key = ctypes.c_ulong(0)

# Pass NULL for pMechanism
rv = raw.C_EncapsulateKey(sh, None, 0, None, 0, ct, ctypes.byref(ct_len), ctypes.byref(enc_key))
print(f"NULL pMechanism -> CKR:0x{rv:08x}")
assert rv == CKR_ARGUMENTS_BAD, "NULL pMechanism should yield CKR_ARGUMENTS_BAD"

# Pass NULL for pulCiphertextLen
rv = raw.C_EncapsulateKey(sh, ctypes.byref(mech), 0, None, 0, ct, None, ctypes.byref(enc_key))
print(f"NULL pulCiphertextLen -> CKR:0x{rv:08x}")
assert rv == CKR_ARGUMENTS_BAD, "NULL pulCiphertextLen should yield CKR_ARGUMENTS_BAD"

print("OK")
""",
        )
        _check(rc, out, err, "C_EncapsulateKey_NULLs")


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

    def test_decapsulate_null_pointers(self, p11_config: Any) -> None:
        """C_DecapsulateKey with NULL pointers must return CKR_ARGUMENTS_BAD without crashing."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x1081
ct = (ctypes.c_ubyte * 1088)(*([0xFF]*1088))
key = ctypes.c_ulong(0)

# Pass NULL for pMechanism
rv = raw.C_DecapsulateKey(sh, None, 0, None, 0, ct, 1088, ctypes.byref(key))
print(f"NULL pMechanism -> CKR:0x{rv:08x}")
assert rv == CKR_ARGUMENTS_BAD, "NULL pMechanism should yield CKR_ARGUMENTS_BAD"

# Pass NULL for phKey
rv = raw.C_DecapsulateKey(sh, ctypes.byref(mech), 0, None, 0, ct, 1088, None)
print(f"NULL phKey -> CKR:0x{rv:08x}")
assert rv in (
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_KEY_HANDLE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
), f"NULL phKey rejected with unexpected CKR 0x{rv:08x}"

# Note: OASIS may allow pCiphertext=None if ulCiphertextLen=0, but otherwise ARGUMENTS_BAD
rv = raw.C_DecapsulateKey(sh, ctypes.byref(mech), 0, None, 0, None, 1088, ctypes.byref(key))
print(f"NULL pCiphertext with length>0 -> CKR:0x{rv:08x}")
assert rv == CKR_ARGUMENTS_BAD, "NULL pCiphertext should yield CKR_ARGUMENTS_BAD"

print("OK")
""",
        )
        _check(rc, out, err, "C_DecapsulateKey_NULLs")


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
ct = (ctypes.c_ubyte * 256)()
ct_len = ctypes.c_ulong(256)
out = (ctypes.c_ubyte * 256)()
out_len = ctypes.c_ulong(256)
rv = raw.C_WrapKeyAuthenticated(
    sh, ctypes.byref(mech), 0, 0, ct, ct_len, out, ctypes.byref(out_len)
)
print(f"CKR:0x{rv:08x}")
assert rv != CKR_OK, f"Should have rejected SHA256 for WrapAuth"
print("OK")
""",
        )
        _check(rc, out, err, "C_WrapKeyAuthenticated")
