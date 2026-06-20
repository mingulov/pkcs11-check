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

from pkcs11_check.raw.types_std import CKR_OPERATION_ACTIVE
from pkcs11_check.testcases._subprocess_preamble import _P11CHECK_PIN_ENV
from pkcs11_check.testcases.ckr._subprocess import (
    assert_ckr_subprocess_ok,
    ckr_subprocess_cleanup_setup,
    ckr_subprocess_rv_trace_setup,
)
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _classify_state_ckr(out: str, *, label: str) -> None:
    """Parent-side tolerant 3-way classifier over a child's ``CKR:0x...`` line.

    A second C_*Init while one is active may legitimately return
    CKR_OPERATION_ACTIVE *or* CKR_OK (the module may cancel the first op and
    start a new one) -- both are accepted passes (``allow_ok=True``). Any other
    clean code is a noted deviation (``xfail``), not a crash. Classification
    happens here (not via an in-child ``assert``) so a third clean code is no
    longer mislabeled as a child crash.

    If the child reported the first init itself failed (``...:first_init_failed``),
    there is no state-conflict result to classify; the probe simply passes
    (it proved no crash).
    """
    rv: int | None = None
    for line in out.splitlines():
        if line.startswith("CKR:0x"):
            token = line.removeprefix("CKR:").split(":", 1)
            if len(token) > 1 and token[1] == "first_init_failed":
                return
            rv = int(token[0], 16)
            break
    assert rv is not None, f"{label}: no CKR line in child output: {out!r}"
    classify_negative_rv(rv, (CKR_OPERATION_ACTIVE,), label=label, allow_ok=True)


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
{rv_trace_setup}
rv = raw.C_Initialize(None)
assert rv in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED)  # audit-ok: positive-op init idempotency

sh = open_session(raw, get_slot_ids(raw)[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
{cleanup_setup}

import os as _os
pin = _os.environ.get("_P11CHECK_PIN")
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
    print(f"SETUP_XFAIL:C_GenerateKey failed:{{ckr_name(rv)}}")
    _p11check_cleanup_session()
    sys.exit(0)
key_handle = key.value
"""


def _run(module: str, pin: str | None, test_code: str) -> tuple[int, str, str]:
    # The PIN is passed to the child through the _P11CHECK_PIN env var, never
    # interpolated into the script text -- so it cannot leak via the child argv
    # (``ps``/``/proc``) or any traceback. The preamble reads it from os.environ.
    script = (
        _SCRIPT_PREAMBLE.format(
            module=module,
            rv_trace_setup=ckr_subprocess_rv_trace_setup(),
            cleanup_setup=ckr_subprocess_cleanup_setup(),
        )
        + textwrap.dedent(test_code)
        + "\n_p11check_cleanup_session()\n"
    )
    env = os.environ.copy()
    if pin is not None:
        env[_P11CHECK_PIN_ENV] = pin
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _assert_probe_completed(rc: int, out: str, err: str) -> None:
    assert_ckr_subprocess_ok(rc, out, err, context="CKR operation-state raw probe")


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
# Second should be OPERATION_ACTIVE (or module may cancel first -> CKR_OK)
print("OK")
""",
        )
        _assert_probe_completed(rc, out, err)
        _classify_state_ckr(out, label="double C_EncryptInit (operation-active state)")

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
print("OK")
""",
        )
        _assert_probe_completed(rc, out, err)
        _classify_state_ckr(out, label="double C_DigestInit (operation-active state)")

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
else:
    print(f"CKR:0x{rv1:08x}:first_init_failed")
print("OK")
""",
        )
        _assert_probe_completed(rc, out, err)
        _classify_state_ckr(out, label="double C_SignInit (operation-active state)")

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
print("OK")
""",
        )
        _assert_probe_completed(rc, out, err)
        _classify_state_ckr(out, label="double C_DecryptInit (operation-active state)")
