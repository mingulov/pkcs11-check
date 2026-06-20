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

from pkcs11_check.testcases._subprocess_preamble import (
    _P11CHECK_PIN_ENV,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

pytestmark = [pytest.mark.access, pytest.mark.subprocess]

_EXTRA_IMPORTS = """\
import ctypes
from ctypes import byref, cast

from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKM_AES_KEY_GEN,
    CKR_ARGUMENTS_BAD,
    CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
)
# NULL mechanism pointer: acceptable CKR codes for operation-init functions
# with cancellation semantics per OASIS PKCS#11 v3.2.
# CKR_ARGUMENTS_BAD -- NULL pointer is bad argument
# CKR_MECHANISM_INVALID -- NULL interpreted as invalid mechanism (NSS)
# CKR_MECHANISM_PARAM_INVALID -- NULL mechanism params interpreted as invalid
# CKR_OK -- v3.0+ spec allows NULL mech to cancel an in-progress operation
_NULL_MECH_OK = (
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)
from pkcs11_check.raw.faults import null_pointer
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template


def _template_ptr(attrs):
    return cast(attrs.array, CK_ATTRIBUTE_PTR)
"""


def _run(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
    preamble = subprocess_session_preamble(
        module,
        pin=pin,
        slot_label="pkcs11-check",
        extra_imports=_EXTRA_IMPORTS,
    )
    script = preamble + textwrap.dedent(code) + "\ncleanup()\n"
    # Pass the PIN via the child env (never embed it in the script source).
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


def _assert_ok(rc: int, out: str, err: str, name: str) -> None:
    assert_ckr_subprocess_ok(rc, out, err, context=name)


class TestArgsBadNullPointers:
    """Pass NULL to functions that require valid pointers."""

    def test_encrypt_init_null_mechanism(self, p11_config: Any) -> None:
        """C_EncryptInit(session, NULL, key) -> CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
attrs = template(
    attr_ulong(CKA_VALUE_LEN, 32),
    attr_bool(CKA_ENCRYPT, True),
    attr_bool(CKA_TOKEN, False),
)
mech_kg = mech_simple(CKM_AES_KEY_GEN)
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_GenerateKey for AES encrypt setup failed: {ckr_name(rv)}")
else:
    # EncryptInit with NULL mechanism
    # PKCS#11 v3.2: NULL mech ptr => ARGUMENTS_BAD; NSS interprets as MECHANISM_INVALID
    rv = raw.C_EncryptInit(sh, null_pointer().pointer, key.value)
    print(f"CKR:0x{rv:08x}")
    assert rv in _NULL_MECH_OK, f"Got 0x{rv:08x}"
    print("OK")
""",
        )
        _assert_ok(rc, out, err, "C_EncryptInit(NULL mech)")

    def test_decrypt_init_null_mechanism(self, p11_config: Any) -> None:
        """C_DecryptInit(session, NULL, key) -> CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
attrs = template(
    attr_ulong(CKA_VALUE_LEN, 32),
    attr_bool(CKA_DECRYPT, True),
    attr_bool(CKA_TOKEN, False),
)
mech_kg = mech_simple(CKM_AES_KEY_GEN)
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_GenerateKey for AES decrypt setup failed: {ckr_name(rv)}")
else:
    # PKCS#11 v3.2: NULL mech ptr => ARGUMENTS_BAD; NSS interprets as MECHANISM_INVALID
    rv = raw.C_DecryptInit(sh, null_pointer().pointer, key.value)
    print(f"CKR:0x{rv:08x}")
    assert rv in _NULL_MECH_OK, f"Got 0x{rv:08x}"
    print("OK")
""",
        )
        _assert_ok(rc, out, err, "C_DecryptInit(NULL mech)")

    def test_sign_init_null_mechanism(self, p11_config: Any) -> None:
        """C_SignInit(session, NULL, key) -> CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# PKCS#11 v3.2: NULL mech ptr => ARGUMENTS_BAD; NSS interprets as MECHANISM_INVALID
rv = raw.C_SignInit(sh, null_pointer().pointer, 0)
print(f"CKR:0x{rv:08x}")
assert rv in _NULL_MECH_OK, f"Got 0x{rv:08x}"
print("OK")
""",
        )
        _assert_ok(rc, out, err, "C_SignInit(NULL mech)")

    def test_verify_init_null_mechanism(self, p11_config: Any) -> None:
        """C_VerifyInit(session, NULL, key) -> CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# PKCS#11 v3.2: NULL mech ptr => ARGUMENTS_BAD; NSS interprets as MECHANISM_INVALID
rv = raw.C_VerifyInit(sh, null_pointer().pointer, 0)
print(f"CKR:0x{rv:08x}")
assert rv in _NULL_MECH_OK, f"Got 0x{rv:08x}"
print("OK")
""",
        )
        _assert_ok(rc, out, err, "C_VerifyInit(NULL mech)")

    def test_digest_init_null_mechanism(self, p11_config: Any) -> None:
        """C_DigestInit(session, NULL) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
rv = raw.C_DigestInit(sh, null_pointer().pointer)
print(f"CKR:0x{rv:08x}")
assert rv in (CKR_ARGUMENTS_BAD, CKR_OK), f"Got 0x{rv:08x}"  # audit-ok: cancel, CKR_OK per v3+
print("OK")
""",
        )
        _assert_ok(rc, out, err, "C_DigestInit(NULL mech)")

    def test_generate_key_null_mechanism(self, p11_config: Any) -> None:
        """C_GenerateKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
key = ctypes.c_ulong(0)
rv = raw.C_GenerateKey(sh, null_pointer().pointer, None, 0, ctypes.byref(key))
print(f"CKR:0x{rv:08x}")
assert rv == CKR_ARGUMENTS_BAD, f"Got 0x{rv:08x}"
print("OK")
""",
        )
        _assert_ok(rc, out, err, "C_GenerateKey(NULL mech)")

    def test_wrap_key_null_mechanism(self, p11_config: Any) -> None:
        """C_WrapKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
out_len = ctypes.c_ulong(256)
rv = raw.C_WrapKey(sh, null_pointer().pointer, 0, 0, None, ctypes.byref(out_len))
print(f"CKR:0x{rv:08x}")
# Providers may validate the NULL mechanism first, or the deliberately invalid
# zero object handles first.
assert rv in (
    CKR_ARGUMENTS_BAD,
    CKR_KEY_HANDLE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_MECHANISM_INVALID,
), \
    f"Got 0x{rv:08x}"
print("OK")
""",
        )
        _assert_ok(rc, out, err, "C_WrapKey(NULL mech)")

    def test_derive_key_null_mechanism(self, p11_config: Any) -> None:
        """C_DeriveKey(session, NULL, ...) -> CKR_ARGUMENTS_BAD or CKR_MECHANISM_INVALID."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# PKCS#11 v3.2: NULL mech ptr => ARGUMENTS_BAD; NSS interprets as MECHANISM_INVALID
key = ctypes.c_ulong(0)
rv = raw.C_DeriveKey(sh, null_pointer().pointer, 0, None, 0, ctypes.byref(key))
print(f"CKR:0x{rv:08x}")
assert rv in (
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_KEY_HANDLE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
), \
    f"Got 0x{rv:08x}"
print("OK")
""",
        )
        _assert_ok(rc, out, err, "C_DeriveKey(NULL mech)")
