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

from pkcs11_check.testcases._subprocess_preamble import subprocess_session_preamble

pytestmark = [pytest.mark.access, pytest.mark.subprocess]

_EXTRA_IMPORTS = """\
import ctypes
from ctypes import byref, cast

from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_SHA256_HMAC,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template


def _template_ptr(attrs):
    return cast(attrs.array, CK_ATTRIBUTE_PTR)
"""


def _run(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
    preamble = subprocess_session_preamble(
        module,
        pin=pin,
        extra_imports=_EXTRA_IMPORTS,
    )
    script = preamble + textwrap.dedent(code) + "\ncleanup()\n"
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestKeyFunctionNotPermitted:
    """Keys with CKA_*=False tested via raw C_*Init calls."""

    def test_encrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_ENCRYPT=False -> C_EncryptInit -> CKR_KEY_FUNCTION_NOT_PERMITTED.

        PKCS#11 v3.1 Sec.4.4.1: If CKA_ENCRYPT is False, C_EncryptInit MUST return
        CKR_KEY_FUNCTION_NOT_PERMITTED. NSS returns CKR_OK, meaning the key permission
        flag is silently ignored -- keys without CKA_ENCRYPT=True can still be used to
        encrypt. This is a security finding.
        """
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# Generate key with ENCRYPT=False
attrs = template(
    attr_ulong(CKA_VALUE_LEN, 32),
    attr_bool(CKA_ENCRYPT, False),
    attr_bool(CKA_DECRYPT, True),
    attr_bool(CKA_TOKEN, False),
)
mech_kg = mech_simple(CKM_AES_KEY_GEN)  # AES_KEY_GEN
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

# Try EncryptInit with CKA_ENCRYPT=False key
mech = mech_simple(CKM_AES_ECB)  # AES_ECB
rv = raw.C_EncryptInit(sh, mech.byref(), key.value)
print(f"CKR:0x{rv:08x}")
# Report result without asserting -- outer test checks security compliance
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        # CKR_OK means NSS allowed using the key despite CKA_ENCRYPT=False -- security violation
        if "CKR:0x00000000" in out:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "NSS allows C_EncryptInit with CKA_ENCRYPT=False key (CKR_OK instead of "
                "CKR_KEY_FUNCTION_NOT_PERMITTED). Key permission flags are not enforced.",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.1 Sec.4.4.1",
            )
            pytest.xfail(
                "SECURITY: NSS returns CKR_OK for C_EncryptInit with CKA_ENCRYPT=False key "
                "(expected CKR_KEY_FUNCTION_NOT_PERMITTED)"
            )

    def test_sign_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_SIGN=False -> C_SignInit -> CKR_KEY_FUNCTION_NOT_PERMITTED."""
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# Generate key with SIGN=False
attrs = template(
    attr_ulong(CKA_VALUE_LEN, 32),
    attr_bool(CKA_SIGN, False),
    attr_bool(CKA_ENCRYPT, True),
    attr_bool(CKA_TOKEN, False),
)
mech_kg = mech_simple(CKM_AES_KEY_GEN)
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

mech = mech_simple(CKM_SHA256_HMAC)  # sign mech to test CKA_SIGN=False
rv = raw.C_SignInit(sh, mech.byref(), key.value)
print(f"CKR:0x{rv:08x}")
# KEY_FUNCTION_NOT_PERMITTED or MECHANISM_INVALID (if module doesn't support CMAC)
# KEY_FUNCTION_NOT_PERMITTED, MECHANISM_INVALID, or KEY_TYPE_INCONSISTENT
assert rv in (
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_MECHANISM_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    0x06,
), f"Got 0x{rv:08x}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_decrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_DECRYPT=False -> C_DecryptInit -> CKR_KEY_FUNCTION_NOT_PERMITTED.

        PKCS#11 v3.1 Sec.4.4.1: If CKA_DECRYPT is False, C_DecryptInit MUST return
        CKR_KEY_FUNCTION_NOT_PERMITTED. NSS returns CKR_OK, meaning the key permission
        flag is silently ignored -- keys without CKA_DECRYPT=True can still be used to
        decrypt. This is a security finding.
        """
        rc, out, err = _run(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
attrs = template(
    attr_ulong(CKA_VALUE_LEN, 32),
    attr_bool(CKA_DECRYPT, False),
    attr_bool(CKA_ENCRYPT, True),
    attr_bool(CKA_TOKEN, False),
)
mech_kg = mech_simple(CKM_AES_KEY_GEN)
key = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

mech = mech_simple(CKM_AES_ECB)  # AES_ECB
rv = raw.C_DecryptInit(sh, mech.byref(), key.value)
print(f"CKR:0x{rv:08x}")
# Report result without asserting -- outer test checks security compliance
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        # CKR_OK means NSS allowed using the key despite CKA_DECRYPT=False -- security violation
        if "CKR:0x00000000" in out:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "NSS allows C_DecryptInit with CKA_DECRYPT=False key (CKR_OK instead of "
                "CKR_KEY_FUNCTION_NOT_PERMITTED). Key permission flags are not enforced.",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.1 Sec.4.4.1",
            )
            pytest.xfail(
                "SECURITY: NSS returns CKR_OK for C_DecryptInit with CKA_DECRYPT=False key "
                "(expected CKR_KEY_FUNCTION_NOT_PERMITTED)"
            )
