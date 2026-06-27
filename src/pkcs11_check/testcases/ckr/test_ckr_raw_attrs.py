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

from pkcs11_check.testcases._subprocess_preamble import (
    _P11CHECK_PIN_ENV,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok
from pkcs11_check.testcases.conftest import classify_policy_enforcement

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _classify_permission_flag(out: str, *, label: str) -> None:
    """policy claim/effect-check from subprocess output.

    The subprocess prints ``CLAIM:0`` (the key read the permission flag back as
    False -- the module claims the restriction) or ``CLAIM:1`` (the flag was not
    honored), and ``CKR:0x...`` for the C_*Init result:

    - claimed (``CLAIM:0``) AND the op returned CKR_OK -> fail (the restriction
      was claimed then ignored -- a self-contradiction),
    - not claimed (``CLAIM:1``) -> xfail (module did not honor the flag at
      create; honest non-support),
    - claimed AND the op was rejected -> pass.
    """
    claimed = "CLAIM:0" in out
    violated = "CKR:0x00000000" in out
    classify_policy_enforcement(claimed=claimed, violated=violated, label=label)


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
    CKR_FUNCTION_FAILED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.recipes import read_attributes


def _template_ptr(attrs):
    return cast(attrs.array, CK_ATTRIBUTE_PTR)


def _claim(sh, key_value, attr):
    # CLAIM:0 if the key reports the permission flag back as False (module
    # claims the restriction), CLAIM:1 otherwise (not honored / absent).
    vals = read_attributes(raw, sh, key_value, [attr])
    print("CLAIM:0" if vals.get(attr) is False else "CLAIM:1")
"""


def _run(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
    preamble = subprocess_session_preamble(
        module,
        pin=pin,
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


class TestKeyFunctionNotPermitted:
    """Keys with CKA_*=False tested via raw C_*Init calls."""

    def test_encrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_ENCRYPT=False -> C_EncryptInit -> CKR_KEY_FUNCTION_NOT_PERMITTED.

        PKCS#11 v3.2: If CKA_ENCRYPT is False, C_EncryptInit MUST return
        CKR_KEY_FUNCTION_NOT_PERMITTED. Some modules return CKR_OK, meaning the key
        permission flag is silently ignored -- keys without CKA_ENCRYPT=True can still
        be used to encrypt. This is a security finding.
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
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_GenerateKey for CKA_ENCRYPT=False failed: {ckr_name(rv)}")
else:
    _claim(sh, key.value, CKA_ENCRYPT)
    # Try EncryptInit with CKA_ENCRYPT=False key
    mech = mech_simple(CKM_AES_ECB)  # AES_ECB
    rv = raw.C_EncryptInit(sh, mech.byref(), key.value)
    print(f"CKR:0x{rv:08x}")
    # Report result without asserting -- outer test checks security compliance
    print("OK")
""",
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_EncryptInit with CKA_ENCRYPT=False")
        # policy: enforcing CKA_ENCRYPT=False is mandatory (PKCS#11 v3.2).
        # claimed = the key read CKA_ENCRYPT back as False; violated = EncryptInit
        # still returned CKR_OK.
        _classify_permission_flag(
            out,
            label="C_EncryptInit with a CKA_ENCRYPT=False key "
            "(PKCS#11 v3.2 requires CKR_KEY_FUNCTION_NOT_PERMITTED)",
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
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_GenerateKey for CKA_SIGN=False failed: {ckr_name(rv)}")
else:
    _claim(sh, key.value, CKA_SIGN)
    mech = mech_simple(CKM_SHA256_HMAC)  # sign mech to test CKA_SIGN=False
    rv = raw.C_SignInit(sh, mech.byref(), key.value)
    print(f"CKR:0x{rv:08x}")
    # Report result without asserting -- outer test checks security compliance
    print("OK")
""",
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_SignInit with CKA_SIGN=False")
        # policy: enforcing CKA_SIGN=False is mandatory (PKCS#11 v3.2).
        _classify_permission_flag(
            out,
            label="C_SignInit with a CKA_SIGN=False key "
            "(PKCS#11 v3.2 requires CKR_KEY_FUNCTION_NOT_PERMITTED)",
        )

    def test_decrypt_not_permitted(self, p11_config: Any) -> None:
        """Key with CKA_DECRYPT=False -> C_DecryptInit -> CKR_KEY_FUNCTION_NOT_PERMITTED.

        PKCS#11 v3.2: If CKA_DECRYPT is False, C_DecryptInit MUST return
        CKR_KEY_FUNCTION_NOT_PERMITTED. Some modules return CKR_OK, meaning the key
        permission flag is silently ignored -- keys without CKA_DECRYPT=True can still
        be used to decrypt. This is a security finding.
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
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_GenerateKey for CKA_DECRYPT=False failed: {ckr_name(rv)}")
else:
    _claim(sh, key.value, CKA_DECRYPT)
    mech = mech_simple(CKM_AES_ECB)  # AES_ECB
    rv = raw.C_DecryptInit(sh, mech.byref(), key.value)
    print(f"CKR:0x{rv:08x}")
    # Report result without asserting -- outer test checks security compliance
    print("OK")
""",
        )
        assert_ckr_subprocess_ok(rc, out, err, context="C_DecryptInit with CKA_DECRYPT=False")
        # policy: enforcing CKA_DECRYPT=False is mandatory (PKCS#11 v3.2).
        _classify_permission_flag(
            out,
            label="C_DecryptInit with a CKA_DECRYPT=False key "
            "(PKCS#11 v3.2 requires CKR_KEY_FUNCTION_NOT_PERMITTED)",
        )
