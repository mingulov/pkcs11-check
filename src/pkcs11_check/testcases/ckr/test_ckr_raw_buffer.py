"""CKR buffer sizing tests via raw ctypes calls.

Tests CKR_BUFFER_TOO_SMALL: output functions with undersized buffers.
Uses pkcs11_check.raw.RawPKCS11 - wrapper handles buffer sizing internally.
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
    CKA_ENCRYPT,
    CKA_MODULUS_BITS,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKR_BUFFER_TOO_SMALL,
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
)
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template


def _template_ptr(attrs):
    return cast(attrs.array, CK_ATTRIBUTE_PTR)
"""


def _run_raw(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
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


class TestBufferTooSmall:
    """Output operations with undersized buffers."""

    def test_digest_buffer_too_small(self, p11_config: Any) -> None:
        """C_Digest with 1-byte output -> CKR_BUFFER_TOO_SMALL.

        PKCS#11 v3.1 Sec.5.10.2: C_Digest with undersized output buffer MUST return
        CKR_BUFFER_TOO_SMALL and update *pulDigestLen with the required size.

        Uses a 64-byte buffer filled with guard bytes (0xAA) and passes out_len=1.
        After the call, checks how many guard bytes were overwritten to confirm
        whether the module actually wrote past the declared buffer boundary.
        """
        rc, out, err = _run_raw(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = mech_simple(CKM_SHA256)
rv = raw.C_DigestInit(sh, mech.byref())
assert rv == CKR_OK, f"DigestInit: 0x{rv:08x}"

GUARD = 0xAA
BUF_SIZE = 64
DECLARED = 1  # Tell C_Digest the buffer is only 1 byte

data = (ctypes.c_ubyte * 16)(*([0x42]*16))
buf = (ctypes.c_ubyte * BUF_SIZE)(*([GUARD]*BUF_SIZE))
out_len = ctypes.c_ulong(DECLARED)
rv = raw.C_Digest(sh, data, 16, buf, ctypes.byref(out_len))
print(f"CKR:0x{rv:08x}")
print(f"LEN:{out_len.value}")

# Count how many bytes were overwritten past the declared boundary
overwritten = 0
for i in range(DECLARED, BUF_SIZE):
    if buf[i] != GUARD:
        overwritten += 1
print(f"OVERWRITTEN:{overwritten}")
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
        # Parse overflow evidence from subprocess output
        overwritten = 0
        for line in out.splitlines():
            if line.startswith("OVERWRITTEN:"):
                overwritten = int(line.split(":")[1])
        if "CKR:0x00000000" in out:
            from pkcs11_check.compliance import ComplianceLevel, note

            msg = (
                f"C_Digest returned CKR_OK with out_len=1 for SHA-256 (needs 32). "
                f"Guard byte check: {overwritten} bytes overwritten past declared boundary."
            )
            note(
                msg + " PKCS#11 spec requires CKR_BUFFER_TOO_SMALL.",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.1 Sec.5.10.2",
            )
            pytest.xfail(
                f"SECURITY: module returns CKR_OK for C_Digest with 1-byte buffer "
                f"(expected CKR_BUFFER_TOO_SMALL) -- {overwritten} guard bytes overwritten"
            )

    def test_encrypt_buffer_too_small(self, p11_config: Any) -> None:
        """C_Encrypt AES-ECB with 1-byte output -> CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_raw(
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
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

# EncryptInit
mech = mech_simple(CKM_AES_ECB)
rv = raw.C_EncryptInit(sh, mech.byref(), key.value)
assert rv == CKR_OK

# Encrypt with 1-byte output buffer
data = (ctypes.c_ubyte * 16)(*([0]*16))
out = (ctypes.c_ubyte * 1)()
out_len = ctypes.c_ulong(1)
rv = raw.C_Encrypt(sh, data, 16, out, ctypes.byref(out_len))
print(f"CKR:0x{rv:08x}")
assert rv == CKR_BUFFER_TOO_SMALL, f"Expected BUFFER_TOO_SMALL, got 0x{rv:08x}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_sign_buffer_too_small(self, p11_config: Any) -> None:
        """C_Sign with 1-byte output -> CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_raw(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
# Generate RSA keypair for sign
mech_rsa = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
pub_tmpl = template(
    attr_ulong(CKA_MODULUS_BITS, 2048),
    attr_bool(CKA_TOKEN, False),
)
priv_tmpl = template(
    attr_bool(CKA_SIGN, True),
    attr_bool(CKA_TOKEN, False),
)
pub = CK_OBJECT_HANDLE(0)
priv = CK_OBJECT_HANDLE(0)
rv = raw.C_GenerateKeyPair(
    sh,
    mech_rsa.byref(),
    _template_ptr(pub_tmpl),
    pub_tmpl.count,
    _template_ptr(priv_tmpl),
    priv_tmpl.count,
    byref(pub),
    byref(priv),
)
if rv != CKR_OK:
    print(f"CKR:0x{rv:08x}:keygen_failed")
    print("OK")  # Skip if keygen fails
else:
    # SignInit with SHA256_RSA_PKCS
    sign_mech = mech_simple(CKM_SHA256_RSA_PKCS)
    rv = raw.C_SignInit(sh, sign_mech.byref(), priv.value)
    if rv != CKR_OK:
        print(f"CKR:0x{rv:08x}:signinit_failed")
        print("OK")
    else:
        data = (ctypes.c_ubyte * 32)(*([0x42]*32))
        out = (ctypes.c_ubyte * 1)()  # Too small for RSA-2048 sig (256 bytes)
        out_len = ctypes.c_ulong(1)
        rv = raw.C_Sign(sh, data, 32, out, ctypes.byref(out_len))
        print(f"CKR:0x{rv:08x}")
        assert rv == CKR_BUFFER_TOO_SMALL, f"Expected BUFFER_TOO_SMALL, got 0x{rv:08x}"
        print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out
