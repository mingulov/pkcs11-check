"""CKR buffer sizing tests via raw ctypes calls.

Tests CKR_BUFFER_TOO_SMALL: output functions with undersized buffers.
Uses pkcs11.raw.RawPKCS11 — wrapper handles buffer sizing internally.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from typing import Any

import pytest

pytestmark = [pytest.mark.access, pytest.mark.subprocess]


def _run_raw(module: str, pin: str | None, code: str) -> tuple[int, str, str]:
    pin_arg = f'"{pin}"' if pin else "None"
    script = textwrap.dedent(f"""\
        import ctypes
        from pkcs11.raw import (
            RawPKCS11, CKR_OK, CKR_BUFFER_TOO_SMALL,
            CK_MECHANISM, CKF_SERIAL_SESSION, CKF_RW_SESSION,
        )
        raw = RawPKCS11.from_lib("{module}")
        raw.C_Initialize(None)
        sc = ctypes.c_ulong(0)
        raw.C_GetSlotList(1, None, ctypes.byref(sc))
        sl = (ctypes.c_ulong * sc.value)()
        raw.C_GetSlotList(1, sl, ctypes.byref(sc))
        sess = ctypes.c_ulong(0)
        raw.C_OpenSession(sl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          None, None, ctypes.byref(sess))
        sh = sess.value
        pin = {pin_arg}
        if pin:
            pb = pin.encode()
            raw.C_Login(sh, 1, (ctypes.c_ubyte * len(pb))(*pb), len(pb))
    """) + textwrap.dedent(code) + "\nraw.C_CloseSession(sh)\nraw.C_Finalize(None)\n"
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=15,
        env=os.environ.copy(),
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class TestBufferTooSmall:
    """Output operations with undersized buffers."""

    def test_digest_buffer_too_small(self, p11_config: Any) -> None:
        """C_Digest with 1-byte output → CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_raw(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
mech = CK_MECHANISM()
mech.mechanism = 0x0250  # CKM_SHA256
rv = raw.C_DigestInit(sh, ctypes.byref(mech))
assert rv == CKR_OK, f"DigestInit: 0x{rv:08x}"

data = (ctypes.c_ubyte * 16)(*([0x42]*16))
out = (ctypes.c_ubyte * 1)()  # Too small for SHA-256 (32 bytes)
out_len = ctypes.c_ulong(1)
rv = raw.C_Digest(sh, data, 16, out, ctypes.byref(out_len))
print(f"CKR:0x{rv:08x}")
# CKR_BUFFER_TOO_SMALL expected; out_len should now contain required size
assert rv == CKR_BUFFER_TOO_SMALL, f"Expected BUFFER_TOO_SMALL, got 0x{rv:08x}"
assert out_len.value >= 32, f"Required size should be >= 32, got {out_len.value}"
print("OK")
""",
        )
        assert rc == 0, f"Crash: {err[-300:]}"
        assert "OK" in out

    def test_encrypt_buffer_too_small(self, p11_config: Any) -> None:
        """C_Encrypt AES-ECB with 1-byte output → CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_raw(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
import struct
# Generate AES key
class CK_ATTR(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("pValue", ctypes.c_void_p), ("ulValueLen", ctypes.c_ulong)]

def mk(t, v):
    b = (ctypes.c_ubyte * len(v))(*v)
    a = CK_ATTR(); a.type = t; a.pValue = ctypes.cast(b, ctypes.c_void_p); a.ulValueLen = len(v)
    return a, b

a1, b1 = mk(0x161, struct.pack("=Q", 32))  # CKA_VALUE_LEN=32
a2, b2 = mk(0x104, b"\\x01")  # CKA_ENCRYPT=True
a3, b3 = mk(0x01, b"\\x00")   # CKA_TOKEN=False
tmpl = (CK_ATTR * 3)(a1, a2, a3)

mech_kg = CK_MECHANISM(); mech_kg.mechanism = 0x1080  # AES_KEY_GEN
key = ctypes.c_ulong(0)
rv = raw.C_GenerateKey(sh, ctypes.byref(mech_kg), tmpl, 3, ctypes.byref(key))
assert rv == CKR_OK, f"GenKey: 0x{rv:08x}"

# EncryptInit
mech = CK_MECHANISM(); mech.mechanism = 0x1081  # AES_ECB
rv = raw.C_EncryptInit(sh, ctypes.byref(mech), key.value)
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
        """C_Sign with 1-byte output → CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_raw(
            str(p11_config.module),
            p11_config.pin.get_secret_value() if p11_config.pin else None,
            """\
import struct
class CK_ATTR(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("pValue", ctypes.c_void_p), ("ulValueLen", ctypes.c_ulong)]
def mk(t, v):
    b = (ctypes.c_ubyte * len(v))(*v)
    a = CK_ATTR(); a.type = t; a.pValue = ctypes.cast(b, ctypes.c_void_p); a.ulValueLen = len(v)
    return a, b

# Generate RSA keypair for sign
from pkcs11.raw import CKR_MECHANISM_INVALID
mech_rsa = CK_MECHANISM(); mech_rsa.mechanism = 0x0000  # CKM_RSA_PKCS_KEY_PAIR_GEN
a1, b1 = mk(0x0121, struct.pack("=Q", 2048))  # CKA_MODULUS_BITS=2048
a2, b2 = mk(0x01, b"\\x00")  # CKA_TOKEN=False
pub_tmpl = (CK_ATTR * 2)(a1, a2)
a3, b3 = mk(0x108, b"\\x01")  # CKA_SIGN=True
a4, b4 = mk(0x01, b"\\x00")
priv_tmpl = (CK_ATTR * 2)(a3, a4)
pub = ctypes.c_ulong(0)
priv = ctypes.c_ulong(0)
rv = raw.C_GenerateKeyPair(sh, ctypes.byref(mech_rsa), pub_tmpl, 2, priv_tmpl, 2, ctypes.byref(pub), ctypes.byref(priv))
if rv != CKR_OK:
    print(f"CKR:0x{rv:08x}:keygen_failed")
    print("OK")  # Skip if keygen fails
else:
    # SignInit with SHA256_RSA_PKCS
    sign_mech = CK_MECHANISM(); sign_mech.mechanism = 0x0040  # CKM_SHA256_RSA_PKCS
    rv = raw.C_SignInit(sh, ctypes.byref(sign_mech), priv.value)
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
