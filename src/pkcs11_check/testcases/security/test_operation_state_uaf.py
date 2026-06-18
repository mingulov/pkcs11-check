"""Operation-state use-after-free: ``C_DestroyObject`` mid-operation.

After ``C_DestroyObject`` on a key with an active operation, the operation's
stored key reference may point to freed memory if the module holds a raw pointer
rather than copying key material at ``*Init`` time.  The next completion call
then dereferences freed memory → heap-use-after-free.

Conformant behaviour: either the destroy is refused while the operation is
active, OR the completion call returns a clean error, OR (for snapshot-based
implementations) the operation completes with ``CKR_OK`` because key material
was copied at ``*Init`` time.  The **one** hard requirement is no crash.

Three probes (single-threaded, no race required):

- Sign   — ``CKM_SHA256_HMAC`` key destroyed between ``C_SignInit`` and
  ``C_Sign``.
- Encrypt — AES key destroyed between ``C_EncryptInit`` and ``C_Encrypt``.
- Digest  — ``C_DigestInit(CKM_SHA256)`` then ``C_DigestKey`` on the already-
  destroyed key handle.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# CKRs accepted as a "clean" completion after the key handle was destroyed.
# allow_ok=True is also passed so snapshot-based modules (which copied key
# material at *Init time) can return CKR_OK without being flagged.
_COMPLETION_REJECT_RVS = (
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_KEY_HANDLE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
)


def _parse_rv(output: str, prefix: str) -> int | None:
    """Return the integer rv printed as ``<prefix>0x…`` or ``None`` if absent."""
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    return None


def _preamble(p11_config: Any) -> str:
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=pin_from_config(p11_config),
    )


# ---------------------------------------------------------------------------
# Sign probe (CKM_SHA256_HMAC)
# ---------------------------------------------------------------------------

_SIGN_UAF_IMPORTS = """
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_OK,
)
"""

_SIGN_UAF_BODY = """
# --- create a 32-byte generic-secret key with CKA_SIGN ---
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
token_false = ctypes.c_ubyte(0)
sign_true = ctypes.c_ubyte(1)

tmpl = (CK_ATTRIBUTE * 5)()
tmpl[0].type = CKA_CLASS
tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
tmpl[1].type = CKA_KEY_TYPE
tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
tmpl[2].type = CKA_TOKEN
tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
tmpl[2].ulValueLen = 1
tmpl[3].type = CKA_VALUE
tmpl[3].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
tmpl[3].ulValueLen = 32
tmpl[4].type = CKA_SIGN
tmpl[4].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
tmpl[4].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:HMAC key import rejected: {ckr_name(rv)}")
    cleanup()
    raise SystemExit(0)

# --- C_SignInit ---
mech = CK_MECHANISM()
mech.mechanism = CKM_SHA256_HMAC
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_SignInit(sh, ctypes.byref(mech), key.value)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_SignInit(CKM_SHA256_HMAC) failed: {ckr_name(rv)}")
    raw.C_DestroyObject(sh, key.value)
    cleanup()
    raise SystemExit(0)

# --- C_DestroyObject while sign operation is active ---
destroy_rv = raw.C_DestroyObject(sh, key.value)
print(f"DESTROY_RV:0x{destroy_rv:08x}")

# --- C_Sign on possibly-freed state ---
data = (ctypes.c_ubyte * 16)(*range(16))
sig_len = CK_ULONG(0)
sign_rv = raw.C_Sign(sh, data, 16, None, ctypes.byref(sig_len))
print(f"SIGN_RV:0x{sign_rv:08x}")
if sign_rv == CKR_OK:
    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    sign_rv2 = raw.C_Sign(sh, data, 16, sig_buf, ctypes.byref(sig_len))
    print(f"SIGN_RV2:0x{sign_rv2:08x}")

cleanup()
"""


class TestSignOperationStateUAF:
    """``C_Sign`` after ``C_DestroyObject`` on the active key must not crash."""

    def test_sign_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the HMAC key mid-sign must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, the operation's stored key
        reference may point to freed memory.  A conformant module either refuses
        the destroy while the operation is active, invalidates the operation so
        ``C_Sign`` returns a clean error, or (snapshot-based) completes normally.
        A crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")

        body = _SIGN_UAF_IMPORTS + _SIGN_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Sign after C_DestroyObject (operation-state UAF)",
        )
        sign_rv = _parse_rv(out, "SIGN_RV:")
        if sign_rv is not None:
            classify_negative_rv(
                sign_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Sign after destroy of active HMAC key",
                allow_ok=True,
            )
        sign_rv2 = _parse_rv(out, "SIGN_RV2:")
        if sign_rv2 is not None:
            classify_negative_rv(
                sign_rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(2nd pass) after destroy of active HMAC key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Encrypt probe (CKM_AES_ECB)
# ---------------------------------------------------------------------------

_ENCRYPT_UAF_IMPORTS = """
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.recipes import gen_aes_key
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKA_ENCRYPT,
    CKA_DECRYPT,
    CKA_TOKEN,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import AES_KEYGEN_RUNTIME_REJECT_RVS
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
"""

_ENCRYPT_UAF_BODY = """
# --- generate a session AES-128 key ---
try:
    aes_key = gen_aes_key(
        raw,
        sh,
        128,
        attrs={
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_TOKEN: False,
        },
    )
except AssertionError as exc:
    if child_setup_reject_known(
        exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"
    ):
        cleanup()
        raise SystemExit(0)
    raise

# --- C_EncryptInit ---
mech = CK_MECHANISM()
mech.mechanism = CKM_AES_ECB
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_EncryptInit(sh, ctypes.byref(mech), aes_key)
if rv != CKR_OK:
    from pkcs11_check.raw.rv import ckr_name as _cn
    print(f"SETUP_XFAIL:C_EncryptInit(CKM_AES_ECB) failed: {_cn(rv)}")
    raw.C_DestroyObject(sh, aes_key)
    cleanup()
    raise SystemExit(0)

# --- C_DestroyObject while encrypt operation is active ---
destroy_rv = raw.C_DestroyObject(sh, aes_key)
print(f"DESTROY_RV:0x{destroy_rv:08x}")

# --- C_Encrypt on possibly-freed state ---
plaintext = (ctypes.c_ubyte * 16)(*range(16))
enc_len = CK_ULONG(0)
enc_rv = raw.C_Encrypt(sh, plaintext, 16, None, ctypes.byref(enc_len))
print(f"ENCRYPT_RV:0x{enc_rv:08x}")
if enc_rv == CKR_OK and enc_len.value > 0:
    enc_buf = (ctypes.c_ubyte * enc_len.value)()
    enc_rv2 = raw.C_Encrypt(sh, plaintext, 16, enc_buf, ctypes.byref(enc_len))
    print(f"ENCRYPT_RV2:0x{enc_rv2:08x}")

cleanup()
"""


class TestEncryptOperationStateUAF:
    """``C_Encrypt`` after ``C_DestroyObject`` on the active key must not crash."""

    def test_encrypt_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the AES key mid-encrypt must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, the operation's stored key
        reference may point to freed memory.  The same UAF pattern applies to
        ``C_EncryptInit`` as to ``C_SignInit``.  A crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        body = _ENCRYPT_UAF_IMPORTS + _ENCRYPT_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Encrypt after C_DestroyObject (operation-state UAF)",
        )
        enc_rv = _parse_rv(out, "ENCRYPT_RV:")
        if enc_rv is not None:
            classify_negative_rv(
                enc_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Encrypt after destroy of active AES key",
                allow_ok=True,
            )
        enc_rv2 = _parse_rv(out, "ENCRYPT_RV2:")
        if enc_rv2 is not None:
            classify_negative_rv(
                enc_rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Encrypt(2nd pass) after destroy of active AES key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Digest probe (CKM_SHA256 + C_DigestKey on destroyed handle)
# ---------------------------------------------------------------------------

_DIGEST_UAF_IMPORTS = """
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_GENERIC_SECRET,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKR_OK,
)
"""

_DIGEST_UAF_BODY = """
# --- create a 32-byte generic-secret key ---
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
token_false = ctypes.c_ubyte(0)

tmpl = (CK_ATTRIBUTE * 4)()
tmpl[0].type = CKA_CLASS
tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
tmpl[1].type = CKA_KEY_TYPE
tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
tmpl[2].type = CKA_TOKEN
tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
tmpl[2].ulValueLen = 1
tmpl[3].type = CKA_VALUE
tmpl[3].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
tmpl[3].ulValueLen = 32

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    4,
    ctypes.byref(key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:key import rejected: {ckr_name(rv)}")
    cleanup()
    raise SystemExit(0)

if "C_DigestKey" not in raw.available_function_names():
    print("SETUP_XFAIL:C_DigestKey is not exposed by this interface")
    raw.C_DestroyObject(sh, key.value)
    cleanup()
    raise SystemExit(0)

# --- C_DigestInit ---
mech = CK_MECHANISM()
mech.mechanism = CKM_SHA256
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DigestInit(sh, ctypes.byref(mech))
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_DigestInit(CKM_SHA256) failed: {ckr_name(rv)}")
    raw.C_DestroyObject(sh, key.value)
    cleanup()
    raise SystemExit(0)

# --- C_DestroyObject before C_DigestKey ---
destroy_rv = raw.C_DestroyObject(sh, key.value)
print(f"DESTROY_RV:0x{destroy_rv:08x}")

# --- C_DigestKey on possibly-freed handle ---
digest_key_rv = raw.C_DigestKey(sh, key.value)
print(f"DIGEST_KEY_RV:0x{digest_key_rv:08x}")

cleanup()
"""


class TestDigestOperationStateUAF:
    """``C_DigestKey`` on a destroyed handle must not cause a use-after-free crash."""

    def test_digest_key_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Using a destroyed key handle in ``C_DigestKey`` must not UAF.

        After ``C_DestroyObject`` on the key, ``C_DigestKey`` may dereference
        the operation's stored key reference, which now points to freed memory.
        A crash is the finding.  A conformant module either refuses the destroy
        while the digest is active, returns a clean error from ``C_DigestKey``,
        or (if it snapshotted the key value at import) succeeds.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256"):
            pytest.skip("CKM_SHA256 not supported")

        body = _DIGEST_UAF_IMPORTS + _DIGEST_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_DigestKey after C_DestroyObject (operation-state UAF)",
        )
        digest_key_rv = _parse_rv(out, "DIGEST_KEY_RV:")
        if digest_key_rv is not None:
            classify_negative_rv(
                digest_key_rv,
                _COMPLETION_REJECT_RVS,
                label="C_DigestKey on destroyed key handle",
                allow_ok=True,
            )
