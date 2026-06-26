"""Operation-state use-after-free: ``C_DestroyObject`` mid-operation.

After ``C_DestroyObject`` on a key with an active operation, the operation's
stored key reference may point to freed memory if the module holds a raw pointer
rather than copying key material at ``*Init`` time.  The next completion call
then dereferences freed memory → heap-use-after-free.

Conformant behaviour: either the destroy is refused while the operation is
active, OR the completion call returns a clean error, OR (for snapshot-based
implementations) the operation completes with ``CKR_OK`` because key material
was copied at ``*Init`` time.  The **one** hard requirement is no crash.

Six probes (single-threaded, no race required):

- Sign          — ``CKM_SHA256_HMAC`` key destroyed between ``C_SignInit`` and
  ``C_Sign``.
- Encrypt       — AES key destroyed between ``C_EncryptInit`` and ``C_Encrypt``.
- Digest        — ``C_DigestInit(CKM_SHA256)`` then ``C_DigestKey`` on the
  already-destroyed key handle.
- Verify        — ``CKM_SHA256_HMAC`` key destroyed between ``C_VerifyInit`` and
  ``C_Verify``.
- Decrypt       — AES key destroyed between ``C_DecryptInit`` and ``C_Decrypt``.
- Derive        — EC private key destroyed before ``C_DeriveKey``; the module
  must reject the stale handle cleanly, not dereference freed memory.
- Cross-session — token HMAC key sign-inited from session A, destroyed from
  session B, then ``C_Sign`` completed in session A; CWE-416 across session
  boundaries. (Token object cleaned up; test skips if token creation fails.)
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
# Encrypt/Decrypt probe (CKM_AES_CBC) — IV-carrying mechanism
# ---------------------------------------------------------------------------

_AES_CBC_IMPORTS = """
import ctypes
from pkcs11_check.raw.recipes import gen_aes_key
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CK_ULONG, CKM_AES_CBC, CKA_ENCRYPT, CKA_DECRYPT, CKA_TOKEN, CKR_OK,
)
from pkcs11_check.testcases.conftest import AES_KEYGEN_RUNTIME_REJECT_RVS
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
"""


def _aes_cbc_body(op: str) -> str:
    """Return a subprocess script body for the AES-CBC destroy-mid-operation probe.

    ``op`` is ``"Encrypt"`` or ``"Decrypt"``; both follow Init → DestroyObject →
    complete.  The IV is a 16-byte counter sequence; AES-CBC requires exactly one
    full block of input (16 bytes).
    """
    return f"""
try:
    aes_key = gen_aes_key(
        raw, sh, 128, attrs={{CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}},
    )
except AssertionError as exc:
    if child_setup_reject_known(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"):
        cleanup(); raise SystemExit(0)
    raise
iv = (ctypes.c_ubyte * 16)(*range(16))
mech = CK_MECHANISM()
mech.mechanism = CKM_AES_CBC
mech.pParameter = ctypes.cast(iv, ctypes.c_void_p)
mech.ulParameterLen = 16
rv = raw.C_{op}Init(sh, ctypes.byref(mech), aes_key)
if rv != CKR_OK:
    from pkcs11_check.raw.rv import ckr_name as _cn
    print(f"SETUP_XFAIL:C_{op}Init(CKM_AES_CBC) failed: {{_cn(rv)}}")
    raw.C_DestroyObject(sh, aes_key); cleanup(); raise SystemExit(0)
destroy_rv = raw.C_DestroyObject(sh, aes_key)
print(f"DESTROY_RV:0x{{destroy_rv:08x}}")
data = (ctypes.c_ubyte * 16)(*range(16))
out_len = CK_ULONG(0)
op_rv = raw.C_{op}(sh, data, 16, None, ctypes.byref(out_len))
print(f"{op.upper()}_RV:0x{{op_rv:08x}}")
cleanup()
"""


class TestEncryptCbcOperationStateUAF:
    """``C_Encrypt`` (CKM_AES_CBC) after ``C_DestroyObject`` on the active key must not crash."""

    def test_encrypt_cbc_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the AES key mid-CBC-encrypt must not cause a use-after-free crash.

        AES-CBC carries an IV in the mechanism parameter; the mechanism is otherwise
        structurally identical to AES-ECB for the UAF pattern.  After
        ``C_DestroyObject`` on the active key, the operation's stored key reference
        may point to freed memory.  A conformant module either refuses the destroy
        while the operation is active, returns a clean error from ``C_Encrypt``, or
        (snapshot-based) completes normally.  A crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + _AES_CBC_IMPORTS + _aes_cbc_body("Encrypt"),
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Encrypt(AES-CBC) after C_DestroyObject (operation-state UAF)",
        )
        rv = _parse_rv(out, "ENCRYPT_RV:")
        if rv is not None:
            classify_negative_rv(
                rv,
                _COMPLETION_REJECT_RVS,
                label="C_Encrypt(AES-CBC) after destroy of active key",
                allow_ok=True,
            )


class TestDecryptCbcOperationStateUAF:
    """``C_Decrypt`` (CKM_AES_CBC) after ``C_DestroyObject`` on the active key must not crash."""

    def test_decrypt_cbc_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the AES key mid-CBC-decrypt must not cause a use-after-free crash.

        AES-CBC carries an IV in the mechanism parameter; the mechanism is otherwise
        structurally identical to AES-ECB for the UAF pattern.  After
        ``C_DestroyObject`` on the active key, the operation's stored key reference
        may point to freed memory.  A conformant module either refuses the destroy
        while the operation is active, returns a clean error from ``C_Decrypt``, or
        (snapshot-based) completes normally.  A crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + _AES_CBC_IMPORTS + _aes_cbc_body("Decrypt"),
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Decrypt(AES-CBC) after C_DestroyObject (operation-state UAF)",
        )
        rv = _parse_rv(out, "DECRYPT_RV:")
        if rv is not None:
            classify_negative_rv(
                rv,
                _COMPLETION_REJECT_RVS,
                label="C_Decrypt(AES-CBC) after destroy of active key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Encrypt/Decrypt probe (CKM_AES_CTR) — counter-mode mechanism
# ---------------------------------------------------------------------------

_AES_CTR_IMPORTS = """
import ctypes
from pkcs11_check.raw.recipes import gen_aes_key
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CK_ULONG, CK_AES_CTR_PARAMS, CKM_AES_CTR,
    CKA_ENCRYPT, CKA_DECRYPT, CKA_TOKEN, CKR_OK,
)
from pkcs11_check.testcases.conftest import AES_KEYGEN_RUNTIME_REJECT_RVS
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
"""


def _aes_ctr_body(op: str) -> str:
    """Return a subprocess script body for the AES-CTR destroy-mid-operation probe.

    ``op`` is ``"Encrypt"`` or ``"Decrypt"``; both follow Init → DestroyObject →
    complete (two-pass: length query then buffer write).  The counter block is a
    16-byte counter sequence; ``ulCounterBits`` is 32.
    """
    return f"""
try:
    aes_key = gen_aes_key(
        raw, sh, 128, attrs={{CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}},
    )
except AssertionError as exc:
    if child_setup_reject_known(exc, AES_KEYGEN_RUNTIME_REJECT_RVS, "AES key generation rejected"):
        cleanup(); raise SystemExit(0)
    raise
params = CK_AES_CTR_PARAMS()
params.ulCounterBits = 32
for i in range(16):
    params.cb[i] = i
mech = CK_MECHANISM()
mech.mechanism = CKM_AES_CTR
mech.pParameter = ctypes.cast(ctypes.byref(params), ctypes.c_void_p)
mech.ulParameterLen = ctypes.sizeof(params)
rv = raw.C_{op}Init(sh, ctypes.byref(mech), aes_key)
if rv != CKR_OK:
    from pkcs11_check.raw.rv import ckr_name as _cn
    print(f"SETUP_XFAIL:C_{op}Init(CKM_AES_CTR) failed: {{_cn(rv)}}")
    raw.C_DestroyObject(sh, aes_key); cleanup(); raise SystemExit(0)
destroy_rv = raw.C_DestroyObject(sh, aes_key)
print(f"DESTROY_RV:0x{{destroy_rv:08x}}")
data = (ctypes.c_ubyte * 16)(*range(16))
out_len = CK_ULONG(0)
op_rv = raw.C_{op}(sh, data, 16, None, ctypes.byref(out_len))
print(f"{op.upper()}_RV:0x{{op_rv:08x}}")
if op_rv == CKR_OK and out_len.value > 0:
    out_buf = (ctypes.c_ubyte * out_len.value)()
    op_rv2 = raw.C_{op}(sh, data, 16, out_buf, ctypes.byref(out_len))
    print(f"{op.upper()}_RV2:0x{{op_rv2:08x}}")
cleanup()
"""


class TestEncryptCtrOperationStateUAF:
    """``C_Encrypt`` (CKM_AES_CTR) after ``C_DestroyObject`` on the active key must not crash."""

    def test_encrypt_ctr_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the AES key mid-CTR-encrypt must not cause a use-after-free crash.

        AES-CTR carries a counter block in the mechanism parameter.  After
        ``C_DestroyObject`` on the active key, the operation's stored key reference
        may point to freed memory.  A conformant module either refuses the destroy
        while the operation is active, returns a clean error from ``C_Encrypt``, or
        (snapshot-based) completes normally.  A crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + _AES_CTR_IMPORTS + _aes_ctr_body("Encrypt"),
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Encrypt(AES-CTR) after C_DestroyObject (operation-state UAF)",
        )
        rv = _parse_rv(out, "ENCRYPT_RV:")
        if rv is not None:
            classify_negative_rv(
                rv,
                _COMPLETION_REJECT_RVS,
                label="C_Encrypt(AES-CTR) after destroy of active key",
                allow_ok=True,
            )
        rv2 = _parse_rv(out, "ENCRYPT_RV2:")
        if rv2 is not None:
            classify_negative_rv(
                rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Encrypt(AES-CTR, 2nd pass) after destroy of active key",
                allow_ok=True,
            )


class TestDecryptCtrOperationStateUAF:
    """``C_Decrypt`` (CKM_AES_CTR) after ``C_DestroyObject`` on the active key must not crash."""

    def test_decrypt_ctr_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the AES key mid-CTR-decrypt must not cause a use-after-free crash.

        AES-CTR carries a counter block in the mechanism parameter.  After
        ``C_DestroyObject`` on the active key, the operation's stored key reference
        may point to freed memory.  A conformant module either refuses the destroy
        while the operation is active, returns a clean error from ``C_Decrypt``, or
        (snapshot-based) completes normally.  A crash is the finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_CTR"):
            pytest.skip("CKM_AES_CTR not supported")
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + _AES_CTR_IMPORTS + _aes_ctr_body("Decrypt"),
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Decrypt(AES-CTR) after C_DestroyObject (operation-state UAF)",
        )
        rv = _parse_rv(out, "DECRYPT_RV:")
        if rv is not None:
            classify_negative_rv(
                rv,
                _COMPLETION_REJECT_RVS,
                label="C_Decrypt(AES-CTR) after destroy of active key",
                allow_ok=True,
            )
        rv2 = _parse_rv(out, "DECRYPT_RV2:")
        if rv2 is not None:
            classify_negative_rv(
                rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Decrypt(AES-CTR, 2nd pass) after destroy of active key",
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


# ---------------------------------------------------------------------------
# Verify probe (CKM_SHA256_HMAC)
# ---------------------------------------------------------------------------

_VERIFY_UAF_IMPORTS = """
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
    CKA_VERIFY,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_OK,
)
"""

_VERIFY_UAF_BODY = """
# --- import a 32-byte generic-secret key with CKA_VERIFY ---
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
token_false = ctypes.c_ubyte(0)
verify_true = ctypes.c_ubyte(1)

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
tmpl[4].type = CKA_VERIFY
tmpl[4].pValue = ctypes.cast(ctypes.pointer(verify_true), ctypes.c_void_p)
tmpl[4].ulValueLen = 1

key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:HMAC verify key import rejected: {ckr_name(rv)}")
    cleanup()
    raise SystemExit(0)

# --- C_VerifyInit ---
mech = CK_MECHANISM()
mech.mechanism = CKM_SHA256_HMAC
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_VerifyInit(sh, ctypes.byref(mech), key.value)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_VerifyInit(CKM_SHA256_HMAC) failed: {ckr_name(rv)}")
    raw.C_DestroyObject(sh, key.value)
    cleanup()
    raise SystemExit(0)

# --- C_DestroyObject while verify operation is active ---
destroy_rv = raw.C_DestroyObject(sh, key.value)
print(f"DESTROY_RV:0x{destroy_rv:08x}")

# --- C_Verify on possibly-freed state (dummy 32-byte signature) ---
data = (ctypes.c_ubyte * 16)(*range(16))
dummy_sig = (ctypes.c_ubyte * 32)(0)
verify_rv = raw.C_Verify(sh, data, 16, dummy_sig, 32)
print(f"VERIFY_RV:0x{verify_rv:08x}")

cleanup()
"""


class TestVerifyOperationStateUAF:
    """``C_Verify`` after ``C_DestroyObject`` on the active key must not crash."""

    def test_verify_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the HMAC key mid-verify must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, ``C_Verify`` may dereference
        the operation's stored key reference, which now points to freed memory
        (CWE-416).  A conformant module either refuses the destroy while the
        operation is active, invalidates the operation so ``C_Verify`` returns a
        clean error, or (snapshot-based) completes normally.  A crash is the
        finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")

        body = _VERIFY_UAF_IMPORTS + _VERIFY_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Verify after C_DestroyObject (operation-state UAF)",
        )
        verify_rv = _parse_rv(out, "VERIFY_RV:")
        if verify_rv is not None:
            classify_negative_rv(
                verify_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Verify after destroy of active HMAC verify key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Decrypt probe (CKM_AES_ECB)
# ---------------------------------------------------------------------------

_DECRYPT_UAF_IMPORTS = """
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.recipes import gen_aes_key
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKM_AES_ECB,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import AES_KEYGEN_RUNTIME_REJECT_RVS
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
"""

_DECRYPT_UAF_BODY = """
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

# --- C_DecryptInit ---
mech = CK_MECHANISM()
mech.mechanism = CKM_AES_ECB
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DecryptInit(sh, ctypes.byref(mech), aes_key)
if rv != CKR_OK:
    from pkcs11_check.raw.rv import ckr_name as _cn
    print(f"SETUP_XFAIL:C_DecryptInit(CKM_AES_ECB) failed: {_cn(rv)}")
    raw.C_DestroyObject(sh, aes_key)
    cleanup()
    raise SystemExit(0)

# --- C_DestroyObject while decrypt operation is active ---
destroy_rv = raw.C_DestroyObject(sh, aes_key)
print(f"DESTROY_RV:0x{destroy_rv:08x}")

# --- C_Decrypt on possibly-freed state (16-byte zero block) ---
ciphertext = (ctypes.c_ubyte * 16)(0)
dec_len = CK_ULONG(0)
dec_rv = raw.C_Decrypt(sh, ciphertext, 16, None, ctypes.byref(dec_len))
print(f"DECRYPT_RV:0x{dec_rv:08x}")
if dec_rv == CKR_OK and dec_len.value > 0:
    dec_buf = (ctypes.c_ubyte * dec_len.value)()
    dec_rv2 = raw.C_Decrypt(sh, ciphertext, 16, dec_buf, ctypes.byref(dec_len))
    print(f"DECRYPT_RV2:0x{dec_rv2:08x}")

cleanup()
"""


class TestDecryptOperationStateUAF:
    """``C_Decrypt`` after ``C_DestroyObject`` on the active key must not crash."""

    def test_decrypt_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying the AES key mid-decrypt must not cause a use-after-free crash.

        After ``C_DestroyObject`` on the active key, ``C_Decrypt`` may dereference
        the operation's stored key reference, which now points to freed memory
        (CWE-416).  A conformant module either refuses the destroy while the
        operation is active, invalidates the operation so ``C_Decrypt`` returns a
        clean error, or (snapshot-based) completes normally.  A crash is the
        finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        body = _DECRYPT_UAF_IMPORTS + _DECRYPT_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Decrypt after C_DestroyObject (operation-state UAF)",
        )
        dec_rv = _parse_rv(out, "DECRYPT_RV:")
        if dec_rv is not None:
            classify_negative_rv(
                dec_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Decrypt after destroy of active AES key",
                allow_ok=True,
            )
        dec_rv2 = _parse_rv(out, "DECRYPT_RV2:")
        if dec_rv2 is not None:
            classify_negative_rv(
                dec_rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Decrypt(2nd pass) after destroy of active AES key",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Derive probe (CKM_ECDH1_DERIVE — use-after-destroy of the base private key)
# ---------------------------------------------------------------------------
#
# C_DeriveKey is atomic (no Init/complete split), so the UAF pattern is
# modelled as a use-after-destroy of the base key handle: generate an EC
# keypair, destroy the private key, then call C_DeriveKey with the stale
# handle.  A conformant module must reject the stale handle with a clean
# CKR (e.g. CKR_KEY_HANDLE_INVALID / CKR_OBJECT_HANDLE_INVALID) without
# dereferencing freed memory.

_DERIVE_UAF_IMPORTS = """
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack_mechanisms import mech_ecdh
from pkcs11_check.raw.recipes import gen_ec_keypair, read_attributes
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKD_NULL,
    CKK_GENERIC_SECRET,
    CKM_ECDH1_DERIVE,
    CKM_EC_KEY_PAIR_GEN,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
"""

_DERIVE_UAF_BODY = """
# --- generate two EC keypairs on P-256 ---
curve_oid = encode_named_curve_parameters("secp256r1")

pub_a = CK_OBJECT_HANDLE(0)
priv_a = CK_OBJECT_HANDLE(0)

# Build the key pair template manually to keep the child script self-contained.
try:
    pub_a_h, priv_a_h = gen_ec_keypair(
        raw,
        sh,
        curve_oid,
        public_attrs={CKA_DERIVE: False, CKA_TOKEN: False},
        private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
    )
except AssertionError as exc:
    print(f"SETUP_XFAIL:EC keypair generation rejected: {exc}")
    cleanup()
    raise SystemExit(0)

try:
    pub_b_h, priv_b_h = gen_ec_keypair(
        raw,
        sh,
        curve_oid,
        public_attrs={CKA_DERIVE: False, CKA_TOKEN: False},
        private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
    )
except AssertionError as exc:
    print(f"SETUP_XFAIL:EC keypair (peer) generation rejected: {exc}")
    raw.C_DestroyObject(sh, pub_a_h)
    raw.C_DestroyObject(sh, priv_a_h)
    cleanup()
    raise SystemExit(0)

# --- read the peer public-key EC point ---
try:
    attrs_b = read_attributes(raw, sh, pub_b_h, [CKA_EC_POINT])
    ec_point_b = bytes(attrs_b[CKA_EC_POINT])
except AssertionError as exc:
    print(f"SETUP_XFAIL:Could not read peer EC point: {exc}")
    for h in (pub_a_h, priv_a_h, pub_b_h, priv_b_h):
        raw.C_DestroyObject(sh, h)
    cleanup()
    raise SystemExit(0)

# Destroy peer keypair — only the peer's public point is needed hereafter.
raw.C_DestroyObject(sh, pub_b_h)
raw.C_DestroyObject(sh, priv_b_h)

# --- destroy the *base* private key before C_DeriveKey ---
destroy_rv = raw.C_DestroyObject(sh, priv_a_h)
print(f"DESTROY_RV:0x{destroy_rv:08x}")
raw.C_DestroyObject(sh, pub_a_h)

# --- derive template: a 32-byte generic-secret ---
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
val_len_val = CK_ULONG(32)
token_false = ctypes.c_ubyte(0)
sensitive_false = ctypes.c_ubyte(0)
extractable_true = ctypes.c_ubyte(1)

derive_tmpl = (CK_ATTRIBUTE * 5)()
derive_tmpl[0].type = CKA_CLASS
derive_tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
derive_tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
derive_tmpl[1].type = CKA_KEY_TYPE
derive_tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
derive_tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
derive_tmpl[2].type = CKA_TOKEN
derive_tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_false), ctypes.c_void_p)
derive_tmpl[2].ulValueLen = 1
derive_tmpl[3].type = CKA_SENSITIVE
derive_tmpl[3].pValue = ctypes.cast(ctypes.pointer(sensitive_false), ctypes.c_void_p)
derive_tmpl[3].ulValueLen = 1
derive_tmpl[4].type = CKA_EXTRACTABLE
derive_tmpl[4].pValue = ctypes.cast(ctypes.pointer(extractable_true), ctypes.c_void_p)
derive_tmpl[4].ulValueLen = 1

packed_mech = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=ec_point_b)
derived_key = CK_OBJECT_HANDLE(0)

# --- C_DeriveKey with the already-destroyed private key handle ---
derive_rv = raw.C_DeriveKey(
    sh,
    packed_mech.byref(),
    priv_a_h,
    ctypes.cast(derive_tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(derived_key),
)
print(f"DERIVE_RV:0x{derive_rv:08x}")

if derive_rv == CKR_OK and derived_key.value != 0:
    raw.C_DestroyObject(sh, derived_key.value)

cleanup()
"""


class TestDeriveOperationStateUAF:
    """``C_DeriveKey`` with a destroyed base-key handle must not cause a UAF crash."""

    def test_derive_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Using a destroyed private-key handle in ``C_DeriveKey`` must not UAF.

        ``C_DeriveKey`` is atomic (no Init/complete split), so the use-after-free
        pattern is modelled as a use-after-destroy of the base key: the EC private
        key is destroyed immediately before ``C_DeriveKey`` is called with the stale
        handle.  A conformant module must reject the stale handle with a clean error
        (CWE-416) rather than dereferencing freed memory.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        body = _DERIVE_UAF_IMPORTS + _DERIVE_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_DeriveKey with destroyed base-key handle (use-after-destroy)",
        )
        derive_rv = _parse_rv(out, "DERIVE_RV:")
        if derive_rv is not None:
            classify_negative_rv(
                derive_rv,
                _COMPLETION_REJECT_RVS,
                label="C_DeriveKey with destroyed EC private key handle",
                allow_ok=True,
            )


# ---------------------------------------------------------------------------
# Cross-session probe: token key sign-inited in session A, destroyed from B
# ---------------------------------------------------------------------------
#
# Token objects are shared across sessions on the same slot.  If the module
# tracks the key reference by raw pointer and a second session frees the
# object store entry, the first session's pending C_Sign may dereference freed
# memory.  The probe exercises this path single-threadedly, sequentially:
#   Session A: C_SignInit(token_key)
#   Session B: C_DestroyObject(token_key)
#   Session A: C_Sign(...)
# A crash is the only finding; completion and clean rejection are both
# conformant (CWE-416, PKCS#11 object-lifecycle / session-sharing semantics).

_XSESSION_UAF_IMPORTS = """
import ctypes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_NOTIFY,
    CK_OBJECT_HANDLE,
    CK_SESSION_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_GENERIC_SECRET,
    CKM_SHA256_HMAC,
    CKO_SECRET_KEY,
    CKR_OK,
)
"""

_XSESSION_UAF_BODY = """
# --- create a TOKEN sign key on session A (sh) ---
key_bytes = (ctypes.c_ubyte * 32)(*range(32))
cls_val = CK_ULONG(CKO_SECRET_KEY)
key_type_val = CK_ULONG(CKK_GENERIC_SECRET)
token_true = ctypes.c_ubyte(1)
sign_true = ctypes.c_ubyte(1)

tmpl = (CK_ATTRIBUTE * 5)()
tmpl[0].type = CKA_CLASS
tmpl[0].pValue = ctypes.cast(ctypes.pointer(cls_val), ctypes.c_void_p)
tmpl[0].ulValueLen = ctypes.sizeof(cls_val)
tmpl[1].type = CKA_KEY_TYPE
tmpl[1].pValue = ctypes.cast(ctypes.pointer(key_type_val), ctypes.c_void_p)
tmpl[1].ulValueLen = ctypes.sizeof(key_type_val)
tmpl[2].type = CKA_TOKEN
tmpl[2].pValue = ctypes.cast(ctypes.pointer(token_true), ctypes.c_void_p)
tmpl[2].ulValueLen = 1
tmpl[3].type = CKA_VALUE
tmpl[3].pValue = ctypes.cast(key_bytes, ctypes.c_void_p)
tmpl[3].ulValueLen = 32
tmpl[4].type = CKA_SIGN
tmpl[4].pValue = ctypes.cast(ctypes.pointer(sign_true), ctypes.c_void_p)
tmpl[4].ulValueLen = 1

token_key = CK_OBJECT_HANDLE(0)
rv = raw.C_CreateObject(
    sh,
    ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE)),
    5,
    ctypes.byref(token_key),
)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:TOKEN HMAC key creation not operational: {ckr_name(rv)}")
    cleanup()
    raise SystemExit(0)

# --- open session B on the same slot ---
sh_b = CK_SESSION_HANDLE(0)
rv_b = raw.C_OpenSession(
    slot_id,
    CKF_SERIAL_SESSION | CKF_RW_SESSION,
    None,
    CK_NOTIFY(),
    ctypes.byref(sh_b),
)
if rv_b != CKR_OK:
    print(f"SETUP_XFAIL:C_OpenSession(session B) failed: {ckr_name(rv_b)}")
    raw.C_DestroyObject(sh, token_key.value)
    cleanup()
    raise SystemExit(0)

# --- C_SignInit in session A with the token key ---
mech = CK_MECHANISM()
mech.mechanism = CKM_SHA256_HMAC
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_SignInit(sh, ctypes.byref(mech), token_key.value)
if rv != CKR_OK:
    print(f"SETUP_XFAIL:C_SignInit(CKM_SHA256_HMAC) in session A failed: {ckr_name(rv)}")
    raw.C_DestroyObject(sh, token_key.value)
    raw.C_CloseSession(sh_b.value)
    cleanup()
    raise SystemExit(0)

# --- C_DestroyObject from session B ---
destroy_rv = raw.C_DestroyObject(sh_b.value, token_key.value)
print(f"DESTROY_RV:0x{destroy_rv:08x}")

# --- C_Sign in session A (operation may reference freed/invalid key) ---
data = (ctypes.c_ubyte * 16)(*range(16))
sig_len = CK_ULONG(0)
xsession_rv = raw.C_Sign(sh, data, 16, None, ctypes.byref(sig_len))
print(f"XSESSION_SIGN_RV:0x{xsession_rv:08x}")
if xsession_rv == CKR_OK:
    sig_buf = (ctypes.c_ubyte * sig_len.value)()
    xsession_rv2 = raw.C_Sign(sh, data, 16, sig_buf, ctypes.byref(sig_len))
    print(f"XSESSION_SIGN_RV2:0x{xsession_rv2:08x}")

# --- clean up session B and token object (best-effort; may already be gone) ---
raw.C_DestroyObject(sh_b.value, token_key.value)
raw.C_CloseSession(sh_b.value)

cleanup()
"""


class TestCrossSessionOperationStateUAF:
    """Cross-session UAF: token key destroyed from session B during active sign in A."""

    def test_cross_session_sign_after_destroy_does_not_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying a token key from session B while session A has it sign-inited.

        Token objects are visible across all sessions on the same slot.  If the
        module tracks the active operation's key by raw pointer and another session
        frees the backing object, the pending ``C_Sign`` in session A may dereference
        freed memory (CWE-416).  Conformant outcomes: the destroy is refused while
        the operation is active, the operation is invalidated so ``C_Sign`` returns a
        clean error, or (snapshot-based) the sign completes normally.  A crash is the
        finding.  The token object is cleaned up before the probe exits so no
        persistent mutation is left on the token.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")

        body = _XSESSION_UAF_IMPORTS + _XSESSION_UAF_BODY
        rc, out, err = run_with_coverage(
            _preamble(p11_config) + body,
            timeout=15,
            pin=pin_from_config(p11_config),
        )
        assert_subprocess_no_crash(
            rc,
            out,
            err,
            context="C_Sign in session A after C_DestroyObject from session B (cross-session UAF)",
        )
        xsession_rv = _parse_rv(out, "XSESSION_SIGN_RV:")
        if xsession_rv is not None:
            classify_negative_rv(
                xsession_rv,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(session A) after cross-session destroy of active token key",
                allow_ok=True,
            )
        xsession_rv2 = _parse_rv(out, "XSESSION_SIGN_RV2:")
        if xsession_rv2 is not None:
            classify_negative_rv(
                xsession_rv2,
                _COMPLETION_REJECT_RVS,
                label="C_Sign(session A, 2nd pass) after cross-session destroy of active token key",
                allow_ok=True,
            )
