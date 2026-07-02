"""Probe: CKR_ARGUMENTS_BAD checks -- NULL pointers to C_* functions.

Tests that passing NULL where a valid pointer is required returns
CKR_ARGUMENTS_BAD (0x07) (or a sanctioned near-equivalent).  Modules that
segfault instead are recorded as crash findings by the parent classifier.

Ported verbatim from the legacy ``ckr/test_ckr_raw_args_bad.py`` child scripts,
which drove the module through a logged-in ``RawPKCS11`` session built by
``subprocess_session_preamble``.  Runs through ``probe_main`` at ``Level.LOGIN``:
the infra does C_Initialize + slot discovery + ``C_OpenSession`` + (only when
``_P11CHECK_PIN`` is set) ``C_Login`` before handing the probe ``ctx.raw`` /
``ctx.sh``.  The PIN travels ONLY via the ``_P11CHECK_PIN`` env var; it is never
read, printed, or embedded here or in the probe params (Invariant I3).  Session
teardown + rv-trace are handled by ``probe_main`` atexit.

Dispatch on ``extra["probe"]`` (one child body each):
  ``"encrypt_init"`` -> generate an AES key, then ``C_EncryptInit`` with NULL mech
  ``"decrypt_init"`` -> generate an AES key, then ``C_DecryptInit`` with NULL mech
  ``"sign_init"``    -> ``C_SignInit`` with NULL mech
  ``"verify_init"``  -> ``C_VerifyInit`` with NULL mech
  ``"digest_init"``  -> ``C_DigestInit`` with NULL mech
  ``"generate_key"`` -> ``C_GenerateKey`` with NULL mech
  ``"wrap_key"``     -> ``C_WrapKey`` with NULL mech
  ``"derive_key"``   -> ``C_DeriveKey`` with NULL mech

Output protocol (byte-identical to the legacy child, for ``assert_ckr_subprocess_ok``):
  ``CKR:0x{rv:08x}``                                          -- return value of the call
  ``OK``                                                      -- probe reached its expected CKR
  ``SETUP_XFAIL:C_GenerateKey for AES encrypt setup failed: {name}``  -- keygen setup reject
  ``SETUP_XFAIL:C_GenerateKey for AES decrypt setup failed: {name}``  -- keygen setup reject

A wrong CK_RV trips the child ``assert`` (non-zero exit) -> the parent reports a child
failure; a crash (returncode < 0) is a provider crash finding.

Required ``extra`` keys:
  ``"probe"`` -- one of the dispatch keys above.

Launch with ``coverage="session"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

import ctypes
from ctypes import byref, cast
from typing import Any

from pkcs11_check.raw.faults import null_pointer
from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
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
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main

# NULL mechanism pointer: acceptable CKR codes for operation-init functions
# with cancellation semantics per OASIS PKCS#11 v3.2.
# CKR_ARGUMENTS_BAD -- NULL pointer is bad argument
# CKR_MECHANISM_INVALID -- NULL interpreted as invalid mechanism (some modules)
# CKR_MECHANISM_PARAM_INVALID -- NULL mechanism params interpreted as invalid
# CKR_OK -- v3.0+ spec allows NULL mech to cancel an in-progress operation
_NULL_MECH_OK = (
    CKR_ARGUMENTS_BAD,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)


def _template_ptr(attrs: Any) -> Any:
    return cast(attrs.array, CK_ATTRIBUTE_PTR)


def _init_with_null_mech(ctx: ProbeContext, *, encrypt: bool, label: str) -> None:
    """Generate an AES key then call C_{En,De}cryptInit with a NULL mechanism."""
    attrs = template(
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(CKA_ENCRYPT if encrypt else CKA_DECRYPT, True),
        attr_bool(CKA_TOKEN, False),
    )
    mech_kg = mech_simple(CKM_AES_KEY_GEN)
    key = CK_OBJECT_HANDLE(0)
    rv = ctx.raw.C_GenerateKey(
        ctx.sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key)
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_GenerateKey for AES {label} setup failed: {ckr_name(rv)}")
        return
    # PKCS#11 v3.2: NULL mech ptr => ARGUMENTS_BAD; some modules interpret it as MECHANISM_INVALID
    init = ctx.raw.C_EncryptInit if encrypt else ctx.raw.C_DecryptInit
    rv = init(ctx.sh, null_pointer().pointer, key.value)
    print(f"CKR:0x{rv:08x}")
    assert rv in _NULL_MECH_OK, f"Got 0x{rv:08x}"
    print("OK")


def _encrypt_init(ctx: ProbeContext) -> None:
    _init_with_null_mech(ctx, encrypt=True, label="encrypt")


def _decrypt_init(ctx: ProbeContext) -> None:
    _init_with_null_mech(ctx, encrypt=False, label="decrypt")


def _sign_init(ctx: ProbeContext) -> None:
    # PKCS#11 v3.2: NULL mech ptr => ARGUMENTS_BAD; some modules interpret it as MECHANISM_INVALID
    rv = ctx.raw.C_SignInit(ctx.sh, null_pointer().pointer, 0)
    print(f"CKR:0x{rv:08x}")
    assert rv in _NULL_MECH_OK, f"Got 0x{rv:08x}"
    print("OK")


def _verify_init(ctx: ProbeContext) -> None:
    # PKCS#11 v3.2: NULL mech ptr => ARGUMENTS_BAD; some modules interpret it as MECHANISM_INVALID
    rv = ctx.raw.C_VerifyInit(ctx.sh, null_pointer().pointer, 0)
    print(f"CKR:0x{rv:08x}")
    assert rv in _NULL_MECH_OK, f"Got 0x{rv:08x}"
    print("OK")


def _digest_init(ctx: ProbeContext) -> None:
    rv = ctx.raw.C_DigestInit(ctx.sh, null_pointer().pointer)
    print(f"CKR:0x{rv:08x}")
    assert rv in (CKR_ARGUMENTS_BAD, CKR_OK), f"Got 0x{rv:08x}"  # audit-ok: cancel, CKR_OK per v3+
    print("OK")


def _generate_key(ctx: ProbeContext) -> None:
    key = ctypes.c_ulong(0)
    rv = ctx.raw.C_GenerateKey(ctx.sh, null_pointer().pointer, None, 0, ctypes.byref(key))
    print(f"CKR:0x{rv:08x}")
    assert rv == CKR_ARGUMENTS_BAD, f"Got 0x{rv:08x}"
    print("OK")


def _wrap_key(ctx: ProbeContext) -> None:
    out_len = ctypes.c_ulong(256)
    rv = ctx.raw.C_WrapKey(ctx.sh, null_pointer().pointer, 0, 0, None, ctypes.byref(out_len))
    print(f"CKR:0x{rv:08x}")
    # Providers may validate the NULL mechanism first, or the deliberately invalid
    # zero object handles first.
    assert rv in (
        CKR_ARGUMENTS_BAD,
        CKR_KEY_HANDLE_INVALID,
        CKR_OBJECT_HANDLE_INVALID,
        CKR_MECHANISM_INVALID,
    ), f"Got 0x{rv:08x}"
    print("OK")


def _derive_key(ctx: ProbeContext) -> None:
    # PKCS#11 v3.2: NULL mech ptr => ARGUMENTS_BAD; some modules interpret it as MECHANISM_INVALID
    key = ctypes.c_ulong(0)
    rv = ctx.raw.C_DeriveKey(ctx.sh, null_pointer().pointer, 0, None, 0, ctypes.byref(key))
    print(f"CKR:0x{rv:08x}")
    assert rv in (
        CKR_ARGUMENTS_BAD,
        CKR_MECHANISM_INVALID,
        CKR_MECHANISM_PARAM_INVALID,
        CKR_KEY_HANDLE_INVALID,
        CKR_OBJECT_HANDLE_INVALID,
    ), f"Got 0x{rv:08x}"
    print("OK")


_PROBES = {
    "encrypt_init": _encrypt_init,
    "decrypt_init": _decrypt_init,
    "sign_init": _sign_init,
    "verify_init": _verify_init,
    "digest_init": _digest_init,
    "generate_key": _generate_key,
    "wrap_key": _wrap_key,
    "derive_key": _derive_key,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    handler(ctx)


if __name__ == "__main__":
    probe_main(_run, level=Level.LOGIN)
