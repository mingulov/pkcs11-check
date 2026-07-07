"""Probe: CKR operation-state violations driven through a logged-in RawPKCS11 session.

Five double-Init / cross-operation state-machine violations, ported verbatim from the
legacy ``ckr/test_ckr_raw_state.py`` child scripts.  Each shares a preamble that generates
a 32-byte AES key (ENCRYPT | DECRYPT | SIGN, session object) then drives the per-probe state
violation; the parent classifies the child's ``CKR:0x...`` line via ``_classify_state_ckr``.

Runs through ``probe_main`` at ``Level.LOGIN``: the infra does C_Initialize + slot discovery
+ ``C_OpenSession`` + (only when ``_P11CHECK_PIN`` is set) ``C_Login`` before handing the
probe ``ctx.raw`` / ``ctx.sh`` -- mirroring the legacy child, which opened a session and
logged in *only* when a PIN was configured.  The PIN travels ONLY via the ``_P11CHECK_PIN``
env var; it is never read, printed, or embedded here or in the probe params (Invariant I3).
This CLOSES the legacy leak that formatted the PIN literal into the generated child script.
Session teardown + rv-trace are handled by ``probe_main`` atexit, matching the legacy
``_p11check_cleanup_session`` / rv-trace setup.  All five probes run the shared keygen
(and hence require login) exactly as the legacy shared preamble did.

Dispatch on ``extra["probe"]`` (one child body each):
  ``"double_encrypt_init"``    -> two ``C_EncryptInit`` (first CKR_OK, print second rv)
  ``"encrypt_then_sign_init"`` -> ``C_EncryptInit`` then ``C_SignInit`` (print sign rv)
  ``"double_digest_init"``     -> two ``C_DigestInit`` (first CKR_OK, print second rv)
  ``"double_sign_init"``       -> two ``C_SignInit`` (or first_init_failed suffix)
  ``"double_decrypt_init"``    -> two ``C_DecryptInit`` (first CKR_OK, print second rv)

Output protocol (byte-identical to the legacy child, for ``assert_ckr_subprocess_ok`` +
the parent ``_classify_state_ckr``):
  ``CKR:0x{rv:08x}``                             -- return value of the second *Init call
  ``CKR:0x{rv:08x}:first_init_failed``           -- double_sign_init when the first fails
  ``OK``                                         -- probe reached its expected point
  ``SETUP_XFAIL:C_GenerateKey failed:{name}``    -- shared AES keygen setup reject

A wrong CK_RV trips the child ``assert`` (non-zero exit) -> the parent reports a child
failure; a crash (returncode < 0) is a provider crash finding.

Required ``extra`` keys:
  ``"probe"`` -- one of the dispatch keys above.

Launch with ``coverage="session"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

from ctypes import byref, cast
from typing import Any

from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _template_ptr(attrs: Any) -> Any:
    return cast(attrs.array, CK_ATTRIBUTE_PTR)


def _gen_key(ctx: ProbeContext) -> int | None:
    """Generate the shared AES key (mirrors the legacy preamble).

    Returns the key handle, or ``None`` after printing the setup-xfail line when
    ``C_GenerateKey`` cleanly refuses (advertised-but-not-operational keygen).
    """
    mech_keygen = mech_simple(CKM_AES_KEY_GEN)
    key = CK_OBJECT_HANDLE(0)
    attrs = template(
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(CKA_ENCRYPT, True),
        attr_bool(CKA_DECRYPT, True),
        attr_bool(CKA_SIGN, True),
        attr_bool(CKA_TOKEN, False),
    )
    rv = ctx.raw.C_GenerateKey(
        ctx.sh, mech_keygen.byref(), _template_ptr(attrs), attrs.count, byref(key)
    )
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_GenerateKey failed:{ckr_name(rv)}")
        return None
    return key.value


def _double_encrypt_init(ctx: ProbeContext, key_handle: int) -> None:
    mech = mech_simple(CKM_AES_ECB)
    rv1 = ctx.raw.C_EncryptInit(ctx.sh, mech.byref(), key_handle)
    assert rv1 == CKR_OK, f"First EncryptInit failed: 0x{rv1:08x}"
    rv2 = ctx.raw.C_EncryptInit(ctx.sh, mech.byref(), key_handle)
    print(f"CKR:0x{rv2:08x}")
    # Second should be OPERATION_ACTIVE (or module may cancel first -> CKR_OK)
    print("OK")


def _encrypt_then_sign_init(ctx: ProbeContext, key_handle: int) -> None:
    mech = mech_simple(CKM_AES_ECB)
    rv1 = ctx.raw.C_EncryptInit(ctx.sh, mech.byref(), key_handle)
    assert rv1 == CKR_OK

    # Now try SignInit - should be OPERATION_ACTIVE
    sign_mech = mech_simple(CKM_SHA256_HMAC)
    rv2 = ctx.raw.C_SignInit(ctx.sh, sign_mech.byref(), key_handle)
    print(f"CKR:0x{rv2:08x}")
    # OPERATION_ACTIVE, OK (dual-crypto), MECHANISM_INVALID (no CMAC support),
    # KEY_FUNCTION_NOT_PERMITTED, or other init errors - all acceptable
    # The key test: did NOT segfault.
    print("OK")
    print("OK")


def _double_digest_init(ctx: ProbeContext, _key_handle: int) -> None:
    mech = mech_simple(CKM_SHA256)
    rv1 = ctx.raw.C_DigestInit(ctx.sh, mech.byref())
    assert rv1 == CKR_OK

    rv2 = ctx.raw.C_DigestInit(ctx.sh, mech.byref())
    print(f"CKR:0x{rv2:08x}")
    print("OK")


def _double_sign_init(ctx: ProbeContext, key_handle: int) -> None:
    mech = mech_simple(CKM_AES_ECB)  # AES_ECB (for testing state)
    # Use key_handle from preamble (AES key with SIGN=True)
    rv1 = ctx.raw.C_SignInit(ctx.sh, mech.byref(), key_handle)
    # First init may fail if AES-ECB not valid for sign - that's OK
    if rv1 == CKR_OK:
        rv2 = ctx.raw.C_SignInit(ctx.sh, mech.byref(), key_handle)
        print(f"CKR:0x{rv2:08x}")
    else:
        print(f"CKR:0x{rv1:08x}:first_init_failed")
    print("OK")


def _double_decrypt_init(ctx: ProbeContext, key_handle: int) -> None:
    mech = mech_simple(CKM_AES_ECB)
    rv1 = ctx.raw.C_DecryptInit(ctx.sh, mech.byref(), key_handle)
    assert rv1 == CKR_OK, f"First DecryptInit: 0x{rv1:08x}"
    rv2 = ctx.raw.C_DecryptInit(ctx.sh, mech.byref(), key_handle)
    print(f"CKR:0x{rv2:08x}")
    print("OK")


_PROBES = {
    "double_encrypt_init": _double_encrypt_init,
    "encrypt_then_sign_init": _encrypt_then_sign_init,
    "double_digest_init": _double_digest_init,
    "double_sign_init": _double_sign_init,
    "double_decrypt_init": _double_decrypt_init,
}


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    try:
        handler = _PROBES[probe]
    except KeyError:
        raise ValueError(f"unknown probe {probe!r}") from None
    key_handle = _gen_key(ctx)
    if key_handle is None:
        return
    handler(ctx, key_handle)


if __name__ == "__main__":
    probe_main(_run, level=Level.LOGIN)
