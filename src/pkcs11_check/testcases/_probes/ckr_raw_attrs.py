"""Probe: CKA_*=False permission flags tested via raw C_*Init calls.

Ported verbatim from the legacy ``ckr/test_ckr_raw_attrs.py`` child scripts, which
drove the module through a logged-in ``RawPKCS11`` session built by
``subprocess_session_preamble``.  Each probe generates an AES key with one usage
attribute (``CKA_ENCRYPT`` / ``CKA_SIGN`` / ``CKA_DECRYPT``) set to False, reads the
flag back (claim check), then issues the matching raw ``C_*Init`` -- bypassing the
python-pkcs11 wrapper's attribute checks -- so the parent can classify whether the
module honored the restriction (PKCS#11 v3.2 requires ``CKR_KEY_FUNCTION_NOT_PERMITTED``).

Runs through ``probe_main`` at ``Level.LOGIN``: the infra does C_Initialize + slot
discovery + ``C_OpenSession`` + (only when ``_P11CHECK_PIN`` is set) ``C_Login`` before
handing the probe ``ctx.raw`` / ``ctx.sh`` -- mirroring the legacy child, which opened a
session and logged in only when a PIN was configured.  The PIN travels ONLY via the
``_P11CHECK_PIN`` env var; it is never read, printed, or embedded here or in the probe
params (Invariant I3).  Session teardown + rv-trace are handled by ``probe_main`` atexit.

Dispatch on ``extra["probe"]`` (one child body each):
  ``"encrypt"`` -> key with CKA_ENCRYPT=False, then ``C_EncryptInit`` (CKM_AES_ECB)
  ``"sign"``    -> key with CKA_SIGN=False, then ``C_SignInit`` (CKM_SHA256_HMAC)
  ``"decrypt"`` -> key with CKA_DECRYPT=False, then ``C_DecryptInit`` (CKM_AES_ECB)

Output protocol (byte-identical to the legacy child, for ``assert_ckr_subprocess_ok``
plus the parent's ``_classify_permission_flag``):
  ``CLAIM:0``                                                 -- key read the flag back as False
  ``CLAIM:1``                                                 -- flag not honored / absent
  ``CKR:0x{rv:08x}``                                          -- return value of the C_*Init call
  ``OK``                                                      -- probe reached its end
  ``SETUP_XFAIL:C_GenerateKey for CKA_ENCRYPT=False failed: {name}``  -- keygen setup reject
  ``SETUP_XFAIL:C_GenerateKey for CKA_SIGN=False failed: {name}``     -- keygen setup reject
  ``SETUP_XFAIL:C_GenerateKey for CKA_DECRYPT=False failed: {name}``  -- keygen setup reject

Required ``extra`` keys:
  ``"probe"`` -- ``"encrypt"``, ``"sign"``, or ``"decrypt"``.

Launch with ``coverage="session"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

from collections.abc import Callable
from ctypes import byref, cast
from typing import Any

from pkcs11_check.raw.pack import attr_bool, attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import read_attributes
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
    CKM_SHA256_HMAC,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _template_ptr(attrs: Any) -> Any:
    return cast(attrs.array, CK_ATTRIBUTE_PTR)


def _claim(ctx: ProbeContext, sh: int, key_value: int, attr: int) -> None:
    # CLAIM:0 if the key reports the permission flag back as False (module
    # claims the restriction), CLAIM:1 otherwise (not honored / absent).
    vals = read_attributes(ctx.raw, sh, key_value, [attr])
    print("CLAIM:0" if vals.get(attr) is False else "CLAIM:1")


def _flag_not_permitted(
    ctx: ProbeContext,
    *,
    false_attr: int,
    false_attr_name: str,
    counterpart_attr: int,
    op_mech: int,
    op_init: str,
) -> None:
    """Generate an AES key with *false_attr*=False, then call *op_init* on it."""
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh
    attrs = template(
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(false_attr, False),
        attr_bool(counterpart_attr, True),
        attr_bool(CKA_TOKEN, False),
    )
    mech_kg = mech_simple(CKM_AES_KEY_GEN)
    key = CK_OBJECT_HANDLE(0)
    rv = ctx.raw.C_GenerateKey(sh, mech_kg.byref(), _template_ptr(attrs), attrs.count, byref(key))
    if rv != CKR_OK:
        print(f"SETUP_XFAIL:C_GenerateKey for {false_attr_name}=False failed: {ckr_name(rv)}")
        return
    _claim(ctx, sh, key.value, false_attr)
    mech = mech_simple(op_mech)
    init = getattr(ctx.raw, op_init)
    rv = init(sh, mech.byref(), key.value)
    print(f"CKR:0x{rv:08x}")
    # Report result without asserting -- outer test checks security compliance
    print("OK")


def _encrypt(ctx: ProbeContext) -> None:
    _flag_not_permitted(
        ctx,
        false_attr=CKA_ENCRYPT,
        false_attr_name="CKA_ENCRYPT",
        counterpart_attr=CKA_DECRYPT,
        op_mech=CKM_AES_ECB,
        op_init="C_EncryptInit",
    )


def _sign(ctx: ProbeContext) -> None:
    _flag_not_permitted(
        ctx,
        false_attr=CKA_SIGN,
        false_attr_name="CKA_SIGN",
        counterpart_attr=CKA_ENCRYPT,
        op_mech=CKM_SHA256_HMAC,
        op_init="C_SignInit",
    )


def _decrypt(ctx: ProbeContext) -> None:
    _flag_not_permitted(
        ctx,
        false_attr=CKA_DECRYPT,
        false_attr_name="CKA_DECRYPT",
        counterpart_attr=CKA_ENCRYPT,
        op_mech=CKM_AES_ECB,
        op_init="C_DecryptInit",
    )


_PROBES: dict[str, Callable[[ProbeContext], None]] = {
    "encrypt": _encrypt,
    "sign": _sign,
    "decrypt": _decrypt,
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
