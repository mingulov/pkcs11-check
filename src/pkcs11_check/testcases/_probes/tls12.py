"""Probe: TLS negative-attribute enforcement via a logged-in RawPKCS11 session.

Two child bodies ported verbatim from the legacy ``test_tls12.py`` negative-attribute
subprocess scripts, dispatched on ``extra["probe"]``.  Each imports a generic secret key that
lacks the attribute under test (``CKA_DERIVE=False`` / ``CKA_SIGN=False``) via
``C_CreateObject`` -- using the raw ctypes path so the python-pkcs11 wrapper cannot strip the
corresponding method -- then drives the operation the missing attribute must forbid and prints
the resulting ``CKR:0x...`` line plus an ``OK:`` / ``FAIL:`` / ``REJECTED:`` verdict for the
parent-side scan.

Runs through ``probe_main`` at ``Level.LOGIN``: the infra does C_Initialize + slot discovery
+ ``C_OpenSession`` + (only when ``_P11CHECK_PIN`` is set) ``C_Login`` before handing the
probe ``ctx.raw`` / ``ctx.sh`` -- mirroring the legacy script, which opened a session and
logged in *only* when a PIN was configured.  The PIN travels ONLY via the ``_P11CHECK_PIN``
env var; it is never read, printed, or embedded here or in the probe params.  This CLOSES the
legacy leak, where the unwrapped user PIN was formatted as a literal into the generated
child-script source (Invariant I3).  Session teardown is handled by ``probe_main`` atexit,
matching the legacy template's trailing ``C_CloseSession`` / ``C_Finalize``.

Output protocol (byte-identical to the legacy child, for the parent scan of ``out``):
  ``SKIP:create_failed:0x{rv:08x}``               -- C_CreateObject refused the setup key
  ``CKR:0x{rv:08x}``                              -- return value of the forbidden operation
  ``OK:KEY_FUNCTION_NOT_PERMITTED``               -- rejected with the expected code
  ``FAIL:allowed_derive_with_DERIVE_false``       -- module permitted derive despite DERIVE=False
  ``FAIL:allowed_sign_with_SIGN_false``           -- module permitted sign despite SIGN=False
  ``REJECTED:0x{rv:08x}``                         -- rejected with some other clean code

The legacy ``sign`` body checks ``rv == 0x69`` (CKR_KEY_NOT_WRAPPABLE) while printing the
``KEY_FUNCTION_NOT_PERMITTED`` label; that exact numeric check and label are preserved
verbatim for byte-identity (I5), not "fixed", so the parent's ``FAIL:``/``SKIP:`` scan sees
identical output.

Required ``extra`` keys:
  ``"probe"`` -- ``"derive_without_derive_attr"`` or ``"sign_without_sign_attr"``.

Launch with ``coverage="session"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

from ctypes import byref, cast
from typing import Any

from pkcs11_check.raw.pack import attr_bool, attr_bytes, attr_ulong, mech_simple, template
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE_PTR,
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_TLS12_MAC,
    CKM_TLS12_MASTER_KEY_DERIVE,
    CKO_SECRET_KEY,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _template_ptr(attrs: Any) -> Any:
    return cast(attrs.array, CK_ATTRIBUTE_PTR)


def _derive_without_derive_attr(ctx: ProbeContext) -> None:
    # Create generic secret key with DERIVE=False
    val = bytes(range(48))
    attrs = template(
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        attr_bytes(CKA_VALUE, val),
        attr_ulong(CKA_VALUE_LEN, 48),
        attr_bool(CKA_DERIVE, False),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
    )
    key = CK_OBJECT_HANDLE(0)
    rv = ctx.raw.C_CreateObject(ctx.sh, _template_ptr(attrs), attrs.count, byref(key))
    if rv != CKR_OK:
        print(f"SKIP:create_failed:0x{rv:08x}")
        return

    # Try C_DeriveKey - should be rejected
    mech = mech_simple(CKM_TLS12_MASTER_KEY_DERIVE)
    out_key = CK_OBJECT_HANDLE(0)
    rv = ctx.raw.C_DeriveKey(ctx.sh, mech.byref(), key.value, None, 0, byref(out_key))
    print(f"CKR:0x{rv:08x}")
    if rv in (CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_NOT_WRAPPABLE):
        print("OK:KEY_FUNCTION_NOT_PERMITTED")
    elif rv == 0:
        print("FAIL:allowed_derive_with_DERIVE_false")
    else:
        print(f"REJECTED:0x{rv:08x}")

    ctx.raw.C_DestroyObject(ctx.sh, key.value)


def _sign_without_sign_attr(ctx: ProbeContext) -> None:
    # Create generic secret key with SIGN=False
    val = bytes(range(32))
    attrs = template(
        attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
        attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
        attr_bytes(CKA_VALUE, val),
        attr_ulong(CKA_VALUE_LEN, 32),
        attr_bool(CKA_SIGN, False),
        attr_bool(CKA_TOKEN, False),
        attr_bool(CKA_SENSITIVE, False),
        attr_bool(CKA_EXTRACTABLE, True),
    )
    key = CK_OBJECT_HANDLE(0)
    rv = ctx.raw.C_CreateObject(ctx.sh, _template_ptr(attrs), attrs.count, byref(key))
    if rv != CKR_OK:
        print(f"SKIP:create_failed:0x{rv:08x}")
        return

    # Try C_SignInit with CKA_SIGN=False key
    mech = mech_simple(CKM_TLS12_MAC)
    rv = ctx.raw.C_SignInit(ctx.sh, mech.byref(), key.value)
    print(f"CKR:0x{rv:08x}")
    # Legacy checks 0x69 (== CKR_KEY_NOT_WRAPPABLE) under the KEY_FUNCTION_NOT_PERMITTED
    # label; the numeric check and label are preserved verbatim for byte-identity (I5).
    if rv == CKR_KEY_NOT_WRAPPABLE:
        print("OK:KEY_FUNCTION_NOT_PERMITTED")
    elif rv == 0:
        print("FAIL:allowed_sign_with_SIGN_false")
    else:
        print(f"REJECTED:0x{rv:08x}")

    ctx.raw.C_DestroyObject(ctx.sh, key.value)


_PROBES = {
    "derive_without_derive_attr": _derive_without_derive_attr,
    "sign_without_sign_attr": _sign_without_sign_attr,
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
